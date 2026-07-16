from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from database.postgres import get_async_db_conn
from database.neo4j_db import get_async_neo4j_driver
from database.elasticsearch_db import get_async_elasticsearch_client
from routers.screening import perform_sanctions_search
from services.auth import get_current_user, RoleChecker

router = APIRouter(prefix="/api/v1/onboard", tags=["Onboarding"])


from pydantic import BaseModel, Field, field_validator
from observability.sanitizer import sanitize_text

class IndividualOnboard(BaseModel):
    tenant_id: str = Field(..., min_length=1, max_length=50)
    account_number: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_-]+$")
    swift_bic: str | None = Field(None, min_length=8, max_length=11, pattern=r"^[A-Z0-9]{8,11}$")
    name: str = Field(..., min_length=1, max_length=200)
    date_of_birth: str | None = Field(None, max_length=10, pattern=r"^\d{4}-\d{2}-\d{2}$")

    @field_validator("name", "tenant_id", "account_number", mode="before")
    @classmethod
    def sanitize_individual_fields(cls, v: str) -> str:
        return sanitize_text(v)

class UboDetail(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    tax_id: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_-]+$")
    ownership_percentage: float = Field(..., ge=0.01, le=100.0)

    @field_validator("name", "tax_id", mode="before")
    @classmethod
    def sanitize_ubo_fields(cls, v: str) -> str:
        return sanitize_text(v)

class CorporateOnboard(BaseModel):
    tenant_id: str = Field(..., min_length=1, max_length=50)
    company_name: str = Field(..., min_length=1, max_length=200)
    registration_number: str = Field(..., min_length=1, max_length=50, pattern=r"^[A-Za-z0-9_-]+$")
    account_number: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_-]+$")
    swift_bic: str | None = Field(None, min_length=8, max_length=11, pattern=r"^[A-Z0-9]{8,11}$")
    ubos: list[UboDetail] = Field(default_factory=list, max_length=50)

    @field_validator("company_name", "registration_number", "tenant_id", "account_number", mode="before")
    @classmethod
    def sanitize_corporate_fields(cls, v: str) -> str:
        return sanitize_text(v)

@router.post("/individual")
async def onboard_individual(payload: IndividualOnboard, current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"]))):
    # Enforce Data-Level RBAC tenant scoping
    authorized_tenant_id = enforce_tenant_data_scope(current_user, payload.tenant_id)

    try:
        es = await get_async_elasticsearch_client()
        screen_res = await perform_sanctions_search(payload.name, 0.80, es)
        # If high risk sanctions hit, default to a high risk score
        risk_score = 0.95 if screen_res["match_found"] else 0.10
    except Exception:
        # Fallback if ES is offline during onboarding
        risk_score = 0.20

    # Step 2: Save to PostgreSQL
    try:
        async with get_async_db_conn(tenant_id=authorized_tenant_id) as conn:
            # Check if tenant exists
            tenant = await conn.fetchrow("SELECT id FROM tenants WHERE id = $1;", authorized_tenant_id)
            if not tenant:
                raise HTTPException(status_code=400, detail="Invalid tenant_id")

            # Create Account
            account_id = await conn.fetchval(
                """
                INSERT INTO accounts (tenant_id, account_number, swift_bic, owner_name, risk_score)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id;
                """,
                authorized_tenant_id, payload.account_number, payload.swift_bic, payload.name, risk_score
            )
            
            return {
                "account_id": str(account_id),
                "status": "APPROVED" if risk_score < 0.8 else "HELD_FOR_REVIEW",
                "risk_score": risk_score
            }
    except Exception as e:
        if "unique constraint" in str(e).lower():
            raise HTTPException(status_code=400, detail="Account number already exists")
        raise HTTPException(status_code=500, detail=f"Onboarding failed: {str(e)}")

@router.post("/corporate")
async def onboard_corporate(payload: CorporateOnboard, neo4j_driver=Depends(get_async_neo4j_driver), current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"]))):
    # Enforce Data-Level RBAC tenant scoping
    authorized_tenant_id = enforce_tenant_data_scope(current_user, payload.tenant_id)

    # Step 1: Save to PostgreSQL (relational profile)
    try:
        async with get_async_db_conn(tenant_id=authorized_tenant_id) as conn:
            tenant = await conn.fetchrow("SELECT id FROM tenants WHERE id = $1;", authorized_tenant_id)
            if not tenant:
                raise HTTPException(status_code=400, detail="Invalid tenant_id")

            # Create company account
            account_id = await conn.fetchval(
                """
                INSERT INTO accounts (tenant_id, account_number, swift_bic, owner_name, risk_score)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id;
                """,
                authorized_tenant_id, payload.account_number, payload.swift_bic, payload.company_name, 0.15
            )
    except Exception as e:
        if "unique constraint" in str(e).lower():
            raise HTTPException(status_code=400, detail="Account number already exists")
        raise HTTPException(status_code=500, detail=f"PostgreSQL corporate onboarding failed: {str(e)}")

    # Step 2: Save corporate structures & UBO tracing to Neo4j
    try:
        async with neo4j_driver.session() as session:
            # Create Company node
            await session.run(
                """
                MERGE (c:Company {registration_number: $reg_num})
                ON CREATE SET c.name = $name, c.id = $id
                ON MATCH SET c.name = $name
                """,
                reg_num=payload.registration_number,
                name=payload.company_name,
                id=str(account_id)
            )
            
            # Create Account node linked to Company
            await session.run(
                """
                MERGE (a:Account {id: $id})
                SET a.account_number = $acc_num
                WITH a
                MATCH (c:Company {registration_number: $reg_num})
                MERGE (a)-[:BELONGS_TO]->(c)
                """,
                id=str(account_id),
                acc_num=payload.account_number,
                reg_num=payload.registration_number
            )

            # Create Person (UBO) nodes & OWNS_UBO relationships
            for ubo in payload.ubos:
                await session.run(
                    """
                    MERGE (p:Person {tax_id: $tax_id})
                    ON CREATE SET p.name = $name
                    WITH p
                    MATCH (c:Company {registration_number: $reg_num})
                    MERGE (p)-[:OWNS_UBO {percentage: $percentage}]->(c)
                    """,
                    tax_id=ubo.tax_id,
                    name=ubo.name,
                    reg_num=payload.registration_number,
                    percentage=ubo.ownership_percentage
                )
                
        return {
            "account_id": str(account_id),
            "status": "APPROVED",
            "ubo_count": len(payload.ubos)
        }
    except Exception as e:
        # Rollback or log error
        raise HTTPException(status_code=500, detail=f"Neo4j corporate onboarding failed: {str(e)}")
