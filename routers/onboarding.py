from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from database.postgres import get_async_db_conn
from database.neo4j_db import get_async_neo4j_driver
from routers.screening import search_sanctions, ScreeningRequest

router = APIRouter(prefix="/api/v1/onboard", tags=["Onboarding"])


class IndividualOnboard(BaseModel):
    tenant_id: str
    account_number: str
    swift_bic: str | None = None
    name: str
    date_of_birth: str | None = None

class UboDetail(BaseModel):
    name: str
    tax_id: str
    ownership_percentage: float

class CorporateOnboard(BaseModel):
    tenant_id: str
    company_name: str
    registration_number: str
    account_number: str
    swift_bic: str | None = None
    ubos: list[UboDetail] = []

@router.post("/individual")
async def onboard_individual(payload: IndividualOnboard):
    # Step 1: Sanctions PEP Screening Check
    screen_req = ScreeningRequest(name=payload.name, date_of_birth=payload.date_of_birth)
    try:
        screen_res = await search_sanctions(screen_req)
        # If high risk sanctions hit, default to a high risk score
        risk_score = 0.95 if screen_res["match_found"] else 0.10
    except Exception:
        # Fallback if ES is offline during onboarding
        risk_score = 0.20

    # Step 2: Save to PostgreSQL
    try:
        async with get_async_db_conn() as conn:
            # Check if tenant exists
            tenant = await conn.fetchrow("SELECT id FROM tenants WHERE id = $1;", payload.tenant_id)
            if not tenant:
                raise HTTPException(status_code=400, detail="Invalid tenant_id")

            # Create Account
            account_id = await conn.fetchval(
                """
                INSERT INTO accounts (tenant_id, account_number, swift_bic, owner_name, risk_score)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id;
                """,
                payload.tenant_id, payload.account_number, payload.swift_bic, payload.name, risk_score
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
async def onboard_corporate(payload: CorporateOnboard, neo4j_driver=Depends(get_async_neo4j_driver)):
    # Step 1: Save to PostgreSQL (relational profile)
    try:
        async with get_async_db_conn() as conn:
            tenant = await conn.fetchrow("SELECT id FROM tenants WHERE id = $1;", payload.tenant_id)
            if not tenant:
                raise HTTPException(status_code=400, detail="Invalid tenant_id")

            # Create company account
            account_id = await conn.fetchval(
                """
                INSERT INTO accounts (tenant_id, account_number, swift_bic, owner_name, risk_score)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id;
                """,
                payload.tenant_id, payload.account_number, payload.swift_bic, payload.company_name, 0.15
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
