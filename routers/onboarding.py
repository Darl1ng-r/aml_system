"""
Customer & Corporate Account Onboarding Router
==============================================
Thin HTTP controller for individual and corporate KYC/sanctions onboarding
with fail-closed screening and compensating Neo4j rollback.
All PostgreSQL SQL lives in `repositories/customer_privacy_repo.py`.
"""

import logging
import uuid
from datetime import date as _date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field, field_validator

from database.elasticsearch_db import get_async_elasticsearch_client
from database.neo4j_db import get_async_neo4j_driver
from database.postgres import get_async_db_conn
from observability.sanitizer import sanitize_text
from repositories.customer_privacy_repo import (
    compensating_delete_account_repo,
    get_onboarded_account_by_id_repo,
    list_onboarded_accounts_repo,
    onboard_corporate_account_repo,
    onboard_individual_account_repo,
)
from routers.screening import perform_sanctions_search
from services.auth import RoleChecker, enforce_tenant_data_scope, get_current_user
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/onboard", tags=["Onboarding"])

IDENTIFIER_REGEX = r"^[A-Za-z0-9_-]+$"


class IndividualOnboard(BaseModel):
    tenant_id: str = Field(..., min_length=1, max_length=50)
    account_number: str = Field(..., min_length=3, max_length=50, pattern=IDENTIFIER_REGEX)
    swift_bic: str | None = Field(None, min_length=8, max_length=11, pattern=r"^[A-Z0-9]{8,11}$")
    name: str = Field(..., min_length=1, max_length=200)
    date_of_birth: str | None = Field(None, max_length=10, pattern=r"^\d{4}-\d{2}-\d{2}$")

    @field_validator("name", "tenant_id", "account_number", mode="before")
    @classmethod
    def sanitize_individual_fields(cls, v: str) -> str:
        return sanitize_text(v)


class UboDetail(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    tax_id: str = Field(..., min_length=3, max_length=50, pattern=IDENTIFIER_REGEX)
    ownership_percentage: float = Field(..., ge=0.01, le=100.0)

    @field_validator("name", "tax_id", mode="before")
    @classmethod
    def sanitize_ubo_fields(cls, v: str) -> str:
        return sanitize_text(v)


class CorporateOnboard(BaseModel):
    tenant_id: str = Field(..., min_length=1, max_length=50)
    company_name: str = Field(..., min_length=1, max_length=200)
    registration_number: str = Field(..., min_length=1, max_length=50, pattern=IDENTIFIER_REGEX)
    account_number: str = Field(..., min_length=3, max_length=50, pattern=IDENTIFIER_REGEX)
    swift_bic: str | None = Field(None, min_length=8, max_length=11, pattern=r"^[A-Z0-9]{8,11}$")
    ubos: list[UboDetail] = Field(default_factory=list, max_length=50)

    @field_validator("company_name", "registration_number", "tenant_id", "account_number", mode="before")
    @classmethod
    def sanitize_corporate_fields(cls, v: str) -> str:
        return sanitize_text(v)


@router.post("/accounts/individual", status_code=status.HTTP_201_CREATED)
@router.post("/individual", status_code=status.HTTP_201_CREATED)
async def onboard_individual(
    payload: IndividualOnboard,
    response: Response = None,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
):
    authorized_tenant_id = enforce_tenant_data_scope(current_user, payload.tenant_id)

    screening_failed = False
    try:
        es = await get_async_elasticsearch_client()
        screen_res = await perform_sanctions_search(payload.name, 0.80, es)
        risk_score = 0.95 if screen_res["match_found"] else 0.10
    except Exception:
        logger.exception("Sanctions screening offline/timed out during onboarding")
        risk_score = 1.0
        screening_failed = True

    dob_val = None
    if payload.date_of_birth:
        try:
            dob_val = _date.fromisoformat(payload.date_of_birth)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid date_of_birth; expected YYYY-MM-DD.")

    persisted_status = "ACTIVE" if (risk_score < 0.8 and not screening_failed) else "HELD_FOR_REVIEW"
    try:
        account_id = await onboard_individual_account_repo(
            authorized_tenant_id=authorized_tenant_id,
            account_number=payload.account_number,
            swift_bic=payload.swift_bic,
            owner_name=payload.name,
            risk_score=risk_score,
            dob_val=dob_val,
            account_status=persisted_status,
            conn_factory=get_async_db_conn,
        )
        if response is not None:
            response.headers["Location"] = f"/api/v1/onboard/accounts/{account_id}"

        return {
            "account_id": str(account_id),
            "status": "APPROVED" if (risk_score < 0.8 and not screening_failed) else "HELD_FOR_REVIEW",
            "risk_score": risk_score,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Onboarding failed")
        if "unique constraint" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account number already exists")
        raise HTTPException(status_code=500, detail="Onboarding failed due to an internal error.")


async def _screen_corporate_and_ubos(company_name: str, ubos: list[UboDetail]) -> tuple[float, bool]:
    corp_risk_score = 0.15
    corp_screening_failed = False
    try:
        es = await get_async_elasticsearch_client()
        comp_screen = await perform_sanctions_search(company_name, 0.80, es)
        if comp_screen.get("match_found"):
            corp_risk_score = 0.95
        for ubo in ubos:
            ubo_screen = await perform_sanctions_search(ubo.name, 0.80, es)
            if ubo_screen.get("match_found"):
                corp_risk_score = 0.95
                break
    except Exception as ex_es:
        logger.warning("Sanctions screening failed during corporate onboarding: %s", ex_es)
        corp_risk_score = 1.0
        corp_screening_failed = True
    return corp_risk_score, corp_screening_failed


async def _persist_corporate_account(
    authorized_tenant_id: Any,
    payload: CorporateOnboard,
    corp_risk_score: float,
    response: Response | None,
    *,
    corp_screening_failed: bool = False,
) -> Any:
    persisted_status = "ACTIVE" if (corp_risk_score < 0.8 and not corp_screening_failed) else "HELD_FOR_REVIEW"
    try:
        account_id = await onboard_corporate_account_repo(
            authorized_tenant_id=authorized_tenant_id,
            account_number=payload.account_number,
            swift_bic=payload.swift_bic,
            company_name=payload.company_name,
            corp_risk_score=corp_risk_score,
            account_status=persisted_status,
            conn_factory=get_async_db_conn,
        )
        if response is not None:
            response.headers["Location"] = f"/api/v1/onboard/accounts/{account_id}"
        return account_id
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("PostgreSQL corporate onboarding failed")
        if "unique constraint" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account number already exists")
        raise HTTPException(status_code=500, detail="Corporate onboarding database error.")


async def _persist_neo4j_corporate_graph(
    neo4j_driver: Any,
    account_id: Any,
    payload: CorporateOnboard,
    tenant_id: str,
) -> None:
    """Persists tenant-isolated Company, Account, and UBO Person graph nodes into Neo4j (V-04)."""
    tid = str(tenant_id)
    async with neo4j_driver.session() as session:
        await session.run(
            """
            MERGE (c:Company {registration_number: $reg_num, tenant_id: $tenant_id})
            ON CREATE SET c.name = $name, c.id = $id
            ON MATCH SET c.name = $name
            """,
            reg_num=payload.registration_number,
            tenant_id=tid,
            name=payload.company_name,
            id=str(account_id),
        )

        await session.run(
            """
            MERGE (a:Account {id: $id, tenant_id: $tenant_id})
            SET a.account_number = $acc_num
            WITH a
            MATCH (c:Company {registration_number: $reg_num, tenant_id: $tenant_id})
            MERGE (a)-[:BELONGS_TO]->(c)
            """,
            id=str(account_id),
            tenant_id=tid,
            acc_num=payload.account_number,
            reg_num=payload.registration_number,
        )

        for ubo in payload.ubos:
            await session.run(
                """
                MERGE (p:Person {tax_id: $tax_id, tenant_id: $tenant_id})
                ON CREATE SET p.name = $name
                WITH p
                MATCH (c:Company {registration_number: $reg_num, tenant_id: $tenant_id})
                MERGE (p)-[:OWNS_UBO {percentage: $percentage, tenant_id: $tenant_id}]->(c)
                """,
                tax_id=ubo.tax_id,
                tenant_id=tid,
                name=ubo.name,
                reg_num=payload.registration_number,
                percentage=ubo.ownership_percentage,
            )


@router.post("/accounts/corporate", status_code=status.HTTP_201_CREATED)
@router.post("/corporate", status_code=status.HTTP_201_CREATED)
async def onboard_corporate(
    payload: CorporateOnboard,
    response: Response = None,
    neo4j_driver=Depends(get_async_neo4j_driver),
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
):
    authorized_tenant_id = enforce_tenant_data_scope(current_user, payload.tenant_id)
    corp_risk_score, corp_screening_failed = await _screen_corporate_and_ubos(payload.company_name, payload.ubos)
    account_id = await _persist_corporate_account(
        authorized_tenant_id,
        payload,
        corp_risk_score,
        response,
        corp_screening_failed=corp_screening_failed,
    )

    try:
        await _persist_neo4j_corporate_graph(neo4j_driver, account_id, payload, tenant_id=str(authorized_tenant_id))
        corp_status = "APPROVED" if (corp_risk_score < 0.8 and not corp_screening_failed) else "HELD_FOR_REVIEW"
        return {
            "account_id": str(account_id),
            "status": corp_status,
            "risk_score": corp_risk_score,
            "ubo_count": len(payload.ubos),
        }
    except HTTPException:
        raise
    except Exception:
        logger.exception("Neo4j corporate onboarding failed")
        try:
            await compensating_delete_account_repo(
                authorized_tenant_id=authorized_tenant_id,
                account_id=account_id,
                conn_factory=get_async_db_conn,
            )
        except Exception:
            logger.exception("Compensating Postgres rollback failed")
        raise HTTPException(status_code=500, detail="Corporate graph registration failed due to an internal error.")


@router.get("/accounts/{id}")
async def get_account_by_id(
    id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Retrieves an onboarded account KYC and risk profile by its UUID."""
    try:
        acc_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid account ID format")

    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        row = await get_onboarded_account_by_id_repo(
            acc_uuid=acc_uuid,
            tenant_id=tenant_id,
            conn_factory=get_async_db_conn,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Account not found")

        dob_raw = row.get("date_of_birth") if hasattr(row, "get") else None
        return {
            "account_id": str(row["id"]),
            "account_number": row["account_number"],
            "swift_bic": row["swift_bic"],
            "owner_name": row["owner_name"],
            "date_of_birth": dob_raw.isoformat() if hasattr(dob_raw, "isoformat") else dob_raw,
            "risk_score": float(row["risk_score"]) if row["risk_score"] else 0.0,
            "risk_tier": row["risk_category"] or "STANDARD",
            "created_at": row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else str(row["created_at"]),
        }
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to fetch account %s", id)
        raise HTTPException(status_code=500, detail="Failed to fetch account details.")


@router.get("/accounts")
async def list_accounts(
    response: Response,
    page: int = Query(default=1, ge=1, le=1000),
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=512),
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Retrieves a paginated list of accounts within the caller's tenant boundary."""
    from database.pagination import encode_keyset_cursor

    tenant_id = enforce_tenant_data_scope(current_user)
    offset = (page - 1) * limit
    try:
        total_count, rows = await list_onboarded_accounts_repo(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            cursor=cursor,
            conn_factory=get_async_db_conn,
        )
        if cursor:
            has_more = len(rows) > limit
            rows = rows[:limit]
        else:
            has_more = (offset + len(rows)) < total_count
        accounts = [
            {
                "account_id": str(r["id"]),
                "account_number": r["account_number"],
                "swift_bic": r["swift_bic"],
                "owner_name": r["owner_name"],
                "risk_score": float(r["risk_score"]) if r["risk_score"] else 0.0,
                "risk_tier": r["risk_category"] or "STANDARD",
                "created_at": r["created_at"].isoformat() if hasattr(r["created_at"], "isoformat") else str(r["created_at"]),
            }
            for r in rows
        ]
        if total_count >= 0:
            response.headers["X-Total-Count"] = str(total_count)
        response.headers["X-Has-More"] = "true" if has_more else "false"
        if accounts and has_more:
            response.headers["X-Next-Cursor"] = encode_keyset_cursor(rows[-1]["created_at"], str(rows[-1]["id"]))
        response.headers["Access-Control-Expose-Headers"] = "X-Total-Count, X-Next-Cursor, X-Has-More"
        return accounts
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to list accounts")
        raise HTTPException(status_code=500, detail="Failed to list accounts.")
