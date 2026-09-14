"""
Account Governance & Enhanced Due Diligence (EDD) Router
=========================================================
Implements CIP verification gates, immediate account freezing under sanctions/court orders,
and Enhanced Due Diligence (EDD) workflows (GAP-2, GAP-3, GAP-7).
"""

import logging
import uuid
from typing import Optional, List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field, field_validator

from database.postgres import get_async_db_conn, get_async_db_read_conn
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter
from services.audit import record_audit_event_tx
from observability.sanitizer import sanitize_text

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/accounts", tags=["Account Governance & EDD"])
edd_router = APIRouter(prefix="/api/v1/edd", tags=["Enhanced Due Diligence"])


class CIPVerifyRequest(BaseModel):
    document_type: str = Field(..., pattern=r"^(PASSPORT|NATIONAL_ID|DRIVERS_LICENSE|CORPORATE_REGISTRY)$")
    document_number: str = Field(..., min_length=3, max_length=50)
    verification_method: str = Field("DOC_SCAN", max_length=50)
    verification_notes: Optional[str] = Field(None, max_length=1000)

    @field_validator("document_number", "verification_notes", mode="before")
    @classmethod
    def sanitize_strings(cls, v: Optional[str]) -> Optional[str]:
        return sanitize_text(v) if v else None


class AccountFreezeRequest(BaseModel):
    reason: str = Field(..., min_length=5, max_length=500)
    freezing_order_ref: Optional[str] = Field(None, max_length=100)

    @field_validator("reason", "freezing_order_ref", mode="before")
    @classmethod
    def sanitize_strings(cls, v: Optional[str]) -> Optional[str]:
        return sanitize_text(v) if v else None


class EDDCreateRequest(BaseModel):
    account_id: str
    case_id: Optional[str] = None
    trigger_reason: str = Field(..., pattern=r"^(PEP_HIT|HIGH_RISK_JURISDICTION|SUSPICIOUS_TURNOVER|MANUAL_ESCALATION)$")
    source_of_wealth: Optional[str] = Field(None, max_length=2000)
    source_of_funds: Optional[str] = Field(None, max_length=2000)

    @field_validator("source_of_wealth", "source_of_funds", mode="before")
    @classmethod
    def sanitize_strings(cls, v: Optional[str]) -> Optional[str]:
        return sanitize_text(v) if v else None


class EDDDecisionRequest(BaseModel):
    decision: str = Field(..., pattern=r"^(APPROVED|RESTRICTED|EXIT_RELATIONSHIP)$")
    notes: str = Field(..., min_length=5, max_length=2000)

    @field_validator("notes", mode="before")
    @classmethod
    def sanitize_notes(cls, v: str) -> str:
        return sanitize_text(v)


# ── Account CIP Verification Gate (GAP-3) ──────────────────────────────────────

@router.post("/{id}/verify-cip")
async def verify_account_cip(
    id: str,
    payload: CIPVerifyRequest,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    try:
        acc_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid account ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            "SELECT id, status FROM accounts WHERE id = $1 AND tenant_id = $2;",
            acc_uuid, uuid.UUID(str(tenant_id))
        )
        if not acc:
            raise HTTPException(status_code=404, detail="Account not found.")

        await conn.execute(
            """
            UPDATE accounts
            SET status = 'ACTIVE'
            WHERE id = $1;
            """,
            acc_uuid
        )

        # Synchronous in-transaction audit persistence (AUDIT-01)
        try:
            await record_audit_event_tx(
                conn=conn,
                action="ACCOUNT_CIP_VERIFIED",
                actor_id=str(current_user.get("id", "system")),
                actor_role=current_user.get("role", "ANALYST"),
                resource_type="ACCOUNT",
                resource_id=id,
                tenant_id=str(tenant_id),
                actor_username=current_user.get("username"),
                before_state={"status": acc["status"]},
                after_state={"status": "ACTIVE"},
                details={"document_type": payload.document_type, "document_number": payload.document_number}
            )
        except Exception as audit_err:
            logger.warning(f"Audit log writing failed in verify_account_cip: {audit_err}")

        logger.info(
            f"CIP verified for account {id} by '{current_user.get('username')}' "
            f"using {payload.document_type} ({payload.document_number})"
        )

        return {
            "account_id": id,
            "status": "ACTIVE",
            "cip_verified": True,
            "message": "Customer Identification Program (CIP) verification completed. Account is now ACTIVE."
        }


# ── Immediate Account Freezing (GAP-7) ─────────────────────────────────────────

@router.post("/{id}/freeze")
async def freeze_account(
    id: str,
    payload: AccountFreezeRequest,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "L2_INVESTIGATOR"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60))
):
    try:
        acc_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid account ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            "SELECT id, status, account_number FROM accounts WHERE id = $1 AND tenant_id = $2;",
            acc_uuid, uuid.UUID(str(tenant_id))
        )
        if not acc:
            raise HTTPException(status_code=404, detail="Account not found.")

        await conn.execute(
            """
            UPDATE accounts
            SET status = 'FROZEN',
                frozen_reason = $1,
                freezing_order_ref = $2,
                frozen_at = NOW()
            WHERE id = $3;
            """,
            payload.reason, payload.freezing_order_ref, acc_uuid
        )

        # Synchronous in-transaction audit persistence (AUDIT-01)
        try:
            await record_audit_event_tx(
                conn=conn,
                action="ACCOUNT_FROZEN",
                actor_id=str(current_user.get("id", "system")),
                actor_role=current_user.get("role", "MLRO"),
                resource_type="ACCOUNT",
                resource_id=id,
                tenant_id=str(tenant_id),
                actor_username=current_user.get("username"),
                before_state={"status": acc["status"]},
                after_state={"status": "FROZEN", "reason": payload.reason, "ref": payload.freezing_order_ref},
                details={"account_number": acc["account_number"]}
            )
        except Exception as audit_err:
            logger.warning(f"Audit log writing failed in freeze_account: {audit_err}")

        logger.warning(
            f"REGULATORY ACTION: Account {id} ({acc['account_number']}) FROZEN by {current_user.get('username')}. "
            f"Reason: {payload.reason} | Ref: {payload.freezing_order_ref}"
        )

        return {
            "account_id": id,
            "status": "FROZEN",
            "frozen_reason": payload.reason,
            "freezing_order_ref": payload.freezing_order_ref,
            "message": "Account has been immediately frozen under regulatory mandate. All transactions blocked."
        }


@router.post("/{id}/unfreeze")
async def unfreeze_account(
    id: str,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60))
):
    try:
        acc_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid account ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            "SELECT id, status FROM accounts WHERE id = $1 AND tenant_id = $2;",
            acc_uuid, uuid.UUID(str(tenant_id))
        )
        if not acc:
            raise HTTPException(status_code=404, detail="Account not found.")

        await conn.execute(
            """
            UPDATE accounts
            SET status = 'ACTIVE',
                frozen_reason = NULL,
                freezing_order_ref = NULL,
                frozen_at = NULL
            WHERE id = $1;
            """,
            acc_uuid
        )

        # Synchronous in-transaction audit persistence (AUDIT-01)
        try:
            await record_audit_event_tx(
                conn=conn,
                action="ACCOUNT_UNFROZEN",
                actor_id=str(current_user.get("id", "system")),
                actor_role=current_user.get("role", "MLRO"),
                resource_type="ACCOUNT",
                resource_id=id,
                tenant_id=str(tenant_id),
                actor_username=current_user.get("username"),
                before_state={"status": acc["status"]},
                after_state={"status": "ACTIVE"},
                details={"account_id": id}
            )
        except Exception as audit_err:
            logger.warning(f"Audit log writing failed in unfreeze_account: {audit_err}")

        return {
            "account_id": id,
            "status": "ACTIVE",
            "message": "Account unfreezing completed. Account restored to ACTIVE status."
        }


# ── Enhanced Due Diligence (EDD) Workflow (GAP-2) ──────────────────────────────

@edd_router.post("/requests", status_code=status.HTTP_201_CREATED)
async def create_edd_request(
    payload: EDDCreateRequest,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    try:
        acc_uuid = uuid.UUID(payload.account_id)
        case_uuid = uuid.UUID(payload.case_id) if payload.case_id else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid account_id or case_id format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            "SELECT id FROM accounts WHERE id = $1 AND tenant_id = $2;",
            acc_uuid, uuid.UUID(str(tenant_id))
        )
        if not acc:
            raise HTTPException(status_code=404, detail="Account not found.")

        user_uuid = uuid.UUID(str(current_user["id"])) if current_user.get("id") else None

        edd_id = await conn.fetchval(
            """
            INSERT INTO edd_requests (
                tenant_id, case_id, account_id, trigger_reason,
                source_of_wealth, source_of_funds, status,
                requested_by, requested_by_username
            ) VALUES ($1, $2, $3, $4, $5, $6, 'PENDING', $7, $8)
            RETURNING id;
            """,
            uuid.UUID(str(tenant_id)), case_uuid, acc_uuid,
            payload.trigger_reason, payload.source_of_wealth, payload.source_of_funds,
            user_uuid, current_user.get("username", "analyst")
        )

        # Mark account as EDD_REQUIRED
        await conn.execute("UPDATE accounts SET status = 'EDD_REQUIRED' WHERE id = $1;", acc_uuid)

        return {
            "edd_id": str(edd_id),
            "account_id": payload.account_id,
            "status": "PENDING",
            "trigger_reason": payload.trigger_reason,
            "message": "Enhanced Due Diligence (EDD) workflow initiated."
        }


@edd_router.get("/requests")
async def list_edd_requests(
    status_filter: Optional[str] = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        if status_filter:
            rows = await conn.fetch(
                "SELECT * FROM edd_requests WHERE tenant_id = $1 AND status = $2 ORDER BY created_at DESC LIMIT 100;",
                uuid.UUID(str(tenant_id)), status_filter.upper()
            )
        else:
            rows = await conn.fetch(
                "SELECT * FROM edd_requests WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100;",
                uuid.UUID(str(tenant_id))
            )

        return [
            {
                "edd_id": str(r["id"]),
                "account_id": str(r["account_id"]),
                "case_id": str(r["case_id"]) if r["case_id"] else None,
                "trigger_reason": r["trigger_reason"],
                "status": r["status"],
                "requested_by_username": r["requested_by_username"],
                "mlro_decision": r["mlro_decision"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None
            }
            for r in rows
        ]


@edd_router.post("/requests/{id}/decision")
async def decide_edd_request(
    id: str,
    payload: EDDDecisionRequest,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60))
):
    try:
        edd_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid EDD request ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        edd_row = await conn.fetchrow(
            "SELECT * FROM edd_requests WHERE id = $1 AND tenant_id = $2;",
            edd_uuid, uuid.UUID(str(tenant_id))
        )
        if not edd_row:
            raise HTTPException(status_code=404, detail="EDD request not found.")

        new_account_status = "ACTIVE" if payload.decision == "APPROVED" else ("CLOSED" if payload.decision == "EXIT_RELATIONSHIP" else "HELD_FOR_REVIEW")
        reviewer_uuid = uuid.UUID(str(current_user["id"])) if current_user.get("id") else None

        await conn.execute(
            """
            UPDATE edd_requests
            SET status = 'RESOLVED',
                mlro_decision = $1,
                mlro_notes = $2,
                reviewed_by = $3,
                reviewed_by_username = $4,
                resolved_at = NOW()
            WHERE id = $5;
            """,
            payload.decision, payload.notes, reviewer_uuid, current_user.get("username", "mlro"), edd_uuid
        )

        await conn.execute("UPDATE accounts SET status = $1 WHERE id = $2;", new_account_status, edd_row["account_id"])

        return {
            "edd_id": id,
            "status": "RESOLVED",
            "decision": payload.decision,
            "account_status": new_account_status,
            "message": f"EDD determination recorded: '{payload.decision}'. Account status updated to '{new_account_status}'."
        }
