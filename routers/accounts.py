"""
Account Governance & Enhanced Due Diligence (EDD) Router
=========================================================
Thin HTTP controller for CIP verification gates, immediate account freezing
under sanctions/court orders, and Enhanced Due Diligence (EDD) workflows.
All PostgreSQL SQL, `FOR UPDATE` locks, transactional audit writes, and
webhook outbox enqueues live in `repositories/account_repo.py`.
"""

import logging
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from database.postgres import get_async_db_conn, get_async_db_read_conn
from observability.sanitizer import sanitize_text
from repositories.account_repo import (
    create_edd_request_atomic,
    decide_edd_request_atomic,
    freeze_account_atomic,
    list_edd_requests_repo,
    unfreeze_account_atomic,
    verify_account_cip_atomic,
)
from services.audit import record_audit_event_tx
from services.auth import PermissionChecker, RoleChecker, enforce_tenant_data_scope
from services.idempotency import run_idempotent_operation
from services.rate_limiter import RateLimiter


def _mask_document_number(doc_num: str) -> str:
    clean = str(doc_num or "").strip()
    if len(clean) <= 4:
        return "****"
    return f"***{clean[-4:]}"


logger = logging.getLogger(__name__)

INVALID_ACCOUNT_ID = "Invalid account ID format."
ACCOUNT_NOT_FOUND = "Account not found."

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
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    try:
        acc_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_ACCOUNT_ID)

    tenant_id = enforce_tenant_data_scope(current_user)

    async def _execute_cip():
        return await verify_account_cip_atomic(
            acc_uuid=acc_uuid,
            tenant_id=str(tenant_id),
            document_type=payload.document_type,
            masked_doc=_mask_document_number(payload.document_number),
            current_user=current_user,
            conn_factory=get_async_db_conn,
        )

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope=f"account_cip:{acc_uuid}",
        body=payload.model_dump(mode="json"),
        handler=_execute_cip,
        success_status_code=status.HTTP_200_OK,
        required=True,
    )


# ── Immediate Account Freezing (GAP-7) ─────────────────────────────────────────

@router.post("/{id}/freeze")
async def freeze_account(
    id: str,
    payload: AccountFreezeRequest,
    request: Request = None,
    current_user: dict = Depends(PermissionChecker("accounts:freeze")),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
):
    try:
        acc_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_ACCOUNT_ID)

    tenant_id = enforce_tenant_data_scope(current_user)

    async def _execute_freeze():
        return await freeze_account_atomic(
            acc_uuid=acc_uuid,
            tenant_id=str(tenant_id),
            reason=payload.reason,
            freezing_order_ref=payload.freezing_order_ref,
            current_user=current_user,
            conn_factory=get_async_db_conn,
            audit_fn=record_audit_event_tx,
        )

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope=f"account_freeze:{acc_uuid}",
        body=payload.model_dump(mode="json"),
        handler=_execute_freeze,
        success_status_code=status.HTTP_200_OK,
        required=True,
    )


@router.post("/{id}/unfreeze")
async def unfreeze_account(
    id: str,
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    try:
        acc_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_ACCOUNT_ID)

    tenant_id = enforce_tenant_data_scope(current_user)

    async def _execute_unfreeze():
        return await unfreeze_account_atomic(
            acc_uuid=acc_uuid,
            tenant_id=str(tenant_id),
            current_user=current_user,
            conn_factory=get_async_db_conn,
        )

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope=f"account_unfreeze:{acc_uuid}",
        body={"account_id": id},
        handler=_execute_unfreeze,
        success_status_code=status.HTTP_200_OK,
        required=True,
    )


# ── Enhanced Due Diligence (EDD) Workflow (GAP-2) ──────────────────────────────

@edd_router.post("/requests", status_code=status.HTTP_201_CREATED)
async def create_edd_request(
    payload: EDDCreateRequest,
    current_user: dict = Depends(RoleChecker(["L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    try:
        acc_uuid = uuid.UUID(payload.account_id)
        case_uuid = uuid.UUID(payload.case_id) if payload.case_id else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid account_id or case_id format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    return await create_edd_request_atomic(
        tenant_id=str(tenant_id),
        acc_uuid=acc_uuid,
        case_uuid=case_uuid,
        trigger_reason=payload.trigger_reason,
        source_of_wealth=payload.source_of_wealth,
        source_of_funds=payload.source_of_funds,
        current_user=current_user,
        conn_factory=get_async_db_conn,
    )


@edd_router.get("/requests")
async def list_edd_requests(
    status_filter: Optional[str] = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)
    return await list_edd_requests_repo(
        tenant_id=str(tenant_id),
        status_filter=status_filter,
        read_conn_factory=get_async_db_read_conn,
    )


@edd_router.post("/requests/{id}/decision")
async def decide_edd_request(
    id: str,
    payload: EDDDecisionRequest,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
):
    try:
        edd_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid EDD request ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    return await decide_edd_request_atomic(
        edd_uuid=edd_uuid,
        tenant_id=str(tenant_id),
        decision=payload.decision,
        notes=payload.notes,
        current_user=current_user,
        conn_factory=get_async_db_conn,
    )
