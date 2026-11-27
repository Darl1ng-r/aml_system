"""
Privacy, DSAR, Legal Hold & GDPR Erasure Router (P0-5)
======================================================
Thin HTTP controller for GDPR Art. 15 DSAR exports (anti-tipping-off sanitized),
internal Legal Holds, and GDPR Art. 17 erasure honoring 5-year BSA retention.
All PostgreSQL SQL lives in `repositories/customer_privacy_repo.py`.
"""

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from database.postgres import get_async_db_conn, get_async_db_read_conn
from observability.logging import log_audit_event
from observability.sanitizer import sanitize_text
from repositories.customer_privacy_repo import (
    create_legal_hold_repo,
    execute_gdpr_erasure_atomic,
    fetch_dsar_export_repo,
    list_legal_holds_repo,
    release_legal_hold_repo,
)
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/privacy", tags=["Data Privacy & Legal Holds"])


class LegalHoldCreate(BaseModel):
    account_id: str
    case_id: Optional[str] = None
    reference_number: str = Field(..., min_length=3, max_length=100)
    reason: str = Field(..., min_length=5, max_length=1000)


class ErasureRequest(BaseModel):
    account_number: str = Field(..., min_length=3, max_length=100)
    reason: str = Field(..., min_length=5, max_length=500)


@router.get("/dsar/export/{account_number}")
async def export_data_subject_dossier(
    account_number: str,
    page: int = Query(default=1, ge=1, le=1000),
    limit: int = Query(default=200, ge=1, le=500),
    cursor: Optional[str] = Query(default=None, max_length=512),
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    """Exports customer-facing GDPR Article 15 / CCPA DSAR (strictly anti-tipping-off sanitized)."""
    from database.pagination import extract_next_cursor

    tenant_id = enforce_tenant_data_scope(current_user)
    page_num = page if isinstance(page, int) else 1
    page_limit = limit if isinstance(limit, int) else 200
    offset = (page_num - 1) * page_limit

    data = await fetch_dsar_export_repo(
        account_number=account_number,
        tenant_id=str(tenant_id),
        page_limit=page_limit,
        offset=offset,
        cursor=cursor if isinstance(cursor, str) else None,
        read_conn_factory=get_async_db_read_conn,
    )
    acc = data["acc"]
    txs = data["txs"]
    total_tx = data["total_tx"]
    if isinstance(cursor, str) and cursor:
        has_more = len(txs) > page_limit
        txs = txs[:page_limit]
    else:
        has_more = (offset + len(txs)) < total_tx

    tx_items = [
        {
            "tx_id": str(t["id"]),
            "amount": float(t["amount"]),
            "amount_str": str(t["amount"]),
            "currency": t["currency"],
            "status": t["status"],
            "timestamp": t["timestamp"].isoformat() if t["timestamp"] else None,
        }
        for t in txs
    ]
    next_cursor = extract_next_cursor(tx_items, has_more=has_more, ts_field="timestamp", id_field="tx_id")

    return {
        "dossier_type": "GDPR_ARTICLE_15_DSAR_EXPORT",
        "tipping_off_sanitized": True,
        "account": {
            "account_number": acc["account_number"],
            "owner_name": acc["owner_name"],
            "swift_bic": acc["swift_bic"],
            "status": acc["status"],
            "created_at": acc["created_at"].isoformat() if acc["created_at"] else None,
        },
        "pagination": {
            "page": page_num,
            "limit": page_limit,
            "total_transactions": total_tx if total_tx >= 0 else None,
            "has_more": has_more,
            "next_cursor": next_cursor,
        },
        "transaction_history_count": len(tx_items),
        "transactions": tx_items,
    }


@router.get("/legal-holds")
async def list_legal_holds(
    account_id: Optional[str] = None,
    active_only: bool = True,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Internal compliance-only endpoint for inspecting active/released legal holds."""
    tenant_id = enforce_tenant_data_scope(current_user)
    acc_uuid = None
    if account_id:
        try:
            acc_uuid = uuid.UUID(account_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid account_id format.")

    rows = await list_legal_holds_repo(
        tenant_id=str(tenant_id),
        acc_uuid=acc_uuid,
        active_only=active_only,
        read_conn_factory=get_async_db_read_conn,
    )
    return [
        {
            "hold_id": str(r["id"]),
            "account_id": str(r["account_id"]),
            "case_id": str(r["case_id"]) if r["case_id"] else None,
            "reference_number": r["reference_number"],
            "reason": r["reason"],
            "is_active": bool(r["is_active"]),
            "created_by_username": r["created_by_username"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]


@router.post("/legal-holds", status_code=status.HTTP_201_CREATED)
async def create_legal_hold(
    payload: LegalHoldCreate,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
):
    try:
        acc_uuid = uuid.UUID(payload.account_id)
        case_uuid = uuid.UUID(payload.case_id) if payload.case_id else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid account_id or case_id format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    hold_id = await create_legal_hold_repo(
        tenant_id=str(tenant_id),
        acc_uuid=acc_uuid,
        case_uuid=case_uuid,
        reference_number=payload.reference_number,
        reason=payload.reason,
        username=current_user.get("username", "mlro"),
        conn_factory=get_async_db_conn,
    )

    logger.info(
        "LEGAL HOLD placed on account %s by %s: Ref %s",
        payload.account_id,
        current_user.get("username"),
        payload.reference_number,
    )
    return {
        "hold_id": str(hold_id),
        "account_id": payload.account_id,
        "reference_number": payload.reference_number,
        "status": "ACTIVE",
        "message": "Legal hold established. Automated data purge/erasure is blocked.",
    }


@router.delete("/legal-holds/{id}")
async def release_legal_hold(
    id: str,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    try:
        hold_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hold ID.")

    tenant_id = enforce_tenant_data_scope(current_user)
    released = await release_legal_hold_repo(
        hold_uuid=hold_uuid,
        tenant_id=str(tenant_id),
        conn_factory=get_async_db_conn,
    )
    if not released:
        raise HTTPException(status_code=404, detail="Legal hold not found.")
    return {"hold_id": id, "status": "RELEASED", "message": "Legal hold released."}


@router.post("/erasure")
async def execute_gdpr_erasure(
    payload: ErasureRequest,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    """Executes GDPR Article 17 Right to Erasure honoring legal holds and 5-year BSA retention."""
    tenant_id = enforce_tenant_data_scope(current_user)
    safe_reason = sanitize_text(payload.reason)
    res = await execute_gdpr_erasure_atomic(
        account_number=payload.account_number,
        safe_reason=safe_reason,
        tenant_id=str(tenant_id),
        conn_factory=get_async_db_conn,
    )
    if res["already_erased"]:
        return {
            "account_number": payload.account_number,
            "status": "ALREADY_ERASED",
            "erased_at": res["erased_at"],
        }

    log_audit_event(
        event_type="GDPR_ERASURE_EXECUTED",
        actor_id=str(current_user.get("id", "")),
        actor_role=current_user.get("role", "MLRO"),
        action="GDPR_ARTICLE_17_ERASURE",
        resource_type="ACCOUNT",
        resource_id=res["acc_id"],
        tenant_id=str(tenant_id),
        details={
            "account_number": payload.account_number,
            "pseudonym": res["pseudonym"],
            "reason": safe_reason,
        },
    )

    return {
        "account_number": payload.account_number,
        "status": "ERASED_PSEUDONYMIZED",
        "pseudonym": res["pseudonym"],
        "message": "Customer PII irreversibly pseudonymized in compliance with GDPR Art. 17.",
    }
