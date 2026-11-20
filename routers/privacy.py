"""
Privacy, DSAR, Legal Hold & GDPR Erasure Router (P0-5)
======================================================
Implements:
  - GDPR Article 15 / CCPA DSAR Export (strictly stripped of SAR / legal-hold / AML risk
    indicators to comply with federal BSA anti-tipping-off law, 31 U.S.C. § 5318(g)(2))
  - Internal-only Legal Hold management (GET / POST / DELETE /api/v1/privacy/legal-holds)
  - GDPR Article 17 Right to Erasure (POST /api/v1/privacy/erasure) honoring active
    legal holds and mandatory 5-year BSA statutory retention (31 CFR § 1010.430)
"""

import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from database.postgres import get_async_db_conn, get_async_db_read_conn
from observability.logging import log_audit_event
from observability.sanitizer import sanitize_text
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
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=200, ge=1, le=500),
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    """
    Exports customer-facing GDPR Article 15 / CCPA Data Subject Access Request (DSAR).

    COMPLIANCE SAFEGUARD (31 U.S.C. § 5318(g)(2)):
    This export NEVER includes `legal_holds_active`, SAR filings, AML risk scores,
    or internal alert flags to prevent unlawful tipping-off.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    page_num = page if isinstance(page, int) else 1
    page_limit = limit if isinstance(limit, int) else 200
    offset = (page_num - 1) * page_limit

    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            """
            SELECT id, account_number, owner_name, swift_bic, status, created_at
            FROM accounts
            WHERE account_number = $1 AND tenant_id = $2;
            """,
            account_number,
            uuid.UUID(str(tenant_id)),
        )
        if not acc:
            raise HTTPException(status_code=404, detail="Account not found.")

        acc_id = acc["id"]

        total_tx = await conn.fetchval(
            """
            SELECT COUNT(*)
            FROM transactions
            WHERE sender_account_id = $1 OR receiver_account_id = $1;
            """,
            acc_id,
        )

        txs = await conn.fetch(
            """
            SELECT id, amount, currency, status, timestamp, country, channel
            FROM transactions
            WHERE (sender_account_id = $1 OR receiver_account_id = $1)
            ORDER BY timestamp DESC
            LIMIT $2 OFFSET $3;
            """,
            acc_id,
            page_limit,
            offset,
        )

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
                "total_transactions": int(total_tx or 0),
                "has_more": (offset + len(txs)) < int(total_tx or 0),
            },
            "transaction_history_count": len(txs),
            "transactions": [
                {
                    "tx_id": str(t["id"]),
                    "amount": float(t["amount"]),
                    "currency": t["currency"],
                    "status": t["status"],
                    "timestamp": t["timestamp"].isoformat() if t["timestamp"] else None,
                }
                for t in txs
            ],
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
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        if account_id:
            try:
                acc_uuid = uuid.UUID(account_id)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid account_id format.")
            rows = await conn.fetch(
                """
                SELECT id, account_id, case_id, reference_number, reason, is_active, created_by_username, created_at
                FROM legal_holds
                WHERE account_id = $1 AND ($2 = FALSE OR is_active = TRUE)
                ORDER BY created_at DESC;
                """,
                acc_uuid,
                active_only,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT id, account_id, case_id, reference_number, reason, is_active, created_by_username, created_at
                FROM legal_holds
                WHERE ($1 = FALSE OR is_active = TRUE)
                ORDER BY created_at DESC
                LIMIT 200;
                """,
                active_only,
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
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        hold_id = await conn.fetchval(
            """
            INSERT INTO legal_holds (
                tenant_id, account_id, case_id, reference_number, reason,
                is_active, created_by_username
            ) VALUES ($1, $2, $3, $4, $5, true, $6)
            RETURNING id;
            """,
            uuid.UUID(str(tenant_id)),
            acc_uuid,
            case_uuid,
            payload.reference_number,
            payload.reason,
            current_user.get("username", "mlro"),
        )

        logger.info(
            f"LEGAL HOLD placed on account {payload.account_id} by {current_user.get('username')}: Ref {payload.reference_number}"
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
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        await conn.execute(
            """
            UPDATE legal_holds
            SET is_active = false, released_at = NOW()
            WHERE id = $1 AND tenant_id = $2;
            """,
            hold_uuid,
            uuid.UUID(str(tenant_id)),
        )
        return {"hold_id": id, "status": "RELEASED", "message": "Legal hold released."}


@router.post("/erasure")
async def execute_gdpr_erasure(
    payload: ErasureRequest,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    """
    Executes GDPR Article 17 Right to Erasure with mandatory statutory safeguards:
      1. Blocks immediately (409) if any active legal hold exists on the account.
      2. Defers (409) if account or latest transaction is within the mandatory
         5-year BSA statutory retention window (31 CFR § 1010.430).
      3. When eligible, irreversibly pseudonymizes PII while preserving anonymized
         ledger rows and recording an immutable audit event.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    five_years_ago = datetime.now(timezone.utc) - timedelta(days=365 * 5)

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            """
            SELECT id, account_number, owner_name, created_at, erased_at
            FROM accounts
            WHERE account_number = $1 AND tenant_id = $2
            FOR UPDATE;
            """,
            payload.account_number,
            uuid.UUID(str(tenant_id)),
        )
        if not acc:
            raise HTTPException(status_code=404, detail="Account not found.")
        if acc.get("erased_at") is not None:
            return {
                "account_number": payload.account_number,
                "status": "ALREADY_ERASED",
                "erased_at": acc["erased_at"].isoformat(),
            }

        acc_id = acc["id"]

        # 1. Non-bypassable active legal hold guard
        active_holds = await conn.fetchval(
            "SELECT COUNT(*) FROM legal_holds WHERE account_id = $1 AND is_active = TRUE;",
            acc_id,
        )
        if int(active_holds or 0) > 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Erasure blocked: active regulatory/legal hold prevents PII deletion.",
            )

        # 2. BSA 5-year statutory retention guard (31 CFR § 1010.430)
        latest_tx_ts = await conn.fetchval(
            """
            SELECT MAX(timestamp)
            FROM transactions
            WHERE sender_account_id = $1 OR receiver_account_id = $1;
            """,
            acc_id,
        )
        anchor_ts = latest_tx_ts or acc["created_at"]
        if anchor_ts is not None:
            if anchor_ts.tzinfo is None:
                anchor_ts = anchor_ts.replace(tzinfo=timezone.utc)
            if anchor_ts > five_years_ago:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Erasure deferred under 31 CFR § 1010.430: mandatory 5-year BSA statutory retention period has not elapsed.",
                )

        # 3. Irreversible cryptographic pseudonymization
        pseudonym = "ERASED-" + hashlib.sha256(f"{tenant_id}:{acc_id}".encode("utf-8")).hexdigest()[:10].upper()
        safe_reason = sanitize_text(payload.reason)
        await conn.execute(
            """
            UPDATE accounts
            SET owner_name = $1,
                erased_at = NOW(),
                erasure_reason = $2
            WHERE id = $3;
            """,
            pseudonym,
            safe_reason,
            acc_id,
        )

    log_audit_event(
        event_type="GDPR_ERASURE_EXECUTED",
        actor_id=str(current_user.get("id", "")),
        actor_role=current_user.get("role", "MLRO"),
        action="GDPR_ARTICLE_17_ERASURE",
        resource_type="ACCOUNT",
        resource_id=str(acc_id),
        tenant_id=str(tenant_id),
        details={"account_number": payload.account_number, "pseudonym": pseudonym, "reason": safe_reason},
    )

    return {
        "account_number": payload.account_number,
        "status": "ERASED_PSEUDONYMIZED",
        "pseudonym": pseudonym,
        "message": "Customer PII irreversibly pseudonymized in compliance with GDPR Art. 17.",
    }
