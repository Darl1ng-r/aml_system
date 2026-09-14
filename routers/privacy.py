"""
Privacy, DSAR & Legal Hold Router (GAP-11, GAP-13)
==================================================
Implements GDPR Article 15 / CCPA Data Subject Access Requests (DSAR),
5-year BSA statutory data retention management, and non-bypassable legal holds.
"""

import logging
import uuid
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from database.postgres import get_async_db_conn, get_async_db_read_conn
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/privacy", tags=["Data Privacy & Legal Holds"])


class LegalHoldCreate(BaseModel):
    account_id: str
    case_id: Optional[str] = None
    reference_number: str = Field(..., min_length=3, max_length=100)
    reason: str = Field(..., min_length=5, max_length=1000)


@router.get("/dsar/export/{account_number}")
async def export_data_subject_dossier(
    account_number: str,
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60))
):
    """
    Exports comprehensive customer PII and transaction records for GDPR/CCPA compliance.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            """
            SELECT id, account_number, owner_name, swift_bic, risk_score, status, created_at
            FROM accounts
            WHERE account_number = $1 AND tenant_id = $2;
            """,
            account_number, uuid.UUID(str(tenant_id))
        )
        if not acc:
            raise HTTPException(status_code=404, detail="Account not found.")

        acc_id = acc["id"]

        # Check for active legal holds
        holds = await conn.fetch(
            "SELECT reference_number, reason, created_at FROM legal_holds WHERE account_id = $1 AND is_active = true;",
            acc_id
        )

        # Retrieve transactions
        txs = await conn.fetch(
            """
            SELECT id, amount, currency, status, timestamp, country, channel
            FROM transactions
            WHERE (sender_account_id = $1 OR receiver_account_id = $1)
            ORDER BY timestamp DESC LIMIT 100;
            """,
            acc_id
        )

        return {
            "dossier_type": "GDPR_ARTICLE_15_DSAR_EXPORT",
            "account": {
                "account_number": acc["account_number"],
                "owner_name": acc["owner_name"],
                "swift_bic": acc["swift_bic"],
                "status": acc["status"],
                "risk_score": float(acc["risk_score"] or 0.0),
                "created_at": acc["created_at"].isoformat() if acc["created_at"] else None
            },
            "legal_holds_active": [
                {"reference": h["reference_number"], "reason": h["reason"]} for h in holds
            ],
            "transaction_history_count": len(txs),
            "transactions": [
                {
                    "tx_id": str(t["id"]),
                    "amount": float(t["amount"]),
                    "currency": t["currency"],
                    "status": t["status"],
                    "timestamp": t["timestamp"].isoformat() if t["timestamp"] else None
                }
                for t in txs
            ]
        }


@router.post("/legal-holds", status_code=status.HTTP_201_CREATED)
async def create_legal_hold(
    payload: LegalHoldCreate,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60))
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
            uuid.UUID(str(tenant_id)), acc_uuid, case_uuid,
            payload.reference_number, payload.reason, current_user.get("username", "mlro")
        )

        logger.info(f"LEGAL HOLD placed on account {payload.account_id} by {current_user.get('username')}: Ref {payload.reference_number}")

        return {
            "hold_id": str(hold_id),
            "account_id": payload.account_id,
            "reference_number": payload.reference_number,
            "status": "ACTIVE",
            "message": "Legal hold established. Automated data purge/erasure is blocked."
        }


@router.delete("/legal-holds/{id}")
async def release_legal_hold(
    id: str,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60))
):
    try:
        hold_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hold ID.")

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        res = await conn.execute(
            """
            UPDATE legal_holds
            SET is_active = false, released_at = NOW()
            WHERE id = $1 AND tenant_id = $2;
            """,
            hold_uuid, uuid.UUID(str(tenant_id))
        )
        return {
            "hold_id": id,
            "status": "RELEASED",
            "message": "Legal hold released."
        }
