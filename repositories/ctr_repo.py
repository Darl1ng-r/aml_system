"""
Currency Transaction Report (CTR) Repository
============================================
Enforces row-level locking (`FOR UPDATE`), deterministic CTR state-machine guards
(`PENDING -> FILED`), and atomic cryptographic WORM `audit_log` persistence inside
a single PostgreSQL ACID transaction.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from database.postgres import get_async_db_conn, get_async_db_read_conn
from domain.state_machine import CTRFilingStatus, validate_ctr_transition_pure
from services.audit import record_audit_event_tx

logger = logging.getLogger(__name__)


async def list_ctr_filings_repo(
    *,
    tenant_id: Any,
    limit: int,
    offset: int,
    status_filter: Optional[str] = None,
    cursor: Optional[str] = None,
) -> list[Any]:
    from database.pagination import decode_keyset_cursor, validate_legacy_offset

    tenant_uuid = uuid.UUID(str(tenant_id))
    async with get_async_db_read_conn(tenant_id=str(tenant_uuid)) as conn:
        if cursor:
            c_ts, c_id = decode_keyset_cursor(cursor)
            if status_filter:
                return await conn.fetch(
                    """
                    SELECT c.*, a.account_number, a.owner_name
                    FROM ctr_filings c
                    JOIN accounts a ON c.account_id = a.id
                    WHERE c.tenant_id = $1 AND c.status = $2 AND (c.created_at, c.id) < ($3, $4)
                    ORDER BY c.created_at DESC, c.id DESC
                    LIMIT $5;
                    """,
                    tenant_uuid,
                    status_filter.upper(),
                    c_ts,
                    c_id,
                    limit + 1,
                )
            return await conn.fetch(
                """
                SELECT c.*, a.account_number, a.owner_name
                FROM ctr_filings c
                JOIN accounts a ON c.account_id = a.id
                WHERE c.tenant_id = $1 AND (c.created_at, c.id) < ($2, $3)
                ORDER BY c.created_at DESC, c.id DESC
                LIMIT $4;
                """,
                tenant_uuid,
                c_ts,
                c_id,
                limit + 1,
            )

        safe_offset = validate_legacy_offset(offset)
        if status_filter:
            return await conn.fetch(
                """
                SELECT c.*, a.account_number, a.owner_name
                FROM ctr_filings c
                JOIN accounts a ON c.account_id = a.id
                WHERE c.tenant_id = $1 AND c.status = $2
                ORDER BY c.due_date ASC, c.id ASC
                LIMIT $3 OFFSET $4;
                """,
                tenant_uuid,
                status_filter.upper(),
                limit,
                safe_offset,
            )
        return await conn.fetch(
            """
            SELECT c.*, a.account_number, a.owner_name
            FROM ctr_filings c
            JOIN accounts a ON c.account_id = a.id
            WHERE c.tenant_id = $1
            ORDER BY c.due_date ASC, c.id ASC
            LIMIT $2 OFFSET $3;
            """,
            tenant_uuid,
            limit,
            safe_offset,
        )


async def submit_ctr_filing_atomic(
    *,
    ctr_uuid: uuid.UUID,
    tenant_id: Any,
    current_user: Mapping[str, Any],
) -> Optional[dict[str, Any]]:
    """
    Atomically locks the CTR record `FOR UPDATE`, validates `PENDING -> FILED` via
    the pure domain FSM, assigns an immutable FinCEN CTR tracking ID, and writes a
    cryptographic WORM `audit_log` event in the same PostgreSQL transaction.

    Returns None if CTR record is not found within tenant scope.
    Raises `CorruptedDomainStateError` or `DomainStateTransitionError` on illegal transitions.
    """
    tenant_uuid = uuid.UUID(str(tenant_id))
    now_utc = datetime.now(timezone.utc)
    tracking_id = f"CTR-{now_utc.year}-{uuid.uuid4().hex[:10].upper()}"
    user_uuid = uuid.UUID(str(current_user["id"])) if current_user.get("id") else None
    username = str(current_user.get("username") or "mlro")
    role = str(current_user.get("role") or "MLRO")

    async with get_async_db_conn(tenant_id=str(tenant_uuid)) as conn:
        ctr = await conn.fetchrow(
            "SELECT * FROM ctr_filings WHERE id = $1 AND tenant_id = $2 FOR UPDATE;",
            ctr_uuid,
            tenant_uuid,
        )
        if not ctr:
            return None

        # Pure deterministic FSM guard — prevents overwriting already-FILED tracking IDs
        validate_ctr_transition_pure(str(ctr["status"]), CTRFilingStatus.FILED.value)

        await conn.execute(
            """
            UPDATE ctr_filings
            SET status = 'FILED',
                fincen_tracking_id = $1,
                filed_at = $2,
                filed_by = $3,
                filed_by_username = $4,
                updated_at = $2
            WHERE id = $5 AND tenant_id = $6;
            """,
            tracking_id,
            now_utc,
            user_uuid,
            username,
            ctr_uuid,
            tenant_uuid,
        )

        await record_audit_event_tx(
            conn=conn,
            action="FINCEN_CTR_FILED",
            actor_id=str(user_uuid or username),
            actor_username=username,
            actor_role=role,
            resource_type="CTR_FILING",
            resource_id=str(ctr_uuid),
            tenant_id=str(tenant_uuid),
            details={
                "fincen_tracking_id": tracking_id,
                "transaction_id": str(ctr["transaction_id"]) if ctr["transaction_id"] else None,
                "account_id": str(ctr["account_id"]) if ctr["account_id"] else None,
                "amount": str(ctr["amount"]),
                "currency": ctr["currency"],
                "filed_at": now_utc.isoformat(),
            },
        )

    logger.info("FinCEN CTR filed for record %s: Tracking ID %s by %s", ctr_uuid, tracking_id, username)
    return {
        "ctr_id": str(ctr_uuid),
        "status": CTRFilingStatus.FILED.value,
        "fincen_tracking_id": tracking_id,
        "filed_at": now_utc.isoformat(),
        "message": "Currency Transaction Report (CTR) filed successfully with FinCEN.",
    }
