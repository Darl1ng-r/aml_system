"""
Durable PostgreSQL L2 Idempotency Repository
============================================
Backs Redis fast-path idempotency with an RLS-enforced PostgreSQL `idempotency_records`
table so Redis evictions, restarts, or failovers can never permit duplicate financial
mutations or compliance filings.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Dict, Optional, Tuple

from database.postgres import get_async_db_conn

logger = logging.getLogger(__name__)


def _parse_tenant_uuid(tenant_id: Optional[str]) -> Optional[uuid.UUID]:
    if not tenant_id:
        return None
    try:
        return uuid.UUID(str(tenant_id))
    except (ValueError, TypeError):
        return None


async def try_reserve_db_idempotency(
    *,
    tenant_id: Optional[str],
    scope: str,
    idempotency_key: str,
    request_hash: str,
    ttl_seconds: int = 86400,
) -> Tuple[str, Optional[Dict[str, Any]]]:
    """
    Atomically reserves `(tenant_id, scope, idempotency_key)` in PostgreSQL.

    Returns `(outcome, record)`:
      - `("RESERVED", None)`      : Fresh reservation acquired; caller may proceed.
      - `("COMPLETED", payload)`  : Durable completed response found; caller should replay.
      - `("IN_FLIGHT", None)`     : Concurrent request with same key is still running (HTTP 409).
      - `("HASH_MISMATCH", None)` : Key was already used with a different body hash (HTTP 422).
      - `("SKIPPED", None)`       : Non-UUID tenant or DB unavailable (caller relies on L1).
    """
    tenant_uuid = _parse_tenant_uuid(tenant_id)
    if tenant_uuid is None or not idempotency_key:
        return "SKIPPED", None

    norm_scope = (scope or "default")[:64]
    norm_key = str(idempotency_key)[:128]
    req_hash = str(request_hash or "")[:64]

    try:
        async with get_async_db_conn(tenant_id=str(tenant_uuid)) as conn:
            # 1. Attempt atomic fresh insert
            inserted = await conn.fetchval(
                """
                INSERT INTO idempotency_records (
                    tenant_id, scope, idempotency_key, request_hash, status, expires_at
                )
                VALUES (
                    $1::uuid, $2, $3, $4, 'IN_FLIGHT',
                    NOW() + ($5 * INTERVAL '1 second')
                )
                ON CONFLICT (tenant_id, scope, idempotency_key) DO NOTHING
                RETURNING idempotency_key;
                """,
                tenant_uuid,
                norm_scope,
                norm_key,
                req_hash,
                int(max(60, ttl_seconds)),
            )
            if inserted is not None:
                return "RESERVED", None

            # 2. Conflict — inspect existing row under row lock to handle expiry or replay cleanly
            row = await conn.fetchrow(
                """
                SELECT request_hash, status, response_status, response_body,
                       (expires_at <= NOW()) AS is_expired
                FROM idempotency_records
                WHERE tenant_id = $1::uuid
                  AND scope = $2
                  AND idempotency_key = $3
                FOR UPDATE;
                """,
                tenant_uuid,
                norm_scope,
                norm_key,
            )
            if not row:
                return "RESERVED", None

            if bool(row["is_expired"]):
                await conn.execute(
                    """
                    UPDATE idempotency_records
                    SET request_hash = $4,
                        status = 'IN_FLIGHT',
                        response_status = NULL,
                        response_body = NULL,
                        updated_at = NOW(),
                        expires_at = NOW() + ($5 * INTERVAL '1 second')
                    WHERE tenant_id = $1::uuid
                      AND scope = $2
                      AND idempotency_key = $3;
                    """,
                    tenant_uuid,
                    norm_scope,
                    norm_key,
                    req_hash,
                    int(max(60, ttl_seconds)),
                )
                return "RESERVED", None

            existing_hash = row["request_hash"] or ""
            if req_hash and existing_hash and existing_hash != req_hash:
                return "HASH_MISMATCH", None

            if row["status"] == "IN_FLIGHT":
                return "IN_FLIGHT", None

            if row["status"] == "COMPLETED":
                body = row["response_body"]
                if isinstance(body, str):
                    try:
                        body = json.loads(body)
                    except Exception:
                        body = {}
                return "COMPLETED", {
                    "status": "COMPLETED",
                    "status_code": int(row["response_status"] or 200),
                    "body": body if body is not None else {},
                    "request_hash": existing_hash,
                }

            return "RESERVED", None
    except Exception as exc:
        logger.debug("PostgreSQL L2 idempotency reserve skipped/unavailable: %s", exc)
        return "SKIPPED", None


async def complete_db_idempotency(
    *,
    tenant_id: Optional[str],
    scope: str,
    idempotency_key: str,
    status_code: int,
    body: Any,
    request_hash: str,
    ttl_seconds: int = 86400,
) -> bool:
    """Marks a durable idempotency record COMPLETED with its canonical JSON response."""
    tenant_uuid = _parse_tenant_uuid(tenant_id)
    if tenant_uuid is None or not idempotency_key:
        return False

    norm_scope = (scope or "default")[:64]
    norm_key = str(idempotency_key)[:128]
    req_hash = str(request_hash or "")[:64]
    body_json = json.dumps(body, default=str)

    try:
        async with get_async_db_conn(tenant_id=str(tenant_uuid)) as conn:
            await conn.execute(
                """
                INSERT INTO idempotency_records (
                    tenant_id, scope, idempotency_key, request_hash,
                    status, response_status, response_body, expires_at
                )
                VALUES (
                    $1::uuid, $2, $3, $4,
                    'COMPLETED', $5, $6::jsonb,
                    NOW() + ($7 * INTERVAL '1 second')
                )
                ON CONFLICT (tenant_id, scope, idempotency_key) DO UPDATE SET
                    status = 'COMPLETED',
                    response_status = EXCLUDED.response_status,
                    response_body = EXCLUDED.response_body,
                    updated_at = NOW(),
                    expires_at = EXCLUDED.expires_at;
                """,
                tenant_uuid,
                norm_scope,
                norm_key,
                req_hash,
                int(status_code),
                body_json,
                int(max(60, ttl_seconds)),
            )
            return True
    except Exception as exc:
        logger.debug("PostgreSQL L2 idempotency complete skipped/unavailable: %s", exc)
        return False


async def release_in_flight_db_idempotency(
    *,
    tenant_id: Optional[str],
    scope: str,
    idempotency_key: str,
) -> bool:
    """Deletes an IN_FLIGHT record on handler failure without ever removing COMPLETED records."""
    tenant_uuid = _parse_tenant_uuid(tenant_id)
    if tenant_uuid is None or not idempotency_key:
        return False

    norm_scope = (scope or "default")[:64]
    norm_key = str(idempotency_key)[:128]

    try:
        async with get_async_db_conn(tenant_id=str(tenant_uuid)) as conn:
            await conn.execute(
                """
                DELETE FROM idempotency_records
                WHERE tenant_id = $1::uuid
                  AND scope = $2
                  AND idempotency_key = $3
                  AND status = 'IN_FLIGHT';
                """,
                tenant_uuid,
                norm_scope,
                norm_key,
            )
            return True
    except Exception as exc:
        logger.debug("PostgreSQL L2 idempotency release skipped/unavailable: %s", exc)
        return False
