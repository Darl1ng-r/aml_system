"""
Compliance Configuration & Regulatory Batch Repository
======================================================
Encapsulates PostgreSQL queries, row locks (`FOR UPDATE`), and transactional
audit writes for institutional risk appetite settings and STR batch filings.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Mapping, Optional

from database.postgres import get_async_db_conn, get_async_db_read_conn
from services.audit import record_audit_event_tx


# ── Risk Appetite Settings ────────────────────────────────────────────────────

async def fetch_risk_appetite_repo(
    tenant_uuid: uuid.UUID,
    *,
    read_conn_factory: Any = None,
) -> Any:
    conn_factory = read_conn_factory or get_async_db_read_conn
    async with conn_factory(tenant_id=str(tenant_uuid)) as conn:
        return await conn.fetchrow(
            """
            SELECT config, updated_by, updated_at
            FROM risk_appetite_settings
            WHERE tenant_id = $1;
            """,
            tenant_uuid,
        )


async def upsert_risk_appetite_atomic(
    *,
    tenant_uuid: uuid.UUID,
    updated_data: dict[str, Any],
    default_before: dict[str, Any],
    actor: Mapping[str, Any],
    now_utc: datetime,
    sla_hours: int,
    edd_threshold: float,
    write_conn_factory: Any = None,
) -> dict[str, Any]:
    conn_factory = write_conn_factory or get_async_db_conn
    before_state = dict(default_before)
    updated_by = str(actor.get("username") or "admin")

    async with conn_factory(tenant_id=str(tenant_uuid)) as conn:
        existing = await conn.fetchrow(
            "SELECT config FROM risk_appetite_settings WHERE tenant_id = $1 FOR UPDATE;",
            tenant_uuid,
        )
        if existing and existing["config"]:
            before_state = (
                json.loads(existing["config"])
                if isinstance(existing["config"], str)
                else dict(existing["config"])
            )

        await conn.execute(
            """
            INSERT INTO risk_appetite_settings (tenant_id, config, updated_by, updated_at)
            VALUES ($1, $2::jsonb, $3, $4)
            ON CONFLICT (tenant_id) DO UPDATE
            SET config = EXCLUDED.config,
                updated_by = EXCLUDED.updated_by,
                updated_at = EXCLUDED.updated_at;
            """,
            tenant_uuid,
            json.dumps(updated_data, default=str),
            updated_by,
            now_utc,
        )

        await record_audit_event_tx(
            conn=conn,
            action="UPDATE_RISK_APPETITE",
            actor_id=str(actor.get("sub") or actor.get("id") or updated_by),
            actor_role=str(actor.get("role") or "MLRO"),
            resource_type="RISK_APPETITE",
            resource_id=str(tenant_uuid),
            tenant_id=str(tenant_uuid),
            actor_username=updated_by,
            before_state=before_state,
            after_state=updated_data,
            details={"sla_hours": sla_hours, "edd_threshold": edd_threshold},
        )

        from services.cache_aside import build_cache_key, record_cache_invalidation_outbox

        invalidation_keys = [
            build_cache_key("metrics_exec", str(tenant_uuid), "summary"),
            build_cache_key("risk_appetite", str(tenant_uuid), "config"),
        ]
        try:
            await record_cache_invalidation_outbox(
                conn,
                keys=invalidation_keys,
                tenant_id=str(tenant_uuid),
                namespace="risk_appetite",
            )
        except Exception as inv_err:
            logger.debug("Outbox cache invalidation skipped in risk_appetite: %s", inv_err)

    # Strictly POST-COMMIT cache invalidation
    from services.cache_aside import invalidate_cache_keys_after_commit

    await invalidate_cache_keys_after_commit(invalidation_keys, namespace="risk_appetite")
    return before_state


# ── STR Regulatory Batches ────────────────────────────────────────────────────

async def list_str_batches_repo(
    tenant_id: str,
    limit: int,
    offset: int,
    *,
    cursor: Optional[str] = None,
    conn_factory: Any = None,
) -> list[Any]:
    from database.pagination import decode_keyset_cursor, validate_legacy_offset

    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        if cursor:
            c_ts, c_id = decode_keyset_cursor(cursor, require_uuid=False)
            return await conn.fetch(
                """
                SELECT id, record_count, total_amount, checksum, status, created_at
                FROM str_batches
                WHERE tenant_id = $1::uuid AND (created_at, id) < ($2, $3)
                ORDER BY created_at DESC, id DESC
                LIMIT $4;
                """,
                str(tenant_id),
                c_ts,
                str(c_id),
                limit + 1,
            )

        safe_offset = validate_legacy_offset(offset)
        return await conn.fetch(
            """
            SELECT id, record_count, total_amount, checksum, status, created_at
            FROM str_batches
            WHERE tenant_id = $1::uuid
            ORDER BY created_at DESC, id DESC
            LIMIT $2 OFFSET $3;
            """,
            str(tenant_id),
            limit,
            safe_offset,
        )


async def fetch_str_batch_xml_repo(
    batch_id: str,
    tenant_id: str,
    *,
    conn_factory: Any = None,
) -> Optional[str]:
    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        row = await conn.fetchrow(
            "SELECT payload_xml FROM str_batches WHERE id = $1 AND tenant_id = $2::uuid;",
            batch_id,
            str(tenant_id),
        )
        return row["payload_xml"] if row else None


async def claim_str_batch_for_transmission_repo(
    batch_id: str,
    tenant_id: str,
    *,
    conn_factory: Any = None,
) -> tuple[Optional[str], Optional[str]]:
    """
    Phase 1 of 3-phase STR transmission Saga.
    Returns `(payload_xml, conflict_or_missing_status)`:
      - `(xml, None)`          : Claimed successfully (`TRANSMITTING`).
      - `(None, None)`         : Batch not found (`404`).
      - `(None, existing_st)`  : Already transmitting/filed (`409`).
    """
    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        claimed = await conn.fetchrow(
            """
            UPDATE str_batches
            SET status = 'TRANSMITTING'
            WHERE id = $1 AND tenant_id = $2::uuid
              AND status IN ('GENERATED', 'READY_FOR_SUBMISSION', 'FAILED')
            RETURNING payload_xml;
            """,
            batch_id,
            str(tenant_id),
        )
        if claimed:
            return claimed["payload_xml"], None
        existing = await conn.fetchrow(
            "SELECT status FROM str_batches WHERE id = $1 AND tenant_id = $2::uuid;",
            batch_id,
            str(tenant_id),
        )
        if not existing:
            return None, None
        return None, str(existing["status"])


async def mark_str_batch_failed_repo(
    batch_id: str,
    tenant_id: str,
    *,
    conn_factory: Any = None,
) -> None:
    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        await conn.execute(
            "UPDATE str_batches SET status = 'FAILED' WHERE id = $1 AND tenant_id = $2::uuid;",
            batch_id,
            str(tenant_id),
        )


async def finalize_str_batch_transmission_atomic(
    *,
    batch_id: str,
    tenant_id: str,
    receipt_status: str,
    fincen_tracking_id: Optional[str],
    actor: Mapping[str, Any],
    conn_factory: Any = None,
) -> None:
    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        await conn.execute(
            """
            UPDATE str_batches
            SET status = $1
            WHERE id = $2 AND tenant_id = $3::uuid;
            """,
            receipt_status,
            batch_id,
            str(tenant_id),
        )
        await record_audit_event_tx(
            conn=conn,
            action="STR_BATCH_TRANSMITTED",
            actor_id=str(actor.get("id") or actor.get("username") or "unknown"),
            actor_username=str(actor.get("username") or "mlro"),
            actor_role=str(actor.get("role") or "MLRO"),
            resource_type="STR_BATCH",
            resource_id=batch_id,
            tenant_id=str(tenant_id) if tenant_id else None,
            details={
                "batch_id": batch_id,
                "status": receipt_status,
                "fincen_tracking_id": fincen_tracking_id,
            },
        )
