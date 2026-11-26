"""
Operations, Webhooks, QA Sampling, Notifications, Watchlist & Health Repository
===============================================================================
Encapsulates all PostgreSQL queries and `FOR UPDATE` row locking for
core-banking webhooks, Four-Eyes QA sampling, in-app notifications,
system/queue health probes, PEP watchlist counts, and PEP screening fallbacks.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any, Callable, Mapping, Optional

from fastapi import HTTPException, status

import database.postgres as _pg
from services.audit import record_audit_event_tx

logger = logging.getLogger(__name__)

SQL_PING_QUERY = "SELECT 1"


def _write_factory(conn_factory: Any = None) -> Any:
    return conn_factory or _pg.get_async_db_conn


def _read_factory(read_conn_factory: Any = None) -> Any:
    return read_conn_factory or _pg.get_async_db_read_conn


# ── Core-Banking Webhooks ─────────────────────────────────────────────────────

async def list_webhooks_repo(*, tenant_id: str, read_conn_factory: Any = None) -> list[Any]:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return list(
            await conn.fetch(
                """
                SELECT id, name, url, subscribed_events, enabled, created_by, created_at, updated_at
                FROM tenant_webhooks
                ORDER BY created_at DESC;
                """
            )
            or []
        )


async def create_webhook_repo(
    *,
    tenant_id: str,
    safe_name: str,
    safe_url: str,
    encrypted_secret: str,
    normalized_events: list[str],
    enabled: bool,
    username: str,
    conn_factory: Any = None,
) -> uuid.UUID:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetchval(
            """
            INSERT INTO tenant_webhooks (
                tenant_id, name, url, signing_secret_enc, subscribed_events, enabled, created_by
            )
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
            RETURNING id;
            """,
            str(tenant_id),
            safe_name,
            safe_url,
            encrypted_secret,
            normalized_events,
            enabled,
            username,
        )


async def delete_webhook_atomic(
    *,
    hook_uuid: uuid.UUID,
    tenant_id: str,
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> None:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        deleted = await conn.fetchval(
            "DELETE FROM tenant_webhooks WHERE id = $1 AND tenant_id = $2::uuid RETURNING id;",
            hook_uuid,
            str(tenant_id),
        )
        if not deleted:
            raise HTTPException(status_code=404, detail="Webhook not found.")
        try:
            await record_audit_event_tx(
                conn=conn,
                action="DELETE_WEBHOOK",
                actor_id=str(current_user.get("id") or current_user.get("username") or "unknown"),
                actor_username=current_user.get("username", "admin"),
                actor_role=current_user.get("role", "ADMIN"),
                resource_type="WEBHOOK",
                resource_id=str(hook_uuid),
                tenant_id=str(tenant_id),
                details={"deleted": True},
            )
        except Exception as audit_err:
            logger.warning("Transactional audit write skipped in delete_webhook: %s", audit_err)


async def list_webhook_deliveries_repo(
    *,
    hook_uuid: uuid.UUID,
    tenant_id: str,
    limit: int,
    read_conn_factory: Any = None,
) -> list[Any]:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return list(
            await conn.fetch(
                """
                SELECT id, event_type, status, http_status, attempts, last_error, delivered_at, created_at
                FROM webhook_deliveries
                WHERE webhook_id = $1
                ORDER BY created_at DESC
                LIMIT $2;
                """,
                hook_uuid,
                limit,
            )
            or []
        )


async def fetch_webhook_for_test_repo(
    *,
    hook_uuid: uuid.UUID,
    tenant_id: str,
    read_conn_factory: Any = None,
) -> Any:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetchrow(
            "SELECT id, url, signing_secret_enc FROM tenant_webhooks WHERE id = $1;",
            hook_uuid,
        )


# ── Quality Assurance (Four-Eyes Sampling) ────────────────────────────────────

async def create_qa_sample_repo(
    *,
    tenant_id: str,
    sampled_by_username: str,
    sample_rate: float,
    max_samples: int,
    sample_fn: Callable[..., Any],
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await sample_fn(
            conn=conn,
            tenant_id=tenant_id,
            sampled_by_username=sampled_by_username,
            sample_rate=sample_rate,
            max_samples=max_samples,
        )


async def fetch_qa_queue_repo(
    *,
    tenant_id: str,
    status_filter: Optional[str],
    limit: int,
    read_conn_factory: Any = None,
) -> tuple[list[Any], Any]:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        if status_filter:
            rows = await conn.fetch(
                """
                SELECT q.*, a.rule_name, a.threat_level, a.ai_risk_score
                FROM qa_reviews q
                LEFT JOIN alerts a ON q.alert_id = a.id
                WHERE q.status = $1
                ORDER BY q.sampled_at DESC
                LIMIT $2;
                """,
                status_filter,
                limit,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT q.*, a.rule_name, a.threat_level, a.ai_risk_score
                FROM qa_reviews q
                LEFT JOIN alerts a ON q.alert_id = a.id
                ORDER BY q.sampled_at DESC
                LIMIT $1;
                """,
                limit,
            )

        stats = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE status = 'PENDING') AS pending_count,
                COUNT(*) FILTER (WHERE status = 'PASSED') AS passed_count,
                COUNT(*) FILTER (WHERE status = 'FAILED_REOPENED') AS failed_count
            FROM qa_reviews;
            """
        )
    return list(rows or []), stats


async def submit_qa_review_atomic(
    *,
    rev_uuid: uuid.UUID,
    tenant_id: str,
    decision: str,
    notes: str,
    reviewer_username: str,
    reviewer_id: str,
    current_user: Mapping[str, Any],
    notify_fn: Callable[..., Any],
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        row = await conn.fetchrow(
            "SELECT * FROM qa_reviews WHERE id = $1 AND tenant_id = $2::uuid FOR UPDATE;",
            rev_uuid,
            str(tenant_id),
        )
        if not row:
            raise HTTPException(status_code=404, detail="QA review item not found.")
        if row["status"] != "PENDING":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"QA review is already finalized ({row['status']}).",
            )

        orig_analyst = str(row["original_analyst_username"] or "").strip()
        orig_analyst_id = str(row.get("original_analyst_id") or "").strip() if hasattr(row, "get") else ""
        if (orig_analyst_id and reviewer_id and orig_analyst_id == reviewer_id) or (
            orig_analyst and orig_analyst.lower() == reviewer_username.lower()
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Segregation of Duties Violation: QA reviewer cannot audit their own dismissed alert.",
            )

        await conn.execute(
            """
            UPDATE qa_reviews
            SET status = $1,
                qa_reviewer_username = $2,
                qa_notes = $3,
                reviewed_at = NOW()
            WHERE id = $4 AND tenant_id = $5::uuid;
            """,
            decision,
            reviewer_username,
            notes,
            rev_uuid,
            str(tenant_id),
        )

        reopened = False
        if decision == "FAILED_REOPENED":
            reopened = True
            await conn.execute(
                "UPDATE alerts SET status = 'OPEN' WHERE id = $1 AND tenant_id = $2::uuid;",
                row["alert_id"],
                str(tenant_id),
            )
            await notify_fn(
                conn=conn,
                tenant_id=tenant_id,
                category="QA_REOPEN",
                severity="CRITICAL",
                recipient_role="MLRO",
                title=f"QA Audit Reopened Alert {str(row['alert_id'])[:8]}",
                body=f"Reviewer {reviewer_username} failed QA on dismissed alert: {notes}",
                link_url=f"/alerts/triage?search={str(row['alert_id'])[:8]}",
                resource_type="ALERT",
                resource_id=str(row["alert_id"]),
                dedup_hours=0,
            )

        try:
            await record_audit_event_tx(
                conn=conn,
                action=f"QA_REVIEW_{decision}",
                actor_id=str(current_user.get("id") or reviewer_username),
                actor_username=reviewer_username,
                actor_role=current_user.get("role", "QA_REVIEWER"),
                resource_type="QA_REVIEW",
                resource_id=str(rev_uuid),
                tenant_id=str(tenant_id),
                details={"alert_id": str(row["alert_id"]), "decision": decision, "reopened": reopened},
            )
        except Exception as audit_err:
            logger.warning("Transactional audit write skipped in submit_qa_review: %s", audit_err)

    return {"alert_id": str(row["alert_id"]), "reopened": reopened}


# ── In-App Notifications & SLA Escalations ────────────────────────────────────

async def list_notifications_repo(
    *,
    tenant_id: str,
    user_uuid: Optional[uuid.UUID],
    user_role: str,
    unread_only: bool,
    limit: int,
    read_conn_factory: Any = None,
) -> tuple[list[Any], int]:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, category, severity, title, body, link_url,
                   resource_type, resource_id, is_read, created_at
            FROM notifications
            WHERE (recipient_user_id IS NULL OR recipient_user_id = $1)
              AND (recipient_role IS NULL OR recipient_role = $2 OR $2 IN ('ADMIN', 'SUPER_ADMIN'))
              AND ($3 = FALSE OR is_read = FALSE)
            ORDER BY created_at DESC
            LIMIT $4;
            """,
            user_uuid,
            user_role,
            unread_only,
            limit,
        )
        unread_count = await conn.fetchval(
            """
            SELECT COUNT(*)
            FROM notifications
            WHERE is_read = FALSE
              AND (recipient_user_id IS NULL OR recipient_user_id = $1)
              AND (recipient_role IS NULL OR recipient_role = $2 OR $2 IN ('ADMIN', 'SUPER_ADMIN'));
            """,
            user_uuid,
            user_role,
        )
    return list(rows or []), int(unread_count or 0)


async def mark_notification_read_repo(
    *,
    nid: uuid.UUID,
    tenant_id: str,
    user_uuid: Optional[uuid.UUID],
    user_role: str,
    conn_factory: Any = None,
) -> Any:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetchval(
            """
            UPDATE notifications
            SET is_read = TRUE
            WHERE id = $1
              AND tenant_id = $4::uuid
              AND (recipient_user_id IS NULL OR recipient_user_id = $2)
              AND (recipient_role IS NULL OR recipient_role = $3 OR $3 IN ('ADMIN', 'TENANT_ADMIN', 'SUPER_ADMIN'))
            RETURNING id;
            """,
            nid,
            user_uuid,
            user_role,
            str(tenant_id),
        )


async def mark_all_notifications_read_repo(
    *,
    tenant_id: str,
    user_uuid: Optional[uuid.UUID],
    user_role: str,
    conn_factory: Any = None,
) -> None:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        await conn.execute(
            """
            UPDATE notifications
            SET is_read = TRUE
            WHERE is_read = FALSE
              AND (recipient_user_id IS NULL OR recipient_user_id = $1)
              AND (recipient_role IS NULL OR recipient_role = $2 OR $2 IN ('ADMIN', 'SUPER_ADMIN'));
            """,
            user_uuid,
            user_role,
        )


async def trigger_sla_sweep_repo(
    *,
    tenant_id: str,
    sweep_fn: Callable[..., Any],
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await sweep_fn(conn=conn, tenant_id=tenant_id)


# ── Health Probes & Queue Telemetry ───────────────────────────────────────────

async def ping_postgres_pool_repo(*, timeout: float = 2.0) -> dict[str, Any]:
    """Pings the active PostgreSQL pool with explicit acquire + query timeout."""
    pool = _pg.db_pool
    if pool is None:
        raise RuntimeError("Connection pool not initialised")
    t0 = time.monotonic()
    async with pool.acquire(timeout=timeout) as conn:
        await asyncio.wait_for(conn.fetchval(SQL_PING_QUERY), timeout=timeout)
    latency_ms = round((time.monotonic() - t0) * 1000, 1)
    pool_size = (
        pool.get_size()
        if callable(getattr(pool, "get_size", None))
        else getattr(pool, "_size", None)
    )
    free_conns = (
        pool.get_idle_size()
        if callable(getattr(pool, "get_idle_size", None))
        else getattr(pool, "_free", None)
    )
    return {
        "latency_ms": latency_ms,
        "pool_size": pool_size,
        "free_connections": free_conns,
    }


async def fetch_queue_health_counts_repo(
    *,
    tenant_id: str,
    conn_factory: Any = None,
) -> tuple[int, float, float]:
    factory = _write_factory(conn_factory)
    tx_rate_per_sec = 0.0
    alert_rate_per_sec = 0.0
    async with factory(tenant_id=tenant_id) as conn:
        pending_outbox = await conn.fetchval(
            "SELECT COUNT(*) FROM transactional_outbox WHERE tenant_id = $1::uuid AND status IN ('PENDING', 'PROCESSING');",
            str(tenant_id),
        )
        pending_outbox = int(pending_outbox or 0)
        try:
            published_60s = await conn.fetchval(
                """
                SELECT COUNT(*) FROM transactional_outbox
                WHERE tenant_id = $1::uuid AND status = 'PUBLISHED' AND updated_at >= NOW() - INTERVAL '60 seconds';
                """,
                str(tenant_id),
            )
            if isinstance(published_60s, (int, float)):
                tx_rate_per_sec = round(float(published_60s) / 60.0, 2)
            alerts_60s = await conn.fetchval(
                "SELECT COUNT(*) FROM alerts WHERE tenant_id = $1::uuid AND created_at >= NOW() - INTERVAL '60 seconds';",
                str(tenant_id),
            )
            if isinstance(alerts_60s, (int, float)):
                alert_rate_per_sec = round(float(alerts_60s) / 60.0, 2)
        except Exception:
            pass
    return pending_outbox, tx_rate_per_sec, alert_rate_per_sec


# ── Watchlist & Screening PG Fallbacks ────────────────────────────────────────

async def fetch_pep_watchlist_status_repo(
    *,
    tenant_id: str,
    read_conn_factory: Any = None,
) -> tuple[int, Any]:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        pg_pep_count = int(await conn.fetchval("SELECT COUNT(*) FROM pep_entities;") or 0)
        pg_last_sync = await conn.fetchval("SELECT MAX(created_at) FROM pep_entities;")
    return pg_pep_count, pg_last_sync


async def query_pep_entities_pg_repo(
    *,
    name: str,
    tenant_id: Optional[str],
    columns: str,
    read_conn_factory: Any = None,
) -> list[Any]:
    factory = _read_factory(read_conn_factory)
    search_pattern = f"%{name.strip()}%"
    clean_name = name.strip()
    async with factory(tenant_id=tenant_id) as conn:
        if tenant_id:
            try:
                t_uuid = uuid.UUID(str(tenant_id))
                return list(
                    await conn.fetch(
                        f"""
                        SELECT {columns}
                        FROM pep_entities
                        WHERE (tenant_id = $1 OR tenant_id IS NULL)
                          AND is_active = true
                          AND (name ILIKE $2 OR $3 ILIKE '%' || name || '%')
                        LIMIT 100;
                        """,
                        t_uuid,
                        search_pattern,
                        clean_name,
                    )
                    or []
                )
            except ValueError:
                pass
        return list(
            await conn.fetch(
                f"""
                SELECT {columns}
                FROM pep_entities
                WHERE tenant_id IS NULL
                  AND is_active = true
                  AND (name ILIKE $1 OR $2 ILIKE '%' || name || '%')
                LIMIT 100;
                """,
                search_pattern,
                clean_name,
            )
            or []
        )
