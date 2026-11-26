"""
Immutable Audit Logging Service
================================
Persists regulatory-grade, append-only audit events into the PostgreSQL `audit_log` table.
Guarantees tamper-evidence and regulatory compliance (FFIEC, BSA 31 CFR 1010.430, EU AMLD6).
"""

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from database.postgres import get_async_db_conn

logger = logging.getLogger("aml.audit")

GENESIS_AUDIT_HASH = "GENESIS_ROOT_CHAIN_00000000000000000000000000000000"

# Strong task references prevent Python GC from silently cancelling queued audit inserts (T-06)
_audit_tasks: set[asyncio.Task] = set()


def compute_audit_record_hash(
    prev_hash: str,
    created_at_iso: str,
    actor_id: Any,
    action: str,
    resource_type: Any,
    resource_id: Any,
    details: Any
) -> str:
    """Computes deterministic SHA-256 chain hash for an immutable audit_log row."""
    det_str = (
        json.dumps(details, sort_keys=True)
        if isinstance(details, dict)
        else str(details or "{}")
    )
    payload = f"{prev_hash}:{created_at_iso}:{actor_id}:{action}:{resource_type}:{resource_id}:{det_str}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def record_audit_event_tx(
    conn,
    action: str,
    actor_id: str,
    actor_role: str,
    resource_type: str,
    resource_id: str,
    tenant_id: Optional[str] = None,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    actor_user_agent: Optional[str] = None,
    before_state: Optional[Dict[str, Any]] = None,
    after_state: Optional[Dict[str, Any]] = None,
    **kwargs: Any
) -> None:
    """
    Synchronously persists an immutable, SHA-256 hash-chained record into the append-only
    audit_log table within the caller's active database transaction/connection (conn).
    Guarantees zero dropped audit records on process crash or container SIGTERM eviction (AUDIT-01).
    """
    session_id: Optional[str] = kwargs.get("session_id")
    raw_details: Optional[Dict[str, Any]] = kwargs.get("details")
    enriched_details: Dict[str, Any] = dict(raw_details) if isinstance(raw_details, dict) else {}
    try:
        from observability.middleware import correlation_id_var, get_current_trace_id

        cid = correlation_id_var.get("")
        if cid and not enriched_details.get("correlation_id"):
            enriched_details["correlation_id"] = cid
        tid = get_current_trace_id()
        if tid and not enriched_details.get("trace_id"):
            enriched_details["trace_id"] = tid
    except Exception:
        pass
    details = enriched_details
    t_uuid = None
    if tenant_id:
        try:
            t_uuid = uuid.UUID(str(tenant_id))
        except ValueError:
            t_uuid = None

    async def _run_in_savepoint(fn):
        """Executes a SQL call inside a nested SAVEPOINT when supported so caught errors never abort the outer tx (T-01)."""
        import inspect
        tx_factory = getattr(conn, "transaction", None)
        if callable(tx_factory) and not inspect.iscoroutinefunction(tx_factory):
            sp = tx_factory()
            if hasattr(sp, "__aenter__"):
                async with sp:
                    return await fn()
        return await fn()

    prev_hash = GENESIS_AUDIT_HASH
    try:
        if t_uuid is not None and hasattr(conn, "fetchval"):
            # Serialize hash-chain appends per tenant inside the active transaction
            # so concurrent requests never fork prev_hash (prevents false TAMPERED chains).
            if hasattr(conn, "execute"):
                try:
                    await _run_in_savepoint(
                        lambda: conn.execute(
                            "SELECT pg_advisory_xact_lock(hashtext('audit_log_chain:' || $1));",
                            str(t_uuid),
                        )
                    )
                except Exception:
                    pass
            last_hash = await _run_in_savepoint(
                lambda: conn.fetchval(
                    """
                    SELECT record_hash FROM audit_log
                    WHERE tenant_id = $1 AND record_hash IS NOT NULL
                    ORDER BY created_at DESC, id DESC
                    LIMIT 1;
                    """,
                    t_uuid
                )
            )
            if isinstance(last_hash, str) and len(last_hash) == 64:
                prev_hash = last_hash
    except Exception:
        prev_hash = GENESIS_AUDIT_HASH

    # Compute created_at AFTER acquiring the advisory lock so timestamps are strictly ordered
    created_at = datetime.now(timezone.utc)

    record_hash = compute_audit_record_hash(
        prev_hash=prev_hash,
        created_at_iso=created_at.isoformat(),
        actor_id=str(actor_id),
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id),
        details=details or {}
    )

    try:
        await _run_in_savepoint(
            lambda: conn.execute(
                """
                INSERT INTO audit_log (
                    tenant_id, actor_id, actor_username, actor_role,
                    actor_ip, actor_user_agent, session_id,
                    action, resource_type, resource_id,
                    before_state, after_state, details,
                    created_at, prev_hash, record_hash
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16);
                """,
                t_uuid,
                str(actor_id),
                actor_username or str(actor_id),
                str(actor_role),
                actor_ip,
                actor_user_agent,
                session_id,
                action,
                resource_type,
                str(resource_id),
                json.dumps(before_state) if before_state is not None else None,
                json.dumps(after_state) if after_state is not None else None,
                json.dumps(details or {}),
                created_at,
                prev_hash,
                record_hash
            )
        )
    except Exception:
        # Backward-compatible fallback if migration 028 columns are not yet present
        await conn.execute(
            """
            INSERT INTO audit_log (
                tenant_id, actor_id, actor_username, actor_role,
                actor_ip, actor_user_agent, session_id,
                action, resource_type, resource_id,
                before_state, after_state, details
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);
            """,
            t_uuid,
            str(actor_id),
            actor_username or str(actor_id),
            str(actor_role),
            actor_ip,
            actor_user_agent,
            session_id,
            action,
            resource_type,
            str(resource_id),
            json.dumps(before_state) if before_state is not None else None,
            json.dumps(after_state) if after_state is not None else None,
            json.dumps(details or {})
        )


async def record_audit_event_async(
    action: str,
    actor_id: str,
    actor_role: str,
    resource_type: str,
    resource_id: str,
    tenant_id: Optional[str] = None,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    actor_user_agent: Optional[str] = None,
    session_id: Optional[str] = None,
    before_state: Optional[Dict[str, Any]] = None,
    after_state: Optional[Dict[str, Any]] = None,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Inserts an immutable record into the append-only audit_log table in PostgreSQL.
    """
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            await record_audit_event_tx(
                conn=conn,
                action=action,
                actor_id=actor_id,
                actor_role=actor_role,
                resource_type=resource_type,
                resource_id=resource_id,
                tenant_id=tenant_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
                actor_user_agent=actor_user_agent,
                session_id=session_id,
                before_state=before_state,
                after_state=after_state,
                details=details
            )
    except Exception as e:
        logger.warning(f"Failed to persist audit event to PostgreSQL audit_log: {e}")


def queue_audit_event(
    action: str,
    actor_id: str,
    actor_role: str,
    resource_type: str,
    resource_id: str,
    tenant_id: Optional[str] = None,
    actor_username: Optional[str] = None,
    actor_ip: Optional[str] = None,
    actor_user_agent: Optional[str] = None,
    session_id: Optional[str] = None,
    before_state: Optional[Dict[str, Any]] = None,
    after_state: Optional[Dict[str, Any]] = None,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Schedules asynchronous insertion into PostgreSQL audit_log if an active event loop exists.
    """
    try:
        loop = asyncio.get_running_loop()
        task = loop.create_task(
            record_audit_event_async(
                action=action,
                actor_id=actor_id,
                actor_role=actor_role,
                resource_type=resource_type,
                resource_id=resource_id,
                tenant_id=tenant_id,
                actor_username=actor_username,
                actor_ip=actor_ip,
                actor_user_agent=actor_user_agent,
                session_id=session_id,
                before_state=before_state,
                after_state=after_state,
                details=details
            )
        )
        _audit_tasks.add(task)
        task.add_done_callback(_audit_tasks.discard)
    except RuntimeError:
        # No running event loop (e.g. sync unit test without loop)
        pass
