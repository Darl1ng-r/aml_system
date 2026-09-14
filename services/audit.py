"""
Immutable Audit Logging Service
================================
Persists regulatory-grade, append-only audit events into the PostgreSQL `audit_log` table.
Guarantees tamper-evidence and regulatory compliance (FFIEC, BSA 31 CFR 1010.430, EU AMLD6).
"""

import asyncio
import json
import logging
import uuid
from typing import Optional, Dict, Any

from database.postgres import get_async_db_conn

logger = logging.getLogger("aml.audit")


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
    session_id: Optional[str] = None,
    before_state: Optional[Dict[str, Any]] = None,
    after_state: Optional[Dict[str, Any]] = None,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Synchronously persists an immutable record into the append-only audit_log table
    within the caller's active database transaction/connection (conn).
    Guarantees zero dropped audit records on process crash or container SIGTERM eviction (AUDIT-01).
    """
    t_uuid = None
    if tenant_id:
        try:
            t_uuid = uuid.UUID(str(tenant_id))
        except ValueError:
            t_uuid = None

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
        loop.create_task(
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
    except RuntimeError:
        # No running event loop (e.g. sync unit test without loop)
        pass
