"""
Immutable Audit Vault & Regulatory Auditor Room Repository
==========================================================
Encapsulates all PostgreSQL queries for WORM audit log filtering, hash-chain
verification reads, regulatory exports, signed examiner packets, and
time-boxed read-only Auditor Rooms.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional

from fastapi import HTTPException, status

import database.postgres as _pg
from services.audit import record_audit_event_tx

logger = logging.getLogger(__name__)


def _write_factory(conn_factory: Any = None) -> Any:
    return conn_factory or _pg.get_async_db_conn


def _read_factory(read_conn_factory: Any = None) -> Any:
    return read_conn_factory or _pg.get_async_db_read_conn


def _escape_ilike(val: str) -> str:
    return val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def build_audit_filter_clause(
    tenant_id: Any,
    actor: Optional[str],
    action: Optional[str],
    resource_type: Optional[str],
    date_from: Optional[str],
    date_to: Optional[str],
) -> tuple[str, list[Any], int]:
    conditions = ["tenant_id = $1"]
    params: list[Any] = [uuid.UUID(str(tenant_id))]
    p_idx = 2

    if actor:
        conditions.append(f"(actor_username ILIKE ${p_idx} ESCAPE '\\' OR actor_id ILIKE ${p_idx} ESCAPE '\\')")
        params.append(f"%{_escape_ilike(actor)}%")
        p_idx += 1

    if action:
        conditions.append(f"action = ${p_idx}")
        params.append(action.upper())
        p_idx += 1

    if resource_type:
        conditions.append(f"resource_type = ${p_idx}")
        params.append(resource_type.upper())
        p_idx += 1

    if date_from:
        try:
            params.append(datetime.fromisoformat(date_from))
            conditions.append(f"created_at >= ${p_idx}")
            p_idx += 1
        except ValueError:
            pass

    if date_to:
        try:
            params.append(datetime.fromisoformat(date_to))
            conditions.append(f"created_at <= ${p_idx}")
            p_idx += 1
        except ValueError:
            pass

    return " AND ".join(conditions), params, p_idx


async def list_audit_logs_repo(
    *,
    tenant_id: Any,
    limit: int,
    offset: int,
    actor: Optional[str],
    action: Optional[str],
    resource_type: Optional[str],
    date_from: Optional[str],
    date_to: Optional[str],
    cursor: Optional[str] = None,
    read_conn_factory: Any = None,
) -> tuple[int, list[Any]]:
    from database.pagination import decode_keyset_cursor, validate_legacy_offset

    where_clause, params, p_idx = build_audit_filter_clause(
        tenant_id, actor, action, resource_type, date_from, date_to
    )
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        if cursor:
            c_ts, c_id = decode_keyset_cursor(cursor)
            where_clause = f"{where_clause} AND (created_at, id) < (${p_idx}, ${p_idx + 1})"
            params.extend([c_ts, c_id])
            p_idx += 2
            data_query = f"""
                SELECT id, created_at, actor_id, actor_username, actor_role,
                       actor_ip, actor_user_agent, session_id,
                       action, resource_type, resource_id,
                       before_state, after_state, details
                FROM audit_log
                WHERE {where_clause}
                ORDER BY created_at DESC, id DESC
                LIMIT ${p_idx};
            """
            rows = await conn.fetch(data_query, *params, limit + 1)
            return -1, list(rows or [])

        safe_offset = validate_legacy_offset(offset)
        total_count = await conn.fetchval(f"SELECT COUNT(*) FROM audit_log WHERE {where_clause};", *params)
        data_query = f"""
            SELECT id, created_at, actor_id, actor_username, actor_role,
                   actor_ip, actor_user_agent, session_id,
                   action, resource_type, resource_id,
                   before_state, after_state, details
            FROM audit_log
            WHERE {where_clause}
            ORDER BY created_at DESC, id DESC
            LIMIT ${p_idx} OFFSET ${p_idx + 1};
        """
        rows = await conn.fetch(data_query, *params, limit, safe_offset)
    return int(total_count or 0), list(rows or [])


async def fetch_audit_chain_rows_repo(
    *,
    tenant_id: Any,
    read_conn_factory: Any = None,
) -> list[Any]:
    factory = _read_factory(read_conn_factory)
    tenant_uuid = uuid.UUID(str(tenant_id))
    async with factory(tenant_id=tenant_id) as conn:
        try:
            rows = await conn.fetch(
                """
                SELECT id, created_at, actor_id, action, resource_type, resource_id, details,
                       prev_hash, record_hash
                FROM audit_log
                WHERE tenant_id = $1
                ORDER BY created_at ASC, id ASC
                LIMIT 5000;
                """,
                tenant_uuid,
            )
        except Exception:
            rows = await conn.fetch(
                """
                SELECT id, created_at, actor_id, action, resource_type, resource_id, details
                FROM audit_log
                WHERE tenant_id = $1
                ORDER BY created_at ASC, id ASC
                LIMIT 5000;
                """,
                tenant_uuid,
            )
    return list(rows or [])


async def fetch_audit_export_rows_repo(
    *,
    tenant_id: Any,
    actor: Optional[str],
    action: Optional[str],
    resource_type: Optional[str],
    read_conn_factory: Any = None,
) -> list[Any]:
    conditions = ["tenant_id = $1"]
    params: list[Any] = [uuid.UUID(str(tenant_id))]
    p_idx = 2

    if actor:
        safe_actor = _escape_ilike(actor)
        conditions.append(f"actor_username ILIKE ${p_idx} ESCAPE '\\'")
        params.append(f"%{safe_actor}%")
        p_idx += 1

    if action:
        conditions.append(f"action = ${p_idx}")
        params.append(action.upper())
        p_idx += 1

    if resource_type:
        conditions.append(f"resource_type = ${p_idx}")
        params.append(resource_type.upper())
        p_idx += 1

    where_clause = " AND ".join(conditions)
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            f"""
            SELECT id, created_at, actor_id, actor_username, actor_role,
                   actor_ip, action, resource_type, resource_id, details
            FROM audit_log
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT 5000;
            """,
            *params,
        )
    return list(rows or [])


async def fetch_audit_log_detail_repo(
    *,
    log_uuid: uuid.UUID,
    tenant_id: Any,
    read_conn_factory: Any = None,
) -> Any:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetchrow(
            """
            SELECT id, created_at, actor_id, actor_username, actor_role,
                   actor_ip, actor_user_agent, session_id,
                   action, resource_type, resource_id,
                   before_state, after_state, details
            FROM audit_log
            WHERE id = $1 AND tenant_id = $2;
            """,
            log_uuid,
            uuid.UUID(str(tenant_id)),
        )


async def build_examiner_packet_repo(
    *,
    tenant_id: Any,
    case_uuid: uuid.UUID,
    generated_by: str,
    build_packet_fn: Callable[..., Any],
    read_conn_factory: Any = None,
):
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await build_packet_fn(
            conn=conn,
            tenant_id=tenant_id,
            case_id=case_uuid,
            generated_by=generated_by,
        )


async def create_auditor_room_atomic(
    *,
    tenant_id: str,
    safe_name: str,
    safe_org: str,
    token_hash: str,
    case_uuids: list[uuid.UUID],
    expires_at: datetime,
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> uuid.UUID:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        owned_rows = await conn.fetch(
            "SELECT id FROM cases WHERE id = ANY($1::uuid[]) AND tenant_id = $2::uuid;",
            case_uuids,
            str(tenant_id),
        )
        owned_ids = {r["id"] for r in (owned_rows or [])}
        missing_cases = [str(cid) for cid in case_uuids if cid not in owned_ids]
        if missing_cases:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="One or more allowed_case_ids do not exist in your tenant.",
            )

        room_id = await conn.fetchval(
            """
            INSERT INTO auditor_rooms (
                tenant_id, room_name, examiner_org, token_hash, allowed_case_ids, expires_at, created_by
            )
            VALUES ($1::uuid, $2, $3, $4, $5::uuid[], $6, $7)
            RETURNING id;
            """,
            str(tenant_id),
            safe_name,
            safe_org,
            token_hash,
            case_uuids,
            expires_at,
            current_user.get("username", "mlro"),
        )
        try:
            await record_audit_event_tx(
                conn=conn,
                action="CREATE_AUDITOR_ROOM",
                actor_id=str(current_user.get("id") or current_user.get("username") or "unknown"),
                actor_username=current_user.get("username", "mlro"),
                actor_role=current_user.get("role", "MLRO"),
                resource_type="AUDITOR_ROOM",
                resource_id=str(room_id),
                tenant_id=str(tenant_id),
                details={"room_name": safe_name, "examiner_org": safe_org, "case_count": len(case_uuids)},
            )
        except Exception as audit_err:
            logger.warning("Transactional audit write skipped in create_auditor_room: %s", audit_err)
    return room_id


async def list_auditor_rooms_repo(
    *,
    tenant_id: str,
    read_conn_factory: Any = None,
) -> list[Any]:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, room_name, examiner_org, allowed_case_ids, expires_at, revoked_at,
                   access_count, last_accessed_at, created_by, created_at
            FROM auditor_rooms
            WHERE tenant_id = $1::uuid
            ORDER BY created_at DESC
            LIMIT 50;
            """,
            str(tenant_id),
        )
    return list(rows or [])


async def revoke_auditor_room_atomic(
    *,
    room_uuid: uuid.UUID,
    tenant_id: str,
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> None:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        revoked = await conn.fetchval(
            "UPDATE auditor_rooms SET revoked_at = NOW() WHERE id = $1 AND tenant_id = $2::uuid AND revoked_at IS NULL RETURNING id;",
            room_uuid,
            str(tenant_id),
        )
        if not revoked:
            raise HTTPException(status_code=404, detail="Active auditor room not found.")
        try:
            await record_audit_event_tx(
                conn=conn,
                action="REVOKE_AUDITOR_ROOM",
                actor_id=str(current_user.get("id") or current_user.get("username") or "unknown"),
                actor_username=current_user.get("username", "mlro"),
                actor_role=current_user.get("role", "MLRO"),
                resource_type="AUDITOR_ROOM",
                resource_id=str(room_uuid),
                tenant_id=str(tenant_id),
                details={"revoked": True},
            )
        except Exception as audit_err:
            logger.warning("Transactional audit write skipped in revoke_auditor_room: %s", audit_err)


async def validate_and_touch_auditor_room_repo(
    *,
    tenant_id: str,
    token_hash: str,
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        room = await conn.fetchrow(
            "SELECT * FROM auditor_rooms WHERE token_hash = $1 FOR UPDATE;",
            token_hash,
        )
        if not room:
            raise HTTPException(status_code=403, detail="Invalid auditor room access token.")
        if room.get("revoked_at") is not None:
            raise HTTPException(status_code=403, detail="Auditor room access has been revoked.")
        exp = room["expires_at"]
        if exp and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp and exp < datetime.now(timezone.utc):
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Auditor room access window has expired.")

        await conn.execute(
            "UPDATE auditor_rooms SET access_count = access_count + 1, last_accessed_at = NOW() WHERE id = $1;",
            room["id"],
        )
        return dict(room)


async def fetch_auditor_room_cases_repo(
    *,
    tenant_id: str,
    allowed_ids: list[uuid.UUID],
    read_conn_factory: Any = None,
) -> list[Any]:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, case_number, title, status, priority, created_at, closed_at
            FROM cases
            WHERE id = ANY($1::uuid[]) AND tenant_id = $2::uuid
            ORDER BY created_at DESC;
            """,
            allowed_ids,
            str(tenant_id),
        )
    return list(rows or [])
