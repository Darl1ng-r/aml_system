"""
Case Management & Case Evidence Locker Repository
=================================================
Encapsulates PostgreSQL persistence, tenant RLS scoping, `FOR UPDATE` locks,
FSM transition enforcement, and transactional WORM audit writes for
AML investigation cases, case notes, and case evidence artifacts.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional

from fastapi import HTTPException, status

from database.postgres import get_async_db_conn, get_async_db_read_conn
from services.audit import record_audit_event_tx
from services.http_cache import build_entity_etag, check_if_match
from services.state_machine import validate_case_transition

logger = logging.getLogger(__name__)

CASE_NOT_FOUND = "Case not found."
SELECT_CASE_BY_ID_AND_TENANT = "SELECT * FROM cases WHERE id = $1 AND tenant_id = $2;"


def _case_row_etag(case_row: Any) -> str:
    updated_val = (
        case_row["updated_at"]
        if ("updated_at" in case_row and case_row["updated_at"])
        else (case_row["created_at"] if ("created_at" in case_row and case_row["created_at"]) else "")
    )
    return build_entity_etag("case", case_row["id"], updated_val, case_row["status"])


# ── Case Lifecycle Repository ─────────────────────────────────────────────────

async def correlate_alerts_into_cases_repo(
    *,
    tenant_id: str,
    alert_ids: list[str],
    actor_id: Any,
    actor_username: str,
    window_days: int,
    conn_factory: Any = None,
) -> Any:
    from services.case_correlation import batch_correlate_alerts

    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        return await batch_correlate_alerts(
            conn=conn,
            tenant_id=tenant_id,
            alert_ids=alert_ids,
            actor_id=actor_id,
            actor_username=actor_username,
            window_days=window_days,
        )


async def create_case_atomic(
    *,
    tenant_id: str,
    title: str,
    priority: str,
    subject_acc_uuid: Optional[uuid.UUID],
    parsed_alert_uuids: list[uuid.UUID],
    narrative: Optional[str],
    user_uuid: Optional[uuid.UUID],
    username: str,
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = conn_factory or get_async_db_conn
    tenant_uuid = uuid.UUID(str(tenant_id))
    case_number = f"CASE-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:6].upper()}"

    async with factory(tenant_id=tenant_id) as conn:
        validated_alert_uuids: list[uuid.UUID] = []
        if parsed_alert_uuids:
            owned_rows = await conn.fetch(
                "SELECT id FROM alerts WHERE id = ANY($1::uuid[]) AND tenant_id = $2;",
                parsed_alert_uuids,
                tenant_uuid,
            )
            owned_ids = {r["id"] for r in (owned_rows or [])}
            missing = [str(u) for u in parsed_alert_uuids if u not in owned_ids]
            if missing:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="One or more alert_ids do not exist in your tenant.",
                )
            validated_alert_uuids = parsed_alert_uuids

        case_id = await conn.fetchval(
            """
            INSERT INTO cases (
                tenant_id, case_number, title, priority, assigned_to, assigned_username,
                subject_account_id, narrative, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'OPEN')
            RETURNING id;
            """,
            tenant_uuid,
            case_number,
            title,
            priority,
            user_uuid,
            username,
            subject_acc_uuid,
            narrative,
        )

        if validated_alert_uuids:
            await conn.execute(
                """
                INSERT INTO case_alerts (case_id, alert_id)
                SELECT $1, unnest($2::uuid[])
                ON CONFLICT DO NOTHING;
                """,
                case_id,
                validated_alert_uuids,
            )

    return {
        "case_id": str(case_id),
        "case_number": case_number,
        "title": title,
        "status": "OPEN",
        "priority": priority,
        "alert_count": len(validated_alert_uuids),
    }


async def list_cases_repo(
    *,
    tenant_id: str,
    limit: int,
    offset: int,
    status_filter: Optional[str] = None,
    priority_filter: Optional[str] = None,
    cursor: Optional[str] = None,
    read_conn_factory: Any = None,
) -> list[dict[str, Any]]:
    from database.pagination import decode_keyset_cursor, validate_legacy_offset

    factory = read_conn_factory or get_async_db_read_conn
    tenant_uuid = uuid.UUID(str(tenant_id))

    async with factory(tenant_id=tenant_id) as conn:
        where_clauses = ["c.tenant_id = $1"]
        params: list[Any] = [tenant_uuid]
        p_idx = 2

        if status_filter and status_filter.upper() != "ALL":
            where_clauses.append(f"c.status = ${p_idx}")
            params.append(status_filter.upper())
            p_idx += 1

        if priority_filter and priority_filter.upper() != "ALL":
            where_clauses.append(f"c.priority = ${p_idx}")
            params.append(priority_filter.upper())
            p_idx += 1

        if cursor:
            c_ts, c_id = decode_keyset_cursor(cursor)
            where_clauses.append(f"(c.created_at, c.id) < (${p_idx}, ${p_idx + 1})")
            params.extend([c_ts, c_id])
            p_idx += 2
            where_sql = " AND ".join(where_clauses)
            rows = await conn.fetch(
                f"""
                SELECT c.*,
                       (SELECT COUNT(*) FROM case_alerts ca WHERE ca.case_id = c.id) AS alert_count
                FROM cases c
                WHERE {where_sql}
                ORDER BY c.created_at DESC, c.id DESC
                LIMIT ${p_idx};
                """,
                *params,
                limit + 1,
            )
        else:
            safe_offset = validate_legacy_offset(offset)
            where_sql = " AND ".join(where_clauses)
            rows = await conn.fetch(
                f"""
                SELECT c.*,
                       (SELECT COUNT(*) FROM case_alerts ca WHERE ca.case_id = c.id) AS alert_count
                FROM cases c
                WHERE {where_sql}
                ORDER BY c.created_at DESC, c.id DESC
                LIMIT ${p_idx} OFFSET ${p_idx + 1};
                """,
                *params,
                limit,
                safe_offset,
            )

    return [
        {
            "case_id": str(r["id"]),
            "case_number": r["case_number"],
            "title": r["title"],
            "status": r["status"],
            "priority": r["priority"],
            "assigned_username": r["assigned_username"],
            "alert_count": int(r["alert_count"] or 0),
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in (rows or [])
    ]


async def get_case_detail_repo(
    *,
    case_uuid: uuid.UUID,
    tenant_id: str,
    read_conn_factory: Any = None,
) -> tuple[dict[str, Any], str]:
    factory = read_conn_factory or get_async_db_read_conn
    tenant_uuid = uuid.UUID(str(tenant_id))

    async with factory(tenant_id=tenant_id) as conn:
        case_row = await conn.fetchrow(
            SELECT_CASE_BY_ID_AND_TENANT,
            case_uuid,
            tenant_uuid,
        )
        if not case_row:
            raise HTTPException(status_code=404, detail=CASE_NOT_FOUND)

        alert_rows = await conn.fetch(
            """
            SELECT a.id, a.rule_name, a.threat_level, a.ai_risk_score, a.status, a.created_at
            FROM case_alerts ca
            JOIN alerts a ON ca.alert_id = a.id
            WHERE ca.case_id = $1;
            """,
            case_uuid,
        )
        note_rows = await conn.fetch(
            "SELECT id, author_username, note, created_at FROM case_notes WHERE case_id = $1 ORDER BY created_at ASC;",
            case_uuid,
        )

    etag = _case_row_etag(case_row)
    payload = {
        "case_id": str(case_row["id"]),
        "case_number": case_row["case_number"],
        "title": case_row["title"],
        "status": case_row["status"],
        "priority": case_row["priority"],
        "assigned_username": case_row["assigned_username"],
        "subject_account_id": str(case_row["subject_account_id"]) if case_row["subject_account_id"] else None,
        "narrative": case_row["narrative"],
        "closure_reason": case_row["closure_reason"],
        "etag": etag,
        "created_at": case_row["created_at"].isoformat() if case_row["created_at"] else None,
        "alerts": [
            {
                "alert_id": str(a["id"]),
                "rule_name": a["rule_name"],
                "threat_level": a["threat_level"],
                "ai_risk_score": float(a["ai_risk_score"] or 0.0),
                "status": a["status"],
            }
            for a in (alert_rows or [])
        ],
        "notes": [
            {
                "id": str(n["id"]),
                "author": n["author_username"],
                "note": n["note"],
                "created_at": n["created_at"].isoformat() if n["created_at"] else None,
            }
            for n in (note_rows or [])
        ],
    }
    return payload, etag


async def add_case_note_atomic(
    *,
    case_uuid: uuid.UUID,
    tenant_id: str,
    note: str,
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = conn_factory or get_async_db_conn
    tenant_uuid = uuid.UUID(str(tenant_id))

    async with factory(tenant_id=tenant_id) as conn:
        case_row = await conn.fetchrow(
            "SELECT id, status FROM cases WHERE id = $1 AND tenant_id = $2;",
            case_uuid,
            tenant_uuid,
        )
        if not case_row:
            raise HTTPException(status_code=404, detail=CASE_NOT_FOUND)

        if case_row["status"] == "CLOSED" and current_user.get("role") not in (
            "ADMIN",
            "MLRO",
            "TENANT_ADMIN",
            "SUPER_ADMIN",
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid workflow state: Cannot append notes to a CLOSED case without MLRO or Admin authorization.",
            )

        note_id = await conn.fetchval(
            """
            INSERT INTO case_notes (case_id, author_id, author_username, note)
            VALUES ($1, $2, $3, $4)
            RETURNING id;
            """,
            case_uuid,
            uuid.UUID(str(current_user["id"])) if current_user.get("id") else None,
            current_user.get("username", "investigator"),
            note,
        )

    return {
        "note_id": str(note_id),
        "message": "Investigation note added successfully.",
    }


async def update_case_atomic(
    *,
    case_uuid: uuid.UUID,
    tenant_id: str,
    payload: Any,
    request: Any,
    build_updates_fn: Callable[[Any], tuple[list[str], list[Any], int]],
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = conn_factory or get_async_db_conn
    tenant_uuid = uuid.UUID(str(tenant_id))

    async with factory(tenant_id=tenant_id) as conn:
        case_row = await conn.fetchrow(
            "SELECT * FROM cases WHERE id = $1 AND tenant_id = $2 FOR UPDATE;",
            case_uuid,
            tenant_uuid,
        )
        if not case_row:
            raise HTTPException(status_code=404, detail=CASE_NOT_FOUND)

        current_etag = _case_row_etag(case_row)
        check_if_match(request, current_etag, resource_label=f"case {case_uuid}")

        if payload.status:
            validate_case_transition(case_row["status"], payload.status)

        updates, params, p_idx = build_updates_fn(payload)
        updated_at_val = (
            case_row["updated_at"]
            if ("updated_at" in case_row and case_row["updated_at"])
            else case_row["created_at"]
        )

        if updates:
            updates.append("updated_at = NOW()")
            params.append(case_uuid)
            params.append(tenant_uuid)
            query = f"UPDATE cases SET {', '.join(updates)} WHERE id = ${p_idx} AND tenant_id = ${p_idx + 1} RETURNING updated_at;"
            ret_ts = await conn.fetchval(query, *params)
            if ret_ts is not None:
                updated_at_val = ret_ts

        final_status = payload.status or case_row["status"]
        new_etag = build_entity_etag("case", case_uuid, updated_at_val, final_status)

    return {
        "case_id": str(case_uuid),
        "status": final_status,
        "etag": new_etag,
        "message": "Case updated successfully.",
    }


async def close_case_atomic(
    *,
    case_uuid: uuid.UUID,
    tenant_id: str,
    closure_reason: str,
    closing_notes: str,
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = conn_factory or get_async_db_conn
    tenant_uuid = uuid.UUID(str(tenant_id))

    async with factory(tenant_id=tenant_id) as conn:
        case_row = await conn.fetchrow(
            "SELECT * FROM cases WHERE id = $1 AND tenant_id = $2 FOR UPDATE;",
            case_uuid,
            tenant_uuid,
        )
        if not case_row:
            raise HTTPException(status_code=404, detail=CASE_NOT_FOUND)

        validate_case_transition(case_row["status"], "CLOSED")

        await conn.execute(
            """
            UPDATE cases
            SET status = 'CLOSED',
                closure_reason = $1,
                closed_at = NOW(),
                updated_at = NOW()
            WHERE id = $2 AND tenant_id = $3 AND status != 'CLOSED';
            """,
            closure_reason,
            case_uuid,
            tenant_uuid,
        )

        await conn.execute(
            """
            INSERT INTO case_notes (case_id, author_id, author_username, note)
            VALUES ($1, $2, $3, $4);
            """,
            case_uuid,
            uuid.UUID(str(current_user["id"])) if current_user.get("id") else None,
            current_user.get("username", "investigator"),
            f"Case closed with disposition '{closure_reason}': {closing_notes}",
        )

    return {
        "case_id": str(case_uuid),
        "status": "CLOSED",
        "closure_reason": closure_reason,
        "message": f"Case closed successfully with status '{closure_reason}'.",
    }


# ── Case Evidence Locker Repository ───────────────────────────────────────────

async def resolve_case_uuid_tx(
    conn: Any,
    raw_uuid: uuid.UUID,
    tenant_id: Any,
    current_user: Mapping[str, Any],
    *,
    auto_create: bool = False,
) -> uuid.UUID:
    """Resolves either a direct `cases.id` or linked `alerts.id` UUID to its `cases.id`."""
    if not hasattr(conn, "fetchval"):
        return raw_uuid
    try:
        existing_case = await conn.fetchval("SELECT id FROM cases WHERE id = $1;", raw_uuid)
        if isinstance(existing_case, uuid.UUID):
            return existing_case

        linked_case = await conn.fetchval(
            "SELECT case_id FROM case_alerts WHERE alert_id = $1 LIMIT 1;",
            raw_uuid,
        )
        if isinstance(linked_case, uuid.UUID):
            return linked_case

        if auto_create:
            alert_exists = await conn.fetchval("SELECT id FROM alerts WHERE id = $1;", raw_uuid)
            if isinstance(alert_exists, uuid.UUID):
                new_case_id = uuid.uuid4()
                case_num = f"CASE-{str(new_case_id)[:8].upper()}"
                await conn.execute(
                    """
                    INSERT INTO cases (id, tenant_id, case_number, title, status, priority, assigned_username)
                    VALUES ($1, $2, $3, $4, 'INVESTIGATING', 'HIGH', $5);
                    """,
                    new_case_id,
                    uuid.UUID(str(tenant_id)),
                    case_num,
                    f"Investigation for Alert {str(raw_uuid)[:8]}",
                    current_user.get("username", "Investigator"),
                )
                await conn.execute(
                    "INSERT INTO case_alerts (case_id, alert_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;",
                    new_case_id,
                    raw_uuid,
                )
                return new_case_id
    except Exception:
        return raw_uuid
    return raw_uuid


async def list_case_evidence_repo(
    *,
    raw_uuid: uuid.UUID,
    tenant_id: str,
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> list[Any]:
    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        case_uuid = await resolve_case_uuid_tx(conn, raw_uuid, tenant_id, current_user, auto_create=False)
        return await conn.fetch(
            """
            SELECT id, case_id, filename, content_type, file_size, storage_key,
                   sha256_digest, storage_backend, scan_status,
                   uploaded_by, uploaded_by_name, uploaded_at, description, tags
            FROM case_evidence
            WHERE case_id = $1
            ORDER BY uploaded_at DESC;
            """,
            case_uuid,
        )


async def insert_case_evidence_atomic(
    *,
    evidence_id: uuid.UUID,
    raw_case_uuid: uuid.UUID,
    tenant_id: str,
    safe_filename: str,
    safe_content_type: str,
    file_size: int,
    stored_key: str,
    sha256_digest: str,
    backend_name: str,
    scan_status: str,
    user_id: Any,
    user_uuid: Optional[uuid.UUID],
    username: str,
    actor_role: str,
    safe_description: str,
    parsed_tags: list[str],
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> uuid.UUID:
    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        resolved_case_uuid = await resolve_case_uuid_tx(
            conn, raw_case_uuid, tenant_id, current_user, auto_create=True
        )
        await conn.execute(
            """
            INSERT INTO case_evidence (
                id, case_id, tenant_id, filename, content_type, file_size,
                storage_key, sha256_digest, storage_backend, scan_status,
                uploaded_by, uploaded_by_name, description, tags
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);
            """,
            evidence_id,
            resolved_case_uuid,
            uuid.UUID(str(tenant_id)),
            safe_filename,
            safe_content_type,
            file_size,
            stored_key,
            sha256_digest,
            backend_name,
            scan_status,
            user_uuid,
            username,
            safe_description,
            parsed_tags,
        )
        await record_audit_event_tx(
            conn=conn,
            action="UPLOAD_EVIDENCE",
            actor_id=str(user_id or username),
            actor_username=username,
            actor_role=actor_role,
            resource_type="CASE",
            resource_id=str(resolved_case_uuid),
            tenant_id=str(tenant_id),
            details={
                "evidence_id": str(evidence_id),
                "filename": safe_filename,
                "size": file_size,
                "sha256": sha256_digest,
                "storage_backend": backend_name,
            },
        )
        return resolved_case_uuid


async def verify_case_exists_for_evidence_repo(
    *,
    raw_uuid: uuid.UUID,
    tenant_id: str,
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> uuid.UUID:
    """Verifies a case (or linked alert's case) exists within the caller's tenant before minting pre-signed URLs."""
    factory = conn_factory or get_async_db_read_conn
    tenant_uuid = uuid.UUID(str(tenant_id))
    async with factory(tenant_id=tenant_id) as conn:
        existing_case = await conn.fetchval(
            "SELECT id FROM cases WHERE id = $1 AND tenant_id = $2;",
            raw_uuid,
            tenant_uuid,
        )
        if isinstance(existing_case, uuid.UUID):
            return existing_case

        linked_case = await conn.fetchval(
            """
            SELECT ca.case_id
            FROM case_alerts ca
            JOIN cases c ON c.id = ca.case_id
            WHERE ca.alert_id = $1 AND c.tenant_id = $2
            LIMIT 1;
            """,
            raw_uuid,
            tenant_uuid,
        )
        if isinstance(linked_case, uuid.UUID):
            return linked_case

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=CASE_NOT_FOUND)


async def fetch_case_evidence_for_download_repo(
    *,
    raw_uuid: uuid.UUID,
    ev_uuid: uuid.UUID,
    tenant_id: str,
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> Any:
    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        resolved_case_uuid = await resolve_case_uuid_tx(conn, raw_uuid, tenant_id, current_user, auto_create=False)
        return await conn.fetchrow(
            "SELECT storage_key, filename, content_type, sha256_digest, storage_backend FROM case_evidence WHERE id = $1 AND case_id = $2;",
            ev_uuid,
            resolved_case_uuid,
        )


async def delete_case_evidence_atomic(
    *,
    raw_uuid: uuid.UUID,
    ev_uuid: uuid.UUID,
    tenant_id: str,
    evidence_storage_dir: str,
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> dict[str, Any]:
    from services.evidence_storage import LocalEvidenceBackend, S3EvidenceBackend

    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        case_uuid = await resolve_case_uuid_tx(conn, raw_uuid, tenant_id, current_user, auto_create=False)
        row = await conn.fetchrow(
            """
            SELECT storage_key, filename, storage_backend FROM case_evidence
            WHERE id = $1 AND case_id = $2
            FOR UPDATE;
            """,
            ev_uuid,
            case_uuid,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Evidence not found")

        storage_key = row["storage_key"]
        if storage_key:
            backend_type = (
                (row.get("storage_backend") if hasattr(row, "get") else None)
                or ("s3" if str(storage_key).startswith("s3://") else "local")
            )
            backend = S3EvidenceBackend() if backend_type == "s3" else LocalEvidenceBackend(evidence_storage_dir)
            try:
                await backend.delete_object(str(tenant_id), storage_key)
            except PermissionError as perm_err:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
            except ValueError as val_err:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

        await conn.execute("DELETE FROM case_evidence WHERE id = $1;", ev_uuid)

        await record_audit_event_tx(
            conn=conn,
            action="DELETE_EVIDENCE",
            actor_id=str(current_user.get("id") or current_user.get("username") or "unknown"),
            actor_username=current_user.get("username", "Investigator"),
            actor_role=current_user.get("role", "ANALYST"),
            resource_type="CASE",
            resource_id=str(case_uuid),
            tenant_id=str(tenant_id),
            details={"evidence_id": str(ev_uuid), "filename": row["filename"]},
        )
        return {"filename": row["filename"]}
