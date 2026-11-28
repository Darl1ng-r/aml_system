"""
Async Background Jobs Repository (Scale Pillar Stage 2)
=======================================================
Encapsulates ACID persistence, Transactional Outbox publishing, keyset
pagination, idempotency deduplication, and atomic job claiming for
queue-leveled exports, analytics, and notifications.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Optional

from database.outbox import record_outbox_event
from database.pagination import decode_keyset_cursor, encode_keyset_cursor
from database.postgres import get_async_db_conn, get_async_db_read_conn


def _serialize_job_row(row: Any) -> dict[str, Any]:
    if row is None:
        return {}
    payload = row["payload"]
    result_meta = row["result_meta"]
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            payload = {}
    if isinstance(result_meta, str):
        try:
            result_meta = json.loads(result_meta)
        except Exception:
            result_meta = {}
    return {
        "job_id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "job_type": row["job_type"],
        "status": row["status"],
        "idempotency_key": row["idempotency_key"],
        "requested_by": row["requested_by"],
        "requested_role": row["requested_role"],
        "payload": payload or {},
        "result_meta": result_meta or {},
        "artifact_storage_key": row["artifact_storage_key"],
        "artifact_sha256": row["artifact_sha256"],
        "artifact_content_type": row["artifact_content_type"],
        "artifact_filename": row["artifact_filename"],
        "error_message": row["error_message"],
        "retry_count": int(row["retry_count"] or 0),
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "started_at": row["started_at"].isoformat() if row["started_at"] else None,
        "completed_at": row["completed_at"].isoformat() if row["completed_at"] else None,
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
    }


async def enqueue_async_job_atomic(
    *,
    tenant_id: str,
    job_type: str,
    payload: dict[str, Any],
    requested_by: str,
    requested_role: str,
    topic: str,
    idempotency_key: Optional[str] = None,
    correlation_id: Optional[str] = None,
    conn_factory: Any = None,
) -> tuple[dict[str, Any], bool]:
    """
    Atomically inserts an `async_jobs` row and its `transactional_outbox` dispatch event.
    If `idempotency_key` already exists for the tenant, returns `(existing_job, True)`
    without duplicating the queued work item.
    """
    factory = conn_factory or get_async_db_conn
    tenant_uuid = uuid.UUID(str(tenant_id))
    clean_idem = idempotency_key.strip()[:255] if idempotency_key and idempotency_key.strip() else None

    async with factory(tenant_id=str(tenant_id)) as conn:
        if clean_idem:
            existing = await conn.fetchrow(
                """
                SELECT * FROM async_jobs
                WHERE tenant_id = $1 AND idempotency_key = $2;
                """,
                tenant_uuid,
                clean_idem,
            )
            if existing:
                return _serialize_job_row(existing), True

        job_id = uuid.uuid4()
        row = await conn.fetchrow(
            """
            INSERT INTO async_jobs (
                id, tenant_id, job_type, status, idempotency_key,
                requested_by, requested_role, payload
            )
            VALUES ($1, $2, $3, 'QUEUED', $4, $5, $6, $7::jsonb)
            RETURNING *;
            """,
            job_id,
            tenant_uuid,
            job_type,
            clean_idem,
            requested_by,
            requested_role,
            json.dumps(payload or {}, default=str),
        )

        outbox_headers: dict[str, str] = {"topic": topic}
        if correlation_id:
            outbox_headers["correlation_id"] = correlation_id

        await record_outbox_event(
            conn=conn,
            aggregate_type="ASYNC_JOB_DISPATCH",
            aggregate_id=str(job_id),
            event_type=f"aml.jobs.{job_type.lower()}.queued.v1",
            payload={
                "job_id": str(job_id),
                "tenant_id": str(tenant_id),
                "job_type": job_type,
                "requested_by": requested_by,
                "requested_role": requested_role,
                "payload": payload or {},
            },
            tenant_id=str(tenant_id),
            headers=outbox_headers,
        )

    return _serialize_job_row(row), False


async def get_async_job_repo(
    *,
    tenant_id: str,
    job_id: uuid.UUID,
    read_conn_factory: Any = None,
) -> Optional[dict[str, Any]]:
    factory = read_conn_factory or get_async_db_read_conn
    tenant_uuid = uuid.UUID(str(tenant_id))
    async with factory(tenant_id=str(tenant_id)) as conn:
        row = await conn.fetchrow(
            "SELECT * FROM async_jobs WHERE id = $1 AND tenant_id = $2;",
            job_id,
            tenant_uuid,
        )
    return _serialize_job_row(row) if row else None


async def list_async_jobs_repo(
    *,
    tenant_id: str,
    limit: int = 25,
    cursor: Optional[str] = None,
    status_filter: Optional[str] = None,
    read_conn_factory: Any = None,
) -> tuple[list[dict[str, Any]], Optional[str], bool]:
    factory = read_conn_factory or get_async_db_read_conn
    tenant_uuid = uuid.UUID(str(tenant_id))
    safe_limit = max(1, min(100, int(limit)))

    async with factory(tenant_id=str(tenant_id)) as conn:
        where_clauses = ["tenant_id = $1"]
        params: list[Any] = [tenant_uuid]
        idx = 2

        if status_filter and status_filter.upper() != "ALL":
            where_clauses.append(f"status = ${idx}")
            params.append(status_filter.upper())
            idx += 1

        if cursor:
            c_ts, c_id = decode_keyset_cursor(cursor)
            where_clauses.append(f"(created_at, id) < (${idx}, ${idx + 1})")
            params.extend([c_ts, c_id])
            idx += 2

        where_sql = " AND ".join(where_clauses)
        rows = await conn.fetch(
            f"""
            SELECT * FROM async_jobs
            WHERE {where_sql}
            ORDER BY created_at DESC, id DESC
            LIMIT ${idx};
            """,
            *params,
            safe_limit + 1,
        )

    has_more = len(rows) > safe_limit
    page_rows = rows[:safe_limit]
    next_cursor = (
        encode_keyset_cursor(page_rows[-1]["created_at"], page_rows[-1]["id"])
        if has_more and page_rows
        else None
    )
    return [_serialize_job_row(r) for r in page_rows], next_cursor, has_more


async def claim_async_job_for_processing_repo(
    *,
    tenant_id: str,
    job_id: uuid.UUID,
    conn_factory: Any = None,
) -> Optional[dict[str, Any]]:
    """
    Idempotently claims a QUEUED or FAILED job for execution.
    Returns `None` if the job is already COMPLETED, DEAD_LETTERED, or in-flight PROCESSING.
    """
    factory = conn_factory or get_async_db_conn
    tenant_uuid = uuid.UUID(str(tenant_id))
    async with factory(tenant_id=str(tenant_id)) as conn:
        row = await conn.fetchrow(
            """
            UPDATE async_jobs
            SET status = 'PROCESSING',
                started_at = COALESCE(started_at, NOW()),
                updated_at = NOW()
            WHERE id = $1
              AND tenant_id = $2
              AND status IN ('QUEUED', 'FAILED')
            RETURNING *;
            """,
            job_id,
            tenant_uuid,
        )
    return _serialize_job_row(row) if row else None


async def complete_async_job_repo(
    *,
    tenant_id: str,
    job_id: uuid.UUID,
    result_meta: dict[str, Any],
    artifact_storage_key: Optional[str] = None,
    artifact_sha256: Optional[str] = None,
    artifact_content_type: Optional[str] = None,
    artifact_filename: Optional[str] = None,
    conn_factory: Any = None,
) -> None:
    factory = conn_factory or get_async_db_conn
    tenant_uuid = uuid.UUID(str(tenant_id))
    async with factory(tenant_id=str(tenant_id)) as conn:
        await conn.execute(
            """
            UPDATE async_jobs
            SET status = 'COMPLETED',
                result_meta = $3::jsonb,
                artifact_storage_key = $4,
                artifact_sha256 = $5,
                artifact_content_type = $6,
                artifact_filename = $7,
                error_message = NULL,
                completed_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2;
            """,
            job_id,
            tenant_uuid,
            json.dumps(result_meta or {}, default=str),
            artifact_storage_key,
            artifact_sha256,
            artifact_content_type,
            artifact_filename,
        )


async def fail_async_job_repo(
    *,
    tenant_id: str,
    job_id: uuid.UUID,
    error_message: str,
    dead_lettered: bool = False,
    conn_factory: Any = None,
) -> None:
    factory = conn_factory or get_async_db_conn
    tenant_uuid = uuid.UUID(str(tenant_id))
    target_status = "DEAD_LETTERED" if dead_lettered else "FAILED"
    async with factory(tenant_id=str(tenant_id)) as conn:
        await conn.execute(
            """
            UPDATE async_jobs
            SET status = $3,
                retry_count = retry_count + 1,
                error_message = $4,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2;
            """,
            job_id,
            tenant_uuid,
            target_status,
            str(error_message)[:2000],
        )
