"""
Async Background Jobs Router (Scale Pillar Stage 2 — Queue-Based Load Leveling)
===============================================================================
Thin HTTP controller for enqueueing and tracking asynchronous exports,
analytical rule backtests, and email notifications backed by the
Transactional Outbox, partitioned Redpanda queues, and DLQs.
All PostgreSQL SQL lives in `repositories/jobs_repo.py`.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from database.postgres import get_async_db_conn, get_async_db_read_conn
from observability.logging import log_audit_event
from observability.middleware import correlation_id_var
from repositories.jobs_repo import (
    enqueue_async_job_atomic,
    get_async_job_repo,
    list_async_jobs_repo,
)
from services.async_jobs import ALLOWED_JOB_TYPES, resolve_topic_for_job_type
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter

logger = logging.getLogger("aml.jobs.router")

router = APIRouter(prefix="/api/v1/jobs", tags=["Async Jobs & Exports"])


class AsyncJobCreateRequest(BaseModel):
    job_type: str = Field(..., min_length=3, max_length=64)
    payload: Dict[str, Any] = Field(default_factory=dict)


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def enqueue_async_job(
    body: AsyncJobCreateRequest,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    current_user: dict = Depends(RoleChecker(["ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN", "AUDITOR", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Enqueues a heavy export, analytics, or notification job onto the Transactional Outbox + Redpanda."""
    job_type = body.job_type.upper().strip()
    if job_type not in ALLOWED_JOB_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported job_type '{job_type}'. Allowed: {sorted(ALLOWED_JOB_TYPES)}",
        )

    tenant_id = enforce_tenant_data_scope(current_user)
    topic = resolve_topic_for_job_type(job_type)
    job, deduplicated = await enqueue_async_job_atomic(
        tenant_id=str(tenant_id),
        job_type=job_type,
        payload=body.payload,
        requested_by=str(current_user.get("username") or current_user.get("id") or "analyst"),
        requested_role=str(current_user.get("role") or "ANALYST"),
        topic=topic,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id_var.get(None),
        conn_factory=get_async_db_conn,
    )

    log_audit_event(
        event_type="ASYNC_JOB_QUEUED",
        actor_id=str(current_user.get("id", "")),
        actor_role=str(current_user.get("role", "ANALYST")),
        action="ENQUEUE_ASYNC_JOB",
        resource_type="ASYNC_JOB",
        resource_id=job["job_id"],
        tenant_id=str(tenant_id),
        details={"job_type": job_type, "topic": topic, "deduplicated": deduplicated},
    )

    return {
        "job_id": job["job_id"],
        "job_type": job["job_type"],
        "status": job["status"],
        "topic": topic,
        "deduplicated": deduplicated,
        "status_url": f"/api/v1/jobs/{job['job_id']}",
    }


@router.get("")
async def list_async_jobs(
    limit: int = Query(default=25, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    current_user: dict = Depends(RoleChecker(["ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN", "AUDITOR", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Lists tenant-scoped async jobs using deterministic keyset cursor pagination."""
    tenant_id = enforce_tenant_data_scope(current_user)
    items, next_cursor, has_more = await list_async_jobs_repo(
        tenant_id=str(tenant_id),
        limit=limit,
        cursor=cursor,
        status_filter=status_filter,
        read_conn_factory=get_async_db_read_conn,
    )
    return {
        "items": items,
        "next_cursor": next_cursor,
        "has_more": has_more,
    }


@router.get("/{job_id}")
async def get_async_job_status(
    job_id: str,
    current_user: dict = Depends(RoleChecker(["ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN", "AUDITOR", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=120, window=60)),
):
    """Returns current job status and a short-lived pre-signed S3 download URL when completed."""
    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    job = await get_async_job_repo(
        tenant_id=str(tenant_id),
        job_id=job_uuid,
        read_conn_factory=get_async_db_read_conn,
    )
    if not job:
        raise HTTPException(status_code=404, detail="Async job not found.")

    download_url: Optional[str] = None
    storage_key = job.get("artifact_storage_key")
    if job["status"] == "COMPLETED" and storage_key and str(storage_key).startswith("s3://"):
        try:
            from services.evidence_storage import S3EvidenceBackend

            signed = S3EvidenceBackend().generate_presigned_get_url(
                str(tenant_id),
                str(storage_key),
                expires_in=300,
                download_filename=job.get("artifact_filename"),
            )
            download_url = signed["url"]
        except Exception:
            logger.debug("Pre-signed download URL generation skipped for job %s", job_id)

    return {
        **job,
        "download_url": download_url,
    }
