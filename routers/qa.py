"""
Independent Quality Assurance (QA) Four-Eyes Sampling Router (P1-5)
===================================================================
Thin HTTP controller for closed false-positive QA sampling and reviews.
All PostgreSQL SQL lives in `repositories/ops_repo.py`.
"""

import logging
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from database.postgres import get_async_db_conn, get_async_db_read_conn
from observability.logging import log_audit_event
from observability.sanitizer import sanitize_text
from repositories.ops_repo import (
    create_qa_sample_repo,
    fetch_qa_queue_repo,
    submit_qa_review_atomic,
)
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.notifications import create_notification
from services.pkyc_and_qa import sample_closed_false_positives_for_qa
from services.rate_limiter import RateLimiter

logger = logging.getLogger("aml.qa")

router = APIRouter(prefix="/api/v1/qa", tags=["Quality Assurance (Four-Eyes Sampling)"])


class QASampleRequest(BaseModel):
    sample_rate: float = Field(default=0.10, ge=0.01, le=1.0)
    max_samples: int = Field(default=25, ge=1, le=100)


class QAReviewDecision(BaseModel):
    decision: str = Field(..., pattern=r"^(PASSED|FAILED_REOPENED)$")
    notes: str = Field(..., min_length=3, max_length=2000)

    @field_validator("notes", mode="before")
    @classmethod
    def sanitize_notes(cls, v: str) -> str:
        return sanitize_text(v)


@router.post("/sample", status_code=status.HTTP_201_CREATED)
async def create_qa_sample(
    payload: QASampleRequest,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "QA_REVIEWER", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=15, window=60)),
) -> Dict[str, Any]:
    """Randomly samples a percentage of closed False Positive alerts into the QA queue."""
    tenant_id = enforce_tenant_data_scope(current_user)
    return await create_qa_sample_repo(
        tenant_id=str(tenant_id),
        sampled_by_username=current_user.get("username", "mlro"),
        sample_rate=payload.sample_rate,
        max_samples=payload.max_samples,
        sample_fn=sample_closed_false_positives_for_qa,
        conn_factory=get_async_db_conn,
    )


@router.get("/queue")
async def get_qa_queue(
    status_filter: Optional[str] = Query(default=None, pattern=r"^(PENDING|PASSED|FAILED_REOPENED)$"),
    limit: int = Query(default=50, ge=1, le=100),
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "QA_REVIEWER", "AUDITOR", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
) -> Dict[str, Any]:
    """Lists QA sampling queue entries along with tenant QA Pass Rate KPI."""
    tenant_id = enforce_tenant_data_scope(current_user)
    rows, stats = await fetch_qa_queue_repo(
        tenant_id=str(tenant_id),
        status_filter=status_filter,
        limit=limit,
        read_conn_factory=get_async_db_read_conn,
    )

    passed = int((stats["passed_count"] if stats else 0) or 0)
    failed = int((stats["failed_count"] if stats else 0) or 0)
    reviewed_total = passed + failed
    pass_rate = round((passed / reviewed_total) * 100.0, 2) if reviewed_total > 0 else 100.0

    return {
        "kpis": {
            "pending": int((stats["pending_count"] if stats else 0) or 0),
            "passed": passed,
            "failed_reopened": failed,
            "qa_pass_rate_pct": pass_rate,
        },
        "items": [
            {
                "review_id": str(r["id"]),
                "alert_id": str(r["alert_id"]),
                "case_id": str(r["case_id"]) if r["case_id"] else None,
                "rule_name": r["rule_name"] if "rule_name" in r else None,
                "threat_level": r["threat_level"] if "threat_level" in r else None,
                "original_disposition": r["original_disposition"],
                "original_analyst_username": r["original_analyst_username"],
                "qa_reviewer_username": r["qa_reviewer_username"],
                "status": r["status"],
                "qa_notes": r["qa_notes"],
                "sampled_at": r["sampled_at"].isoformat() if r["sampled_at"] else None,
                "reviewed_at": r["reviewed_at"].isoformat() if r["reviewed_at"] else None,
            }
            for r in rows
        ],
    }


@router.post("/{review_id}/review")
async def submit_qa_review(
    review_id: str,
    payload: QAReviewDecision,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "QA_REVIEWER", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
) -> Dict[str, Any]:
    """Completes an independent QA review enforcing Segregation of Duties."""
    try:
        rev_uuid = uuid.UUID(review_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid QA review ID.")

    tenant_id = enforce_tenant_data_scope(current_user)
    reviewer_username = str(current_user.get("username") or "").strip()
    reviewer_id = str(current_user.get("id") or "").strip()

    res = await submit_qa_review_atomic(
        rev_uuid=rev_uuid,
        tenant_id=str(tenant_id),
        decision=payload.decision,
        notes=payload.notes,
        reviewer_username=reviewer_username,
        reviewer_id=reviewer_id,
        current_user=current_user,
        notify_fn=create_notification,
        conn_factory=get_async_db_conn,
    )

    log_audit_event(
        event_type=f"QA_REVIEW_{payload.decision}",
        actor_id=str(current_user.get("id", reviewer_username)),
        actor_role=current_user.get("role", "MLRO"),
        action="QA_REVIEW",
        resource_type="QA_REVIEW",
        resource_id=review_id,
        tenant_id=str(tenant_id),
        details={
            "alert_id": res["alert_id"],
            "decision": payload.decision,
            "reopened": res["reopened"],
            "notes": payload.notes,
        },
    )

    return {
        "review_id": review_id,
        "alert_id": res["alert_id"],
        "status": payload.decision,
        "reopened": res["reopened"],
        "qa_reviewer_username": reviewer_username,
    }
