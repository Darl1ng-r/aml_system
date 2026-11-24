"""
Independent Quality Assurance (QA) Four-Eyes Sampling Router (P1-5)
===================================================================
Samples closed False Positive alerts for independent QA audit (OCC / FCA mandate),
enforces Segregation of Duties (QA reviewer != original dismissing analyst),
and reopens faulty dismissals back into the active investigation queue.
"""

import logging
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from database.postgres import get_async_db_conn, get_async_db_read_conn
from observability.logging import log_audit_event
from observability.sanitizer import sanitize_text
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
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        return await sample_closed_false_positives_for_qa(
            conn=conn,
            tenant_id=tenant_id,
            sampled_by_username=current_user.get("username", "mlro"),
            sample_rate=payload.sample_rate,
            max_samples=payload.max_samples,
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
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
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
            for r in (rows or [])
        ],
    }


@router.post("/{review_id}/review")
async def submit_qa_review(
    review_id: str,
    payload: QAReviewDecision,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "QA_REVIEWER", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
) -> Dict[str, Any]:
    """
    Completes an independent QA review.
    Enforces Segregation of Duties (original dismissing analyst cannot QA their own closure).
    On FAILED_REOPENED, transitions the alert back to OPEN and emits a QA_REOPEN notification.
    """
    try:
        rev_uuid = uuid.UUID(review_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid QA review ID.")

    tenant_id = enforce_tenant_data_scope(current_user)
    reviewer_username = str(current_user.get("username") or "").strip()
    reviewer_id = str(current_user.get("id") or "").strip()

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
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
            payload.decision,
            reviewer_username,
            payload.notes,
            rev_uuid,
            str(tenant_id),
        )

        reopened = False
        if payload.decision == "FAILED_REOPENED":
            reopened = True
            await conn.execute(
                "UPDATE alerts SET status = 'OPEN' WHERE id = $1 AND tenant_id = $2::uuid;",
                row["alert_id"],
                str(tenant_id),
            )
            await create_notification(
                conn=conn,
                tenant_id=tenant_id,
                category="QA_REOPEN",
                severity="CRITICAL",
                recipient_role="MLRO",
                title=f"QA Audit Reopened Alert {str(row['alert_id'])[:8]}",
                body=f"Reviewer {reviewer_username} failed QA on dismissed alert: {payload.notes}",
                link_url=f"/alerts/triage?search={str(row['alert_id'])[:8]}",
                resource_type="ALERT",
                resource_id=str(row["alert_id"]),
                dedup_hours=0,
            )

        try:
            from services.audit import record_audit_event_tx
            await record_audit_event_tx(
                conn=conn,
                action=f"QA_REVIEW_{payload.decision}",
                actor_id=str(current_user.get("id") or reviewer_username),
                actor_username=reviewer_username,
                actor_role=current_user.get("role", "QA_REVIEWER"),
                resource_type="QA_REVIEW",
                resource_id=review_id,
                tenant_id=str(tenant_id),
                details={"alert_id": str(row["alert_id"]), "decision": payload.decision, "reopened": reopened},
            )
        except Exception as audit_err:
            logger.warning(f"Transactional audit write skipped in submit_qa_review: {audit_err}")

    log_audit_event(
        event_type=f"QA_REVIEW_{payload.decision}",
        actor_id=str(current_user.get("id", reviewer_username)),
        actor_role=current_user.get("role", "MLRO"),
        action="QA_REVIEW",
        resource_type="QA_REVIEW",
        resource_id=review_id,
        tenant_id=str(tenant_id),
        details={
            "alert_id": str(row["alert_id"]),
            "decision": payload.decision,
            "reopened": reopened,
            "notes": payload.notes,
        },
    )

    return {
        "review_id": review_id,
        "alert_id": str(row["alert_id"]),
        "status": payload.decision,
        "reopened": reopened,
        "qa_reviewer_username": reviewer_username,
    }
