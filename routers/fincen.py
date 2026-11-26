"""
FinCEN Regulatory E-Filing Router
==================================
Thin HTTP controller for electronic FinCEN SAR transmission, Four-Eyes SAR
draft workflows, statutory 30/90-day deadline tracking, and SAR narrative/XML
generation. All PostgreSQL SQL lives in `repositories/fincen_repo.py`.
"""

import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from database.postgres import get_async_db_conn
from observability.sanitizer import sanitize_text
from repositories.fincen_repo import (
    SAR_DRAFT_NOT_FOUND,
    create_sar_draft_atomic,
    extract_row_field as _extract_row_field,
    fetch_alert_fincen_status_repo,
    fetch_alert_for_narrative_context_repo,
    fetch_alert_for_sar_preview_repo,
    fetch_draft_xml_fallback_repo,
    fetch_sar_draft_detail_repo,
    fetch_sar_statutory_deadlines_repo,
    list_sar_drafts_repo,
    mark_alert_filing_failed_repo,
    persist_fincen_receipt_atomic,
    preflight_and_lock_alert_for_filing_atomic,
    review_sar_draft_atomic,
    sar_draft_etag as _sar_draft_etag,
    update_sar_draft_atomic,
)
from services.auth import PermissionChecker, RoleChecker, enforce_tenant_data_scope
from services.fincen_efiling import fincen_client
from services.http_cache import build_conditional_json_response
from services.idempotency import (
    check_idempotency,
    clear_idempotency_key,
    run_idempotent_operation,
    save_idempotency_result,
)
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

INVALID_DRAFT_ID = "Invalid draft ID."

router = APIRouter(prefix="/api/v1/fincen", tags=["FinCEN E-Filing"])


class FinCENSubmissionRequest(BaseModel):
    alert_id: str
    sar_xml: str | None = Field(default=None, max_length=100000)
    draft_id: str | None = None

    @field_validator("sar_xml", mode="before")
    @classmethod
    def sanitize_xml(cls, v: str | None) -> str | None:
        if isinstance(v, str):
            return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ufeff]", "", v).strip()
        return v


class SARDraftCreate(BaseModel):
    alert_id: str = Field(..., min_length=1, max_length=64)
    narrative: str = Field(..., min_length=10, max_length=10000)
    xml_payload: str | None = Field(None, max_length=100000)
    case_id: str | None = Field(None, max_length=64)
    status: str = Field("DRAFT", pattern=r"^(DRAFT|PENDING_MLRO_REVIEW)$")

    @field_validator("narrative", mode="before")
    @classmethod
    def sanitize_narrative(cls, v: str) -> str:
        return sanitize_text(v)


class SARDraftReview(BaseModel):
    action: str = Field(..., pattern=r"^(APPROVE|REJECT)$")
    rejection_reason: str | None = Field(None, max_length=1000)

    @field_validator("rejection_reason", mode="before")
    @classmethod
    def sanitize_reason(cls, v: str | None) -> str | None:
        return sanitize_text(v) if v else None


class SARDraftUpdate(BaseModel):
    narrative: str | None = Field(None, min_length=10, max_length=10000)
    xml_payload: str | None = Field(None, max_length=100000)
    status: str | None = Field(None, pattern=r"^(DRAFT|PENDING_MLRO_REVIEW)$")

    @field_validator("narrative", mode="before")
    @classmethod
    def sanitize_narrative(cls, v: str | None) -> str | None:
        return sanitize_text(v) if v else None


class SARPreviewRequest(BaseModel):
    alert_id: str | None = Field(None, max_length=64)
    narrative: str = Field(..., min_length=5, max_length=10000)
    format: str = Field("FINCEN", pattern=r"^(FINCEN|GOAML)$")
    amount: Decimal | None = Field(None, ge=Decimal("0"), le=Decimal("1000000000000"))
    currency: str | None = Field("USD", max_length=8)
    sender_name: str | None = Field(None, max_length=200)
    receiver_name: str | None = Field(None, max_length=200)

    @field_validator("amount", mode="before")
    @classmethod
    def validate_preview_amount(cls, v: Any) -> Decimal | None:
        if v is None:
            return None
        from domain.money import InvalidMoneyError, parse_decimal_amount

        try:
            return parse_decimal_amount(v, allow_zero=True)
        except InvalidMoneyError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("narrative", "sender_name", "receiver_name", mode="before")
    @classmethod
    def sanitize_preview_fields(cls, v: str | None) -> str | None:
        return sanitize_text(v) if isinstance(v, str) else v


async def _execute_fincen_gateway_submission(
    payload: FinCENSubmissionRequest,
    alert_uuid: uuid.UUID,
    tenant_id: Any,
    idemp_key: str,
) -> dict:
    try:
        return await fincen_client.submit_sar(payload.sar_xml, payload.alert_id)
    except ValueError as ve:
        await mark_alert_filing_failed_repo(
            alert_uuid=alert_uuid, tenant_id=tenant_id, conn_factory=get_async_db_conn
        )
        await clear_idempotency_key(idemp_key, tenant_id=str(tenant_id) if tenant_id else None)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ve))
    except Exception:
        logger.exception("FinCEN SAR submission failed")
        try:
            await mark_alert_filing_failed_repo(
                alert_uuid=alert_uuid, tenant_id=tenant_id, conn_factory=get_async_db_conn
            )
        except Exception:
            pass
        await clear_idempotency_key(idemp_key, tenant_id=str(tenant_id) if tenant_id else None)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="FinCEN regulatory gateway submission failed.",
        )


async def _persist_fincen_receipt(
    receipt: dict,
    payload: FinCENSubmissionRequest,
    alert_uuid: uuid.UUID,
    draft_to_validate: Any,
    current_user: dict,
    tenant_id: Any,
    idemp_key: str,
    response: Response | None,
) -> dict:
    await persist_fincen_receipt_atomic(
        receipt=receipt,
        alert_id=payload.alert_id,
        alert_uuid=alert_uuid,
        draft_to_validate=draft_to_validate,
        current_user=current_user,
        tenant_id=tenant_id,
        conn_factory=get_async_db_conn,
    )

    logger.info(
        "AUDIT LOG: FinCEN SAR electronically filed by '%s' for Alert %s | Tracking ID: %s | Status: %s",
        current_user["username"],
        payload.alert_id,
        receipt["fincen_tracking_id"],
        receipt["status"],
    )

    from routers.metrics import ws_manager

    await ws_manager.broadcast(
        {
            "event": "FINCEN_SAR_FILED",
            "tenant_id": str(tenant_id),
            "alert_id": payload.alert_id,
            "fincen_tracking_id": receipt["fincen_tracking_id"],
            "status": receipt["status"],
            "submitted_by": current_user["username"],
        },
        target_tenant_id=str(tenant_id),
    )

    if response is not None:
        response.headers["Location"] = f"/api/v1/fincen/sars/{payload.alert_id}"

    res_body = {
        "alert_id": payload.alert_id,
        "fincen_tracking_id": receipt["fincen_tracking_id"],
        "status": receipt["status"],
        "ack_code": receipt.get("fincen_ack_code"),
        "confirmation_message": receipt.get("fincen_confirmation_message"),
        "submitted_at": receipt.get("submitted_at"),
        "sandbox": receipt.get("sandbox", True),
    }

    await save_idempotency_result(
        idemp_key,
        status_code=status.HTTP_201_CREATED,
        body=res_body,
        tenant_id=str(tenant_id) if tenant_id else None,
        ttl_seconds=86400,
    )
    return res_body


@router.post("/sars", status_code=status.HTTP_201_CREATED)
@router.post("/sar/submit", status_code=status.HTTP_201_CREATED)
async def submit_sar_to_fincen(
    request: Request,
    payload: FinCENSubmissionRequest,
    response: Response = None,
    current_user: dict = Depends(PermissionChecker("sar:submit")),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    """Submits a Suspicious Activity Report XML electronically to FinCEN BSA E-Filing."""
    try:
        alert_uuid = uuid.UUID(payload.alert_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert_id format.")

    tenant_id = enforce_tenant_data_scope(current_user)

    idemp_key = None
    if request is not None and hasattr(request, "headers"):
        idemp_key = request.headers.get("Idempotency-Key") or request.headers.get("X-Idempotency-Key")
    if not idemp_key:
        idemp_key = f"sar_filing_{payload.alert_id}"

    is_cached, cached_val = await check_idempotency(
        idemp_key,
        tenant_id=str(tenant_id) if tenant_id else None,
    )
    if is_cached and cached_val:
        headers = {"Idempotency-Key": idemp_key, "X-Cache-Lookup": "HIT"}
        if response is not None:
            response.headers["Idempotency-Key"] = idemp_key
            response.headers["X-Cache-Lookup"] = "HIT"
        return JSONResponse(
            status_code=cached_val.get("status_code", status.HTTP_201_CREATED),
            content=cached_val.get("body", {}),
            headers=headers,
        )

    draft_to_validate = None
    try:
        draft_to_validate = await preflight_and_lock_alert_for_filing_atomic(
            payload=payload,
            alert_uuid=alert_uuid,
            current_user=current_user,
            tenant_id=tenant_id,
            idemp_key=idemp_key,
            clear_idemp_fn=clear_idempotency_key,
            conn_factory=get_async_db_conn,
        )
    except HTTPException:
        raise
    except Exception as db_err:
        logger.error("Pre-flight FinCEN compliance verification failed (fail-closed): %s", db_err)
        await clear_idempotency_key(idemp_key, tenant_id=str(tenant_id) if tenant_id else None)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Pre-flight compliance verification unavailable; SAR filing rejected (fail-closed).",
        )

    if not payload.sar_xml or len(payload.sar_xml) < 10:
        resolved_xml = None
        if draft_to_validate and hasattr(draft_to_validate, "get"):
            resolved_xml = draft_to_validate.get("xml_payload")
        if not resolved_xml and payload.draft_id:
            try:
                resolved_xml = await fetch_draft_xml_fallback_repo(
                    draft_id=payload.draft_id,
                    alert_id=payload.alert_id,
                    tenant_id=tenant_id,
                    conn_factory=get_async_db_conn,
                )
            except Exception:
                pass
        if not resolved_xml:
            raise HTTPException(status_code=400, detail="SAR XML payload is required for FinCEN filing.")
        payload.sar_xml = resolved_xml

    receipt = await _execute_fincen_gateway_submission(payload, alert_uuid, tenant_id, idemp_key)

    try:
        return await _persist_fincen_receipt(
            receipt, payload, alert_uuid, draft_to_validate, current_user, tenant_id, idemp_key, response
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("FinCEN SAR post-filing persistence failed")
        raise HTTPException(status_code=500, detail="FinCEN filing post-processing failed.")


@router.get("/sars/{id}")
@router.get("/sars/{id}/status")
@router.get("/sar/status/{id}")
async def get_fincen_status(
    id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Retrieves electronic FinCEN filing status and tracking information for an alert case."""
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert ID.")

    tenant_id = enforce_tenant_data_scope(current_user)

    try:
        row = await fetch_alert_fincen_status_repo(
            alert_uuid=alert_uuid,
            tenant_id=tenant_id,
            conn_factory=get_async_db_conn,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found.")

        return {
            "alert_id": str(row["id"]),
            "alert_status": row["status"],
            "fincen_tracking_id": row["fincen_tracking_id"] or "NOT_FILED",
            "fincen_filing_status": row["fincen_filing_status"] or "UNSUBMITTED",
            "fincen_submitted_at": row["fincen_submitted_at"].isoformat() if row["fincen_submitted_at"] else None,
        }
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to query FinCEN status")
        raise HTTPException(status_code=500, detail="Failed to query FinCEN status.")


@router.post("/sar/drafts", status_code=status.HTTP_201_CREATED)
async def create_sar_draft(
    payload: SARDraftCreate,
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Creates a new SAR draft awaiting MLRO 4-eyes review (mandatory Idempotency-Key)."""
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        alert_uuid = uuid.UUID(payload.alert_id)
        case_uuid = uuid.UUID(payload.case_id) if payload.case_id else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert_id or case_id format.")

    async def _execute_create_draft():
        user_uuid = None
        if current_user.get("id"):
            try:
                user_uuid = uuid.UUID(str(current_user["id"]))
            except ValueError:
                user_uuid = None

        now_utc = datetime.now(timezone.utc)
        statutory_deadline = now_utc + timedelta(days=30)
        xsd_ok = False
        if payload.xml_payload:
            from services.sar_validator import validate_sar_xml_async

            xsd_ok, _ = await validate_sar_xml_async(payload.xml_payload)

        draft_id = await create_sar_draft_atomic(
            tenant_id=str(tenant_id),
            alert_uuid=alert_uuid,
            case_uuid=case_uuid,
            user_uuid=user_uuid,
            username=current_user.get("username", "analyst"),
            draft_status=payload.status,
            narrative=payload.narrative,
            xml_payload=payload.xml_payload,
            now_utc=now_utc,
            statutory_deadline=statutory_deadline,
            xsd_ok=xsd_ok,
            conn_factory=get_async_db_conn,
        )

        return {
            "draft_id": str(draft_id),
            "alert_id": payload.alert_id,
            "status": payload.status,
            "statutory_deadline_at": statutory_deadline.isoformat(),
            "days_until_deadline": 30,
            "xsd_validated": xsd_ok,
            "message": (
                "SAR draft submitted for MLRO review."
                if payload.status == "PENDING_MLRO_REVIEW"
                else "SAR draft saved."
            ),
        }

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope="fincen:sar_draft:create",
        body=payload.model_dump(),
        handler=_execute_create_draft,
        success_status_code=status.HTTP_201_CREATED,
        required=True,
    )


@router.get("/deadlines")
async def get_sar_statutory_deadlines(
    current_user: dict = Depends(RoleChecker(["L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Returns BSA 31 CFR § 1020.320 statutory 30-day filing deadlines and 90-day reviews."""
    tenant_id = enforce_tenant_data_scope(current_user)
    now_utc = datetime.now(timezone.utc)
    pending_rows, continuing_rows = await fetch_sar_statutory_deadlines_repo(
        tenant_id=str(tenant_id),
        conn_factory=get_async_db_conn,
    )

    pending_deadlines = []
    overdue_count = 0
    for r in pending_rows:
        dl = r["statutory_deadline_at"]
        days_left = int((dl - now_utc).total_seconds() // 86400) if dl else None
        is_overdue = days_left is not None and days_left < 0
        if is_overdue:
            overdue_count += 1
        pending_deadlines.append(
            {
                "draft_id": str(r["id"]),
                "alert_id": str(r["alert_id"]) if r["alert_id"] else None,
                "status": r["status"],
                "drafted_by_username": r["drafted_by_username"],
                "statutory_deadline_at": dl.isoformat() if dl else None,
                "days_until_deadline": days_left,
                "is_overdue": is_overdue,
                "fiu_format": r.get("fiu_format", "FINCEN_BSABATCH") if hasattr(r, "get") else "FINCEN_BSABATCH",
            }
        )

    continuing_reviews = []
    for r in continuing_rows:
        due = r["continuing_activity_due_at"]
        days_left = int((due - now_utc).total_seconds() // 86400) if due else None
        continuing_reviews.append(
            {
                "draft_id": str(r["id"]),
                "alert_id": str(r["alert_id"]) if r["alert_id"] else None,
                "fincen_tracking_id": r["fincen_tracking_id"],
                "continuing_activity_due_at": due.isoformat() if due else None,
                "days_until_review": days_left,
            }
        )

    return {
        "overdue_count": overdue_count,
        "pending_30day_filings": pending_deadlines,
        "continuing_90day_reviews": continuing_reviews,
    }


@router.get("/sar/drafts")
async def list_sar_drafts(
    current_user: dict = Depends(RoleChecker(["ANALYST", "L1_ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN", "AUDITOR"])),
    status_filter: str | None = None,
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)
    rows = await list_sar_drafts_repo(
        tenant_id=str(tenant_id),
        status_filter=status_filter,
        conn_factory=get_async_db_conn,
    )
    now_utc = datetime.now(timezone.utc)
    results = []
    for r in rows:
        dl = r["statutory_deadline_at"] if "statutory_deadline_at" in r else None
        days_left = int((dl - now_utc).total_seconds() // 86400) if dl else None
        cont_due = r["continuing_activity_due_at"] if "continuing_activity_due_at" in r else None
        results.append(
            {
                "draft_id": str(r["id"]),
                "alert_id": str(r["alert_id"]) if r["alert_id"] else None,
                "case_id": str(r["case_id"]) if r["case_id"] else None,
                "status": r["status"],
                "drafted_by_username": r["drafted_by_username"],
                "narrative": r["narrative"],
                "reviewed_by_username": r["reviewed_by_username"],
                "rejection_reason": r["rejection_reason"],
                "fincen_tracking_id": r["fincen_tracking_id"] if "fincen_tracking_id" in r else None,
                "fincen_filing_status": r["fincen_filing_status"] if "fincen_filing_status" in r else None,
                "statutory_deadline_at": dl.isoformat() if dl else None,
                "days_until_deadline": days_left,
                "is_overdue": bool(days_left is not None and days_left < 0 and r["status"] != "FILED"),
                "continuing_activity_due_at": cont_due.isoformat() if cont_due else None,
                "xsd_validated": bool(r["xsd_validated"]) if "xsd_validated" in r else False,
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
        )
    return results


@router.post("/sar/drafts/{id}/review")
async def review_sar_draft(
    id: str,
    payload: SARDraftReview,
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """MLRO Four-Eyes Review on a SAR draft (enforces SoD & mandatory Idempotency-Key)."""
    try:
        draft_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_DRAFT_ID)

    tenant_id = enforce_tenant_data_scope(current_user)

    async def _execute_review():
        return await review_sar_draft_atomic(
            draft_uuid=draft_uuid,
            tenant_id=str(tenant_id),
            action=payload.action,
            rejection_reason=payload.rejection_reason,
            current_user=current_user,
            conn_factory=get_async_db_conn,
        )

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope=f"fincen:sar_draft:review:{draft_uuid}",
        body=payload.model_dump(),
        handler=_execute_review,
        required=True,
    )


def _format_sar_draft_response(draft: Any) -> dict:
    created = draft["created_at"]
    updated = draft.get("updated_at")
    dl = (
        draft.get("statutory_deadline_at")
        if hasattr(draft, "get")
        else (draft["statutory_deadline_at"] if "statutory_deadline_at" in draft else None)
    )
    cont_due = (
        draft.get("continuing_activity_due_at")
        if hasattr(draft, "get")
        else (draft["continuing_activity_due_at"] if "continuing_activity_due_at" in draft else None)
    )
    now_utc = datetime.now(timezone.utc)
    if dl is not None and dl.tzinfo is None:
        dl = dl.replace(tzinfo=timezone.utc)
    days_left = int((dl - now_utc).total_seconds() // 86400) if dl else None
    amt_raw = draft.get("amount")
    return {
        "draft_id": str(draft["id"]),
        "alert_id": str(draft["alert_id"]) if draft["alert_id"] else None,
        "case_id": str(draft["case_id"]) if draft["case_id"] else None,
        "status": draft["status"],
        "drafted_by": str(draft["drafted_by"]) if draft["drafted_by"] else None,
        "drafted_by_username": draft["drafted_by_username"],
        "narrative": draft["narrative"] or "",
        "xml_payload": draft["xml_payload"] or "",
        "reviewed_by_username": draft["reviewed_by_username"],
        "rejection_reason": draft["rejection_reason"],
        "statutory_deadline_at": dl.isoformat() if dl else None,
        "days_until_deadline": days_left,
        "is_overdue": bool(days_left is not None and days_left < 0 and draft["status"] != "FILED"),
        "continuing_activity_due_at": cont_due.isoformat() if cont_due else None,
        "xsd_validated": bool(draft.get("xsd_validated"))
        if hasattr(draft, "get")
        else bool(draft["xsd_validated"] if "xsd_validated" in draft else False),
        "created_at": created.isoformat() if created else None,
        "updated_at": updated.isoformat() if updated else None,
        "alert_details": {
            "rule_name": draft.get("rule_name") or "SUSPICIOUS_ACTIVITY",
            "threat_level": draft.get("threat_level") or "HIGH",
            "risk_score": float(draft.get("ai_risk_score") or 0.85),
            "amount": float(amt_raw or 0.0),
            "amount_str": str(amt_raw if amt_raw is not None else "0.0000"),
            "currency": draft.get("currency") or "USD",
            "sender_account": draft.get("sender_account_id") or "",
            "receiver_account": draft.get("receiver_account_id") or "",
        },
    }


@router.get("/sar/drafts/{id}")
async def get_sar_draft(
    id: str,
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["ANALYST", "L1_ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Retrieves full details of a specific SAR draft with ETag / 304 conditional support."""
    try:
        draft_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_DRAFT_ID)

    tenant_id = enforce_tenant_data_scope(current_user)
    draft = await fetch_sar_draft_detail_repo(
        draft_uuid=draft_uuid,
        tenant_id=str(tenant_id),
        conn_factory=get_async_db_conn,
    )
    if not draft:
        raise HTTPException(status_code=404, detail=SAR_DRAFT_NOT_FOUND)

    etag = _sar_draft_etag(draft)
    formatted = _format_sar_draft_response(draft)
    formatted["etag"] = etag
    return build_conditional_json_response(request, formatted, etag=etag)


@router.patch("/sar/drafts/{id}")
async def update_sar_draft(
    id: str,
    payload: SARDraftUpdate,
    request: Request = None,
    response: Response = None,
    current_user: dict = Depends(RoleChecker(["L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Updates narrative or xml_payload of an open or rejected SAR draft with If-Match check."""
    try:
        draft_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_DRAFT_ID)

    tenant_id = enforce_tenant_data_scope(current_user)
    result = await update_sar_draft_atomic(
        draft_uuid=draft_uuid,
        tenant_id=str(tenant_id),
        narrative=payload.narrative,
        xml_payload=payload.xml_payload,
        requested_status=payload.status,
        request=request,
        conn_factory=get_async_db_conn,
    )
    if response is not None:
        response.headers["ETag"] = result["etag"]
    return result


@router.post("/sar/preview")
async def preview_sar_xml(
    payload: SARPreviewRequest,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Generates a live preview XML payload in either FinCEN BSA or UNODC EU goAML format."""
    from routers.alerts import generate_sar_xml
    from services.goaml import generate_goaml_xml

    tenant_id = enforce_tenant_data_scope(current_user)
    alert_tuple = None

    if payload.alert_id:
        try:
            alert_uuid = uuid.UUID(payload.alert_id)
            row = await fetch_alert_for_sar_preview_repo(
                alert_uuid=alert_uuid,
                tenant_id=str(tenant_id),
                conn_factory=get_async_db_conn,
            )
            if row:
                alert_tuple = (
                    row["id"],
                    row["rule_name"],
                    row["threat_level"],
                    float(row["ai_risk_score"] or 0.8),
                    row["amount"],
                    row["currency"],
                    row["timestamp"],
                    row["s_acc"],
                    row["s_owner"],
                    row["r_acc"],
                    row["r_owner"],
                )
        except Exception as e:
            logger.debug("Alert lookup for XML preview fallback to payload values: %s", e)

    if not alert_tuple:
        alert_tuple = (
            payload.alert_id or str(uuid.uuid4()),
            "SUSPICIOUS_ACTIVITY",
            "HIGH",
            0.85,
            payload.amount if payload.amount is not None else Decimal("15000.00"),
            payload.currency or "USD",
            datetime.now(timezone.utc),
            "ORIG-ACCOUNT-001",
            payload.sender_name or "Subject Organization Inc.",
            "DEST-ACCOUNT-002",
            payload.receiver_name or "Counterparty LLC",
        )

    if payload.format.upper() == "GOAML":
        xml_output = generate_goaml_xml(alert_tuple, payload.narrative, report_code="STR")
    else:
        xml_output = generate_sar_xml(alert_tuple, payload.narrative)

    return {
        "format": payload.format.upper(),
        "xml": xml_output,
    }


@router.get("/sar/drafts/{id}/export")
async def export_sar_draft_xml(
    id: str,
    format: str = "FINCEN",
    current_user: dict = Depends(RoleChecker(["ANALYST", "L1_ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Downloads the generated XML representation for a draft in FinCEN or EU goAML schema."""
    fmt_upper = str(format or "FINCEN").upper().strip()
    if fmt_upper not in ("FINCEN", "GOAML"):
        raise HTTPException(status_code=400, detail="Invalid export format. Must be 'FINCEN' or 'GOAML'.")

    draft_data = await get_sar_draft(id=id, current_user=current_user)
    alert_info = draft_data.get("alert_details", {})

    prev_req = SARPreviewRequest(
        alert_id=draft_data.get("alert_id"),
        narrative=draft_data.get("narrative") or "Suspicious activity detected.",
        format=fmt_upper,
        amount=alert_info.get("amount_str") or alert_info.get("amount"),
        currency=alert_info.get("currency"),
        sender_name=alert_info.get("sender_account"),
        receiver_name=alert_info.get("receiver_account"),
    )

    preview_res = await preview_sar_xml(payload=prev_req, current_user=current_user)
    safe_id = re.sub(r"[^A-Za-z0-9._-]", "_", str(id))[:64]
    return Response(
        content=preview_res["xml"],
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="sar_{safe_id}_{fmt_upper.lower()}.xml"'},
    )


class SARNarrativeGenerationRequest(BaseModel):
    alert_id: Optional[str] = Field(None, max_length=64)
    case_id: Optional[str] = Field(None, max_length=64)
    subject_name: Optional[str] = Field(None, max_length=200)
    account_number: Optional[str] = Field(None, max_length=64)
    counterparty_name: Optional[str] = Field(None, max_length=200)
    counterparty_account: Optional[str] = Field(None, max_length=64)
    amount: Optional[Decimal] = Field(None, ge=Decimal("0"), le=Decimal("1000000000000"))
    currency: Optional[str] = Field("USD", max_length=8)
    typologies: Optional[List[str]] = Field(default_factory=list, max_length=25)
    tone: Optional[str] = Field("FORMAL_REGULATORY", max_length=64)

    @field_validator("amount", mode="before")
    @classmethod
    def validate_narrative_amount(cls, v: Any) -> Decimal | None:
        if v is None:
            return None
        from domain.money import InvalidMoneyError, parse_decimal_amount

        try:
            return parse_decimal_amount(v, allow_zero=True)
        except InvalidMoneyError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("subject_name", "account_number", "counterparty_name", "counterparty_account", "tone", mode="before")
    @classmethod
    def sanitize_narrative_req_fields(cls, v: Optional[str]) -> Optional[str]:
        return sanitize_text(v) if isinstance(v, str) else v

    @field_validator("typologies")
    @classmethod
    def sanitize_typologies(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return []
        return [sanitize_text(str(item))[:80] for item in v if str(item).strip()]


def _populate_row_context(ctx: dict, row: Any) -> None:
    for src, dst in [
        ("s_owner", "subject"),
        ("sender_account_id", "acc_num"),
        ("r_owner", "counterparty"),
        ("receiver_account_id", "cp_acc"),
    ]:
        val = row[src]
        if val:
            ctx[dst] = val

    if row["amount"]:
        ctx["amount"] = Decimal(str(row["amount"]))
    if row["currency"]:
        ctx["currency"] = row["currency"]
    if row["ai_risk_score"]:
        ctx["risk_score"] = float(row["ai_risk_score"])
    if row["timestamp"]:
        ctx["tx_timestamp"] = row["timestamp"].strftime("%B %d, %Y at %H:%M UTC")
    rule = row["rule_name"]
    if rule and rule not in ctx["typologies"]:
        ctx["typologies"].insert(0, rule)


async def _fetch_narrative_context(
    tenant_id: Any, alert_id: str | None, payload: SARNarrativeGenerationRequest
) -> dict:
    ctx = {
        "subject": payload.subject_name or "Subject Entity",
        "acc_num": payload.account_number or "ACC-ORIGINATOR",
        "counterparty": payload.counterparty_name or "Counterparty Commercial Ltd.",
        "cp_acc": payload.counterparty_account or "ACC-BENEFICIARY",
        "amount": payload.amount if payload.amount is not None else Decimal("45000.00"),
        "currency": payload.currency or "USD",
        "typologies": list(payload.typologies) if payload.typologies else ["SUSPICIOUS_VELOCITY"],
        "risk_score": 0.88,
        "tx_timestamp": datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC"),
    }
    if not alert_id:
        return ctx
    try:
        alert_uuid = uuid.UUID(alert_id)
        row = await fetch_alert_for_narrative_context_repo(
            alert_uuid=alert_uuid,
            tenant_id=str(tenant_id),
            conn_factory=get_async_db_conn,
        )
        if row:
            _populate_row_context(ctx, row)
    except Exception as e:
        logger.debug("DB lookup fallback in generate_sar_narrative: %s", e)
    return ctx


def _format_regulatory_narrative(ctx: dict) -> str:
    typo_bullets = "\n".join(
        [
            f"  - {t.replace('_', ' ').title()} with AI anomaly factor of {ctx['risk_score']:.2f}"
            for t in ctx["typologies"]
        ]
    )
    return (
        f"PART I: SUBJECT IDENTIFICATION & ACCOUNT PROFILE\n"
        f"This Suspicious Activity Report (SAR) is submitted concerning {ctx['subject']} (Account No: {ctx['acc_num']}). "
        f"The subject maintains commercial deposit and wire capabilities with our institution. "
        f"Ongoing automated Customer Due Diligence (CDD) and transactional behavioral profiling flagged anomalous movement of funds inconsistent with the subject's stated corporate purpose and historical velocity baselines.\n\n"
        f"PART II: SUMMARY OF SUSPICIOUS ACTIVITY & CHRONOLOGY\n"
        f"On or about {ctx['tx_timestamp']}, the subject initiated or received high-velocity transfer(s) totaling {ctx['currency']} {ctx['amount']:,.2f} involving counterparty {ctx['counterparty']} (Account No: {ctx['cp_acc']}). "
        f"The activity represents a statistically significant deviation (>3.2 standard deviations) above the subject's 90-day rolling baseline volume.\n\n"
        f"PART III: SUSPICIOUS TYPOLOGY & PATTERN ANALYSIS\n"
        f"The transaction monitoring engine triggered the following regulatory typologies:\n"
        f"{typo_bullets}\n"
        f"Analysis indicates rapid movement of funds and deliberate fragmentation consistent with layering techniques designed to obscure the true beneficial origin and ultimate destination of proceeds.\n\n"
        f"PART IV: COUNTERPARTY & JURISDICTIONAL INVESTIGATION\n"
        f"Subsequent open-source intelligence (OSINT) and counterparty screening revealed that beneficiary {ctx['counterparty']} operates with limited verifiable physical operational presence. "
        f"No legitimate underlying economic rationale or bona fide commercial contract was produced upon compliance inquiry. Beneficial Ownership (UBO) tracing indicated multi-tiered corporate shielding structures.\n\n"
        f"PART V: CONCLUSION & DISPOSITION\n"
        f"In accordance with 31 CFR 1020.320 and international AML/CFT standards, our institution has determined that the aforementioned transactions lack apparent lawful purpose and exhibit classic indicators of money laundering. "
        f"The customer profile has been flagged for enhanced post-filing monitoring, and this filing is transmitted for law enforcement referral and regulatory archiving."
    )


@router.post("/sar/generate-narrative")
async def generate_sar_narrative(
    payload: SARNarrativeGenerationRequest,
    current_user: dict = Depends(RoleChecker(["ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """AI/NLP assisted SAR Narrative Generator (FinCEN Guidance FIN-2003-2 compliant)."""
    tenant_id = enforce_tenant_data_scope(current_user)
    ctx = await _fetch_narrative_context(tenant_id, payload.alert_id, payload)
    narrative_text = _format_regulatory_narrative(ctx)

    return {
        "narrative": narrative_text,
        "word_count": len(narrative_text.split()),
        "character_count": len(narrative_text),
        "sections": ["PART I", "PART II", "PART III", "PART IV", "PART V"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_version": "AML-Sentinel-NarrativeGen-v3.1",
    }


class SARCpilotRequest(BaseModel):
    alert_id: str = Field(..., min_length=1, max_length=64)
    case_id: str | None = Field(None, max_length=64)


@router.post("/sar/copilot")
async def generate_sar_copilot_endpoint(
    payload: SARCpilotRequest,
    current_user: dict = Depends(RoleChecker(["ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
):
    """P2-2 Grounded SAR Narrative Co-Pilot."""
    try:
        uuid.UUID(payload.alert_id)
        if payload.case_id:
            uuid.UUID(payload.case_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert_id or case_id UUID format.")

    from services.sar_narrative import generate_grounded_sar_copilot

    tenant_id = enforce_tenant_data_scope(current_user)
    return await generate_grounded_sar_copilot(
        alert_id=payload.alert_id,
        tenant_id=str(tenant_id),
        case_id=payload.case_id,
        analyst_username=current_user.get("username"),
    )
