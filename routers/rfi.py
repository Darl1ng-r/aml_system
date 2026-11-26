"""
External Customer / RM RFI Portal Router (P2-1)
================================================
Thin HTTP controller for authenticated RFI workflows and token-gated
zero-tipping-off external portal submissions.
All PostgreSQL SQL lives in `repositories/rfi_repo.py`.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile, status
from pydantic import BaseModel, Field, field_validator

from database.postgres import get_async_db_conn, get_async_db_read_conn
from observability.logging import log_audit_event
from observability.sanitizer import sanitize_text
from repositories.rfi_repo import (
    cancel_rfi_atomic,
    create_case_rfi_atomic,
    fetch_public_rfi_by_token_hash_repo,
    list_case_rfis_repo,
    submit_public_rfi_atomic,
)
from routers.evidence import (
    ALLOWED_EVIDENCE_MIMES,
    FORBIDDEN_EXTENSIONS,
    MAX_EVIDENCE_BYTES,
    _sanitize_evidence_filename,
)
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.evidence_storage import get_evidence_storage_backend, scan_bytes_for_malware
from services.idempotency import run_idempotent_operation
from services.notifications import create_notification
from services.rate_limiter import RateLimiter
from services.rfi import (
    generate_rfi_token,
    parse_rfi_token,
    pause_case_sla_for_rfi,
    resume_case_sla_after_rfi,
    serialize_public_rfi_safe,
)

logger = logging.getLogger("aml.rfi")

router = APIRouter(prefix="/api/v1/rfi", tags=["External RFI Portal"])


class RFICreateRequest(BaseModel):
    recipient_email: str = Field(default="", max_length=255)
    recipient_role: str = Field(default="CUSTOMER", pattern=r"^(CUSTOMER|RM)$")
    prompt_message: str = Field(
        default="Please provide supporting documentation verifying the source of funds and commercial purpose for recent account activity.",
        min_length=10,
        max_length=2000,
    )
    requested_docs: List[str] = Field(
        default_factory=lambda: ["Source of Funds Statement", "Commercial Invoice / Contract"],
        max_length=10,
    )
    expires_in_hours: int = Field(default=72, ge=1, le=720)

    @field_validator("prompt_message", mode="before")
    @classmethod
    def sanitize_prompt(cls, v: str) -> str:
        return sanitize_text(v)


@router.post("/cases/{case_id}", status_code=status.HTTP_201_CREATED)
async def create_case_rfi(
    case_id: str,
    payload: RFICreateRequest,
    request: Request,
    current_user: dict = Depends(RoleChecker(["L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
) -> Dict[str, Any]:
    """Issues a tokenized external RFI link, pauses SLA, and commits WORM audit inside one ACID tx."""
    try:
        case_uuid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case ID.")

    tenant_id = enforce_tenant_data_scope(current_user)

    async def _execute_create():
        raw_token, token_hash = generate_rfi_token(tenant_id)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=payload.expires_in_hours)
        safe_docs = [sanitize_text(d) for d in payload.requested_docs if str(d).strip()]

        rfi_id = await create_case_rfi_atomic(
            case_uuid=case_uuid,
            tenant_id=str(tenant_id),
            token_hash=token_hash,
            recipient_email=payload.recipient_email.strip(),
            recipient_role=payload.recipient_role,
            prompt_message=payload.prompt_message,
            safe_docs=safe_docs,
            expires_at=expires_at,
            current_user=current_user,
            pause_sla_fn=pause_case_sla_for_rfi,
            conn_factory=get_async_db_conn,
        )

        log_audit_event(
            event_type="RFI_ISSUED_SLA_PAUSED",
            actor_id=str(current_user.get("id", "")),
            actor_role=current_user.get("role", "ANALYST"),
            action="ISSUE_RFI",
            resource_type="CASE",
            resource_id=case_id,
            tenant_id=str(tenant_id),
            details={"rfi_id": str(rfi_id), "recipient_role": payload.recipient_role, "expires_at": expires_at.isoformat()},
        )

        from config import settings

        configured_base = (getattr(settings, "public_base_url", "") or "").strip().rstrip("/")
        if configured_base:
            base_url = configured_base
        elif getattr(settings, "is_hardened", settings.is_production):
            first_origin = next((o.strip().rstrip("/") for o in settings.allowed_origins.split(",") if o.strip()), "")
            base_url = first_origin or str(request.base_url).rstrip("/")
        else:
            base_url = str(request.base_url).rstrip("/")
        return {
            "rfi_id": str(rfi_id),
            "case_id": case_id,
            "status": "OPEN",
            "sla_clock_paused": True,
            "expires_at": expires_at.isoformat(),
            "rfi_token": raw_token,
            "portal_url": f"{base_url}/rfi/{raw_token}",
            "note": "Share this one-time link securely with the Customer or RM; the token is not retrievable again.",
        }

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope=f"rfi_create:{case_uuid}",
        body=payload.model_dump(mode="json"),
        handler=_execute_create,
        success_status_code=status.HTTP_201_CREATED,
        required=True,
    )


@router.get("/cases/{case_id}")
async def list_case_rfis(
    case_id: str,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
) -> List[Dict[str, Any]]:
    try:
        case_uuid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case ID.")
    tenant_id = enforce_tenant_data_scope(current_user)
    rows = await list_case_rfis_repo(
        case_uuid=case_uuid,
        tenant_id=str(tenant_id),
        read_conn_factory=get_async_db_read_conn,
    )
    return [
        {
            "rfi_id": str(r["id"]),
            "case_id": str(r["case_id"]),
            "recipient_email": r["recipient_email"],
            "recipient_role": r["recipient_role"],
            "prompt_message": r["prompt_message"],
            "requested_docs": list(r["requested_docs"] or []),
            "status": r["status"],
            "response_notes": r["response_notes"],
            "submitted_evidence_ids": [str(x) for x in (r["submitted_evidence_ids"] or [])],
            "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
            "submitted_at": r["submitted_at"].isoformat() if r["submitted_at"] else None,
            "created_by": r["created_by"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in (rows or [])
    ]


@router.post("/{rfi_id}/cancel")
async def cancel_rfi(
    rfi_id: str,
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
) -> Dict[str, Any]:
    try:
        rfi_uuid = uuid.UUID(rfi_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid RFI ID.")
    tenant_id = enforce_tenant_data_scope(current_user)

    async def _execute_cancel():
        resumed_secs = await cancel_rfi_atomic(
            rfi_uuid=rfi_uuid,
            tenant_id=str(tenant_id),
            current_user=current_user,
            resume_sla_fn=resume_case_sla_after_rfi,
            conn_factory=get_async_db_conn,
        )
        return {"rfi_id": rfi_id, "status": "CANCELLED", "sla_paused_seconds_added": resumed_secs}

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope=f"rfi_cancel:{rfi_uuid}",
        body={"rfi_id": rfi_id},
        handler=_execute_cancel,
        success_status_code=status.HTTP_200_OK,
        required=True,
    )


@router.get("/public/{token}")
async def get_public_rfi_prompt(
    token: str,
    response: Response,
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
) -> Dict[str, Any]:
    """Unauthenticated token-gated RFI metadata endpoint (strictly customer-safe)."""
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    tenant_id, token_hash = parse_rfi_token(token)
    if not tenant_id:
        raise HTTPException(status_code=404, detail="Invalid or expired documentation link.")

    row = await fetch_public_rfi_by_token_hash_repo(
        tenant_id=tenant_id,
        token_hash=token_hash,
        read_conn_factory=get_async_db_read_conn,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Invalid or expired documentation link.")

    expires = row["expires_at"]
    if expires and expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if row["status"] == "OPEN" and expires and expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="This documentation request link has expired.")
    if row["status"] in ("CANCELLED", "EXPIRED"):
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="This documentation request link is no longer active.")

    return serialize_public_rfi_safe(dict(row))


@router.post("/public/{token}/submit")
async def submit_public_rfi_response(
    token: str,
    response: Response,
    response_notes: str = Form(..., min_length=3, max_length=4000),
    file: Optional[UploadFile] = File(default=None),
    _rate_limit=Depends(RateLimiter(limit=15, window=60)),
) -> Dict[str, Any]:
    """Accepts external Customer/RM RFI response + optional malware-scanned document upload."""
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    tenant_id, token_hash = parse_rfi_token(token)
    if not tenant_id:
        raise HTTPException(status_code=404, detail="Invalid documentation request link.")

    safe_notes = sanitize_text(response_notes)
    return await submit_public_rfi_atomic(
        tenant_id=tenant_id,
        token_hash=token_hash,
        safe_notes=safe_notes,
        file=file,
        sanitize_filename_fn=_sanitize_evidence_filename,
        allowed_mimes=ALLOWED_EVIDENCE_MIMES,
        forbidden_extensions=FORBIDDEN_EXTENSIONS,
        max_evidence_bytes=MAX_EVIDENCE_BYTES,
        scan_fn=scan_bytes_for_malware,
        storage_factory=get_evidence_storage_backend,
        resume_sla_fn=resume_case_sla_after_rfi,
        notify_fn=create_notification,
        conn_factory=get_async_db_conn,
    )
