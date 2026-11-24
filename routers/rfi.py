"""
External Customer / RM RFI Portal Router (P2-1)
================================================
Investigator Routes (Authenticated):
  - POST /api/v1/rfi/cases/{case_id} : Issue time-boxed RFI upload link & pause Case SLA clock
  - GET  /api/v1/rfi/cases/{case_id} : List RFIs & SLA pause status for a case
  - POST /api/v1/rfi/{rfi_id}/cancel : Revoke open RFI & resume Case SLA clock

External Public Portal Routes (Token-Gated, Zero-Tipping-Off):
  - GET  /api/v1/rfi/public/{token}        : Customer-safe questionnaire prompt & expiry
  - POST /api/v1/rfi/public/{token}/submit : Malware-scanned upload -> case_evidence + SLA resume + Notification
"""

import hashlib
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile, status
from pydantic import BaseModel, Field, field_validator

from database.postgres import get_async_db_conn, get_async_db_read_conn
from observability.logging import log_audit_event
from observability.sanitizer import sanitize_text
from routers.evidence import (
    ALLOWED_EVIDENCE_MIMES,
    FORBIDDEN_EXTENSIONS,
    MAX_EVIDENCE_BYTES,
    _sanitize_evidence_filename,
)
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.evidence_storage import get_evidence_storage_backend, scan_bytes_for_malware
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
    """Issues a tokenized external RFI link and automatically pauses the case SLA clock."""
    try:
        case_uuid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case ID.")

    tenant_id = enforce_tenant_data_scope(current_user)
    raw_token, token_hash = generate_rfi_token(tenant_id)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=payload.expires_in_hours)
    safe_docs = [sanitize_text(d) for d in payload.requested_docs if str(d).strip()]

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        case_row = await conn.fetchrow(
            "SELECT id, subject_account_id, status FROM cases WHERE id = $1;",
            case_uuid,
        )
        if not case_row:
            raise HTTPException(status_code=404, detail="Case not found.")

        rfi_id = await conn.fetchval(
            """
            INSERT INTO rfi_requests (
                tenant_id, case_id, account_id, token_hash, recipient_email,
                recipient_role, prompt_message, requested_docs, status, expires_at, created_by
            )
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8::text[], 'OPEN', $9, $10)
            RETURNING id;
            """,
            str(tenant_id),
            case_uuid,
            case_row.get("subject_account_id"),
            token_hash,
            payload.recipient_email.strip(),
            payload.recipient_role,
            payload.prompt_message,
            safe_docs,
            expires_at,
            current_user.get("username", "investigator"),
        )
        await pause_case_sla_for_rfi(conn, case_uuid)

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
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, case_id, recipient_email, recipient_role, prompt_message, requested_docs,
                   status, response_notes, submitted_evidence_ids, expires_at, submitted_at, created_by, created_at
            FROM rfi_requests
            WHERE case_id = $1
            ORDER BY created_at DESC;
            """,
            case_uuid,
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
    current_user: dict = Depends(RoleChecker(["L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
) -> Dict[str, Any]:
    try:
        rfi_uuid = uuid.UUID(rfi_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid RFI ID.")
    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        row = await conn.fetchrow(
            "UPDATE rfi_requests SET status = 'CANCELLED' WHERE id = $1 AND tenant_id = $2::uuid AND status = 'OPEN' RETURNING case_id;",
            rfi_uuid, str(tenant_id),
        )
        if not row:
            raise HTTPException(status_code=404, detail="Open RFI not found.")
        resumed_secs = await resume_case_sla_after_rfi(conn, row["case_id"])
        try:
            from services.audit import record_audit_event_tx
            await record_audit_event_tx(
                conn=conn,
                action="CANCEL_RFI",
                actor_id=str(current_user.get("id") or current_user.get("username") or "unknown"),
                actor_username=current_user.get("username", "investigator"),
                actor_role=current_user.get("role", "L2_INVESTIGATOR"),
                resource_type="RFI",
                resource_id=rfi_id,
                tenant_id=str(tenant_id),
                details={"case_id": str(row["case_id"]), "sla_paused_seconds_added": resumed_secs},
            )
        except Exception as audit_err:
            logger.warning(f"Transactional audit write skipped in cancel_rfi: {audit_err}")
    return {"rfi_id": rfi_id, "status": "CANCELLED", "sla_paused_seconds_added": resumed_secs}


@router.get("/public/{token}")
async def get_public_rfi_prompt(
    token: str,
    response: Response,
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
) -> Dict[str, Any]:
    """
    Unauthenticated token-gated RFI metadata endpoint.
    Strictly customer-safe: NEVER leaks internal case titles, risk scores, or SAR/AML metadata.
    """
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    tenant_id, token_hash = parse_rfi_token(token)
    if not tenant_id:
        raise HTTPException(status_code=404, detail="Invalid or expired documentation link.")

    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        row = await conn.fetchrow(
            """
            SELECT status, recipient_role, prompt_message, requested_docs, expires_at, submitted_at
            FROM rfi_requests
            WHERE token_hash = $1;
            """,
            token_hash,
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
    """
    Accepts external Customer/RM RFI response + optional document upload:
      - Enforces token validity, expiry, and single-use submission (`410` on replay/expired)
      - Malware-scans uploaded document (`422` on EICAR/ClamAV hit)
      - Persists file via P0-3 EvidenceStorageBackend with SHA-256 chain of custody
      - Automatically resumes the case SLA clock and notifies the investigator
    """
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    tenant_id, token_hash = parse_rfi_token(token)
    if not tenant_id:
        raise HTTPException(status_code=404, detail="Invalid documentation request link.")

    safe_notes = sanitize_text(response_notes)

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        rfi = await conn.fetchrow(
            "SELECT * FROM rfi_requests WHERE token_hash = $1 FOR UPDATE;",
            token_hash,
        )
        if not rfi:
            raise HTTPException(status_code=404, detail="Invalid documentation request link.")

        expires = rfi["expires_at"]
        if expires and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if rfi["status"] != "OPEN" or (expires and expires < datetime.now(timezone.utc)):
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="This documentation request has expired or was already submitted.")

        evidence_ids: List[uuid.UUID] = []
        uploaded_sha256: Optional[str] = None
        uploaded_filename: Optional[str] = None
        stored_backend = None
        stored_key: Optional[str] = None

        try:
            if file is not None and file.filename:
                safe_name = _sanitize_evidence_filename(file.filename)
                ext = os.path.splitext(safe_name)[1].lower()
                mime = (file.content_type or "application/octet-stream").lower().split(";")[0].strip()
                if ext in FORBIDDEN_EXTENSIONS or mime not in ALLOWED_EVIDENCE_MIMES:
                    raise HTTPException(status_code=400, detail="Unsupported document type. Upload PDF, PNG, JPEG, TXT, or CSV.")

                raw_bytes = await file.read(MAX_EVIDENCE_BYTES + 1)
                if len(raw_bytes) > MAX_EVIDENCE_BYTES:
                    raise HTTPException(status_code=413, detail="Uploaded document exceeds the 25 MB limit.")

                is_clean, scan_detail = await scan_bytes_for_malware(raw_bytes)
                if not is_clean:
                    log_audit_event(
                        event_type="SECURITY_ALERT",
                        actor_id=f"rfi:{rfi['id']}",
                        actor_role="EXTERNAL_RFI",
                        action="MALWARE_BLOCKED_RFI_UPLOAD",
                        resource_type="RFI",
                        resource_id=str(rfi["id"]),
                        tenant_id=tenant_id,
                        details={"file_name": safe_name, "scanner": scan_detail},
                    )
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"File rejected by security scanner: {scan_detail}")

                uploaded_sha256 = hashlib.sha256(raw_bytes).hexdigest()
                uploaded_filename = safe_name
                evidence_id = uuid.uuid4()
                stored_backend = get_evidence_storage_backend()
                object_key = f"rfi_{evidence_id}_{safe_name}"
                stored_key = await stored_backend.put_object(
                    str(tenant_id),
                    object_key,
                    raw_bytes,
                    mime,
                )

                # V-02: Insert using canonical `case_evidence` production column names
                ev_id = await conn.fetchval(
                    """
                    INSERT INTO case_evidence (
                        id, case_id, tenant_id, filename, content_type, file_size,
                        storage_key, sha256_digest, storage_backend, scan_status,
                        uploaded_by_name, description
                    )
                    VALUES ($1, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    RETURNING id;
                    """,
                    evidence_id,
                    rfi["case_id"],
                    tenant_id,
                    safe_name,
                    mime,
                    len(raw_bytes),
                    stored_key,
                    uploaded_sha256,
                    getattr(stored_backend, "backend_name", "local"),
                    scan_detail or "CLEAN",
                    f"EXTERNAL_{rfi['recipient_role']}",
                    f"Submitted via External RFI Portal ({rfi['id']})",
                )
                evidence_ids.append(ev_id or evidence_id)

            await conn.execute(
                """
                UPDATE rfi_requests
                SET status = 'SUBMITTED',
                    response_notes = $1,
                    submitted_evidence_ids = $2::uuid[],
                    submitted_at = NOW()
                WHERE id = $3;
                """,
                safe_notes,
                evidence_ids,
                rfi["id"],
            )

            # Resume case SLA clock automatically & log timeline note
            paused_delta = await resume_case_sla_after_rfi(conn, rfi["case_id"])
            await conn.execute(
                """
                INSERT INTO case_notes (case_id, author_id, author_username, note)
                VALUES ($1, NULL, $2, $3);
                """,
                rfi["case_id"],
                f"EXTERNAL_{rfi['recipient_role']}",
                f"External RFI submitted (SLA resumed after +{paused_delta}s pause): {safe_notes[:500]}",
            )
            await create_notification(
                conn=conn,
                tenant_id=tenant_id,
                category="RFI_SUBMITTED",
                severity="INFO",
                recipient_role="L2_INVESTIGATOR",
                title=f"RFI Response Received ({rfi['recipient_role']})",
                body=f"Supporting documentation uploaded for Case {str(rfi['case_id'])[:8]}. Case SLA clock has automatically resumed.",
                link_url=f"/dashboard?case_id={rfi['case_id']}",
                resource_type="CASE",
                resource_id=str(rfi["case_id"]),
                dedup_hours=0,
            )

            # T-06: Record cryptographic WORM audit_log inside the RFI submission transaction
            from services.audit import record_audit_event_tx
            await record_audit_event_tx(
                conn=conn,
                action="EXTERNAL_RFI_SUBMITTED",
                actor_id=f"rfi:{rfi['id']}",
                actor_username=f"EXTERNAL_{rfi['recipient_role']}",
                actor_role="EXTERNAL_RFI",
                resource_type="CASE",
                resource_id=str(rfi["case_id"]),
                tenant_id=str(tenant_id),
                details={
                    "rfi_id": str(rfi["id"]),
                    "filename": uploaded_filename,
                    "sha256": uploaded_sha256,
                    "evidence_ids": [str(eid) for eid in evidence_ids],
                },
            )
        except HTTPException:
            if stored_backend is not None and stored_key:
                try:
                    await stored_backend.delete_object(str(tenant_id), stored_key)
                except Exception:
                    pass
            raise
        except Exception:
            if stored_backend is not None and stored_key:
                try:
                    await stored_backend.delete_object(str(tenant_id), stored_key)
                except Exception:
                    pass
            raise

    return {
        "status": "SUBMITTED",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "document_received": uploaded_filename,
        "sha256_receipt": uploaded_sha256,
        "message": "Thank you. Your response and supporting documentation have been securely received.",
    }
