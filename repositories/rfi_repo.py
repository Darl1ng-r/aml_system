"""
External RFI Portal Repository
==============================
Encapsulates PostgreSQL persistence, `FOR UPDATE` locking, SLA clock pauses/resumes,
evidence attachment, and transactional WORM audit logging for RFI workflows.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional

from fastapi import HTTPException, status

from database.postgres import get_async_db_conn, get_async_db_read_conn
from observability.logging import log_audit_event
from services.audit import record_audit_event_tx
from services.state_machine import validate_rfi_transition

logger = logging.getLogger("aml.rfi")


async def create_case_rfi_atomic(
    *,
    case_uuid: uuid.UUID,
    tenant_id: str,
    token_hash: str,
    recipient_email: str,
    recipient_role: str,
    prompt_message: str,
    safe_docs: list[str],
    expires_at: datetime,
    current_user: Mapping[str, Any],
    pause_sla_fn: Callable[..., Any],
    conn_factory: Any = None,
) -> uuid.UUID:
    factory = conn_factory or get_async_db_conn
    case_id = str(case_uuid)

    async with factory(tenant_id=tenant_id) as conn:
        case_row = await conn.fetchrow(
            "SELECT id, subject_account_id, status FROM cases WHERE id = $1 FOR UPDATE;",
            case_uuid,
        )
        if not case_row:
            raise HTTPException(status_code=404, detail="Case not found.")
        if str(case_row.get("status") or "").upper() == "CLOSED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Deterministic state guard violation: Cannot issue RFI on a CLOSED case.",
            )

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
            recipient_email,
            recipient_role,
            prompt_message,
            safe_docs,
            expires_at,
            current_user.get("username", "investigator"),
        )
        await pause_sla_fn(conn, case_uuid)
        try:
            await record_audit_event_tx(
                conn=conn,
                action="ISSUE_RFI",
                actor_id=str(current_user.get("id") or current_user.get("username") or ""),
                actor_username=current_user.get("username", "investigator"),
                actor_role=current_user.get("role", "ANALYST"),
                resource_type="CASE",
                resource_id=case_id,
                tenant_id=str(tenant_id),
                details={
                    "rfi_id": str(rfi_id),
                    "recipient_role": recipient_role,
                    "expires_at": expires_at.isoformat(),
                },
            )
        except Exception as audit_err:
            logger.warning("Transactional audit write skipped in create_case_rfi: %s", audit_err)
    return rfi_id


async def list_case_rfis_repo(
    *,
    case_uuid: uuid.UUID,
    tenant_id: str,
    read_conn_factory: Any = None,
) -> list[Any]:
    factory = read_conn_factory or get_async_db_read_conn
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetch(
            """
            SELECT id, case_id, recipient_email, recipient_role, prompt_message, requested_docs,
                   status, response_notes, submitted_evidence_ids, expires_at, submitted_at, created_by, created_at
            FROM rfi_requests
            WHERE case_id = $1
            ORDER BY created_at DESC;
            """,
            case_uuid,
        )


async def cancel_rfi_atomic(
    *,
    rfi_uuid: uuid.UUID,
    tenant_id: str,
    current_user: Mapping[str, Any],
    resume_sla_fn: Callable[..., Any],
    conn_factory: Any = None,
) -> int:
    factory = conn_factory or get_async_db_conn
    rfi_id = str(rfi_uuid)

    async with factory(tenant_id=tenant_id) as conn:
        existing = await conn.fetchrow(
            "SELECT id, case_id, status FROM rfi_requests WHERE id = $1 AND tenant_id = $2::uuid FOR UPDATE;",
            rfi_uuid,
            str(tenant_id),
        )
        if not existing:
            raise HTTPException(status_code=404, detail="Open RFI not found.")
        validate_rfi_transition(str(existing["status"]), "CANCELLED")
        await conn.execute(
            "UPDATE rfi_requests SET status = 'CANCELLED' WHERE id = $1 AND tenant_id = $2::uuid;",
            rfi_uuid,
            str(tenant_id),
        )
        resumed_secs = await resume_sla_fn(conn, existing["case_id"])
        try:
            await record_audit_event_tx(
                conn=conn,
                action="CANCEL_RFI",
                actor_id=str(current_user.get("id") or current_user.get("username") or "unknown"),
                actor_username=current_user.get("username", "investigator"),
                actor_role=current_user.get("role", "L2_INVESTIGATOR"),
                resource_type="RFI",
                resource_id=rfi_id,
                tenant_id=str(tenant_id),
                details={"case_id": str(existing["case_id"]), "sla_paused_seconds_added": resumed_secs},
            )
        except Exception as audit_err:
            logger.warning("Transactional audit write skipped in cancel_rfi: %s", audit_err)
    return resumed_secs


async def fetch_public_rfi_by_token_hash_repo(
    *,
    tenant_id: str,
    token_hash: str,
    read_conn_factory: Any = None,
) -> Any:
    factory = read_conn_factory or get_async_db_read_conn
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetchrow(
            """
            SELECT status, recipient_role, prompt_message, requested_docs, expires_at, submitted_at
            FROM rfi_requests
            WHERE token_hash = $1;
            """,
            token_hash,
        )


async def submit_public_rfi_atomic(
    *,
    tenant_id: str,
    token_hash: str,
    safe_notes: str,
    file: Any,
    sanitize_filename_fn: Callable[[str], str],
    allowed_mimes: Any,
    forbidden_extensions: Any,
    max_evidence_bytes: int,
    scan_fn: Callable[..., Any],
    storage_factory: Callable[[], Any],
    resume_sla_fn: Callable[..., Any],
    notify_fn: Callable[..., Any],
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = conn_factory or get_async_db_conn

    async with factory(tenant_id=tenant_id) as conn:
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
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="This documentation request has expired or was already submitted.",
            )

        evidence_ids: list[uuid.UUID] = []
        uploaded_sha256: Optional[str] = None
        uploaded_filename: Optional[str] = None
        stored_backend = None
        stored_key: Optional[str] = None

        try:
            if file is not None and file.filename:
                safe_name = sanitize_filename_fn(file.filename)
                ext = os.path.splitext(safe_name)[1].lower()
                mime = (file.content_type or "application/octet-stream").lower().split(";")[0].strip()
                if ext in forbidden_extensions or mime not in allowed_mimes:
                    raise HTTPException(
                        status_code=400,
                        detail="Unsupported document type. Upload PDF, PNG, JPEG, TXT, or CSV.",
                    )

                buf = bytearray()
                while True:
                    chunk = await file.read(65536)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    if len(buf) > max_evidence_bytes:
                        raise HTTPException(
                            status_code=413,
                            detail="Uploaded document exceeds the 25 MB limit.",
                        )
                raw_bytes = bytes(buf)

                is_clean, scan_detail = await scan_fn(raw_bytes)
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
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail="Uploaded document did not pass automated security screening.",
                    )

                uploaded_sha256 = hashlib.sha256(raw_bytes).hexdigest()
                uploaded_filename = safe_name
                evidence_id = uuid.uuid4()
                stored_backend = storage_factory()
                object_key = f"rfi_{evidence_id}_{safe_name}"
                stored_key = await stored_backend.put_object(
                    str(tenant_id),
                    object_key,
                    raw_bytes,
                    mime,
                )

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

            paused_delta = await resume_sla_fn(conn, rfi["case_id"])
            await conn.execute(
                """
                INSERT INTO case_notes (case_id, author_id, author_username, note)
                VALUES ($1, NULL, $2, $3);
                """,
                rfi["case_id"],
                f"EXTERNAL_{rfi['recipient_role']}",
                f"External RFI submitted (SLA resumed after +{paused_delta}s pause): {safe_notes[:500]}",
            )
            await notify_fn(
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
