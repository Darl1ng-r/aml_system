"""
Case Evidence Locker Router (Task 1.9 Audit Remediation)
========================================================
Thin HTTP controller for uploading, listing, downloading, and managing
evidence documents attached to AML cases.
All PostgreSQL SQL lives in `repositories/case_repo.py`.
"""

import logging
import os
import re
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile, status
from pydantic import BaseModel, Field

from database.postgres import get_async_db_conn
from observability.logging import log_audit_event
from observability.sanitizer import sanitize_text
from repositories.case_repo import (
    delete_case_evidence_atomic,
    fetch_case_evidence_for_download_repo,
    insert_case_evidence_atomic,
    list_case_evidence_repo,
    resolve_case_uuid_tx as _resolve_case_uuid,
)
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

DEFAULT_CONTENT_TYPE = "application/octet-stream"
MAX_EVIDENCE_BYTES = 25 * 1024 * 1024  # 25 MB hard cap
CHUNK_SIZE_BYTES = 64 * 1024  # 64 KiB streaming chunks

ALLOWED_EVIDENCE_MIMES = {
    "application/pdf",
    "image/png",
    "image/jpeg",
    "text/csv",
    "text/plain",
    "application/json",
    "application/octet-stream",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

FORBIDDEN_EXTENSIONS = {
    ".html", ".htm", ".xhtml", ".svg", ".js", ".mjs", ".cjs",
    ".php", ".jsp", ".asp", ".aspx", ".sh", ".bash", ".exe", ".bat", ".cmd",
}


def _sanitize_evidence_filename(raw_filename: str | None) -> str:
    """Strictly validates and sanitizes an uploaded filename to prevent path traversal and active content."""
    candidate = (raw_filename or "evidence.bin").strip()
    if ".." in candidate or "/" in candidate or "\\" in candidate or "\x00" in candidate:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename: path traversal characters are forbidden.",
        )
    base = os.path.basename(sanitize_text(candidate))
    clean = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")
    if not clean:
        clean = "evidence.bin"
    clean = clean[:180]
    _, ext = os.path.splitext(clean.lower())
    if ext in FORBIDDEN_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File extension '{ext}' is not permitted in the Evidence Locker.",
        )
    return clean


def _validate_content_type(content_type: str | None) -> str:
    normalized = (content_type or DEFAULT_CONTENT_TYPE).split(";")[0].strip().lower()
    if normalized not in ALLOWED_EVIDENCE_MIMES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported content type '{normalized}'. Permitted types: PDF, PNG, JPEG, CSV, TXT, JSON, DOCX, XLSX.",
        )
    return normalized


def _ensure_within_tenant_dir(tenant_dir: str, candidate_path: str) -> str:
    real_base = os.path.realpath(tenant_dir)
    real_target = os.path.realpath(candidate_path)
    if os.path.commonpath([real_base, real_target]) != real_base:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid storage path outside tenant evidence boundary.",
        )
    return real_target


def _append_file_chunk(path: str, chunk: bytes, first: bool) -> None:
    mode = "wb" if first else "ab"
    with open(path, mode) as f:
        f.write(chunk)


router = APIRouter(prefix="/api/v1/cases/{case_id}/evidence", tags=["Case Evidence Locker"])

EVIDENCE_STORAGE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "storage", "evidence"))


def _ensure_local_evidence_dir() -> str:
    """P0-01: Lazily create local evidence directory only when backend=='local'."""
    from config import settings

    if str(getattr(settings, "evidence_storage_backend", "local")).strip().lower() == "local":
        os.makedirs(EVIDENCE_STORAGE_DIR, exist_ok=True)
    return EVIDENCE_STORAGE_DIR


class EvidenceMetadata(BaseModel):
    id: str
    case_id: str
    filename: str
    content_type: str
    file_size: int
    storage_key: str
    sha256_digest: Optional[str] = None
    storage_backend: str = "local"
    scan_status: str = "CLEAN"
    uploaded_by: Optional[str] = None
    uploaded_by_name: str
    uploaded_at: str
    description: Optional[str] = None
    tags: List[str] = []


class EvidenceCreatePayload(BaseModel):
    filename: str = Field(..., max_length=500)
    description: Optional[str] = Field(None, max_length=2000)
    tags: Optional[List[str]] = []
    content_type: Optional[str] = DEFAULT_CONTENT_TYPE


@router.get("", response_model=List[EvidenceMetadata])
async def list_case_evidence(
    case_id: str,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """List all evidence attachments registered to an AML case."""
    try:
        raw_uuid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case ID format")

    tenant_id = enforce_tenant_data_scope(current_user)

    try:
        rows = await list_case_evidence_repo(
            raw_uuid=raw_uuid,
            tenant_id=str(tenant_id),
            current_user=current_user,
            conn_factory=get_async_db_conn,
        )
        return [
            EvidenceMetadata(
                id=str(r["id"]),
                case_id=str(r["case_id"]),
                filename=r["filename"],
                content_type=r["content_type"] or DEFAULT_CONTENT_TYPE,
                file_size=r["file_size"] or 0,
                storage_key=r["storage_key"],
                sha256_digest=r.get("sha256_digest") if hasattr(r, "get") else None,
                storage_backend=(r.get("storage_backend") if hasattr(r, "get") else None) or "local",
                scan_status=(r.get("scan_status") if hasattr(r, "get") else None) or "CLEAN",
                uploaded_by=str(r["uploaded_by"]) if r["uploaded_by"] else None,
                uploaded_by_name=r["uploaded_by_name"],
                uploaded_at=r["uploaded_at"].isoformat() if r["uploaded_at"] else "",
                description=r["description"],
                tags=list(r["tags"]) if r["tags"] else [],
            )
            for r in rows
        ]
    except Exception:
        logger.exception("Failed to query case evidence")
        raise HTTPException(status_code=500, detail="Failed to query case evidence.")


@router.post("", status_code=status.HTTP_201_CREATED)
async def upload_case_evidence(
    case_id: str,
    file: UploadFile = File(...),
    description: Optional[str] = Form(None, max_length=2000),
    tags: Optional[str] = Form("", max_length=500),
    current_user: dict = Depends(RoleChecker(["L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Upload a document, screenshot, or audit artifact to the Case Evidence Locker."""
    try:
        case_uuid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case ID format")

    tenant_id = enforce_tenant_data_scope(current_user)
    user_id = current_user.get("id")
    user_uuid = None
    if user_id:
        try:
            user_uuid = uuid.UUID(str(user_id))
        except (ValueError, TypeError):
            user_uuid = None
    username = current_user.get("username", "Investigator")

    safe_filename = _sanitize_evidence_filename(file.filename)
    safe_content_type = _validate_content_type(file.content_type)
    safe_description = sanitize_text(description or "")
    parsed_tags = [sanitize_text(t.strip()) for t in tags.split(",") if t.strip()] if tags else []

    from services.evidence_storage import (
        compute_sha256_hex,
        get_evidence_storage_backend,
        scan_bytes_for_malware,
    )

    evidence_id = uuid.uuid4()
    buf = bytearray()
    file_size = 0
    while True:
        chunk = await file.read(CHUNK_SIZE_BYTES)
        if not chunk:
            break
        file_size += len(chunk)
        if file_size > MAX_EVIDENCE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Evidence file exceeds maximum allowed size of {MAX_EVIDENCE_BYTES // (1024 * 1024)} MB.",
            )
        buf.extend(chunk)

    raw_bytes = bytes(buf)
    is_clean, scan_status = await scan_bytes_for_malware(raw_bytes)
    if not is_clean:
        log_audit_event(
            event_type="SECURITY_ALERT",
            actor_id=str(user_id),
            actor_role=current_user.get("role", "ANALYST"),
            action="MALWARE_UPLOAD_BLOCKED",
            resource_type="CASE",
            resource_id=case_id,
            tenant_id=tenant_id,
            details={"filename": safe_filename, "scan_status": scan_status},
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Evidence upload rejected by security malware scan.",
        )

    sha256_digest = compute_sha256_hex(raw_bytes)
    backend = get_evidence_storage_backend(_ensure_local_evidence_dir())
    object_key = f"{evidence_id}_{safe_filename}"
    try:
        stored_key = await backend.put_object(str(tenant_id), object_key, raw_bytes, safe_content_type)
    except Exception:
        logger.exception("Failed to persist evidence artifact")
        raise HTTPException(status_code=500, detail="Failed to persist evidence artifact.")

    try:
        await insert_case_evidence_atomic(
            evidence_id=evidence_id,
            raw_case_uuid=case_uuid,
            tenant_id=str(tenant_id),
            safe_filename=safe_filename,
            safe_content_type=safe_content_type,
            file_size=file_size,
            stored_key=stored_key,
            sha256_digest=sha256_digest,
            backend_name=backend.backend_name,
            scan_status=scan_status,
            user_id=user_id,
            user_uuid=user_uuid,
            username=username,
            actor_role=current_user.get("role", "ANALYST"),
            safe_description=safe_description,
            parsed_tags=parsed_tags,
            current_user=current_user,
            conn_factory=get_async_db_conn,
        )

        log_audit_event(
            event_type="CASE_EVIDENCE_ATTACHED",
            actor_id=str(user_id),
            actor_role=current_user.get("role", "ANALYST"),
            action="UPLOAD_EVIDENCE",
            resource_type="CASE",
            resource_id=case_id,
            tenant_id=tenant_id,
            details={
                "evidence_id": str(evidence_id),
                "filename": safe_filename,
                "size": file_size,
                "sha256": sha256_digest,
                "storage_backend": backend.backend_name,
            },
        )

        return {
            "status": "UPLOADED",
            "evidence_id": str(evidence_id),
            "filename": safe_filename,
            "file_size": file_size,
            "sha256_digest": sha256_digest,
            "storage_backend": backend.backend_name,
            "scan_status": scan_status,
            "uploaded_by": username,
        }
    except Exception:
        try:
            await backend.delete_object(str(tenant_id), stored_key)
        except Exception:
            pass
        logger.exception("Failed to record evidence metadata")
        raise HTTPException(status_code=500, detail="Failed to record evidence.")


@router.get("/{evidence_id}/download")
async def download_case_evidence(
    case_id: str,
    evidence_id: str,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Downloads a stored evidence attachment for an AML case."""
    try:
        raw_uuid = uuid.UUID(case_id)
        ev_uuid = uuid.UUID(evidence_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    tenant_id = enforce_tenant_data_scope(current_user)
    row = await fetch_case_evidence_for_download_repo(
        raw_uuid=raw_uuid,
        ev_uuid=ev_uuid,
        tenant_id=str(tenant_id),
        current_user=current_user,
        conn_factory=get_async_db_conn,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Evidence not found")

    from services.evidence_storage import LocalEvidenceBackend, S3EvidenceBackend, compute_sha256_hex

    storage_key = row["storage_key"]
    backend_type = (row.get("storage_backend") if hasattr(row, "get") else None) or (
        "s3" if str(storage_key).startswith("s3://") else "local"
    )
    backend = S3EvidenceBackend() if backend_type == "s3" else LocalEvidenceBackend(EVIDENCE_STORAGE_DIR)

    try:
        payload_bytes = await backend.get_object(str(tenant_id), storage_key)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Evidence file missing from storage")
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

    expected_sha = row.get("sha256_digest") if hasattr(row, "get") else None
    actual_sha = compute_sha256_hex(payload_bytes)
    if expected_sha and actual_sha != expected_sha:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Evidence integrity verification failed: SHA-256 chain-of-custody mismatch.",
        )

    safe_download_name = _sanitize_evidence_filename(row["filename"])
    stored_mime = (row["content_type"] or DEFAULT_CONTENT_TYPE).split(";")[0].strip().lower()
    safe_media_type = stored_mime if stored_mime in ALLOWED_EVIDENCE_MIMES else DEFAULT_CONTENT_TYPE

    return Response(
        content=payload_bytes,
        media_type=safe_media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{safe_download_name}"',
            "X-Content-Type-Options": "nosniff",
            "X-Evidence-SHA256": actual_sha,
        },
    )


@router.delete("/{evidence_id}")
async def delete_case_evidence(
    case_id: str,
    evidence_id: str,
    current_user: dict = Depends(RoleChecker(["L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Removes an evidence attachment from a case (authorized investigator/MLRO only)."""
    try:
        raw_uuid = uuid.UUID(case_id)
        ev_uuid = uuid.UUID(evidence_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    tenant_id = enforce_tenant_data_scope(current_user)

    try:
        result = await delete_case_evidence_atomic(
            raw_uuid=raw_uuid,
            ev_uuid=ev_uuid,
            tenant_id=str(tenant_id),
            evidence_storage_dir=EVIDENCE_STORAGE_DIR,
            current_user=current_user,
            conn_factory=get_async_db_conn,
        )

        log_audit_event(
            event_type="CASE_EVIDENCE_DELETED",
            actor_id=str(current_user.get("id")),
            actor_role=current_user.get("role", "ANALYST"),
            action="DELETE_EVIDENCE",
            resource_type="CASE",
            resource_id=case_id,
            tenant_id=tenant_id,
            details={"evidence_id": evidence_id, "filename": result["filename"]},
        )

        return {"status": "DELETED", "evidence_id": evidence_id}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to delete case evidence")
        raise HTTPException(status_code=500, detail="Failed to delete evidence.")
