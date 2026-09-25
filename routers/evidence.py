"""
Case Evidence Locker Router (Task 1.9 Audit Remediation)
========================================================
Endpoints for uploading, listing, downloading, and managing evidence documents,
screenshots, and dossiers attached to AML cases.
"""

import os
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status, Response
from pydantic import BaseModel, Field
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter
from database.postgres import get_async_db_conn
from observability.logging import log_audit_event
from observability.sanitizer import sanitize_text

router = APIRouter(prefix="/api/v1/cases/{case_id}/evidence", tags=["Case Evidence Locker"])

EVIDENCE_STORAGE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "storage", "evidence"))
os.makedirs(EVIDENCE_STORAGE_DIR, exist_ok=True)


class EvidenceMetadata(BaseModel):
    id: str
    case_id: str
    filename: str
    content_type: str
    file_size: int
    storage_key: str
    uploaded_by: Optional[str] = None
    uploaded_by_name: str
    uploaded_at: str
    description: Optional[str] = None
    tags: List[str] = []


class EvidenceCreatePayload(BaseModel):
    filename: str = Field(..., max_length=500)
    description: Optional[str] = Field(None, max_length=2000)
    tags: Optional[List[str]] = []
    content_type: Optional[str] = "application/octet-stream"


@router.get("", response_model=List[EvidenceMetadata])
async def list_case_evidence(
    case_id: str,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"]))
):
    """
    List all evidence attachments registered to an AML case.
    """
    try:
        case_uuid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case ID format")

    tenant_id = enforce_tenant_data_scope(current_user)

    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            rows = await conn.fetch(
                """
                SELECT id, case_id, filename, content_type, file_size, storage_key,
                       uploaded_by, uploaded_by_name, uploaded_at, description, tags
                FROM case_evidence
                WHERE case_id = $1
                ORDER BY uploaded_at DESC;
                """,
                case_uuid
            )
            return [
                EvidenceMetadata(
                    id=str(r["id"]),
                    case_id=str(r["case_id"]),
                    filename=r["filename"],
                    content_type=r["content_type"] or "application/octet-stream",
                    file_size=r["file_size"] or 0,
                    storage_key=r["storage_key"],
                    uploaded_by=str(r["uploaded_by"]) if r["uploaded_by"] else None,
                    uploaded_by_name=r["uploaded_by_name"],
                    uploaded_at=r["uploaded_at"].isoformat() if r["uploaded_at"] else "",
                    description=r["description"],
                    tags=list(r["tags"]) if r["tags"] else []
                )
                for r in rows
            ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query case evidence: {e}")


@router.post("", status_code=status.HTTP_201_CREATED)
async def upload_case_evidence(
    case_id: str,
    file: UploadFile = File(...),
    description: Optional[str] = Form(None),
    tags: Optional[str] = Form(""),
    current_user: dict = Depends(RoleChecker(["L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """
    Upload a document, screenshot, or audit artifact to the Case Evidence Locker.
    """
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

    # Sanitize inputs
    safe_filename = sanitize_text(file.filename or "evidence.bin")
    safe_description = sanitize_text(description or "")
    parsed_tags = [sanitize_text(t.strip()) for t in tags.split(",") if t.strip()] if tags else []

    # Store file to disk (or S3/MinIO in production)
    evidence_id = uuid.uuid4()
    storage_subfolder = os.path.join(EVIDENCE_STORAGE_DIR, str(tenant_id))
    os.makedirs(storage_subfolder, exist_ok=True)
    stored_path = os.path.join(storage_subfolder, f"{evidence_id}_{safe_filename}")

    content = await file.read()
    file_size = len(content)

    with open(stored_path, "wb") as f:
        f.write(content)

    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            await conn.execute(
                """
                INSERT INTO case_evidence (
                    id, case_id, tenant_id, filename, content_type, file_size,
                    storage_key, uploaded_by, uploaded_by_name, description, tags
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
                """,
                evidence_id, case_uuid, uuid.UUID(str(tenant_id)),
                safe_filename, file.content_type or "application/octet-stream",
                file_size, stored_path, user_uuid, username, safe_description, parsed_tags
            )

        log_audit_event(
            event_type="CASE_EVIDENCE_ATTACHED",
            actor_id=str(user_id),
            actor_role=current_user.get("role", "ANALYST"),
            action="UPLOAD_EVIDENCE",
            resource_type="CASE",
            resource_id=case_id,
            tenant_id=tenant_id,
            details={"evidence_id": str(evidence_id), "filename": safe_filename, "size": file_size}
        )

        return {
            "status": "UPLOADED",
            "evidence_id": str(evidence_id),
            "filename": safe_filename,
            "file_size": file_size,
            "uploaded_by": username
        }
    except Exception as e:
        if os.path.exists(stored_path):
            os.remove(stored_path)
        raise HTTPException(status_code=500, detail=f"Failed to record evidence: {e}")


@router.delete("/{evidence_id}")
async def delete_case_evidence(
    case_id: str,
    evidence_id: str,
    current_user: dict = Depends(RoleChecker(["L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"]))
):
    """
    Removes an evidence attachment from a case (authorized investigator/MLRO only).
    """
    try:
        case_uuid = uuid.UUID(case_id)
        ev_uuid = uuid.UUID(evidence_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    tenant_id = enforce_tenant_data_scope(current_user)

    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            row = await conn.fetchrow(
                """
                SELECT storage_key, filename FROM case_evidence
                WHERE id = $1 AND case_id = $2;
                """,
                ev_uuid, case_uuid
            )
            if not row:
                raise HTTPException(status_code=404, detail="Evidence not found")

            await conn.execute("DELETE FROM case_evidence WHERE id = $1;", ev_uuid)

            storage_key = row["storage_key"]
            if storage_key and os.path.exists(storage_key):
                try:
                    os.remove(storage_key)
                except Exception:
                    pass

        log_audit_event(
            event_type="CASE_EVIDENCE_DELETED",
            actor_id=str(current_user.get("id")),
            actor_role=current_user.get("role", "ANALYST"),
            action="DELETE_EVIDENCE",
            resource_type="CASE",
            resource_id=case_id,
            tenant_id=tenant_id,
            details={"evidence_id": evidence_id, "filename": row["filename"]}
        )

        return {"status": "DELETED", "evidence_id": evidence_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete evidence: {e}")
