"""
Enterprise Case Management System Router
========================================
Implements complete case lifecycle investigation, evidence gathering,
alert aggregation, and disposition tracking (GAP-1).
"""

import logging
import uuid
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field, field_validator

from database.postgres import get_async_db_conn, get_async_db_read_conn
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter
from observability.sanitizer import sanitize_text

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cases", tags=["Case Management"])


class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    priority: str = Field("MEDIUM", pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    subject_account_id: Optional[str] = None
    alert_ids: List[str] = Field(default_factory=list)
    narrative: Optional[str] = Field(None, max_length=5000)

    @field_validator("title", "narrative", mode="before")
    @classmethod
    def sanitize_strings(cls, v: Optional[str]) -> Optional[str]:
        return sanitize_text(v) if v else None


class CaseUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=200)
    priority: Optional[str] = Field(None, pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    status: Optional[str] = Field(None, pattern=r"^(OPEN|INVESTIGATING|PENDING_EDD|PENDING_SAR|CLOSED)$")
    assigned_to: Optional[str] = None
    narrative: Optional[str] = Field(None, max_length=5000)

    @field_validator("title", "narrative", mode="before")
    @classmethod
    def sanitize_strings(cls, v: Optional[str]) -> Optional[str]:
        return sanitize_text(v) if v else None


class CaseNoteRequest(BaseModel):
    note: str = Field(..., min_length=2, max_length=2000)

    @field_validator("note", mode="before")
    @classmethod
    def sanitize_note(cls, v: str) -> str:
        return sanitize_text(v)


class CaseCloseRequest(BaseModel):
    closure_reason: str = Field(..., pattern=r"^(FALSE_POSITIVE|SAR_FILED|LAW_ENFORCEMENT_REFERRAL|CLOSED_CLEARED)$")
    closing_notes: str = Field(..., min_length=3, max_length=2000)

    @field_validator("closing_notes", mode="before")
    @classmethod
    def sanitize_notes(cls, v: str) -> str:
        return sanitize_text(v)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_case(
    payload: CaseCreateRequest,
    response: Response = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    tenant_id = enforce_tenant_data_scope(current_user)
    tenant_uuid = uuid.UUID(str(tenant_id))
    case_number = f"CASE-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:6].upper()}"

    subject_acc_uuid = None
    if payload.subject_account_id:
        try:
            subject_acc_uuid = uuid.UUID(payload.subject_account_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid subject_account_id format.")

    user_uuid = None
    if current_user.get("id"):
        try:
            user_uuid = uuid.UUID(str(current_user["id"]))
        except ValueError:
            user_uuid = None

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        case_id = await conn.fetchval(
            """
            INSERT INTO cases (
                tenant_id, case_number, title, priority, assigned_to, assigned_username,
                subject_account_id, narrative, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'OPEN')
            RETURNING id;
            """,
            tenant_uuid, case_number, payload.title, payload.priority,
            user_uuid, current_user.get("username", "investigator"),
            subject_acc_uuid, payload.narrative
        )

        # Link any associated alert IDs
        for alert_str in payload.alert_ids:
            try:
                alert_uuid = uuid.UUID(alert_str)
                await conn.execute(
                    """
                    INSERT INTO case_alerts (case_id, alert_id)
                    VALUES ($1, $2)
                    ON CONFLICT DO NOTHING;
                    """,
                    case_id, alert_uuid
                )
            except ValueError:
                pass

        if response:
            response.headers["Location"] = f"/api/v1/cases/{case_id}"

        return {
            "case_id": str(case_id),
            "case_number": case_number,
            "title": payload.title,
            "status": "OPEN",
            "priority": payload.priority,
            "alert_count": len(payload.alert_ids)
        }


@router.get("")
async def list_cases(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=100),
    status_filter: Optional[str] = None,
    priority_filter: Optional[str] = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    tenant_id = enforce_tenant_data_scope(current_user)
    tenant_uuid = uuid.UUID(str(tenant_id))
    offset = (page - 1) * limit

    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        where_clauses = ["tenant_id = $1"]
        params = [tenant_uuid]
        p_idx = 2

        if status_filter and status_filter.upper() != "ALL":
            where_clauses.append(f"status = ${p_idx}")
            params.append(status_filter.upper())
            p_idx += 1

        if priority_filter and priority_filter.upper() != "ALL":
            where_clauses.append(f"priority = ${p_idx}")
            params.append(priority_filter.upper())
            p_idx += 1

        where_sql = " AND ".join(where_clauses)
        params_page = params + [limit, offset]

        rows = await conn.fetch(
            f"""
            SELECT c.*, 
                   (SELECT COUNT(*) FROM case_alerts ca WHERE ca.case_id = c.id) AS alert_count
            FROM cases c
            WHERE {where_sql}
            ORDER BY c.created_at DESC
            LIMIT ${p_idx} OFFSET ${p_idx + 1};
            """,
            *params_page
        )

        return [
            {
                "case_id": str(r["id"]),
                "case_number": r["case_number"],
                "title": r["title"],
                "status": r["status"],
                "priority": r["priority"],
                "assigned_username": r["assigned_username"],
                "alert_count": int(r["alert_count"] or 0),
                "created_at": r["created_at"].isoformat() if r["created_at"] else None
            }
            for r in rows
        ]


@router.get("/{id}")
async def get_case_detail(
    id: str,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    try:
        case_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        case_row = await conn.fetchrow(
            "SELECT * FROM cases WHERE id = $1 AND tenant_id = $2;",
            case_uuid, uuid.UUID(str(tenant_id))
        )
        if not case_row:
            raise HTTPException(status_code=404, detail="Case not found.")

        # Fetch linked alerts
        alert_rows = await conn.fetch(
            """
            SELECT a.id, a.rule_name, a.threat_level, a.ai_risk_score, a.status, a.created_at
            FROM case_alerts ca
            JOIN alerts a ON ca.alert_id = a.id
            WHERE ca.case_id = $1;
            """,
            case_uuid
        )

        # Fetch timeline notes
        note_rows = await conn.fetch(
            "SELECT id, author_username, note, created_at FROM case_notes WHERE case_id = $1 ORDER BY created_at ASC;",
            case_uuid
        )

        return {
            "case_id": str(case_row["id"]),
            "case_number": case_row["case_number"],
            "title": case_row["title"],
            "status": case_row["status"],
            "priority": case_row["priority"],
            "assigned_username": case_row["assigned_username"],
            "subject_account_id": str(case_row["subject_account_id"]) if case_row["subject_account_id"] else None,
            "narrative": case_row["narrative"],
            "closure_reason": case_row["closure_reason"],
            "created_at": case_row["created_at"].isoformat() if case_row["created_at"] else None,
            "alerts": [
                {
                    "alert_id": str(a["id"]),
                    "rule_name": a["rule_name"],
                    "threat_level": a["threat_level"],
                    "ai_risk_score": float(a["ai_risk_score"] or 0.0),
                    "status": a["status"]
                }
                for a in alert_rows
            ],
            "notes": [
                {
                    "id": str(n["id"]),
                    "author": n["author_username"],
                    "note": n["note"],
                    "created_at": n["created_at"].isoformat() if n["created_at"] else None
                }
                for n in note_rows
            ]
        }


@router.post("/{id}/notes")
async def add_case_note(
    id: str,
    payload: CaseNoteRequest,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    try:
        case_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        case_exists = await conn.fetchval(
            "SELECT 1 FROM cases WHERE id = $1 AND tenant_id = $2;",
            case_uuid, uuid.UUID(str(tenant_id))
        )
        if not case_exists:
            raise HTTPException(status_code=404, detail="Case not found.")

        note_id = await conn.fetchval(
            """
            INSERT INTO case_notes (case_id, author_id, author_username, note)
            VALUES ($1, $2, $3, $4)
            RETURNING id;
            """,
            case_uuid,
            uuid.UUID(str(current_user["id"])) if current_user.get("id") else None,
            current_user.get("username", "investigator"),
            payload.note
        )

        return {
            "note_id": str(note_id),
            "message": "Investigation note added successfully."
        }


@router.post("/{id}/close")
async def close_case(
    id: str,
    payload: CaseCloseRequest,
    current_user: dict = Depends(RoleChecker(["L2_INVESTIGATOR", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60))
):
    try:
        case_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        case_row = await conn.fetchrow(
            "SELECT * FROM cases WHERE id = $1 AND tenant_id = $2;",
            case_uuid, uuid.UUID(str(tenant_id))
        )
        if not case_row:
            raise HTTPException(status_code=404, detail="Case not found.")

        await conn.execute(
            """
            UPDATE cases
            SET status = 'CLOSED',
                closure_reason = $1,
                closed_at = NOW(),
                updated_at = NOW()
            WHERE id = $2;
            """,
            payload.closure_reason, case_uuid
        )

        # Add closure note to timeline
        await conn.execute(
            """
            INSERT INTO case_notes (case_id, author_id, author_username, note)
            VALUES ($1, $2, $3, $4);
            """,
            case_uuid,
            uuid.UUID(str(current_user["id"])) if current_user.get("id") else None,
            current_user.get("username", "investigator"),
            f"Case closed with disposition '{payload.closure_reason}': {payload.closing_notes}"
        )

        return {
            "case_id": str(case_uuid),
            "status": "CLOSED",
            "closure_reason": payload.closure_reason,
            "message": f"Case closed successfully with status '{payload.closure_reason}'."
        }
