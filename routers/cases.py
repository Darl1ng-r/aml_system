"""
Enterprise Case Management System Router
========================================
Thin HTTP controller for case lifecycle investigation, alert correlation,
notes, optimistic concurrency, and disposition tracking.
All PostgreSQL SQL lives in `repositories/case_repo.py`.
"""

import logging
import uuid
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from database.postgres import get_async_db_conn, get_async_db_read_conn
from observability.sanitizer import sanitize_text
from repositories.case_repo import (
    CASE_NOT_FOUND,
    _case_row_etag,
    add_case_note_atomic,
    close_case_atomic,
    correlate_alerts_into_cases_repo,
    create_case_atomic,
    get_case_detail_repo,
    list_cases_repo,
    update_case_atomic,
)
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.http_cache import build_conditional_json_response
from services.idempotency import run_idempotent_operation
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

INVALID_CASE_ID = "Invalid case ID format."

router = APIRouter(prefix="/api/v1/cases", tags=["Case Management"])


class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    priority: str = Field("MEDIUM", pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    subject_account_id: Optional[str] = Field(None, max_length=64)
    alert_ids: List[str] = Field(default_factory=list, max_length=100)
    narrative: Optional[str] = Field(None, max_length=5000)

    @field_validator("alert_ids")
    @classmethod
    def validate_alert_ids_elements(cls, v: List[str]) -> List[str]:
        return [str(x).strip()[:64] for x in v]

    @field_validator("title", "narrative", mode="before")
    @classmethod
    def sanitize_strings(cls, v: Optional[str]) -> Optional[str]:
        return sanitize_text(v) if v else None


class CaseUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=200)
    priority: Optional[str] = Field(None, pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    status: Optional[str] = Field(None, pattern=r"^(OPEN|INVESTIGATING|PENDING_EDD|PENDING_SAR)$")
    assigned_to: Optional[str] = Field(None, max_length=64)
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


class CaseCorrelateRequest(BaseModel):
    alert_ids: List[str] = Field(..., min_length=1, max_length=100)
    window_days: int = Field(default=7, ge=1, le=90)


@router.post("/correlate")
async def correlate_alerts_into_cases(
    payload: CaseCorrelateRequest,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Entity-Centric Case Auto-Correlation (P1-1)."""
    for aid in payload.alert_ids:
        try:
            uuid.UUID(aid)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid alert UUID: {aid}")

    tenant_id = enforce_tenant_data_scope(current_user)
    return await correlate_alerts_into_cases_repo(
        tenant_id=str(tenant_id),
        alert_ids=payload.alert_ids,
        actor_id=current_user.get("id"),
        actor_username=current_user.get("username", "analyst"),
        window_days=payload.window_days,
        conn_factory=get_async_db_conn,
    )


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_case(
    payload: CaseCreateRequest,
    request: Request = None,
    response: Response = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)

    async def _execute_create():
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

        parsed_uuids: list[uuid.UUID] = []
        for alert_str in payload.alert_ids:
            try:
                parsed_uuids.append(uuid.UUID(alert_str))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid alert UUID format: {alert_str}")

        body = await create_case_atomic(
            tenant_id=str(tenant_id),
            title=payload.title,
            priority=payload.priority,
            subject_acc_uuid=subject_acc_uuid,
            parsed_alert_uuids=parsed_uuids,
            narrative=payload.narrative,
            user_uuid=user_uuid,
            username=current_user.get("username", "investigator"),
            conn_factory=get_async_db_conn,
        )
        case_id = body["case_id"]
        if request is None:
            if response:
                response.headers["Location"] = f"/api/v1/cases/{case_id}"
            return body
        return JSONResponse(
            content=body,
            status_code=status.HTTP_201_CREATED,
            headers={"Location": f"/api/v1/cases/{case_id}"},
        )

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope="cases:create",
        body=payload.model_dump(),
        handler=_execute_create,
        success_status_code=status.HTTP_201_CREATED,
        required=True,
    )


@router.get("")
async def list_cases(
    page: int = Query(default=1, ge=1, le=1000),
    limit: int = Query(default=50, ge=1, le=100),
    status_filter: Optional[str] = None,
    priority_filter: Optional[str] = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)
    offset = (page - 1) * limit
    return await list_cases_repo(
        tenant_id=str(tenant_id),
        limit=limit,
        offset=offset,
        status_filter=status_filter,
        priority_filter=priority_filter,
        read_conn_factory=get_async_db_read_conn,
    )


@router.get("/{id}")
async def get_case_detail(
    id: str,
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    try:
        case_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_CASE_ID)

    tenant_id = enforce_tenant_data_scope(current_user)
    payload, etag = await get_case_detail_repo(
        case_uuid=case_uuid,
        tenant_id=str(tenant_id),
        read_conn_factory=get_async_db_read_conn,
    )
    return build_conditional_json_response(request, payload, etag=etag)


@router.post("/{id}/notes")
async def add_case_note(
    id: str,
    payload: CaseNoteRequest,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    try:
        case_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_CASE_ID)

    tenant_id = enforce_tenant_data_scope(current_user)
    return await add_case_note_atomic(
        case_uuid=case_uuid,
        tenant_id=str(tenant_id),
        note=payload.note,
        current_user=current_user,
        conn_factory=get_async_db_conn,
    )


def _build_case_updates(payload: CaseUpdateRequest) -> tuple[list[str], list[Any], int]:
    updates = []
    params = []
    p_idx = 1

    if payload.title is not None:
        updates.append(f"title = ${p_idx}")
        params.append(payload.title)
        p_idx += 1
    if payload.priority is not None:
        updates.append(f"priority = ${p_idx}")
        params.append(payload.priority)
        p_idx += 1
    if payload.status is not None:
        updates.append(f"status = ${p_idx}")
        params.append(payload.status)
        p_idx += 1
    if payload.assigned_to is not None:
        try:
            assigned_uuid = uuid.UUID(payload.assigned_to) if payload.assigned_to else None
        except ValueError:
            assigned_uuid = None
        updates.append(f"assigned_to = ${p_idx}")
        params.append(assigned_uuid)
        p_idx += 1
    if payload.narrative is not None:
        updates.append(f"narrative = ${p_idx}")
        params.append(payload.narrative)
        p_idx += 1

    return updates, params, p_idx


@router.patch("/{id}")
async def update_case(
    id: str,
    payload: CaseUpdateRequest,
    request: Request = None,
    response: Response = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    try:
        case_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_CASE_ID)

    tenant_id = enforce_tenant_data_scope(current_user)
    result = await update_case_atomic(
        case_uuid=case_uuid,
        tenant_id=str(tenant_id),
        payload=payload,
        request=request,
        build_updates_fn=_build_case_updates,
        conn_factory=get_async_db_conn,
    )
    if response is not None:
        response.headers["ETag"] = result["etag"]
    return result


@router.post("/{id}/close")
async def close_case(
    id: str,
    payload: CaseCloseRequest,
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["L2_INVESTIGATOR", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
):
    try:
        case_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_CASE_ID)

    tenant_id = enforce_tenant_data_scope(current_user)

    async def _execute_close():
        return await close_case_atomic(
            case_uuid=case_uuid,
            tenant_id=str(tenant_id),
            closure_reason=payload.closure_reason,
            closing_notes=payload.closing_notes,
            current_user=current_user,
            conn_factory=get_async_db_conn,
        )

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope=f"cases:close:{case_uuid}",
        body=payload.model_dump(),
        handler=_execute_close,
        required=True,
    )
