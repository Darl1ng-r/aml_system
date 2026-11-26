"""
In-App Notifications & SLA Escalation Router (P1-4)
====================================================
Thin HTTP controller for tenant-scoped notifications and SLA sweeps.
All PostgreSQL SQL lives in `repositories/ops_repo.py`.
"""

import logging
import uuid
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from database.postgres import get_async_db_conn, get_async_db_read_conn
from repositories.ops_repo import (
    list_notifications_repo,
    mark_all_notifications_read_repo,
    mark_notification_read_repo,
    trigger_sla_sweep_repo,
)
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.http_cache import build_conditional_json_response
from services.notifications import run_sla_escalation_sweep
from services.rate_limiter import RateLimiter

logger = logging.getLogger("aml.notifications")

router = APIRouter(prefix="/api/v1/notifications", tags=["Notifications & SLA Escalations"])


def _parse_user_uuid(current_user: dict) -> uuid.UUID | None:
    user_id = current_user.get("id") or current_user.get("sub")
    if not user_id:
        return None
    try:
        return uuid.UUID(str(user_id))
    except ValueError:
        return None


@router.get("")
async def list_notifications(
    request: Request = None,
    unread_only: bool = Query(default=False),
    limit: int = Query(default=30, ge=1, le=100),
    current_user: dict = Depends(
        RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR", "SUPER_ADMIN"])
    ),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
) -> Any:
    """Returns tenant-scoped in-app notifications visible to the current user or their role."""
    tenant_id = enforce_tenant_data_scope(current_user)
    user_role = str(current_user.get("role") or "L1_ANALYST").upper()
    user_uuid = _parse_user_uuid(current_user)

    rows, unread_count = await list_notifications_repo(
        tenant_id=str(tenant_id),
        user_uuid=user_uuid,
        user_role=user_role,
        unread_only=unread_only,
        limit=limit,
        read_conn_factory=get_async_db_read_conn,
    )

    payload = {
        "unread_count": unread_count,
        "items": [
            {
                "id": str(r["id"]),
                "category": r["category"],
                "severity": r["severity"],
                "title": r["title"],
                "body": r["body"],
                "link_url": r["link_url"],
                "resource_type": r["resource_type"],
                "resource_id": r["resource_id"],
                "is_read": bool(r["is_read"]),
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ],
    }
    return build_conditional_json_response(request, payload)


@router.patch("/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    current_user: dict = Depends(
        RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR", "SUPER_ADMIN"])
    ),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
) -> Dict[str, Any]:
    try:
        nid = uuid.UUID(notification_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid notification ID.")

    tenant_id = enforce_tenant_data_scope(current_user)
    user_role = str(current_user.get("role") or "").upper()
    user_uuid = _parse_user_uuid(current_user)

    updated = await mark_notification_read_repo(
        nid=nid,
        tenant_id=str(tenant_id),
        user_uuid=user_uuid,
        user_role=user_role,
        conn_factory=get_async_db_conn,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Notification not found.")
    return {"id": notification_id, "is_read": True}


@router.post("/read-all")
async def mark_all_notifications_read(
    current_user: dict = Depends(
        RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR", "SUPER_ADMIN"])
    ),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
) -> Dict[str, Any]:
    tenant_id = enforce_tenant_data_scope(current_user)
    user_role = str(current_user.get("role") or "L1_ANALYST").upper()
    user_uuid = _parse_user_uuid(current_user)

    await mark_all_notifications_read_repo(
        tenant_id=str(tenant_id),
        user_uuid=user_uuid,
        user_role=user_role,
        conn_factory=get_async_db_conn,
    )
    return {"status": "ALL_READ"}


@router.post("/check-sla")
async def trigger_sla_check(
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=15, window=60)),
) -> Dict[str, Any]:
    """Executes an on-demand SLA breach & 30-day SAR statutory deadline escalation sweep."""
    tenant_id = enforce_tenant_data_scope(current_user)
    return await trigger_sla_sweep_repo(
        tenant_id=str(tenant_id),
        sweep_fn=run_sla_escalation_sweep,
        conn_factory=get_async_db_conn,
    )
