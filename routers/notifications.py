"""
In-App Notifications & SLA Escalation Router (P1-4)
====================================================
Exposes tenant-scoped notification inbox endpoints for the shared topbar bell
and triggers SLA breach / 30-day BSA SAR statutory deadline sweeps.
"""

import logging
import uuid
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from database.postgres import get_async_db_conn, get_async_db_read_conn
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.http_cache import build_conditional_json_response
from services.notifications import run_sla_escalation_sweep
from services.rate_limiter import RateLimiter

logger = logging.getLogger("aml.notifications")

router = APIRouter(prefix="/api/v1/notifications", tags=["Notifications & SLA Escalations"])


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
    user_id = current_user.get("id") or current_user.get("sub")
    user_uuid = None
    if user_id:
        try:
            user_uuid = uuid.UUID(str(user_id))
        except ValueError:
            user_uuid = None

    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, category, severity, title, body, link_url,
                   resource_type, resource_id, is_read, created_at
            FROM notifications
            WHERE (recipient_user_id IS NULL OR recipient_user_id = $1)
              AND (recipient_role IS NULL OR recipient_role = $2 OR $2 IN ('ADMIN', 'SUPER_ADMIN'))
              AND ($3 = FALSE OR is_read = FALSE)
            ORDER BY created_at DESC
            LIMIT $4;
            """,
            user_uuid,
            user_role,
            unread_only,
            limit,
        )
        unread_count = await conn.fetchval(
            """
            SELECT COUNT(*)
            FROM notifications
            WHERE is_read = FALSE
              AND (recipient_user_id IS NULL OR recipient_user_id = $1)
              AND (recipient_role IS NULL OR recipient_role = $2 OR $2 IN ('ADMIN', 'SUPER_ADMIN'));
            """,
            user_uuid,
            user_role,
        )

    payload = {
        "unread_count": int(unread_count or 0),
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
            for r in (rows or [])
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
    user_id = current_user.get("id") or current_user.get("sub")
    user_uuid = None
    if user_id:
        try:
            user_uuid = uuid.UUID(str(user_id))
        except ValueError:
            user_uuid = None

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        updated = await conn.fetchval(
            """
            UPDATE notifications
            SET is_read = TRUE
            WHERE id = $1
              AND tenant_id = $4::uuid
              AND (recipient_user_id IS NULL OR recipient_user_id = $2)
              AND (recipient_role IS NULL OR recipient_role = $3 OR $3 IN ('ADMIN', 'TENANT_ADMIN', 'SUPER_ADMIN'))
            RETURNING id;
            """,
            nid,
            user_uuid,
            user_role,
            str(tenant_id),
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
    user_id = current_user.get("id") or current_user.get("sub")
    user_uuid = None
    if user_id:
        try:
            user_uuid = uuid.UUID(str(user_id))
        except ValueError:
            user_uuid = None

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        await conn.execute(
            """
            UPDATE notifications
            SET is_read = TRUE
            WHERE is_read = FALSE
              AND (recipient_user_id IS NULL OR recipient_user_id = $1)
              AND (recipient_role IS NULL OR recipient_role = $2 OR $2 IN ('ADMIN', 'SUPER_ADMIN'));
            """,
            user_uuid,
            user_role,
        )
    return {"status": "ALL_READ"}


@router.post("/check-sla")
async def trigger_sla_check(
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=15, window=60)),
) -> Dict[str, Any]:
    """Executes an on-demand SLA breach & 30-day SAR statutory deadline escalation sweep."""
    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        return await run_sla_escalation_sweep(conn=conn, tenant_id=tenant_id)
