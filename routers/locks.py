"""
Pessimistic Resource Locking Router (Section 4.1 Audit Remediation)
===================================================================
Endpoints to acquire, inspect, heartbeat-refresh, and release pessimistic locks
on alerts and cases to prevent multi-analyst collision.
"""

import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from typing import Optional
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.locking import (
    acquire_resource_lock,
    refresh_resource_lock,
    release_resource_lock,
    get_resource_lock_status,
    DEFAULT_LOCK_TTL_SECONDS
)
from services.rate_limiter import RateLimiter

router = APIRouter(prefix="/api/v1/locks", tags=["Pessimistic Locking"])

INVALID_RESOURCE_TYPE_DETAIL = "Invalid resource_type. Must be 'ALERT' or 'CASE'."


def _validate_resource_uuid(resource_id: str) -> str:
    try:
        return str(uuid.UUID(str(resource_id)))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid resource_id UUID format.")


class LockAcquireRequest(BaseModel):
    ttl_seconds: Optional[int] = Field(DEFAULT_LOCK_TTL_SECONDS, ge=30, le=1800)


class LockRefreshRequest(BaseModel):
    lock_token: Optional[str] = None
    ttl_seconds: Optional[int] = Field(DEFAULT_LOCK_TTL_SECONDS, ge=30, le=1800)


@router.post("/{resource_type}/{resource_id}", status_code=status.HTTP_200_OK)
async def acquire_lock(
    resource_type: str,
    resource_id: str,
    payload: Optional[LockAcquireRequest] = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    """
    Acquire a pessimistic lock on an ALERT or CASE within the caller's tenant.
    Returns 200 with lease details if acquired, or 409 Conflict if held by another analyst.
    """
    res_type = resource_type.upper()
    if res_type not in ("ALERT", "CASE"):
        raise HTTPException(status_code=400, detail=INVALID_RESOURCE_TYPE_DETAIL)
    safe_resource_id = _validate_resource_uuid(resource_id)

    tenant_id = str(enforce_tenant_data_scope(current_user))
    user_id = str(current_user.get("id", ""))
    username = current_user.get("username", "Analyst")
    ttl = payload.ttl_seconds if payload and payload.ttl_seconds else DEFAULT_LOCK_TTL_SECONDS

    success, result = await acquire_resource_lock(
        resource_type=res_type,
        resource_id=safe_resource_id,
        user_id=user_id,
        username=username,
        tenant_id=tenant_id,
        ttl_seconds=ttl
    )

    if not success:
        safe_lock_info = {k: v for k, v in result.items() if k != "lock_token"}
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": f"Resource is currently locked by {safe_lock_info.get('locked_by_name', 'another user')}.",
                "lock_info": safe_lock_info
            }
        )

    return {
        "status": "ACQUIRED",
        "lock": result
    }


@router.get("/{resource_type}/{resource_id}")
async def check_lock_status(
    resource_type: str,
    resource_id: str,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    """
    Check if a resource is currently locked within the caller's tenant.
    """
    res_type = resource_type.upper()
    if res_type not in ("ALERT", "CASE"):
        raise HTTPException(status_code=400, detail=INVALID_RESOURCE_TYPE_DETAIL)
    safe_resource_id = _validate_resource_uuid(resource_id)
    tenant_id = str(enforce_tenant_data_scope(current_user))

    return await get_resource_lock_status(res_type, safe_resource_id, tenant_id=tenant_id)


@router.put("/{resource_type}/{resource_id}")
async def refresh_lock(
    resource_type: str,
    resource_id: str,
    payload: Optional[LockRefreshRequest] = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    """
    Heartbeat to extend the lease TTL on an active lock within the caller's tenant.
    """
    res_type = resource_type.upper()
    if res_type not in ("ALERT", "CASE"):
        raise HTTPException(status_code=400, detail=INVALID_RESOURCE_TYPE_DETAIL)
    safe_resource_id = _validate_resource_uuid(resource_id)
    tenant_id = str(enforce_tenant_data_scope(current_user))

    user_id = str(current_user.get("id", ""))
    ttl = payload.ttl_seconds if payload and payload.ttl_seconds else DEFAULT_LOCK_TTL_SECONDS
    lock_token = payload.lock_token if payload else None

    success, result = await refresh_resource_lock(
        resource_type=res_type,
        resource_id=safe_resource_id,
        user_id=user_id,
        lock_token=lock_token,
        ttl_seconds=ttl,
        tenant_id=tenant_id,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result.get("detail", "Failed to refresh lock lease")
        )

    return {
        "status": "REFRESHED",
        "lock": result
    }


@router.delete("/{resource_type}/{resource_id}")
async def release_lock(
    resource_type: str,
    resource_id: str,
    force: bool = Query(False, description="Force unlock even if held by another user (MLRO/ADMIN only)"),
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    """
    Explicitly release a resource lock within the caller's tenant.
    """
    res_type = resource_type.upper()
    if res_type not in ("ALERT", "CASE"):
        raise HTTPException(status_code=400, detail=INVALID_RESOURCE_TYPE_DETAIL)
    safe_resource_id = _validate_resource_uuid(resource_id)
    tenant_id = str(enforce_tenant_data_scope(current_user))

    user_id = str(current_user.get("id", ""))
    user_role = current_user.get("role", "")

    if force and user_role not in ("MLRO", "ADMIN", "SUPER_ADMIN", "TENANT_ADMIN"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Force-breaking a lock requires MLRO or ADMIN role."
        )

    success, message = await release_resource_lock(
        resource_type=res_type,
        resource_id=safe_resource_id,
        user_id=user_id,
        user_role=user_role,
        force=force,
        tenant_id=tenant_id,
    )

    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

    return {"status": "RELEASED", "message": message}
