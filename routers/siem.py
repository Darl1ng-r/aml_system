"""
SIEM Compliance Event Forwarder Router
======================================
Provides administrative controls for configuring and testing external SIEM forwarder
integrations (Splunk HEC, Logstash, Datadog, RFC 5424 Syslog).
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl

from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter
from services.siem_forwarder import siem_service, validate_siem_destination_url

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin/siem", tags=["SIEM Forwarder"])


class SiemConfigRequest(BaseModel):
    enabled: bool = True
    destination_url: HttpUrl
    auth_token: Optional[str] = None
    format: Optional[str] = "SPLUNK_HEC"


class SiemTestRequest(BaseModel):
    destination_url: Optional[HttpUrl] = None
    auth_token: Optional[str] = None


@router.get("/status")
async def get_siem_status(
    current_user: dict = Depends(RoleChecker(["ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """Retrieves persisted tenant SIEM forwarder configuration & dispatch metrics."""
    tenant_id = enforce_tenant_data_scope(current_user)
    return await siem_service.load_tenant_config(str(tenant_id))


@router.post("/test")
async def test_siem_forwarder(
    payload: SiemTestRequest,
    current_user: dict = Depends(RoleChecker(["ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60))
):
    """Sends a synthetic test heartbeat probe to verify target SIEM connectivity."""
    tenant_id = enforce_tenant_data_scope(current_user)
    target = str(payload.destination_url) if payload.destination_url else None
    if not target:
        persisted = await siem_service.load_tenant_config(str(tenant_id))
        target = persisted.get("destination_url")
    if target:
        try:
            validate_siem_destination_url(target)
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    try:
        result = await siem_service.test_connection(
            target_url=target,
            token=payload.auth_token
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return result


@router.put("/config")
async def update_siem_config(
    payload: SiemConfigRequest,
    current_user: dict = Depends(RoleChecker(["ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60))
):
    """Persists SIEM forwarder target endpoint, encrypted token, and format to PostgreSQL."""
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        saved_cfg = await siem_service.save_tenant_config(
            tenant_id=str(tenant_id),
            enabled=payload.enabled,
            destination_url=str(payload.destination_url),
            auth_token=payload.auth_token,
            fmt=payload.format or "SPLUNK_HEC",
            updated_by=current_user["username"],
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return {
        "status": "UPDATED",
        "config": saved_cfg,
        "updated_by": current_user["username"]
    }
