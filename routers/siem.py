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

from services.auth import RoleChecker
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
    """Retrieves current SIEM forwarder status, buffer depth, and total dispatches."""
    return siem_service.get_status()


@router.post("/test")
async def test_siem_forwarder(
    payload: SiemTestRequest,
    current_user: dict = Depends(RoleChecker(["ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60))
):
    """Sends a synthetic test heartbeat probe to verify target SIEM connectivity."""
    target = str(payload.destination_url) if payload.destination_url else None
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
    """Updates SIEM forwarder target endpoint, token, and format."""
    try:
        validated_url = validate_siem_destination_url(str(payload.destination_url))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    siem_service.enabled = payload.enabled
    siem_service.destination_url = validated_url
    if payload.auth_token:
        siem_service.auth_token = payload.auth_token
    if payload.format:
        siem_service.format = payload.format.upper()

    return {
        "status": "UPDATED",
        "config": siem_service.get_status(),
        "updated_by": current_user["username"]
    }
