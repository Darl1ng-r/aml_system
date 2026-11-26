"""
Core-Banking Outbound Webhooks Administration Router (P0-2)
===========================================================
Thin HTTP controller for registering, testing, auditing, and removing
HMAC-SHA256 signed outbound webhooks.
All PostgreSQL SQL lives in `repositories/ops_repo.py`.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl

from database.postgres import get_async_db_conn, get_async_db_read_conn
from observability.logging import log_audit_event
from observability.sanitizer import sanitize_text
from repositories.ops_repo import (
    create_webhook_repo,
    delete_webhook_atomic,
    fetch_webhook_for_test_repo,
    list_webhook_deliveries_repo,
    list_webhooks_repo,
)
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.encryption import decrypt_pii, encrypt_pii
from services.rate_limiter import RateLimiter
from services.siem_forwarder import validate_siem_destination_url
from services.webhooks import (
    SUPPORTED_WEBHOOK_EVENTS,
    deliver_single_webhook,
    generate_webhook_secret,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin/webhooks", tags=["Core-Banking Webhooks"])


class WebhookCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=150)
    url: HttpUrl
    subscribed_events: List[str] = Field(
        default_factory=lambda: ["ACCOUNT_FROZEN", "ACCOUNT_UNFROZEN", "TRANSACTION_HELD", "SAR_FILED"],
        max_length=20,
    )
    enabled: bool = True


@router.get("")
async def list_webhooks(
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)
    rows = await list_webhooks_repo(
        tenant_id=str(tenant_id),
        read_conn_factory=get_async_db_read_conn,
    )
    return [
        {
            "id": str(r["id"]),
            "name": r["name"],
            "url": r["url"],
            "subscribed_events": list(r["subscribed_events"] or []),
            "enabled": bool(r["enabled"]),
            "created_by": r["created_by"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_webhook(
    payload: WebhookCreateRequest,
    current_user: dict = Depends(RoleChecker(["ADMIN", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        safe_url = validate_siem_destination_url(str(payload.url))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    normalized_events = [e.strip().upper() for e in payload.subscribed_events if e.strip()]
    invalid = [e for e in normalized_events if e != "*" and e not in SUPPORTED_WEBHOOK_EVENTS]
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported webhook event types: {invalid}. Allowed: {sorted(SUPPORTED_WEBHOOK_EVENTS)}",
        )

    signing_secret = generate_webhook_secret()
    encrypted_secret = encrypt_pii(signing_secret, tenant_id=str(tenant_id))
    safe_name = sanitize_text(payload.name)

    hook_id = await create_webhook_repo(
        tenant_id=str(tenant_id),
        safe_name=safe_name,
        safe_url=safe_url,
        encrypted_secret=encrypted_secret,
        normalized_events=normalized_events,
        enabled=payload.enabled,
        username=current_user.get("username", "admin"),
        conn_factory=get_async_db_conn,
    )

    log_audit_event(
        event_type="WEBHOOK_CREATED",
        actor_id=str(current_user.get("id", "")),
        actor_role=current_user.get("role", "ADMIN"),
        action="CREATE_WEBHOOK",
        resource_type="WEBHOOK",
        resource_id=str(hook_id),
        tenant_id=str(tenant_id),
        details={"name": safe_name, "url": safe_url, "events": normalized_events},
    )

    return {
        "id": str(hook_id),
        "name": safe_name,
        "url": safe_url,
        "subscribed_events": normalized_events,
        "enabled": payload.enabled,
        "signing_secret": signing_secret,
        "warning": "Store this signing_secret securely; it will not be shown again.",
    }


@router.delete("/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
):
    try:
        hook_uuid = uuid.UUID(webhook_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid webhook ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    await delete_webhook_atomic(
        hook_uuid=hook_uuid,
        tenant_id=str(tenant_id),
        current_user=current_user,
        conn_factory=get_async_db_conn,
    )
    return {"status": "DELETED", "id": webhook_id}


@router.get("/{webhook_id}/deliveries")
async def list_webhook_deliveries(
    webhook_id: str,
    limit: int = 50,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    try:
        hook_uuid = uuid.UUID(webhook_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid webhook ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    clamped = max(1, min(limit, 200))
    rows = await list_webhook_deliveries_repo(
        hook_uuid=hook_uuid,
        tenant_id=str(tenant_id),
        limit=clamped,
        read_conn_factory=get_async_db_read_conn,
    )
    return [
        {
            "id": str(r["id"]),
            "event_type": r["event_type"],
            "status": r["status"],
            "http_status": r["http_status"],
            "attempts": r["attempts"],
            "last_error": r["last_error"],
            "delivered_at": r["delivered_at"].isoformat() if r["delivered_at"] else None,
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]


@router.post("/{webhook_id}/test")
async def test_webhook_delivery(
    webhook_id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    try:
        hook_uuid = uuid.UUID(webhook_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid webhook ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    row = await fetch_webhook_for_test_repo(
        hook_uuid=hook_uuid,
        tenant_id=str(tenant_id),
        read_conn_factory=get_async_db_read_conn,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Webhook not found.")

    secret_plain = decrypt_pii(row["signing_secret_enc"], tenant_id=str(tenant_id)) or ""
    envelope = {
        "event_id": str(uuid.uuid4()),
        "event_type": "WEBHOOK_TEST_PROBE",
        "tenant_id": str(tenant_id),
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "data": {"message": "AML Sentinel HMAC-SHA256 signed webhook verification probe."},
    }
    ok, http_status, last_error = await deliver_single_webhook(
        webhook_id=str(row["id"]),
        tenant_id=str(tenant_id),
        url=row["url"],
        secret_plain=secret_plain,
        event_type="WEBHOOK_TEST_PROBE",
        envelope=envelope,
    )
    return {
        "delivered": ok,
        "http_status": http_status,
        "error": last_error,
        "target_url": row["url"],
    }
