"""
Core-Banking Outbound Webhooks Administration Router (P0-2)
===========================================================
Allows compliance admins / MLROs to register, test, audit, and remove
HMAC-SHA256 signed outbound webhooks for real-time payment interdiction.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl

from database.postgres import get_async_db_conn, get_async_db_read_conn
from observability.logging import log_audit_event
from observability.sanitizer import sanitize_text
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.encryption import encrypt_pii, decrypt_pii
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
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, name, url, subscribed_events, enabled, created_by, created_at, updated_at
            FROM tenant_webhooks
            ORDER BY created_at DESC;
            """
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

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        hook_id = await conn.fetchval(
            """
            INSERT INTO tenant_webhooks (
                tenant_id, name, url, signing_secret_enc, subscribed_events, enabled, created_by
            )
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
            RETURNING id;
            """,
            str(tenant_id),
            safe_name,
            safe_url,
            encrypted_secret,
            normalized_events,
            payload.enabled,
            current_user.get("username", "admin"),
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
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        deleted = await conn.fetchval(
            "DELETE FROM tenant_webhooks WHERE id = $1 AND tenant_id = $2::uuid RETURNING id;",
            hook_uuid,
            str(tenant_id),
        )
        if not deleted:
            raise HTTPException(status_code=404, detail="Webhook not found.")
        try:
            from services.audit import record_audit_event_tx
            await record_audit_event_tx(
                conn=conn,
                action="DELETE_WEBHOOK",
                actor_id=str(current_user.get("id") or current_user.get("username") or "unknown"),
                actor_username=current_user.get("username", "admin"),
                actor_role=current_user.get("role", "ADMIN"),
                resource_type="WEBHOOK",
                resource_id=webhook_id,
                tenant_id=str(tenant_id),
                details={"deleted": True},
            )
        except Exception as audit_err:
            logger.warning(f"Transactional audit write skipped in delete_webhook: {audit_err}")

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
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, event_type, status, http_status, attempts, last_error, delivered_at, created_at
            FROM webhook_deliveries
            WHERE webhook_id = $1
            ORDER BY created_at DESC
            LIMIT $2;
            """,
            hook_uuid,
            clamped,
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
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        row = await conn.fetchrow(
            "SELECT id, url, signing_secret_enc FROM tenant_webhooks WHERE id = $1;",
            hook_uuid,
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
