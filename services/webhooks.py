"""
Outbound Signed Core-Banking Webhook Dispatcher (P0-2)
=======================================================
Delivers tamper-evident, HMAC-SHA256 signed compliance action webhooks
(ACCOUNT_FROZEN, ACCOUNT_UNFROZEN, TRANSACTION_HELD, SAR_FILED) to core
banking / payment rails via the durable transactional outbox.

Signature Format (Stripe / Standard Webhook compatible):
  Header: X-Sentinel-Timestamp: <unix_epoch_seconds>
  Header: X-Sentinel-Signature-256: sha256=<hex(HMAC_SHA256(secret, f"{ts}.{raw_body}"))>
"""

import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from database.postgres import get_async_db_conn
from database.outbox import record_outbox_event
from services.encryption import encrypt_pii, decrypt_pii
from services.siem_forwarder import validate_siem_destination_url

logger = logging.getLogger("aml.webhooks")

SUPPORTED_WEBHOOK_EVENTS = {
    "ACCOUNT_FROZEN",
    "ACCOUNT_UNFROZEN",
    "TRANSACTION_HELD",
    "SAR_FILED",
    "CTR_FILED",
    "KYC_RISK_UPGRADED",
    "SLA_ESCALATION",
}


def generate_webhook_secret() -> str:
    return f"whsec_{secrets.token_hex(24)}"


def sign_webhook_payload(secret: str, timestamp: str, raw_body: bytes) -> str:
    """Computes HMAC-SHA256 signature over '<timestamp>.<raw_body>'."""
    signed_content = f"{timestamp}.".encode("utf-8") + raw_body
    digest = hmac.new(secret.encode("utf-8"), signed_content, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_webhook_signature(secret: str, timestamp: str, raw_body: bytes, signature_header: str) -> bool:
    expected = sign_webhook_payload(secret, timestamp, raw_body)
    return hmac.compare_digest(expected, signature_header or "")


async def enqueue_webhook_event_tx(
    conn: Any,
    tenant_id: str,
    event_type: str,
    payload: Dict[str, Any],
    aggregate_id: Optional[str] = None,
) -> Optional[str]:
    """
    Atomically enqueues an outbound core-banking webhook event inside the caller's
    PostgreSQL transaction via `transactional_outbox`.
    """
    if not conn or not hasattr(conn, "execute") or not tenant_id:
        return None
    try:
        envelope = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "tenant_id": str(tenant_id),
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": payload,
        }
        return await record_outbox_event(
            conn=conn,
            aggregate_type="WEBHOOK_DISPATCH",
            aggregate_id=str(aggregate_id or envelope["event_id"]),
            event_type=event_type,
            payload=envelope,
            tenant_id=str(tenant_id),
            headers={"dispatch_target": "CORE_BANKING_WEBHOOK"},
        )
    except Exception as exc:
        logger.warning(f"Failed to enqueue webhook outbox event ({event_type}): {exc}")
        return None


async def deliver_single_webhook(
    webhook_id: str,
    tenant_id: str,
    url: str,
    secret_plain: str,
    event_type: str,
    envelope: Dict[str, Any],
    correlation_id: Optional[str] = None,
) -> tuple[bool, int | None, str | None]:
    """Validates SSRF safety, signs payload, sends HTTP POST, and records delivery row."""
    try:
        safe_url = validate_siem_destination_url(url)
    except ValueError as ssrf_err:
        err_msg = f"SSRF validation rejected webhook URL: {ssrf_err}"
        logger.warning(err_msg)
        await _record_delivery(tenant_id, webhook_id, event_type, envelope, "BLOCKED_SSRF", None, err_msg)
        return False, None, err_msg

    ts = str(int(time.time()))
    raw_body = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = sign_webhook_payload(secret_plain, ts, raw_body)

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "AML-Sentinel-Webhooks/1.0",
        "X-Sentinel-Event": event_type,
        "X-Sentinel-Timestamp": ts,
        "X-Sentinel-Signature-256": signature,
    }
    if correlation_id:
        headers["X-Correlation-ID"] = str(correlation_id)

    from services.http_client import CircuitOpenError, is_outbound_egress_allowed, request_with_resilience

    if not is_outbound_egress_allowed("webhooks"):
        logger.info("Webhook outbound egress suppressed in non-production mode (webhook=%s).", webhook_id)
        await _record_delivery(tenant_id, webhook_id, event_type, envelope, "SUPPRESSED_NON_PROD", None, None)
        return True, None, None

    http_status = None
    last_error = None
    ok = False
    try:
        resp = await request_with_resilience(
            "POST",
            safe_url,
            target=f"webhook:{webhook_id}",
            timeout=httpx.Timeout(connect=2.0, read=5.0, write=5.0, pool=2.0),
            follow_redirects=False,
            retries=0,
            content=raw_body,
            headers=headers,
        )
        http_status = resp.status_code
        ok = 200 <= resp.status_code < 300
        if not ok:
            logger.warning("Webhook %s returned HTTP %s: %s", webhook_id, resp.status_code, resp.text[:300])
            last_error = f"Upstream webhook returned HTTP {resp.status_code}"
    except CircuitOpenError:
        last_error = "Webhook endpoint circuit breaker open"
    except Exception as exc:
        logger.warning("Webhook %s delivery transport error: %s", webhook_id, exc)
        last_error = "Webhook delivery transport error"

    status_label = "DELIVERED" if ok else "FAILED"
    await _record_delivery(tenant_id, webhook_id, event_type, envelope, status_label, http_status, last_error)
    return ok, http_status, last_error


async def _record_delivery(
    tenant_id: str,
    webhook_id: str,
    event_type: str,
    envelope: Dict[str, Any],
    status_label: str,
    http_status: Optional[int],
    last_error: Optional[str],
) -> None:
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            await conn.execute(
                """
                INSERT INTO webhook_deliveries (
                    tenant_id, webhook_id, event_type, payload, status, http_status, last_error, delivered_at
                )
                VALUES ($1::uuid, $2::uuid, $3, $4::jsonb, $5, $6, $7, CASE WHEN $5 = 'DELIVERED' THEN NOW() ELSE NULL END);
                """,
                str(tenant_id),
                str(webhook_id),
                event_type,
                json.dumps(envelope),
                status_label,
                http_status,
                last_error,
            )
    except Exception as exc:
        logger.debug(f"Could not persist webhook delivery audit row: {exc}")


async def dispatch_webhook_outbox_event(event: Dict[str, Any]) -> tuple[bool, str | None]:
    """
    Called by OutboxRelayEngine for `aggregate_type == 'WEBHOOK_DISPATCH'`.
    Fans out signed HTTP POSTs to every enabled tenant webhook subscribed to `event_type`.
    Uses crash-safe `webhook_deliveries` deduplication (T-04) so partial-failure retries
    never re-deliver to subscribers that already returned HTTP 2xx.
    """
    tenant_id = event.get("tenant_id") or (event.get("payload") or {}).get("tenant_id")
    event_type = event.get("event_type", "")
    envelope = event.get("payload") or {}
    event_headers = event.get("headers") or {}
    correlation_id = event_headers.get("correlation_id")
    envelope_event_id = str(envelope.get("event_id") or "")
    if not tenant_id:
        return True, None

    already_delivered_ids: set[str] = set()
    try:
        async with get_async_db_conn(tenant_id=str(tenant_id)) as conn:
            hooks = await conn.fetch(
                """
                SELECT id, url, signing_secret_enc
                FROM tenant_webhooks
                WHERE enabled = TRUE
                  AND ($1 = ANY(subscribed_events) OR '*' = ANY(subscribed_events));
                """,
                event_type,
            )
            if hooks and envelope_event_id:
                delivered_rows = await conn.fetch(
                    """
                    SELECT DISTINCT webhook_id
                    FROM webhook_deliveries
                    WHERE tenant_id = $1::uuid
                      AND status = 'DELIVERED'
                      AND payload->>'event_id' = $2;
                    """,
                    str(tenant_id),
                    envelope_event_id,
                )
                already_delivered_ids = {str(r["webhook_id"]) for r in (delivered_rows or [])}
    except Exception as db_err:
        return False, f"Failed to load tenant webhooks: {db_err}"

    if not hooks:
        return True, None

    errors: List[str] = []
    for hook in hooks:
        hook_id_str = str(hook["id"])
        if hook_id_str in already_delivered_ids:
            logger.debug(
                "Skipping already-DELIVERED webhook %s for event_id=%s (idempotent retry guard)",
                hook_id_str,
                envelope_event_id,
            )
            continue
        try:
            secret_plain = decrypt_pii(hook["signing_secret_enc"], tenant_id=str(tenant_id)) or ""
        except Exception:
            secret_plain = ""
        ok, _, err = await deliver_single_webhook(
            webhook_id=hook_id_str,
            tenant_id=str(tenant_id),
            url=hook["url"],
            secret_plain=secret_plain,
            event_type=event_type,
            envelope=envelope,
            correlation_id=correlation_id,
        )
        if not ok and err:
            errors.append(f"{hook['id']}: {err}")

    if errors:
        return False, "; ".join(errors)
    return True, None
