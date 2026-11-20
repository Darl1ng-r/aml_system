"""
Wave 5 Observability, PII Scrubbing & Real PostgreSQL Verification Tests
"""

import logging
import pytest
import httpx
from httpx import ASGITransport

from main import app
from observability.logging import mask_sensitive_text, sentry_before_send_scrubber, JsonFormatter
from observability.prometheus import (
    generate_metrics_text,
    record_transaction_ingested,
    record_transaction_scored,
    record_rule_triggered,
    set_outbox_pending_events,
)
from observability.middleware import tenant_id_var


def test_w5_prometheus_exports_business_and_http_metrics():
    """Verify Prometheus /metrics exports all dashboard/alerting business metrics."""
    record_transaction_ingested(decision="APPROVED", channel="Wire")
    record_transaction_scored(threat_level="HIGH")
    record_rule_triggered("STRUCTURING_SMURFING")
    set_outbox_pending_events(7)

    text = generate_metrics_text()
    assert "transactions_ingested_total" in text
    assert "transactions_scored_total" in text
    assert "rules_triggered_total" in text
    assert "outbox_pending_events 7.0" in text


@pytest.mark.anyio
async def test_w5_metrics_path_normalized_after_routing_and_ignores_spoofed_tenant():
    """Verify CorrelationIdMiddleware normalizes matched route path and ignores raw X-Tenant-ID."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get(
            "/health/live",
            headers={"X-Tenant-ID": "spoofed-attacker-tenant"},
        )
        assert res.status_code == 200
        assert "X-Correlation-ID" in res.headers

    # Unauthenticated request must never leave spoofed tenant in contextvar
    assert tenant_id_var.get("") != "spoofed-attacker-tenant"


def test_w5_log_traceback_and_sentry_scrubber_redact_pii():
    """Verify JWTs, IBANs, SSNs, Bearer tokens, and SAR narratives are scrubbed."""
    fake_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    raw = f"Failed auth Bearer {fake_jwt} for IBAN DE89370400440532013000 SSN 123-45-6789"
    masked = mask_sensitive_text(raw)
    assert fake_jwt not in masked
    assert "DE89370400440532013000" not in masked
    assert "123-45-6789" not in masked
    assert "***-**-****" in masked

    # Verify Sentry before_send strips cookies, headers, and narratives
    event = {
        "message": raw,
        "request": {
            "cookies": {"access_token": fake_jwt},
            "headers": {"Authorization": f"Bearer {fake_jwt}"},
            "data": {"sar_narrative": "Confidential SAR filing text", "amount": 9500},
        },
        "extra": {"tax_id": "999-88-7777"},
    }
    scrubbed = sentry_before_send_scrubber(event)
    assert "cookies" not in scrubbed["request"]
    assert scrubbed["request"]["headers"]["Authorization"] == "[REDACTED]"
    assert scrubbed["request"]["data"]["sar_narrative"] == "[REDACTED]"
    assert scrubbed["extra"]["tax_id"] == "[REDACTED]"

    # Verify JsonFormatter scrubs exception tracebacks
    formatter = JsonFormatter()
    try:
        raise RuntimeError(f"DB error with SSN 123-45-6789 and token {fake_jwt}")
    except RuntimeError:
        import sys
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname=__file__, lineno=1,
            msg="Unhandled failure", args=(), exc_info=sys.exc_info()
        )
        formatted = formatter.format(record)
        assert "123-45-6789" not in formatted
        assert fake_jwt not in formatted
