import json
import logging
import sys
import pytest
from unittest.mock import patch, MagicMock
from starlette.requests import Request
from starlette.responses import Response

from observability.logging import setup_json_logging, JsonFormatter, log_audit_event
from observability.middleware import CorrelationIdMiddleware, correlation_id_var, tenant_id_var, user_id_var


def test_json_formatter_outputs_valid_json():
    """Verify JsonFormatter serializes log records into valid SIEM-ready JSON."""
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test audit message",
        args=(),
        exc_info=None
    )
    record.correlation_id = "test-corr-123"
    record.tenant_id = "tenant-abc"
    record.user_id = "user-789"

    output = formatter.format(record)
    parsed = json.loads(output)

    assert parsed["logger"] == "test_logger"
    assert parsed["level"] == "INFO"
    assert parsed["message"] == "Test audit message"
    assert parsed["correlation_id"] == "test-corr-123"
    assert parsed["tenant_id"] == "tenant-abc"
    assert parsed["user_id"] == "user-789"
    assert "timestamp" in parsed


def test_log_audit_event_emits_structured_fields(capsys):
    """Verify log_audit_event emits audit-grade JSON payload with actor, action, and resource attributes."""
    setup_json_logging(logging.INFO)

    log_audit_event(
        event_type="SAR_FILING",
        actor_id="analyst_123",
        actor_role="SENIOR_ANALYST",
        action="FILE_SAR",
        resource_type="CASE",
        resource_id="case_999",
        tenant_id="tenant_def",
        details={"sar_id": "sar_001"}
    )

    captured = capsys.readouterr()
    assert len(captured.out.strip()) > 0
    output = json.loads(captured.out.strip())

    assert output["audit_event"] is True
    assert output["event_type"] == "SAR_FILING"
    assert output["actor"]["id"] == "analyst_123"
    assert output["actor"]["role"] == "SENIOR_ANALYST"
    assert output["action"] == "FILE_SAR"
    assert output["resource"]["type"] == "CASE"
    assert output["resource"]["id"] == "case_999"
    assert output["tenant_id"] == "tenant_def"


@pytest.mark.anyio
async def test_correlation_id_middleware_sets_contextvars():
    """Verify CorrelationIdMiddleware sets correlation_id_var and tenant_id_var and returns response header."""
    middleware = CorrelationIdMiddleware(app=MagicMock())

    req_headers = [
        (b"x-correlation-id", b"custom-correlation-id-777"),
        (b"x-tenant-id", b"tenant-999")
    ]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "headers": req_headers,
    }
    request = Request(scope)

    async def dummy_call_next(req: Request) -> Response:
        assert correlation_id_var.get() == "custom-correlation-id-777"
        assert tenant_id_var.get() == "tenant-999"
        return Response("OK")

    response = await middleware.dispatch(request, dummy_call_next)
    assert response.headers["X-Correlation-ID"] == "custom-correlation-id-777"
