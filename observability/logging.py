"""
Structured JSON Logging
========================
Replaces the default plaintext formatter with a JSON formatter suitable for
SIEM / ELK ingestion.  Every log line includes:

  - timestamp (ISO 8601)
  - level
  - logger name
  - message
  - correlation_id  (from CorrelationIdMiddleware)
  - trace_id / span_id  (from OpenTelemetry, when available)
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict

from observability.middleware import correlation_id_var, tenant_id_var, user_id_var


class JsonFormatter(logging.Formatter):
    """
    Structured JSON log formatter for compliance SIEM / ELK ingestion.
    Converts log records into standardized, audit-grade single-line JSON objects.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_payload: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": getattr(record, "correlation_id", correlation_id_var.get("")),
            "trace_id": getattr(record, "trace_id", ""),
            "span_id": getattr(record, "span_id", ""),
            "tenant_id": getattr(record, "tenant_id", tenant_id_var.get("")),
            "user_id": getattr(record, "user_id", user_id_var.get("")),
        }

        # Include exception traceback if present
        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        # Include audit event structured data if marked
        if getattr(record, "audit_event", False):
            log_payload["audit_event"] = True
            log_payload["event_type"] = getattr(record, "event_type", "AUDIT")
            log_payload["actor"] = {
                "id": getattr(record, "actor_id", getattr(record, "user_id", "")),
                "role": getattr(record, "actor_role", "")
            }
            log_payload["action"] = getattr(record, "action", "")
            log_payload["resource"] = {
                "type": getattr(record, "resource_type", ""),
                "id": getattr(record, "resource_id", "")
            }

        # Collect extra parameters passed during logger calls
        custom_extras = {}
        for k, v in record.__dict__.items():
            if k not in (
                "args", "asctime", "created", "exc_info", "exc_text", "filename",
                "funcName", "levelname", "levelno", "lineno", "module", "msecs",
                "message", "msg", "name", "pathname", "process", "processName",
                "relativeCreated", "stack_info", "thread", "threadName",
                "correlation_id", "trace_id", "span_id", "tenant_id", "user_id",
                "audit_event", "event_type", "actor_id", "actor_role", "action",
                "resource_type", "resource_id", "details"
            ):
                try:
                    json.dumps(v)
                    custom_extras[k] = v
                except (TypeError, OverflowError):
                    custom_extras[k] = str(v)

        details = getattr(record, "details", None)
        if details:
            custom_extras["details"] = details

        if custom_extras:
            log_payload["extra"] = custom_extras

        return json.dumps(log_payload)


class _CorrelationFilter(logging.Filter):
    """Injects correlation_id, tenant_id, user_id, and OTel trace/span IDs into every LogRecord."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "correlation_id") or not record.correlation_id:
            record.correlation_id = correlation_id_var.get("")
        if not hasattr(record, "tenant_id") or not record.tenant_id:
            record.tenant_id = tenant_id_var.get("")
        if not hasattr(record, "user_id") or not record.user_id:
            record.user_id = user_id_var.get("")

        # Attach OTel trace/span IDs when available
        try:
            from opentelemetry import trace

            span = trace.get_current_span()
            ctx = span.get_span_context()
            if ctx and ctx.trace_id:
                record.trace_id = format(ctx.trace_id, "032x")
                record.span_id = format(ctx.span_id, "016x")
            else:
                record.trace_id = ""
                record.span_id = ""
        except Exception:
            record.trace_id = ""
            record.span_id = ""

        return True


def setup_json_logging(level: int = logging.INFO) -> None:
    """
    Configures the root logger and web framework loggers with JSON output.

    Call once at application startup — before any other logger is used.
    """
    root = logging.getLogger()
    root.setLevel(level)

    # Remove any pre-existing handlers
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(_CorrelationFilter())

    root.addHandler(handler)

    # Route uvicorn and fastapi loggers to root handlers for 100% structured JSON logs
    for uvi_name in ("uvicorn", "uvicorn.access", "uvicorn.error", "fastapi"):
        uvi_logger = logging.getLogger(uvi_name)
        uvi_logger.handlers.clear()
        uvi_logger.propagate = True

    # Suppress overly chatty third-party loggers
    for noisy in ("asyncio", "aiokafka", "neo4j", "elasticsearch", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def log_audit_event(
    event_type: str,
    actor_id: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str,
    tenant_id: str | None = None,
    details: dict | None = None
) -> None:
    """
    Emits an immutable audit-grade structured JSON log entry for SIEM compliance ingestion.
    """
    audit_logger = logging.getLogger("aml.audit")
    msg = f"AUDIT_EVENT [{event_type}] actor={actor_id} action={action} resource={resource_type}:{resource_id}"
    extra = {
        "audit_event": True,
        "event_type": event_type,
        "actor_id": actor_id,
        "actor_role": actor_role,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "tenant_id": tenant_id or "",
        "user_id": actor_id,
        "details": details or {}
    }
    audit_logger.info(msg, extra=extra)

