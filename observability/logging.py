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

import logging
import sys

from pythonjsonlogger import jsonlogger

from observability.middleware import correlation_id_var


class _CorrelationFilter(logging.Filter):
    """Injects the current correlation_id into every LogRecord."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = correlation_id_var.get("")  # type: ignore[attr-defined]

        # Attach OTel trace/span IDs when available
        try:
            from opentelemetry import trace

            span = trace.get_current_span()
            ctx = span.get_span_context()
            if ctx and ctx.trace_id:
                record.trace_id = format(ctx.trace_id, "032x")  # type: ignore[attr-defined]
                record.span_id = format(ctx.span_id, "016x")  # type: ignore[attr-defined]
            else:
                record.trace_id = ""  # type: ignore[attr-defined]
                record.span_id = ""  # type: ignore[attr-defined]
        except ImportError:
            record.trace_id = ""  # type: ignore[attr-defined]
            record.span_id = ""  # type: ignore[attr-defined]

        return True


def setup_json_logging(level: int = logging.INFO) -> None:
    """
    Configures the root logger with JSON output.

    Call once at application startup — before any other logger is created.
    """
    root = logging.getLogger()
    root.setLevel(level)

    # Remove any pre-existing handlers (e.g. from basicConfig)
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    formatter = jsonlogger.JsonFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s "
        "%(correlation_id)s %(trace_id)s %(span_id)s",
        rename_fields={
            "asctime": "timestamp",
            "levelname": "level",
            "name": "logger",
        },
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    handler.setFormatter(formatter)
    handler.addFilter(_CorrelationFilter())

    root.addHandler(handler)

    # Suppress overly chatty third-party loggers
    for noisy in ("asyncio", "aiokafka", "neo4j", "elasticsearch", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
