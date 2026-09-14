"""
Prometheus Metrics Registry and Exposition (Official prometheus-client)
======================================================================
Provides standard Prometheus metrics tracking for compliance, SLOs, and alerting (Finding #7):
- http_requests_total{method, endpoint, status}
- http_request_duration_seconds_bucket{endpoint, le}
- audit_events_total{event_type}

Supports shared-memory multi-process mode via PROMETHEUS_MULTIPROC_DIR.
"""

import os
from prometheus_client import (
    Counter,
    Histogram,
    CollectorRegistry,
    generate_latest,
    multiprocess,
    REGISTRY
)

DURATION_BUCKETS = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

_is_multiproc = "PROMETHEUS_MULTIPROC_DIR" in os.environ

if _is_multiproc:
    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)
else:
    registry = REGISTRY

# Use custom registry or default REGISTRY
try:
    http_requests_total = Counter(
        "http_requests_total",
        "Total number of HTTP requests processed.",
        ["method", "endpoint", "status"]
    )
except ValueError:
    http_requests_total = REGISTRY._names_to_collectors.get("http_requests_total")

try:
    http_request_duration_seconds = Histogram(
        "http_request_duration_seconds",
        "HTTP request latency histogram in seconds.",
        ["endpoint"],
        buckets=DURATION_BUCKETS
    )
except ValueError:
    http_request_duration_seconds = REGISTRY._names_to_collectors.get("http_request_duration_seconds")

try:
    audit_events_total = Counter(
        "audit_events_total",
        "Total security and compliance audit events emitted.",
        ["event_type"]
    )
except ValueError:
    audit_events_total = REGISTRY._names_to_collectors.get("audit_events_total")


def record_http_request(method: str, endpoint: str, status_code: int, duration_seconds: float):
    """Records an incoming HTTP request execution."""
    if http_requests_total:
        http_requests_total.labels(method=method, endpoint=endpoint, status=str(status_code)).inc()
    if http_request_duration_seconds:
        http_request_duration_seconds.labels(endpoint=endpoint).observe(duration_seconds)


def record_audit_event(event_type: str):
    """Records an emitted security / compliance audit event."""
    if audit_events_total:
        audit_events_total.labels(event_type=event_type).inc()


def generate_metrics_text() -> str:
    """Renders all registered metrics into Prometheus text exposition format."""
    if "PROMETHEUS_MULTIPROC_DIR" in os.environ:
        reg = CollectorRegistry()
        multiprocess.MultiProcessCollector(reg)
        return generate_latest(reg).decode("utf-8")
    return generate_latest(REGISTRY).decode("utf-8")
