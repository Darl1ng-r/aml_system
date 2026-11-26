"""
Prometheus Metrics Registry and Exposition (Official prometheus-client)
======================================================================
Provides standard Prometheus metrics tracking for compliance, SLOs, and alerting:
- http_requests_total{method, endpoint, status}
- http_request_duration_seconds_bucket{endpoint, le}
- audit_events_total{event_type}
- transactions_ingested_total{decision, channel}
- transactions_scored_total{threat_level}
- rules_triggered_total{rule_name}
- outbox_pending_events
- asyncio_event_loop_lag_seconds / asyncio_event_loop_lag_current_seconds
- logic_rule_evaluation_duration_seconds
- logic_ml_inference_duration_seconds{model, status}
- logic_rule_degraded_total{rule_name}
- logic_idempotency_conflicts_total{layer, outcome}
- compute_executor_active_tasks{pool}

Supports shared-memory multi-process mode via PROMETHEUS_MULTIPROC_DIR.
"""

import os
from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    CollectorRegistry,
    generate_latest,
    multiprocess,
    REGISTRY,
)

DURATION_BUCKETS = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
LAG_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0)
FAST_LOGIC_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)

_is_multiproc = "PROMETHEUS_MULTIPROC_DIR" in os.environ

if _is_multiproc:
    # P0-01: Ensure multiproc dir exists even when K8s mounts fresh emptyDir over /tmp
    _multiproc_dir = os.environ["PROMETHEUS_MULTIPROC_DIR"]
    os.makedirs(_multiproc_dir, exist_ok=True)
    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)
else:
    registry = REGISTRY


def _get_or_create_counter(name: str, documentation: str, labelnames: list[str] | None = None):
    try:
        return Counter(name, documentation, labelnames or [])
    except ValueError:
        return REGISTRY._names_to_collectors.get(name)


def _get_or_create_histogram(
    name: str,
    documentation: str,
    labelnames: list[str] | None = None,
    buckets=DURATION_BUCKETS,
):
    try:
        return Histogram(name, documentation, labelnames or [], buckets=buckets)
    except ValueError:
        return REGISTRY._names_to_collectors.get(name)


def _get_or_create_gauge(name: str, documentation: str, labelnames: list[str] | None = None):
    try:
        return Gauge(name, documentation, labelnames or [])
    except ValueError:
        return REGISTRY._names_to_collectors.get(name)


http_requests_total = _get_or_create_counter(
    "http_requests_total",
    "Total number of HTTP requests processed.",
    ["method", "endpoint", "status"],
)

http_request_duration_seconds = _get_or_create_histogram(
    "http_request_duration_seconds",
    "HTTP request latency histogram in seconds.",
    ["endpoint"],
    buckets=DURATION_BUCKETS,
)

audit_events_total = _get_or_create_counter(
    "audit_events_total",
    "Total security and compliance audit events emitted.",
    ["event_type"],
)

transactions_ingested_total = _get_or_create_counter(
    "transactions_ingested_total",
    "Total financial transactions ingested by decision and channel.",
    ["decision", "channel"],
)

transactions_scored_total = _get_or_create_counter(
    "transactions_scored_total",
    "Total transactions scored by final compliance threat level.",
    ["threat_level"],
)

rules_triggered_total = _get_or_create_counter(
    "rules_triggered_total",
    "Total AML detection rule triggers by rule identifier.",
    ["rule_name"],
)

outbox_pending_events = _get_or_create_gauge(
    "outbox_pending_events",
    "Current count of pending/processing events in the transactional outbox.",
)

# ── Logic Pillar Runtime, Compute & Reliability SLIs ──────────────────────────

asyncio_event_loop_lag_seconds = _get_or_create_histogram(
    "asyncio_event_loop_lag_seconds",
    "Observed asyncio event loop scheduling lag in seconds.",
    buckets=LAG_BUCKETS,
)

asyncio_event_loop_lag_current_seconds = _get_or_create_gauge(
    "asyncio_event_loop_lag_current_seconds",
    "Most recent observed asyncio event loop scheduling lag in seconds.",
)

logic_rule_evaluation_duration_seconds = _get_or_create_histogram(
    "logic_rule_evaluation_duration_seconds",
    "End-to-end AML rules evaluation duration in seconds.",
    buckets=FAST_LOGIC_BUCKETS,
)

logic_ml_inference_duration_seconds = _get_or_create_histogram(
    "logic_ml_inference_duration_seconds",
    "ML risk inference duration in seconds by model and outcome status.",
    ["model", "status"],
    buckets=FAST_LOGIC_BUCKETS,
)

logic_rule_degraded_total = _get_or_create_counter(
    "logic_rule_degraded_total",
    "Total degraded AML rule evaluations caused by downstream dependency failures.",
    ["rule_name"],
)

logic_idempotency_conflicts_total = _get_or_create_counter(
    "logic_idempotency_conflicts_total",
    "Total idempotency cache hits, conflicts, mismatches, and L2 PostgreSQL fallbacks.",
    ["layer", "outcome"],
)

compute_executor_active_tasks = _get_or_create_gauge(
    "compute_executor_active_tasks",
    "Current active tasks executing in bounded bulkhead compute executors.",
    ["pool"],
)


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


def record_transaction_ingested(decision: str = "APPROVED", channel: str = "Wire"):
    if transactions_ingested_total:
        transactions_ingested_total.labels(decision=str(decision), channel=str(channel or "Unknown")).inc()


def record_transaction_scored(threat_level: str = "NONE"):
    if transactions_scored_total:
        transactions_scored_total.labels(threat_level=str(threat_level or "NONE")).inc()


def record_rule_triggered(rule_name: str):
    if rules_triggered_total:
        rules_triggered_total.labels(rule_name=str(rule_name)).inc()


def set_outbox_pending_events(count: int):
    if outbox_pending_events:
        outbox_pending_events.set(max(0, int(count)))


def record_event_loop_lag(lag_seconds: float):
    val = max(0.0, float(lag_seconds))
    if asyncio_event_loop_lag_seconds:
        asyncio_event_loop_lag_seconds.observe(val)
    if asyncio_event_loop_lag_current_seconds:
        asyncio_event_loop_lag_current_seconds.set(val)


def record_rule_evaluation_duration(duration_seconds: float):
    if logic_rule_evaluation_duration_seconds:
        logic_rule_evaluation_duration_seconds.observe(max(0.0, float(duration_seconds)))


def record_ml_inference_duration(model: str, status: str, duration_seconds: float):
    if logic_ml_inference_duration_seconds:
        logic_ml_inference_duration_seconds.labels(model=str(model), status=str(status)).observe(
            max(0.0, float(duration_seconds))
        )


def record_rule_degraded(rule_name: str):
    if logic_rule_degraded_total:
        logic_rule_degraded_total.labels(rule_name=str(rule_name)).inc()


def record_idempotency_event(layer: str, outcome: str):
    if logic_idempotency_conflicts_total:
        logic_idempotency_conflicts_total.labels(layer=str(layer), outcome=str(outcome)).inc()


def update_executor_active_tasks(pool: str, delta: int):
    if compute_executor_active_tasks:
        gauge = compute_executor_active_tasks.labels(pool=str(pool))
        if delta > 0:
            gauge.inc(delta)
        elif delta < 0:
            gauge.dec(abs(delta))


def generate_metrics_text() -> str:
    """Renders all registered metrics into Prometheus text exposition format."""
    if "PROMETHEUS_MULTIPROC_DIR" in os.environ:
        reg = CollectorRegistry()
        multiprocess.MultiProcessCollector(reg)
        return generate_latest(reg).decode("utf-8")
    return generate_latest(REGISTRY).decode("utf-8")
