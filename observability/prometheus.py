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

# ── Storage Pillar SLIs (PostgreSQL Pools, Replication, Autovacuum & Redis) ──

db_pool_acquire_duration_seconds = _get_or_create_histogram(
    "db_pool_acquire_duration_seconds",
    "Time spent acquiring a PostgreSQL connection from asyncpg pool.",
    ["pool"],
    buckets=FAST_LOGIC_BUCKETS,
)

db_pool_connections_in_use = _get_or_create_gauge(
    "db_pool_connections_in_use",
    "Active checked-out connections in the asyncpg pool.",
    ["pool"],
)

db_pool_connections_idle = _get_or_create_gauge(
    "db_pool_connections_idle",
    "Idle available connections in the asyncpg pool.",
    ["pool"],
)

db_pool_connections_max = _get_or_create_gauge(
    "db_pool_connections_max",
    "Configured maximum size of the asyncpg connection pool.",
    ["pool"],
)

db_read_routing_total = _get_or_create_counter(
    "db_read_routing_total",
    "Read query routing decisions across replica vs primary stickiness/failover.",
    ["target", "reason"],
)

pg_replication_lag_seconds = _get_or_create_gauge(
    "pg_replication_lag_seconds",
    "Observed PostgreSQL streaming replication replay lag in seconds.",
)

pg_table_dead_tuples = _get_or_create_gauge(
    "pg_table_dead_tuples",
    "Estimated dead tuple count per hot PostgreSQL table (autovacuum health).",
    ["table"],
)

pg_table_live_tuples = _get_or_create_gauge(
    "pg_table_live_tuples",
    "Estimated live tuple count per hot PostgreSQL table.",
    ["table"],
)

pg_table_dead_tuple_ratio = _get_or_create_gauge(
    "pg_table_dead_tuple_ratio",
    "Dead-to-total tuple bloat ratio per hot PostgreSQL table.",
    ["table"],
)

pg_stat_statements_mean_exec_seconds = _get_or_create_gauge(
    "pg_stat_statements_mean_exec_seconds",
    "Mean execution duration in seconds for top slow SQL query groups from pg_stat_statements.",
    ["query_group"],
)

pg_stat_statements_max_exec_seconds = _get_or_create_gauge(
    "pg_stat_statements_max_exec_seconds",
    "Max execution duration in seconds for top slow SQL query groups from pg_stat_statements.",
    ["query_group"],
)

redis_cache_hit_ratio = _get_or_create_gauge(
    "redis_cache_hit_ratio",
    "Redis keyspace hit ratio (hits / (hits + misses)) by role (state vs cache).",
    ["role"],
)

redis_evicted_keys_total = _get_or_create_gauge(
    "redis_evicted_keys_total",
    "Cumulative Redis evicted keys reported by INFO stats by role.",
    ["role"],
)

redis_mem_fragmentation_ratio = _get_or_create_gauge(
    "redis_mem_fragmentation_ratio",
    "Redis memory fragmentation ratio reported by INFO memory by role.",
    ["role"],
)

redis_used_memory_bytes = _get_or_create_gauge(
    "redis_used_memory_bytes",
    "Redis used memory in bytes reported by INFO memory by role.",
    ["role"],
)

storage_cache_operations_total = _get_or_create_counter(
    "storage_cache_operations_total",
    "Cache-aside operation outcomes by namespace (hit, miss, negative_hit, stampede_wait_hit, per_refresh, error_failopen, invalidate).",
    ["namespace", "outcome"],
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


def record_db_pool_acquire(
    pool_name: str,
    duration_seconds: float,
    *,
    in_use: int | None = None,
    idle: int | None = None,
    max_size: int | None = None,
):
    label = str(pool_name)
    if db_pool_acquire_duration_seconds:
        db_pool_acquire_duration_seconds.labels(pool=label).observe(max(0.0, float(duration_seconds)))
    if in_use is not None and db_pool_connections_in_use:
        db_pool_connections_in_use.labels(pool=label).set(max(0, int(in_use)))
    if idle is not None and db_pool_connections_idle:
        db_pool_connections_idle.labels(pool=label).set(max(0, int(idle)))
    if max_size is not None and db_pool_connections_max:
        db_pool_connections_max.labels(pool=label).set(max(0, int(max_size)))


def record_db_read_routing(target: str, reason: str):
    if db_read_routing_total:
        db_read_routing_total.labels(target=str(target), reason=str(reason)).inc()


def set_pg_replication_lag(lag_seconds: float):
    if pg_replication_lag_seconds:
        pg_replication_lag_seconds.set(max(0.0, float(lag_seconds)))


def set_pg_table_bloat(table: str, live_tuples: int, dead_tuples: int):
    tbl = str(table)
    live = max(0, int(live_tuples))
    dead = max(0, int(dead_tuples))
    total = live + dead
    ratio = (dead / total) if total > 0 else 0.0
    if pg_table_live_tuples:
        pg_table_live_tuples.labels(table=tbl).set(live)
    if pg_table_dead_tuples:
        pg_table_dead_tuples.labels(table=tbl).set(dead)
    if pg_table_dead_tuple_ratio:
        pg_table_dead_tuple_ratio.labels(table=tbl).set(ratio)


def set_pg_stat_statement_latency(query_group: str, mean_seconds: float, max_seconds: float):
    grp = str(query_group)
    if pg_stat_statements_mean_exec_seconds:
        pg_stat_statements_mean_exec_seconds.labels(query_group=grp).set(max(0.0, float(mean_seconds)))
    if pg_stat_statements_max_exec_seconds:
        pg_stat_statements_max_exec_seconds.labels(query_group=grp).set(max(0.0, float(max_seconds)))


def set_redis_storage_stats(
    role: str,
    *,
    hit_ratio: float,
    evicted_keys: int,
    mem_fragmentation_ratio: float,
    used_memory_bytes: int,
):
    r = str(role)
    if redis_cache_hit_ratio:
        redis_cache_hit_ratio.labels(role=r).set(max(0.0, min(1.0, float(hit_ratio))))
    if redis_evicted_keys_total:
        redis_evicted_keys_total.labels(role=r).set(max(0, int(evicted_keys)))
    if redis_mem_fragmentation_ratio:
        redis_mem_fragmentation_ratio.labels(role=r).set(max(0.0, float(mem_fragmentation_ratio)))
    if redis_used_memory_bytes:
        redis_used_memory_bytes.labels(role=r).set(max(0, int(used_memory_bytes)))


def record_cache_operation(namespace: str, outcome: str):
    if storage_cache_operations_total:
        storage_cache_operations_total.labels(namespace=str(namespace), outcome=str(outcome)).inc()


def generate_metrics_text() -> str:
    """Renders all registered metrics into Prometheus text exposition format."""
    if "PROMETHEUS_MULTIPROC_DIR" in os.environ:
        reg = CollectorRegistry()
        multiprocess.MultiProcessCollector(reg)
        return generate_latest(reg).decode("utf-8")
    return generate_latest(REGISTRY).decode("utf-8")
