"""
Storage Pillar Observability Monitor (PostgreSQL & Dual-Redis Telemetry)
========================================================================
Periodically samples (default every 15s) live data-infrastructure SLIs without
adding latency to request hot paths:
  - PostgreSQL: streaming replication lag (`pg_stat_replication` / standby
    `pg_last_xact_replay_timestamp`), dead-tuple / autovacuum health
    (`pg_stat_user_tables`), and optional `pg_stat_statements` mean/max latency.
  - Redis (both `state` and `cache` roles): keyspace hit ratio, `evicted_keys`,
    `mem_fragmentation_ratio`, and `used_memory`.

Also exposes `get_observed_replica_lag_seconds()` so `get_async_db_read_conn()`
automatically fails over reads to the Primary whenever replica lag exceeds
`settings.replica_max_lag_seconds` (default 2.0s).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from observability.prometheus import (
    set_pg_replication_lag,
    set_pg_stat_statement_latency,
    set_pg_table_bloat,
    set_redis_storage_stats,
)

logger = logging.getLogger(__name__)

_HOT_TABLES = (
    "transactions",
    "alerts",
    "cases",
    "audit_log",
    "transactional_outbox",
    "ctr_filings",
    "sar_drafts",
    "resource_locks",
    "idempotency_records",
    "accounts",
)

_observed_replica_lag_seconds: float = 0.0
_last_sample_ts: float = 0.0
_last_snapshot: dict[str, Any] = {
    "replica_lag_seconds": 0.0,
    "pg_stat_statements_enabled": False,
    "redis_state": {},
    "redis_cache": {},
    "hot_tables_sampled": 0,
}


def get_observed_replica_lag_seconds() -> float:
    return float(_observed_replica_lag_seconds)


def set_observed_replica_lag_seconds(lag_seconds: float) -> None:
    """Updates observed replication lag (also used by telemetry sampler & failover tests)."""
    global _observed_replica_lag_seconds
    _observed_replica_lag_seconds = max(0.0, float(lag_seconds))
    _last_snapshot["replica_lag_seconds"] = _observed_replica_lag_seconds
    set_pg_replication_lag(_observed_replica_lag_seconds)


def get_storage_health_snapshot() -> dict[str, Any]:
    return {
        **_last_snapshot,
        "last_sample_age_seconds": round(max(0.0, time.monotonic() - _last_sample_ts), 2)
        if _last_sample_ts > 0
        else None,
    }


def _extract_redis_metrics(info_stats: dict[str, Any], info_memory: dict[str, Any]) -> dict[str, Any]:
    hits = int(info_stats.get("keyspace_hits", 0) or 0)
    misses = int(info_stats.get("keyspace_misses", 0) or 0)
    total = hits + misses
    hit_ratio = (hits / total) if total > 0 else 1.0
    evicted = int(info_stats.get("evicted_keys", 0) or 0)
    frag_ratio = float(info_memory.get("mem_fragmentation_ratio", 1.0) or 1.0)
    used_mem = int(info_memory.get("used_memory", 0) or 0)
    return {
        "hit_ratio": round(hit_ratio, 4),
        "evicted_keys": evicted,
        "mem_fragmentation_ratio": round(frag_ratio, 3),
        "used_memory_bytes": used_mem,
    }


async def _sample_postgres_telemetry() -> dict[str, Any]:
    import database.postgres as _pg

    snapshot: dict[str, Any] = {
        "replica_lag_seconds": 0.0,
        "pg_stat_statements_enabled": False,
        "hot_tables_sampled": 0,
    }
    pool = _pg.db_pool
    if pool is None:
        return snapshot

    try:
        async with pool.acquire(timeout=2.0) as conn:
            # 1. Dead-tuple / autovacuum health on hot tables
            bloat_rows = await conn.fetch(
                """
                SELECT relname, COALESCE(n_live_tup, 0) AS live_tup, COALESCE(n_dead_tup, 0) AS dead_tup
                FROM pg_stat_user_tables
                WHERE relname = ANY($1::text[]);
                """,
                list(_HOT_TABLES),
            )
            for row in bloat_rows or []:
                set_pg_table_bloat(row["relname"], int(row["live_tup"]), int(row["dead_tup"]))
            snapshot["hot_tables_sampled"] = len(bloat_rows or [])

            # 2. Replication lag (primary view via pg_stat_replication, or standby view if replica)
            lag_sec = 0.0
            try:
                is_standby = await conn.fetchval("SELECT pg_is_in_recovery();")
                if is_standby:
                    lag_val = await conn.fetchval(
                        "SELECT COALESCE(EXTRACT(EPOCH FROM (NOW() - pg_last_xact_replay_timestamp())), 0.0);"
                    )
                    lag_sec = max(0.0, float(lag_val or 0.0))
                else:
                    lag_val = await conn.fetchval(
                        """
                        SELECT COALESCE(MAX(EXTRACT(EPOCH FROM replay_lag)), 0.0)
                        FROM pg_stat_replication;
                        """
                    )
                    lag_sec = max(0.0, float(lag_val or 0.0))
            except Exception:
                # Non-superuser `aml_app` may lack pg_monitor grant on pg_stat_replication; degrade gracefully
                lag_sec = 0.0

            # Also check replica pool directly when physically distinct from primary
            if lag_sec == 0.0 and _pg.db_replica_pool is not None and _pg.db_replica_pool is not _pg.db_pool:
                try:
                    async with _pg.db_replica_pool.acquire(timeout=1.5) as rconn:
                        r_standby = await rconn.fetchval("SELECT pg_is_in_recovery();")
                        if r_standby:
                            r_lag = await rconn.fetchval(
                                "SELECT COALESCE(EXTRACT(EPOCH FROM (NOW() - pg_last_xact_replay_timestamp())), 0.0);"
                            )
                            lag_sec = max(0.0, float(r_lag or 0.0))
                except Exception:
                    pass

            set_observed_replica_lag_seconds(lag_sec)
            snapshot["replica_lag_seconds"] = round(lag_sec, 4)

            # 3. Optional pg_stat_statements top slow query groups
            try:
                has_pgss = await conn.fetchval(
                    "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements');"
                )
                if has_pgss:
                    snapshot["pg_stat_statements_enabled"] = True
                    stmt_rows = await conn.fetch(
                        """
                        SELECT LEFT(REGEXP_REPLACE(query, '\\s+', ' ', 'g'), 40) AS query_group,
                               mean_exec_time / 1000.0 AS mean_sec,
                               max_exec_time / 1000.0 AS max_sec
                        FROM pg_stat_statements
                        WHERE calls >= 5
                        ORDER BY mean_exec_time DESC
                        LIMIT 5;
                        """
                    )
                    for idx, srow in enumerate(stmt_rows or [], start=1):
                        set_pg_stat_statement_latency(
                            f"top_{idx}",
                            float(srow["mean_sec"] or 0.0),
                            float(srow["max_sec"] or 0.0),
                        )
            except Exception:
                pass
    except Exception as exc:
        logger.debug("PostgreSQL storage telemetry sample skipped: %s", exc)

    return snapshot


async def _sample_single_redis(role: str, client_coro) -> dict[str, Any]:
    try:
        client = await asyncio.wait_for(client_coro(), timeout=0.5)
        if client is None:
            return {}
        stats = await asyncio.wait_for(client.info("stats"), timeout=0.5)
        memory = await asyncio.wait_for(client.info("memory"), timeout=0.5)
        parsed = _extract_redis_metrics(stats or {}, memory or {})
        set_redis_storage_stats(
            role,
            hit_ratio=parsed["hit_ratio"],
            evicted_keys=parsed["evicted_keys"],
            mem_fragmentation_ratio=parsed["mem_fragmentation_ratio"],
            used_memory_bytes=parsed["used_memory_bytes"],
        )
        return parsed
    except Exception as exc:
        logger.debug("Redis (%s) storage telemetry sample skipped: %s", role, exc)
        return {}


async def sample_storage_telemetry_once() -> dict[str, Any]:
    """Executes one complete PostgreSQL + Dual-Redis telemetry sample and updates Prometheus."""
    global _last_sample_ts
    from database.redis_db import get_async_cache_redis_client, get_async_redis_client

    pg_snap = await _sample_postgres_telemetry()
    state_snap = await _sample_single_redis("state", get_async_redis_client)
    cache_snap = await _sample_single_redis("cache", get_async_cache_redis_client)

    _last_snapshot.update(pg_snap)
    _last_snapshot["redis_state"] = state_snap
    _last_snapshot["redis_cache"] = cache_snap
    _last_sample_ts = time.monotonic()
    return dict(_last_snapshot)


async def start_storage_monitor(
    interval_seconds: float = 15.0,
    shutdown_event: asyncio.Event | None = None,
) -> None:
    """Runs periodic PostgreSQL and Redis storage telemetry sampling until shutdown."""
    interval = max(2.0, float(interval_seconds))
    logger.info("Starting storage observability monitor (interval=%.1fs).", interval)
    try:
        while True:
            if shutdown_event is not None and shutdown_event.is_set():
                break
            await sample_storage_telemetry_once()
            if shutdown_event is not None:
                try:
                    await asyncio.wait_for(shutdown_event.wait(), timeout=interval)
                    break
                except asyncio.TimeoutError:
                    continue
            else:
                await asyncio.sleep(interval)
    except asyncio.CancelledError:
        logger.info("Storage observability monitor cancelled.")
        raise
