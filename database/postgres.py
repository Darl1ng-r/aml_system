import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager

import asyncpg

from config import settings
from services.secrets_manager import (
    get_outbox_postgres_dsn,
    get_postgres_dsn,
    get_postgres_replica_dsn,
    get_postgres_replica_dsns,
)
from services.tls_manager import get_ssl_context

logger = logging.getLogger(__name__)

db_pool = None
db_replica_pool = None
db_outbox_pool = None
db_replica_pools: list = []
_replica_rr_index: int = 0
_pool_init_lock: asyncio.Lock | None = None
_pool_init_lock_loop = None


def _get_pool_lock() -> asyncio.Lock:
    global _pool_init_lock, _pool_init_lock_loop
    current_loop = asyncio.get_running_loop()
    if _pool_init_lock is None or _pool_init_lock_loop is not current_loop:
        _pool_init_lock = asyncio.Lock()
        _pool_init_lock_loop = current_loop
    return _pool_init_lock


def _pool_needs_init(pool) -> bool:
    return pool is None or getattr(pool, "_loop", None) is None or pool._loop.is_closed()


async def init_db_pool():
    """Initializes primary and one or more read-replica asyncpg pools safely under asyncio.Lock."""
    global db_pool, db_replica_pool, db_replica_pools, _replica_rr_index
    async with _get_pool_lock():
        pgbouncer_enabled = os.getenv("PGBOUNCER_ENABLED", "false").lower() == "true"
        pool_kwargs = {}
        if pgbouncer_enabled:
            # Transaction-mode PgBouncer requires disabling per-connection prepared statement caches
            pool_kwargs["statement_cache_size"] = 0

        if _pool_needs_init(db_pool):
            dsn = get_postgres_dsn()
            ssl_ctx = get_ssl_context()
            min_sz = max(1, int(getattr(settings, "postgres_pool_min_size", 2)))
            max_sz = max(min_sz, int(getattr(settings, "postgres_pool_max_size", 15)))
            acq_timeout = max(1.0, float(getattr(settings, "postgres_acquire_timeout_seconds", 5.0)))
            db_pool = await asyncpg.create_pool(
                dsn=dsn,
                ssl=ssl_ctx,
                min_size=min_sz,
                max_size=max_sz,
                timeout=acq_timeout,
                command_timeout=15.0,
                **pool_kwargs,
            )
            logger.info(
                "Primary asyncpg connection pool initialized (min=%d max=%d timeout=%.1fs pgbouncer=%s).",
                min_sz,
                max_sz,
                acq_timeout,
                pgbouncer_enabled,
            )

        if _pool_needs_init(db_replica_pool):
            replica_dsns = get_postgres_replica_dsns()
            ssl_ctx = get_ssl_context()
            rep_max = max(1, int(getattr(settings, "postgres_replica_pool_max_size", 4)))
            per_replica_max = max(1, rep_max // max(1, len(replica_dsns))) if len(replica_dsns) > 1 else rep_max
            acq_timeout = max(1.0, float(getattr(settings, "postgres_acquire_timeout_seconds", 5.0)))
            initialized_replicas = []
            for idx, replica_dsn in enumerate(replica_dsns):
                try:
                    r_pool = await asyncpg.create_pool(
                        dsn=replica_dsn,
                        ssl=ssl_ctx,
                        min_size=1,
                        max_size=per_replica_max,
                        timeout=acq_timeout,
                        command_timeout=15.0,
                        **pool_kwargs,
                    )
                    initialized_replicas.append(r_pool)
                except Exception as e:
                    logger.warning("Read replica #%d pool initialization failed: %s", idx + 1, e)

            if initialized_replicas:
                db_replica_pools = initialized_replicas
                db_replica_pool = initialized_replicas[0]
                _replica_rr_index = 0
                logger.info(
                    "Read replica asyncpg pool(s) initialized (count=%d, max_per_replica=%d).",
                    len(initialized_replicas),
                    per_replica_max,
                )
            else:
                logger.warning("All read replica pools unavailable; falling back to primary pool.")
                db_replica_pools = []
                db_replica_pool = db_pool

        return db_pool


async def get_db_pool():
    """Returns the active asyncpg connection pool, initializing it if necessary."""
    global db_pool
    if _pool_needs_init(db_pool):
        await init_db_pool()
    return db_pool


async def get_outbox_db_pool():
    """
    Returns the dedicated least-privilege `aml_outbox_worker` pool (BYPASSRLS scoped
    to `transactional_outbox`) when `OUTBOX_DATABASE_URL` / `AML_OUTBOX_WORKER_PASSWORD`
    is configured; falls back to the primary pool in local dev/superuser setups.
    """
    global db_outbox_pool
    outbox_dsn = get_outbox_postgres_dsn()
    if not outbox_dsn:
        return await get_db_pool()
    async with _get_pool_lock():
        if _pool_needs_init(db_outbox_pool):
            pgbouncer_enabled = os.getenv("PGBOUNCER_ENABLED", "false").lower() == "true"
            pool_kwargs = {"statement_cache_size": 0} if pgbouncer_enabled else {}
            db_outbox_pool = await asyncpg.create_pool(
                dsn=outbox_dsn,
                ssl=get_ssl_context(),
                min_size=1,
                max_size=4,
                timeout=max(1.0, float(getattr(settings, "postgres_acquire_timeout_seconds", 5.0))),
                command_timeout=15.0,
                **pool_kwargs,
            )
            logger.info("Dedicated aml_outbox_worker asyncpg pool initialized.")
        return db_outbox_pool


async def close_db_pool():
    global db_pool, db_replica_pool, db_outbox_pool, db_replica_pools, _replica_rr_index
    if db_outbox_pool and db_outbox_pool is not db_pool:
        try:
            await db_outbox_pool.close()
        except Exception:
            pass
    db_outbox_pool = None
    closed_ids: set[int] = set()
    for r_pool in list(db_replica_pools):
        if r_pool and r_pool is not db_pool and id(r_pool) not in closed_ids:
            await r_pool.close()
            closed_ids.add(id(r_pool))
    if db_replica_pool and db_replica_pool is not db_pool and id(db_replica_pool) not in closed_ids:
        await db_replica_pool.close()
        closed_ids.add(id(db_replica_pool))
    if closed_ids:
        logger.info("Closed %d read replica asyncpg connection pool(s).", len(closed_ids))
    db_replica_pools = []
    db_replica_pool = None
    _replica_rr_index = 0
    if db_pool:
        await db_pool.close()
        db_pool = None
        logger.info("Primary asyncpg connection pool closed.")


async def _apply_rls_tenant_context(
    conn,
    tenant_id: str | None,
    auth_lookup: bool = False,
) -> None:
    """Sets transaction-scoped PostgreSQL RLS tenant context, failing closed on missing or invalid UUID."""
    if tenant_id:
        try:
            import uuid
            uuid.UUID(str(tenant_id))
            await conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", str(tenant_id))
        except (ValueError, TypeError):
            raise ValueError(f"Invalid tenant_id format: '{tenant_id}'")
    else:
        await conn.execute("SELECT set_config('app.current_tenant_id', '00000000-0000-0000-0000-000000000000', true);")
    if auth_lookup:
        await conn.execute("SELECT set_config('app.auth_lookup', 'true', true);")


def _emit_pool_metrics(pool_name: str, pool_obj, acquire_elapsed: float) -> None:
    try:
        from observability.prometheus import record_db_pool_acquire

        size = pool_obj.get_size() if hasattr(pool_obj, "get_size") else None
        idle = pool_obj.get_idle_size() if hasattr(pool_obj, "get_idle_size") else None
        max_sz = pool_obj.get_max_size() if hasattr(pool_obj, "get_max_size") else None
        in_use = (size - idle) if (size is not None and idle is not None) else None
        record_db_pool_acquire(
            pool_name,
            acquire_elapsed,
            in_use=in_use,
            idle=idle,
            max_size=max_sz,
        )
    except Exception:
        pass


@asynccontextmanager
async def get_async_db_conn(tenant_id: str | None = None, auth_lookup: bool = False):
    global db_pool
    if _pool_needs_init(db_pool):
        await init_db_pool()
    acq_timeout = max(1.0, float(getattr(settings, "postgres_acquire_timeout_seconds", 5.0)))
    t0 = time.monotonic()
    async with db_pool.acquire(timeout=acq_timeout) as conn:
        _emit_pool_metrics("primary", db_pool, time.monotonic() - t0)
        async with conn.transaction():
            await _apply_rls_tenant_context(conn, tenant_id, auth_lookup=auth_lookup)
            yield conn


def _candidate_replica_pools() -> list:
    """Returns ordered replica pools starting from the next round-robin slot."""
    global _replica_rr_index
    active = [p for p in db_replica_pools if p is not None and p is not db_pool]
    # Honor direct test monkeypatching of `db_replica_pool`
    if db_replica_pool is not None and db_replica_pool is not db_pool and db_replica_pool not in active:
        return [db_replica_pool]
    if not active:
        return []
    start = _replica_rr_index % len(active)
    _replica_rr_index = (start + 1) % len(active)
    return active[start:] + active[:start]


@asynccontextmanager
async def get_async_db_read_conn(
    tenant_id: str | None = None,
    auth_lookup: bool = False,
    prefer_primary: bool = False,
):
    """
    Acquires a read-only database connection with multi-replica round-robin load balancing,
    Read-After-Write (RAW) primary stickiness, and streaming replication lag failover:
      - Routes to Primary when `prefer_primary=True`, active RAW stickiness is set
        in `force_primary_read_var`, or observed replica lag exceeds
        `settings.replica_max_lag_seconds`.
      - Otherwise rotates across configured read-replica pools, failing over to sibling
        replicas first and then Primary if all replicas fail.
    """
    global db_pool, db_replica_pool
    if _pool_needs_init(db_replica_pool) or _pool_needs_init(db_pool):
        await init_db_pool()

    from database.read_after_write import force_primary_read_var, read_routing_reason_var
    from observability.prometheus import record_db_read_routing
    from observability.storage_monitor import get_observed_replica_lag_seconds

    acq_timeout = max(1.0, float(getattr(settings, "postgres_acquire_timeout_seconds", 5.0)))
    max_lag = max(0.1, float(getattr(settings, "replica_max_lag_seconds", 2.0)))
    observed_lag = get_observed_replica_lag_seconds()
    replica_candidates = _candidate_replica_pools()

    use_primary = False
    routing_reason = "replica"
    if prefer_primary:
        use_primary = True
        routing_reason = "primary_explicit"
    elif force_primary_read_var.get(False):
        use_primary = True
        routing_reason = read_routing_reason_var.get("primary_raw_stickiness") or "primary_raw_stickiness"
    elif observed_lag > max_lag:
        use_primary = True
        routing_reason = "primary_replica_lag"
    elif not replica_candidates:
        use_primary = True
        routing_reason = "primary_shared_pool"

    target_pool = db_pool
    conn = None
    if use_primary:
        t0 = time.monotonic()
        conn = await db_pool.acquire(timeout=acq_timeout)
        _emit_pool_metrics("primary", db_pool, time.monotonic() - t0)
        record_db_read_routing("primary", routing_reason)
    else:
        last_err: Exception | None = None
        for r_pool in replica_candidates:
            t0 = time.monotonic()
            try:
                conn = await r_pool.acquire(timeout=acq_timeout)
                target_pool = r_pool
                _emit_pool_metrics("replica", r_pool, time.monotonic() - t0)
                record_db_read_routing("replica", routing_reason)
                break
            except Exception as e:
                last_err = e
                logger.warning("Read replica acquire failed, trying next standby/primary: %s", e)

        if conn is None:
            logger.warning("All read replicas failed (%s); falling back to primary pool.", last_err)
            target_pool = db_pool
            t0 = time.monotonic()
            conn = await db_pool.acquire(timeout=acq_timeout)
            _emit_pool_metrics("primary", db_pool, time.monotonic() - t0)
            record_db_read_routing("primary", "primary_fallback")

    try:
        async with conn.transaction(readonly=True):
            await _apply_rls_tenant_context(conn, tenant_id, auth_lookup=auth_lookup)
            yield conn
    finally:
        if conn:
            await target_pool.release(conn)
