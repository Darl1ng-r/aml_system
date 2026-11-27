import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager

import asyncpg

from config import settings
from services.secrets_manager import get_postgres_dsn, get_postgres_replica_dsn
from services.tls_manager import get_ssl_context

logger = logging.getLogger(__name__)

db_pool = None
db_replica_pool = None
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
    """Initializes primary and read-replica asyncpg pools safely under asyncio.Lock."""
    global db_pool, db_replica_pool
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
            try:
                replica_dsn = get_postgres_replica_dsn()
                ssl_ctx = get_ssl_context()
                rep_max = max(1, int(getattr(settings, "postgres_replica_pool_max_size", 4)))
                acq_timeout = max(1.0, float(getattr(settings, "postgres_acquire_timeout_seconds", 5.0)))
                # P2-24: Cap replica pool at max_size=4 per worker (4 * 2 workers * 10 HPA pods = 80 < 200 max_connections)
                db_replica_pool = await asyncpg.create_pool(
                    dsn=replica_dsn,
                    ssl=ssl_ctx,
                    min_size=1,
                    max_size=rep_max,
                    timeout=acq_timeout,
                    command_timeout=15.0,
                    **pool_kwargs,
                )
                logger.info("Read replica asyncpg connection pool initialized (max=%d).", rep_max)
            except Exception as e:
                logger.warning("Read replica pool initialization fallback to primary: %s", e)
                db_replica_pool = db_pool

        return db_pool


async def get_db_pool():
    """Returns the active asyncpg connection pool, initializing it if necessary."""
    global db_pool
    if _pool_needs_init(db_pool):
        await init_db_pool()
    return db_pool


async def close_db_pool():
    global db_pool, db_replica_pool
    if db_replica_pool and db_replica_pool is not db_pool:
        await db_replica_pool.close()
        logger.info("Read replica asyncpg connection pool closed.")
    db_replica_pool = None
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


@asynccontextmanager
async def get_async_db_read_conn(
    tenant_id: str | None = None,
    auth_lookup: bool = False,
    prefer_primary: bool = False,
):
    """
    Acquires a read-only database connection with automatic Read-After-Write (RAW)
    primary stickiness and streaming replication lag failover:
      - Routes to Primary when `prefer_primary=True`, active RAW stickiness is set
        in `force_primary_read_var`, or observed replica lag exceeds
        `settings.replica_max_lag_seconds`.
      - Otherwise acquires from the read-replica pool with fallback to Primary.
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
    elif db_replica_pool is None or db_replica_pool is db_pool:
        use_primary = True
        routing_reason = "primary_shared_pool"

    target_pool = db_pool if use_primary else db_replica_pool
    pool_label = "primary" if target_pool is db_pool else "replica"
    conn = None
    t0 = time.monotonic()
    try:
        conn = await target_pool.acquire(timeout=acq_timeout)
        _emit_pool_metrics(pool_label, target_pool, time.monotonic() - t0)
        record_db_read_routing(pool_label, routing_reason)
    except Exception as e:
        if target_pool is db_pool:
            raise
        logger.warning("Read replica acquire failed, falling back to primary pool: %s", e)
        target_pool = db_pool
        t0 = time.monotonic()
        conn = await target_pool.acquire(timeout=acq_timeout)
        _emit_pool_metrics("primary", target_pool, time.monotonic() - t0)
        record_db_read_routing("primary", "primary_fallback")

    try:
        async with conn.transaction(readonly=True):
            await _apply_rls_tenant_context(conn, tenant_id, auth_lookup=auth_lookup)
            yield conn
    finally:
        if conn:
            await target_pool.release(conn)
