import asyncio
import logging
import os
from contextlib import asynccontextmanager

import asyncpg

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
            db_pool = await asyncpg.create_pool(
                dsn=dsn,
                ssl=ssl_ctx,
                min_size=2,
                max_size=15,
                timeout=10.0,
                command_timeout=15.0,
                **pool_kwargs,
            )
            logger.info("Primary asyncpg connection pool initialized (pgbouncer=%s).", pgbouncer_enabled)

        if _pool_needs_init(db_replica_pool):
            try:
                replica_dsn = get_postgres_replica_dsn()
                ssl_ctx = get_ssl_context()
                # P2-24: Cap replica pool at max_size=4 per worker (4 * 2 workers * 10 HPA pods = 80 < 200 max_connections)
                db_replica_pool = await asyncpg.create_pool(
                    dsn=replica_dsn,
                    ssl=ssl_ctx,
                    min_size=1,
                    max_size=4,
                    timeout=5.0,
                    command_timeout=15.0,
                    **pool_kwargs,
                )
                logger.info("Read replica asyncpg connection pool initialized.")
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


@asynccontextmanager
async def get_async_db_conn(tenant_id: str | None = None, auth_lookup: bool = False):
    global db_pool
    if _pool_needs_init(db_pool):
        await init_db_pool()
    async with db_pool.acquire(timeout=5.0) as conn, conn.transaction():
        await _apply_rls_tenant_context(conn, tenant_id, auth_lookup=auth_lookup)
        yield conn


@asynccontextmanager
async def get_async_db_read_conn(tenant_id: str | None = None, auth_lookup: bool = False):
    """Acquires a read-only database connection from the read-replica pool with fallback to primary."""
    global db_pool, db_replica_pool
    if _pool_needs_init(db_replica_pool) or _pool_needs_init(db_pool):
        await init_db_pool()

    target_pool = db_replica_pool or db_pool
    conn = None
    try:
        conn = await target_pool.acquire(timeout=5.0)
    except Exception as e:
        logger.warning("Read replica acquire failed, falling back to primary pool: %s", e)
        target_pool = db_pool
        conn = await target_pool.acquire(timeout=5.0)

    try:
        async with conn.transaction(readonly=True):
            await _apply_rls_tenant_context(conn, tenant_id, auth_lookup=auth_lookup)
            yield conn
    finally:
        if conn:
            await target_pool.release(conn)
