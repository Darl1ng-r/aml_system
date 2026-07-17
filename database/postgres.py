import logging
from services.secrets_manager import get_postgres_dsn
from services.tls_manager import get_ssl_context

logger = logging.getLogger(__name__)

# --- asyncpg Async Support for FastAPI ---
import asyncpg
from contextlib import asynccontextmanager

db_pool = None
db_replica_pool = None

async def init_db_pool():
    global db_pool, db_replica_pool
    if db_pool is None:
        dsn = get_postgres_dsn()
        ssl_ctx = get_ssl_context()
        db_pool = await asyncpg.create_pool(
            dsn=dsn,
            ssl=ssl_ctx,
            min_size=5,
            max_size=20
        )
        logger.info("Primary asyncpg connection pool initialized.")

    if db_replica_pool is None:
        try:
            from config import POSTGRES_REPLICA_URL
            ssl_ctx = get_ssl_context()
            db_replica_pool = await asyncpg.create_pool(
                dsn=POSTGRES_REPLICA_URL,
                ssl=ssl_ctx,
                min_size=2,
                max_size=15
            )
            logger.info("Read replica asyncpg connection pool initialized.")
        except Exception as e:
            logger.warning(f"Read replica pool initialization fallback to primary: {e}")
            db_replica_pool = db_pool

    return db_pool

async def close_db_pool():
    global db_pool, db_replica_pool
    if db_pool:
        await db_pool.close()
        db_pool = None
        logger.info("Primary asyncpg connection pool closed.")
    if db_replica_pool and db_replica_pool != db_pool:
        await db_replica_pool.close()
        db_replica_pool = None
        logger.info("Read replica asyncpg connection pool closed.")

@asynccontextmanager
async def get_async_db_conn(tenant_id: str | None = None):
    global db_pool
    if db_pool is None:
        await init_db_pool()
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            if tenant_id:
                # Set transaction-scoped configuration variable for PostgreSQL Row Level Security (RLS)
                await conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", str(tenant_id))
            yield conn

@asynccontextmanager
async def get_async_db_read_conn(tenant_id: str | None = None):
    """Acquires a read-only database connection from the read-replica pool with fallback to primary."""
    global db_pool, db_replica_pool
    if db_pool is None or db_replica_pool is None:
        await init_db_pool()

    target_pool = db_replica_pool or db_pool
    try:
        async with target_pool.acquire() as conn:
            async with conn.transaction(readonly=True):
                if tenant_id:
                    await conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", str(tenant_id))
                yield conn
    except Exception as e:
        logger.warning(f"Read replica query failed, falling back to primary pool: {e}")
        async with db_pool.acquire() as conn:
            async with conn.transaction(readonly=True):
                if tenant_id:
                    await conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", str(tenant_id))
                yield conn

