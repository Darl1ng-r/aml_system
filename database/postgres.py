import logging
from config import POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_URL

logger = logging.getLogger(__name__)

# --- asyncpg Async Support for FastAPI ---
import asyncpg
from contextlib import asynccontextmanager

db_pool = None

async def init_db_pool():
    global db_pool
    if db_pool is None:
        db_pool = await asyncpg.create_pool(
            dsn=POSTGRES_URL,
            min_size=5,
            max_size=20
        )
    logger.info("asyncpg connection pool initialized.")
    return db_pool

async def close_db_pool():
    global db_pool
    if db_pool:
        await db_pool.close()
        db_pool = None
        logger.info("asyncpg connection pool closed.")

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

