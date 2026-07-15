from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from routers import onboarding, screening, transactions, alerts, auth, rules, network
from database.neo4j_db import close_neo4j_driver
from config import settings
import asyncio
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Shutdown event shared between the FastAPI app and the sync worker
_worker_shutdown_event = asyncio.Event()

app = FastAPI(
    title="AML Compliance & Transaction Monitoring API",
    description="Synchronous transaction scoring and asynchronous graph auditing platform.",
    version="1.0.0"
)

# Enable CORS for frontend dashboard console
allowed_origins_list = [origin.strip() for origin in settings.allowed_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth.router)
app.include_router(onboarding.router)
app.include_router(screening.router)
app.include_router(transactions.router)
app.include_router(alerts.router)
app.include_router(rules.router)
app.include_router(network.router)

# Mount static folder
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def read_root():
    return {
        "status": "ONLINE",
        "service": "AML Platform Ingestion Gateway",
        "version": "1.0.0"
    }

@app.get("/dashboard", response_class=FileResponse)
def read_dashboard():
    return FileResponse("static/index.html")

@app.get("/login", response_class=FileResponse)
def read_login():
    return FileResponse("static/login.html")

@app.on_event("startup")
async def startup_db_clients():
    logger.info("Starting up database connections...")
    import sys
    import asyncio
    from database.postgres import init_db_pool
    from database.redis_db import get_redis_client, get_async_redis_client
    from database.neo4j_db import get_neo4j_driver, get_async_neo4j_driver
    from database.elasticsearch_db import get_elasticsearch_client, get_async_elasticsearch_client
    from scripts.sync_worker import main as run_sync_worker
    
    # 1. Initialize & Fail-Fast PostgreSQL
    try:
        await init_db_pool()
        # Run Phase 2 schema migrations
        from database.postgres import get_async_db_conn
        async with get_async_db_conn() as conn:
            await conn.execute(
                """
                ALTER TABLE transactions ADD COLUMN IF NOT EXISTS country VARCHAR(3);
                ALTER TABLE transactions ADD COLUMN IF NOT EXISTS merchant VARCHAR(100);
                ALTER TABLE transactions ADD COLUMN IF NOT EXISTS device VARCHAR(100);
                ALTER TABLE transactions ADD COLUMN IF NOT EXISTS channel VARCHAR(50);
                
                CREATE TABLE IF NOT EXISTS customer_profiles (
                    account_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                    avg_amount NUMERIC(15, 2) DEFAULT 0.00,
                    median_amount NUMERIC(15, 2) DEFAULT 0.00,
                    variance_amount NUMERIC(15, 2) DEFAULT 0.00,
                    daily_frequency NUMERIC(10, 4) DEFAULT 0.00,
                    weekly_frequency NUMERIC(10, 4) DEFAULT 0.00,
                    monthly_frequency INT DEFAULT 0,
                    unique_receivers_count INT DEFAULT 0,
                    unique_receiver_countries_count INT DEFAULT 0,
                    avg_hour NUMERIC(4, 2) DEFAULT 0.00,
                    variance_hour NUMERIC(6, 2) DEFAULT 0.00,
                    top_countries TEXT[],
                    top_merchants TEXT[],
                    top_devices TEXT[],
                    top_channels TEXT[],
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                );
                """
            )
        logger.info("Phase 2 PostgreSQL schema migrations completed successfully.")
    except Exception as e:
        logger.critical(f"CRITICAL: Could not initialize PostgreSQL or execute migrations: {e}")
        raise RuntimeError("PostgreSQL database initialization failed") from e
        
    # 2. Initialize & Fail-Fast Redis
    try:
        get_redis_client()
        await get_async_redis_client()
    except Exception as e:
        logger.critical(f"CRITICAL: Could not connect to Redis: {e}")
        raise RuntimeError("Redis cache is required for startup") from e
        
    # 3. Initialize & Fail-Fast Neo4j
    try:
        get_neo4j_driver()
        await get_async_neo4j_driver()
    except Exception as e:
        logger.critical(f"CRITICAL: Could not connect to Neo4j: {e}")
        raise RuntimeError("Neo4j database is required for startup") from e
        
    # 4. Initialize & Fail-Fast Elasticsearch
    try:
        get_elasticsearch_client()
        await get_async_elasticsearch_client()
    except Exception as e:
        logger.critical(f"CRITICAL: Could not connect to Elasticsearch: {e}")
        raise RuntimeError("Elasticsearch database is required for startup") from e

    # 5. Start Neo4j Graph Sync Worker (Redpanda consumer or PostgreSQL fallback)
    logger.info("Starting background Neo4j graph synchronization worker...")
    asyncio.create_task(run_sync_worker(shutdown_event=_worker_shutdown_event))

@app.on_event("shutdown")
async def shutdown_db_clients():
    # Signal the sync worker to stop cleanly before closing connections
    _worker_shutdown_event.set()
    await asyncio.sleep(1)  # give the consumer loop one cycle to exit

    # Flush and close the Kafka producer
    try:
        from services.redpanda import close_producer
        await close_producer()
        logger.info("Kafka producer flushed and closed.")
    except Exception as e:
        logger.warning(f"Failed to close Kafka producer: {e}")

    logger.info("Closing database connections...")
    # Close Postgres pools
    from database.postgres import close_db_pool
    from database.neo4j_db import close_neo4j_driver, close_async_neo4j_driver
    from database.elasticsearch_db import get_async_elasticsearch_client
    from database.redis_db import get_async_redis_client
    try:
        await close_db_pool()
    except Exception as e:
        logger.warning(f"Failed to close asyncpg pool: {e}")

    # Close Neo4j drivers
    try:
        close_neo4j_driver()
        await close_async_neo4j_driver()
    except Exception as e:
        logger.warning(f"Failed to close Neo4j drivers: {e}")

    # Close Elasticsearch async client
    try:
        es_async = await get_async_elasticsearch_client()
        await es_async.close()
        logger.info("Async Elasticsearch client closed.")
    except Exception as e:
        logger.warning(f"Failed to close Async Elasticsearch client: {e}")

    # Close Redis async client
    try:
        redis_async = await get_async_redis_client()
        await redis_async.close()
        logger.info("Async Redis client closed.")
    except Exception as e:
        logger.warning(f"Failed to close Async Redis client: {e}")

