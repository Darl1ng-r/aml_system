from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from routers import onboarding, screening, transactions, alerts, auth
# pg8000 connection_pool import removed
from database.neo4j_db import close_neo4j_driver
from config import settings
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

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
    except Exception as e:
        logger.critical(f"CRITICAL: Could not initialize PostgreSQL pool: {e}")
        raise RuntimeError("PostgreSQL database is required for startup") from e
        
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

    # 5. Autostart Neo4j Graph Synchronization Worker
    logger.info("Starting background Neo4j graph synchronization worker...")
    asyncio.create_task(run_sync_worker())

@app.on_event("shutdown")
async def shutdown_db_clients():
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
        
    # pg8000 connection_pool closeall removed
        
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
