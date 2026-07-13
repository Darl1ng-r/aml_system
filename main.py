from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import onboarding, screening, transactions, alerts
from database.postgres import connection_pool
from database.neo4j_db import close_neo4j_driver
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AML Compliance & Transaction Monitoring API",
    description="Synchronous transaction scoring and asynchronous graph auditing platform.",
    version="1.0.0"
)

# Enable CORS for frontend dashboard console
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(onboarding.router)
app.include_router(screening.router)
app.include_router(transactions.router)
app.include_router(alerts.router)

@app.get("/")
def read_root():
    return {
        "status": "ONLINE",
        "service": "AML Platform Ingestion Gateway",
        "version": "1.0.0"
    }

@app.on_event("startup")
def startup_db_clients():
    logger.info("Starting up database connections...")
    # Trigger lazy load validation
    from database.postgres import get_db_connection
    from database.redis_db import get_redis_client
    from database.neo4j_db import get_neo4j_driver
    from database.elasticsearch_db import get_elasticsearch_client
    
    try:
        get_redis_client()
    except Exception as e:
        logger.warning(f"Could not connect to Redis: {e}")
        
    try:
        get_neo4j_driver()
    except Exception as e:
        logger.warning(f"Could not connect to Neo4j: {e}")
        
    try:
        get_elasticsearch_client()
    except Exception as e:
        logger.warning(f"Could not connect to Elasticsearch: {e}")

@app.on_event("shutdown")
def shutdown_db_clients():
    logger.info("Closing database connections...")
    # Close Postgres pool
    if connection_pool:
        connection_pool.closeall()
        logger.info("PostgreSQL connection pool closed.")
        
    # Close Neo4j driver
    try:
        close_neo4j_driver()
    except Exception as e:
        logger.warning(f"Failed to close Neo4j driver: {e}")
