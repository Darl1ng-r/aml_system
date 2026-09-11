from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from routers import onboarding, screening, transactions, alerts, auth, rules, network
from routers import health, metrics, fincen, str_batch, ml_feedback, watchlist, jwks
from database.neo4j_db import close_neo4j_driver
from config import settings
from observability.logging import setup_json_logging
from observability.middleware import CorrelationIdMiddleware
from services.trusted_proxy import TrustedProxyMiddleware
from services.csrf import CSRFProtectionMiddleware
import asyncio
import logging

# ── Structured JSON logging (called early; re-applied after Alembic in startup) ──
setup_json_logging(level=logging.INFO)
logger = logging.getLogger(__name__)

# Shutdown event shared between the FastAPI app and the sync worker
_worker_shutdown_event = asyncio.Event()

app = FastAPI(
    title="AML Compliance & Transaction Monitoring API",
    description="Synchronous transaction scoring and asynchronous graph auditing platform.",
    version="1.0.0"
)

# ── Middleware ────────────────────────────────────────────────────────────
# Trusted proxy resolution (must be first to ensure accurate peer/forwarded IP)
app.add_middleware(TrustedProxyMiddleware)

# Correlation-ID middleware (must wrap requests early)
app.add_middleware(CorrelationIdMiddleware)

# Anti-CSRF protection middleware
app.add_middleware(CSRFProtectionMiddleware)

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
app.include_router(health.router)  # /health, /health/live, /health/ready — must be before static mount


@app.get("/metrics", tags=["Observability"], summary="Prometheus Metrics Scrape Endpoint")
def prometheus_metrics():
    """Exposes internal compliance, SLO, and performance metrics in Prometheus exposition format."""
    from observability.prometheus import generate_metrics_text
    return Response(
        content=generate_metrics_text(),
        media_type="text/plain; version=0.0.4; charset=utf-8"
    )


app.include_router(jwks.router)    # /.well-known/jwks.json public key publishing
app.include_router(auth.router)
app.include_router(metrics.router)
app.include_router(fincen.router)
app.include_router(str_batch.router)
app.include_router(ml_feedback.router)
app.include_router(watchlist.router)
app.include_router(onboarding.router)
app.include_router(screening.router)
app.include_router(transactions.router)
app.include_router(alerts.router)
app.include_router(rules.router)
app.include_router(network.router)

# Mount static files directory for dashboard styling and frontend client logic
app.mount("/static", StaticFiles(directory="static"), name="static")

# ── Exception Handlers ───────────────────────────────────────────────────
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from observability.middleware import correlation_id_var

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    messages = []
    for err in errors:
        loc = ".".join(str(l) for l in err.get("loc", []) if l != "body")
        msg = err.get("msg", "Invalid value")
        messages.append(f"{loc}: {msg}" if loc else msg)
    friendly_msg = "; ".join(messages) if messages else "Invalid request data."
    return JSONResponse(
        status_code=422,
        content={"detail": friendly_msg, "errors": errors}
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    correlation_id = correlation_id_var.get("")
    logger.error(
        f"Unhandled application exception: {exc}",
        exc_info=exc,
        extra={"correlation_id": correlation_id}
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal server error occurred.",
            "correlation_id": correlation_id
        }
    )

@app.get("/")
def read_root(request: Request):
    accept = request.headers.get("accept", "")
    sec_fetch_dest = request.headers.get("sec-fetch-dest", "")
    if sec_fetch_dest == "document" or ("text/html" in accept and "application/json" not in accept):
        return FileResponse("static/landing.html")
    return {
        "status": "ONLINE",
        "service": "AML Platform Ingestion Gateway",
        "version": "1.0.0"
    }

@app.get("/landing", response_class=FileResponse)
def read_landing():
    return FileResponse("static/landing.html")

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
    import os
    import asyncio
    from database.postgres import init_db_pool
    from database.redis_db import get_redis_client, get_async_redis_client
    from database.neo4j_db import get_neo4j_driver, get_async_neo4j_driver
    from database.elasticsearch_db import get_elasticsearch_client, get_async_elasticsearch_client
    from scripts.sync_worker import main as run_sync_worker

    # ── 0. Bootstrap Vault secrets (must be FIRST — all subsequent steps depend on it) ──
    try:
        from services.vault_loader import VaultSecretsLoader
        await VaultSecretsLoader.bootstrap()
        logger.info("Vault secrets loaded successfully.")
    except RuntimeError as e:
        logger.critical(f"CRITICAL: Vault secrets bootstrap failed: {e}")
        raise

    # ── 0b. TLS/mTLS validation ──────────────────────────────────────────
    from services.tls_manager import validate_mtls_configuration
    validate_mtls_configuration(strict=settings.strict_mtls or settings.enable_tls)

    # ── 0c. Initialise OpenTelemetry tracing ──────────────────────────────

    try:
        from observability.tracing import init_tracer
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        init_tracer(
            service_name=settings.otel_service_name,
            endpoint=settings.otel_exporter_endpoint,
        )
        FastAPIInstrumentor.instrument_app(app)
        logger.info("OpenTelemetry FastAPI instrumentation enabled.")
    except Exception as e:
        logger.warning(f"OpenTelemetry init skipped (non-fatal): {e}")
    
    allow_offline = os.getenv("ALLOW_OFFLINE_DEV", "false").lower() == "true"
    pg_connected = False

    # ── 1. Initialize & Fail-Fast PostgreSQL ─────────────────────────────
    try:
        await init_db_pool()
        pg_connected = True
    except Exception as e:
        logger.critical(f"CRITICAL: Could not initialize PostgreSQL: {e}")
        if not allow_offline:
            raise RuntimeError("PostgreSQL database initialization failed") from e
        logger.warning("ALLOW_OFFLINE_DEV active: Continuing without PostgreSQL connection.")
    
    # ── 1b. Run Alembic migrations ───────────────────────────────────────
    if pg_connected:
        try:
            from alembic.config import Config as AlembicConfig
            from alembic import command as alembic_command
            alembic_cfg = AlembicConfig("alembic.ini")
            alembic_command.upgrade(alembic_cfg, "head")
            # Re-apply JSON logging after Alembic's fileConfig may have overwritten handlers
            setup_json_logging(level=logging.INFO)
            logger.info("Alembic database migrations applied successfully.")
        except Exception as e:
            logger.critical(f"CRITICAL: Alembic migration failed: {e}")
            if not allow_offline:
                raise RuntimeError("Database migration failed") from e
            logger.warning("ALLOW_OFFLINE_DEV active: Continuing without running Alembic migrations.")
    elif allow_offline:
        logger.warning("ALLOW_OFFLINE_DEV active: Skipping Alembic migrations because PostgreSQL is offline.")
        
    # ── 2. Initialize & Fail-Fast Redis ──────────────────────────────────
    try:
        get_redis_client()
        await get_async_redis_client()
    except Exception as e:
        logger.critical(f"CRITICAL: Could not connect to Redis: {e}")
        if not allow_offline:
            raise RuntimeError("Redis cache is required for startup") from e
        logger.warning("ALLOW_OFFLINE_DEV active: Continuing without Redis connection.")
        
    # ── 3. Initialize & Fail-Fast Neo4j ──────────────────────────────────
    try:
        get_neo4j_driver()
        await get_async_neo4j_driver()
    except Exception as e:
        logger.critical(f"CRITICAL: Could not connect to Neo4j: {e}")
        if not allow_offline:
            raise RuntimeError("Neo4j database is required for startup") from e
        logger.warning("ALLOW_OFFLINE_DEV active: Continuing without Neo4j connection.")
        
    # ── 4. Initialize & Fail-Fast Elasticsearch ──────────────────────────
    try:
        get_elasticsearch_client()
        es_async = await get_async_elasticsearch_client()
        from services.watchlist_sync import watchlist_sync_engine
        await watchlist_sync_engine.ensure_indices_and_seed(es_async)
        logger.info("Elasticsearch sanctions and PEP indices verified and seeded.")
    except Exception as e:
        logger.critical(f"CRITICAL: Could not connect to Elasticsearch: {e}")
        if not allow_offline:
            raise RuntimeError("Elasticsearch database is required for startup") from e
        logger.warning("ALLOW_OFFLINE_DEV active: Continuing without Elasticsearch connection.")

    # ── 5. Pre-warm Isolation Forest model ──────────────────────────────
    # Running before first request prevents a cold-start delay on the first transaction.
    try:
        from services.isolation_forest import retrain_system_iforest
        await retrain_system_iforest()
        logger.info("Isolation Forest model pre-warmed successfully.")
    except Exception as e:
        logger.warning(f"Isolation Forest pre-warm failed (non-fatal, will retry on first request): {e}")

    # ── 6. Start Neo4j Graph Sync Worker (Optional in-process runner) ────
    import os
    if os.getenv("RUN_EMBEDDED_WORKER", "false").lower() == "true":
        logger.info("Starting embedded background Neo4j graph synchronization worker...")
        asyncio.create_task(run_sync_worker(shutdown_event=_worker_shutdown_event))
    else:
        logger.info("Embedded graph sync worker disabled (running as standalone service).")

    # ── 7. Start Periodic Background Watchlist Sync Task ─────────────────
    if not allow_offline:
        from services.watchlist_sync import schedule_periodic_watchlist_sync
        logger.info("Starting background periodic watchlist sync task...")
        asyncio.create_task(schedule_periodic_watchlist_sync(interval_seconds=86400, shutdown_event=_worker_shutdown_event))

    # ── 8. Start Distributed Redis WebSocket PubSub Listener ───────────
    if not allow_offline:
        from routers.metrics import ws_manager, start_redis_ws_listener
        logger.info("Starting distributed Redis WebSocket pubsub listener task...")
        asyncio.create_task(start_redis_ws_listener(ws_manager, shutdown_event=_worker_shutdown_event))

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

    # Shutdown OpenTelemetry tracer
    try:
        from opentelemetry import trace
        provider = trace.get_tracer_provider()
        if hasattr(provider, "shutdown"):
            provider.shutdown()
    except Exception:
        pass
