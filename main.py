from fastapi import FastAPI, Response, Header, HTTPException, status
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import os
from contextlib import asynccontextmanager
from routers import onboarding, screening, transactions, alerts, auth, rules, network
from routers import health, metrics, fincen, str_batch, ml_feedback, watchlist, jwks
from routers import cases, accounts, ctr, compliance_reporting, privacy, locks, evidence, audit, customers, siem, risk_appetite, webhooks, sso, search, notifications, qa, rfi, jobs
from database.neo4j_db import close_neo4j_driver
from config import settings
from observability.logging import setup_json_logging
from observability.middleware import (
    CorrelationIdMiddleware,
    ReadAfterWriteStickinessMiddleware,
    RequestTimeoutMiddleware,
)
from observability.event_loop_monitor import event_loop_monitor
from services.trusted_proxy import TrustedProxyMiddleware
from services.csrf import CSRFProtectionMiddleware
import asyncio
import hmac
import logging

# ── Structured JSON logging (called early; re-applied after Alembic in startup) ──
setup_json_logging(level=logging.INFO)
logger = logging.getLogger(__name__)

MIME_TEXT_HTML = "text/html"
LOGIN_ROUTE = "/login"

# Shutdown event shared between the FastAPI app and the sync worker
_worker_shutdown_event = asyncio.Event()

# Task reference retention to prevent premature garbage collection
_background_tasks: set[asyncio.Task] = set()


def create_background_task(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


_observability_initialized = False


def _init_observability(app_instance: FastAPI) -> None:
    import sys
    global _observability_initialized
    if _observability_initialized:
        return
    _observability_initialized = True

    # 0c. Initialise OpenTelemetry tracing (skip live OTLP gRPC socket exporter during pytest)
    if "pytest" not in sys.modules and not os.getenv("PYTEST_CURRENT_TEST"):
        try:
            from observability.tracing import init_tracer
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            init_tracer(
                service_name=settings.otel_service_name,
                endpoint=settings.otel_exporter_endpoint,
            )
            FastAPIInstrumentor.instrument_app(app_instance)
            logger.info("OpenTelemetry FastAPI instrumentation enabled.")
        except Exception as e:
            logger.warning(f"OpenTelemetry init skipped (non-fatal): {e}")

    # 0d. Initialise Sentry error tracking with mandatory PII/SAR before_send scrubber
    if getattr(settings, "sentry_dsn", None):
        try:
            import sentry_sdk
            from observability.logging import sentry_before_send_scrubber
            sentry_sdk.init(
                dsn=settings.sentry_dsn,
                environment=settings.environment,
                traces_sample_rate=settings.sentry_traces_sample_rate,
                send_default_pii=False,
                before_send=sentry_before_send_scrubber,
            )
            logger.info("Sentry APM & error tracking initialized (PII scrubbing enabled).")
        except Exception as e:
            logger.warning(f"Sentry init skipped (non-fatal): {e}")


async def _init_postgres_and_migrations(allow_offline: bool) -> bool:
    from database.postgres import init_db_pool
    pg_connected = False
    try:
        await init_db_pool()
        pg_connected = True
    except Exception as e:
        logger.critical(f"CRITICAL: Could not initialize PostgreSQL: {e}")
        if not allow_offline:
            raise RuntimeError("PostgreSQL database initialization failed") from e
        logger.warning("ALLOW_OFFLINE_DEV active: Continuing without PostgreSQL connection.")

    run_migrations = getattr(settings, "run_migrations_on_startup", False) or os.getenv("RUN_MIGRATIONS_ON_STARTUP", "false").lower() == "true"
    if pg_connected and run_migrations:
        try:
            from alembic.config import Config as AlembicConfig
            from alembic import command as alembic_command
            alembic_cfg = AlembicConfig("alembic.ini")
            await asyncio.to_thread(alembic_command.upgrade, alembic_cfg, "head")
            setup_json_logging(level=logging.INFO)
            logger.info("Alembic database migrations applied successfully.")
        except Exception as e:
            logger.critical(f"CRITICAL: Alembic migration failed: {e}")
            if not allow_offline:
                raise RuntimeError("Database migration failed") from e
            logger.warning("ALLOW_OFFLINE_DEV active: Continuing without running Alembic migrations.")
    elif pg_connected:
        logger.info("Startup Alembic migrations skipped (managed via dedicated Kubernetes Job).")
    return pg_connected


async def _init_redis(allow_offline: bool) -> None:
    from database.redis_db import (
        get_async_cache_redis_client,
        get_async_redis_client,
        get_redis_client,
    )
    try:
        get_redis_client()
        await get_async_redis_client()
    except Exception as e:
        logger.critical(f"CRITICAL: Could not connect to Redis: {e}")
        if not allow_offline:
            raise RuntimeError("Redis state store is required for startup") from e
        logger.warning("ALLOW_OFFLINE_DEV active: Continuing without Redis connection.")

    # Fail-open warmup of dedicated Cache Redis (allkeys-lfu, <= 200ms timeout)
    try:
        await get_async_cache_redis_client()
    except Exception as e:
        logger.warning("Dedicated Cache Redis warmup skipped (failing open to DB): %s", e)


async def startup_db_clients(app_instance: FastAPI):
    logger.info("Starting up database connections...")
    from services.vault_loader import VaultSecretsLoader
    from services.tls_manager import validate_mtls_configuration

    # 0. Bootstrap Vault secrets (must be FIRST — all subsequent steps depend on it)
    try:
        await VaultSecretsLoader.bootstrap()
        logger.info("Vault secrets loaded successfully.")
    except RuntimeError as e:
        logger.critical(f"CRITICAL: Vault secrets bootstrap failed: {e}")
        raise

    # 0b. TLS/mTLS validation
    validate_mtls_configuration(strict=settings.strict_mtls or settings.enable_tls)

    # 0c & 0d. Observability
    _init_observability(app_instance)

    # P0-08: Single source of truth — never let raw os.getenv("ALLOW_OFFLINE_DEV") override settings.allow_offline_dev
    allow_offline = bool(getattr(settings, "allow_offline_dev", False)) and not getattr(
        settings, "is_hardened", settings.is_production
    )

    # 1. PostgreSQL & Migrations
    await _init_postgres_and_migrations(allow_offline)

    # 2. Redis
    await _init_redis(allow_offline)

    # Tier 2 (Soft Dependencies & Warmup): Async Non-Blocking
    create_background_task(warm_soft_dependencies(allow_offline))


async def warm_soft_dependencies(allow_offline: bool):
    """Asynchronously initializes and pre-warms soft dependencies without blocking startup (Finding #1)."""
    from database.neo4j_db import get_neo4j_driver, get_async_neo4j_driver
    from database.elasticsearch_db import get_elasticsearch_client, get_async_elasticsearch_client
    from scripts.sync_worker import main as run_sync_worker

    # 3. Initialize Neo4j only when explicitly enabled (P2-22)
    if getattr(settings, "enable_neo4j", False):
        try:
            get_neo4j_driver()
            await get_async_neo4j_driver()
            logger.info("Neo4j database connection established.")
        except Exception as e:
            logger.warning(f"Neo4j async warmup warning: {e}")

    # 4. Initialize Elasticsearch only when explicitly enabled (P2-22)
    if getattr(settings, "enable_elasticsearch", False):
        try:
            get_elasticsearch_client()
            es_async = await get_async_elasticsearch_client()
            from services.watchlist_sync import watchlist_sync_engine
            await watchlist_sync_engine.ensure_indices_and_seed(es_async)
            logger.info("Elasticsearch sanctions and PEP indices verified and seeded.")
        except Exception as e:
            logger.warning(f"Elasticsearch async warmup warning: {e}")

    # 5. Pre-warm Isolation Forest model
    try:
        from services.isolation_forest import retrain_system_iforest
        await retrain_system_iforest()
        logger.info("Isolation Forest model pre-warmed successfully.")
    except Exception as e:
        logger.warning(f"Isolation Forest pre-warm warning: {e}")

    # 6. Start Neo4j Graph Sync Worker only when embedded worker & Neo4j are enabled (P2-21)
    if bool(getattr(settings, "run_embedded_worker", False)) and getattr(settings, "enable_neo4j", False):
        logger.info("Starting embedded background Neo4j graph synchronization worker...")
        create_background_task(run_sync_worker(shutdown_event=_worker_shutdown_event))

    # 7. Start Periodic Background Watchlist Sync Task
    if not allow_offline and getattr(settings, "enable_elasticsearch", False):
        from services.watchlist_sync import schedule_periodic_watchlist_sync
        logger.info("Starting background periodic watchlist sync task...")
        create_background_task(schedule_periodic_watchlist_sync(interval_seconds=86400, shutdown_event=_worker_shutdown_event))

    # 8. Start Distributed Redis WebSocket PubSub Listener
    if not allow_offline:
        from routers.metrics import ws_manager, start_redis_ws_listener
        logger.info("Starting distributed Redis WebSocket pubsub listener task...")
        create_background_task(start_redis_ws_listener(ws_manager, shutdown_event=_worker_shutdown_event))

    # 9. Start Distributed Redis Rules Invalidation Listener
    if not allow_offline:
        from services.rules import start_redis_rules_listener
        logger.info("Starting distributed Redis rules cache invalidation listener task...")
        create_background_task(start_redis_rules_listener(shutdown_event=_worker_shutdown_event))

    # 10. Start Distributed Redis Whitelist Invalidation Listener
    if not allow_offline:
        from services.whitelisting import start_redis_whitelist_listener
        logger.info("Starting distributed Redis whitelist cache invalidation listener task...")
        create_background_task(start_redis_whitelist_listener(shutdown_event=_worker_shutdown_event))



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
    from database.postgres import close_db_pool
    from database.neo4j_db import close_neo4j_driver, close_async_neo4j_driver
    from database.elasticsearch_db import close_elasticsearch_clients
    from database.redis_db import close_redis_client
    from services.http_client import close_http_client

    try:
        await close_http_client()
    except Exception as e:
        logger.warning(f"Failed to close shared HTTP client: {e}")

    try:
        await close_db_pool()
    except Exception as e:
        logger.warning(f"Failed to close asyncpg pool: {e}")

    try:
        close_neo4j_driver()
        await close_async_neo4j_driver()
    except Exception as e:
        logger.warning(f"Failed to close Neo4j drivers: {e}")

    try:
        await close_elasticsearch_clients()
    except Exception as e:
        logger.warning(f"Failed to close Elasticsearch clients: {e}")

    try:
        await close_redis_client()
    except Exception as e:
        logger.warning(f"Failed to close Redis clients: {e}")

    # Cancel background Vault lease renewal task if running
    try:
        from services.vault_loader import VaultSecretsLoader
        await VaultSecretsLoader.shutdown()
    except Exception:
        pass

    # Shutdown OpenTelemetry tracer
    try:
        from opentelemetry import trace
        provider = trace.get_tracer_provider()
        if hasattr(provider, "shutdown"):
            provider.shutdown()
    except Exception:
        pass


_outbox_shutdown_event = asyncio.Event()
_outbox_relay_task: Optional[asyncio.Task] = None


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    global _outbox_relay_task
    health.reset_server_draining()
    await startup_db_clients(app_instance)

    # P2-21: Consistent single source of truth via settings.run_embedded_worker
    run_embedded = bool(getattr(settings, "run_embedded_worker", False))
    if run_embedded:
        from database.outbox import OutboxRelayEngine
        _outbox_shutdown_event.clear()
        relay_engine = OutboxRelayEngine(poll_interval_seconds=1.0, batch_size=50)
        _outbox_relay_task = asyncio.create_task(
            relay_engine.run(shutdown_event=_outbox_shutdown_event),
            name="outbox-relay-engine"
        )
        logger.info("Transactional Outbox Relay Engine started in embedded worker mode.")
    else:
        logger.info("RUN_EMBEDDED_WORKER=false; skipping embedded Outbox Relay (handled by dedicated worker).")

    # Start AsyncIO Event-Loop Lag Watchdog & Storage Telemetry Sampler (skip under pytest)
    import sys as _sys
    _storage_monitor_task = None
    if "pytest" not in _sys.modules and not os.getenv("PYTEST_CURRENT_TEST"):
        event_loop_monitor.start()
        logger.info("AsyncIO event-loop lag monitor started (100ms sampling interval).")
        from observability.storage_monitor import start_storage_monitor

        _storage_monitor_task = asyncio.create_task(
            start_storage_monitor(interval_seconds=15.0, shutdown_event=_worker_shutdown_event),
            name="storage-observability-monitor",
        )

    yield

    # Immediately flip /health/ready -> 503 {"status": "draining"} while keeping /health/live -> 200
    # so ingress/Service endpoints deregister this pod cleanly before resources close.
    health.mark_server_draining()
    logger.info("Server entering graceful drain mode (/health/ready -> 503).")

    # Stop Event-Loop Lag Watchdog, Storage Monitor & compute bulkhead executors cleanly
    if _storage_monitor_task is not None and not _storage_monitor_task.done():
        _storage_monitor_task.cancel()
        try:
            await _storage_monitor_task
        except (asyncio.CancelledError, Exception):
            pass
    try:
        await event_loop_monitor.stop()
    except Exception:
        pass
    try:
        from services.compute_executor import shutdown_compute_executors
        shutdown_compute_executors(wait=False)
    except Exception:
        pass

    # Shutdown Outbox Relay Engine gracefully
    if _outbox_relay_task:
        logger.info("Signaling Outbox Relay Engine shutdown...")
        _outbox_shutdown_event.set()
        try:
            await asyncio.wait_for(_outbox_relay_task, timeout=5.0)
            logger.info("Outbox Relay Engine stopped gracefully.")
        except (asyncio.TimeoutError, asyncio.CancelledError):
            logger.warning("Outbox Relay shutdown timed out (5s); cancelling task.")
            _outbox_relay_task.cancel()
            try:
                await _outbox_relay_task
            except (asyncio.CancelledError, Exception):
                pass
        _outbox_relay_task = None

    # Cancel Vault background secret renewal loop cleanly to prevent leaked tasks
    try:
        from services.vault_loader import VaultSecretsLoader
        renewal_task = getattr(VaultSecretsLoader, "_renewal_task", None)
        if renewal_task and not renewal_task.done():
            renewal_task.cancel()
            try:
                await renewal_task
            except (asyncio.CancelledError, Exception):
                pass
            VaultSecretsLoader._renewal_task = None
    except Exception:
        pass

    await shutdown_db_clients()


is_hardened_env = getattr(settings, "is_hardened", settings.is_production)

app = FastAPI(
    title="AML Compliance & Transaction Monitoring API",
    description="Synchronous transaction scoring and asynchronous graph auditing platform.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if is_hardened_env else "/docs",
    redoc_url=None if is_hardened_env else "/redoc",
    openapi_url=None if is_hardened_env else "/openapi.json"
)

# ── Middleware (Starlette LIFO: registered bottom-up, outermost runs FIRST) ─
# 8. Innermost: Response GZip compression for API JSON and static assets
from starlette.middleware.gzip import GZipMiddleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

# 7. Anti-CSRF protection middleware (includes Login-CSRF Origin check)
app.add_middleware(CSRFProtectionMiddleware)

# 6. Pure-ASGI global request body size limit + pre-spool RFI token validation (P1-02, P1-03)
from services.body_limit import RequestBodySizeLimitMiddleware
app.add_middleware(RequestBodySizeLimitMiddleware)

# 5. CORS for frontend dashboard console (strict method & header allowlists)
allowed_origins_list = [origin.strip() for origin in settings.allowed_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-CSRF-Protection",
        "X-Requested-With",
        "Idempotency-Key",
        "X-Idempotency-Key",
        "If-Match",
        "If-None-Match",
        "X-Read-Consistency",
        "X-Client-Mode",
        "X-API-Key",
        "Accept",
    ],
    expose_headers=[
        "ETag",
        "Idempotency-Replayed",
        "X-Correlation-ID",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "Retry-After",
        "X-Total-Count",
        "X-Next-Cursor",
        "X-Has-More",
        "X-Read-Consistency-Window",
        "X-Load-Shed-Tier",
        "X-Load-Shed-Reason",
    ],
)

# 4. Browser security hardening headers (CSP, X-Frame-Options, nosniff, Cache-Control: no-store)
from services.security_headers import SecurityHeadersMiddleware
app.add_middleware(SecurityHeadersMiddleware)

# 3d. Pure-ASGI Priority-Tiered Adaptive Load Shedding (protects P0 auth/writes from overload collapse)
from observability.load_shedding import AdaptiveLoadSheddingMiddleware
app.add_middleware(AdaptiveLoadSheddingMiddleware)

# 3c. Pure-ASGI Read-After-Write Primary stickiness guard (prevents stale replica reads after mutations)
app.add_middleware(ReadAfterWriteStickinessMiddleware)

# 3b. Pure-ASGI bounded request deadline guard (20s default; 60s for exports/packets/network)
app.add_middleware(RequestTimeoutMiddleware, default_timeout_seconds=20.0, extended_timeout_seconds=60.0)

# 3. Correlation-ID & request telemetry middleware (pure ASGI)
app.add_middleware(CorrelationIdMiddleware)

# 2. Trusted Host enforcement in hardened environments when ALLOWED_HOSTS is configured (P2-09)
_allowed_hosts_raw = getattr(settings, "allowed_hosts", "").strip()
if is_hardened_env and _allowed_hosts_raw:
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    _hosts = [h.strip() for h in _allowed_hosts_raw.split(",") if h.strip()]
    if _hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=_hosts)

# 1. Outermost (runs FIRST on every request): Trusted proxy IP resolution
app.add_middleware(TrustedProxyMiddleware)

# Include Routers
app.include_router(health.router)  # /health, /health/live, /health/ready — must be before static mount


from fastapi import Depends
from services.rate_limiter import RateLimiter


@app.get("/metrics", tags=["Observability"], summary="Prometheus Metrics Scrape Endpoint")
def prometheus_metrics(
    authorization: Optional[str] = Header(None),
    x_metrics_token: Optional[str] = Header(None),
    _rate_limit=Depends(RateLimiter(limit=120, window=60, ip_only=True)),
):
    """Exposes internal compliance, SLO, and performance metrics in Prometheus exposition format."""
    metrics_secret = getattr(settings, "metrics_secret", "") or os.getenv("METRICS_SECRET", "")
    is_hardened_now = getattr(settings, "is_hardened", settings.is_production)
    # PRR: Fail-closed in production & staging or whenever METRICS_SECRET is configured
    if is_hardened_now or metrics_secret:
        token = None
        if authorization and authorization.startswith("Bearer "):
            token = authorization[7:].strip()
        elif x_metrics_token:
            token = x_metrics_token.strip()
        if not metrics_secret or not token or not hmac.compare_digest(token, metrics_secret):
            raise HTTPException(
                status_code=401,
                detail="Unauthorized metrics scrape access.",
                headers={"WWW-Authenticate": "Bearer"},
            )

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
app.include_router(cases.router)
app.include_router(accounts.router)
app.include_router(accounts.edd_router)
app.include_router(ctr.router)
app.include_router(compliance_reporting.router)
app.include_router(privacy.router)
app.include_router(locks.router)
app.include_router(evidence.router)
app.include_router(audit.router)
app.include_router(customers.router)
app.include_router(siem.router)
app.include_router(webhooks.router)
app.include_router(sso.router)
app.include_router(search.router)
app.include_router(notifications.router)
app.include_router(qa.router)
app.include_router(rfi.router)
app.include_router(risk_appetite.router)
app.include_router(jobs.router)

# Mount static files directory for dashboard styling and frontend client logic
class VersionedStaticFiles(StaticFiles):
    """Serves versioned static assets (?v=...) with immutable caching to eliminate 304 stalls during page navigation."""

    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            qs = (scope.get("query_string") or b"").decode("latin-1")
            if "v=" in qs:
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
                response.headers["CDN-Cache-Control"] = "public, max-age=31536000, immutable"
            else:
                response.headers["Cache-Control"] = "public, max-age=300"
                response.headers["CDN-Cache-Control"] = "public, max-age=300, stale-while-revalidate=60"
        return response


app.mount("/static", VersionedStaticFiles(directory="static"), name="static")

# Initialize OpenTelemetry FastAPI instrumentation & Sentry PII-scrubbing at app setup time
_init_observability(app)

# ── Exception Handlers ───────────────────────────────────────────────────
from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from observability.middleware import correlation_id_var, get_current_trace_id

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """P1-04: Strip raw `input` payloads from Pydantic v2 errors to prevent secret echoing."""
    errors = exc.errors()
    messages = []
    sanitized_errors = []
    for err in errors:
        loc_raw = err.get("loc", [])
        loc = ".".join(str(l) for l in loc_raw if l != "body")
        msg = err.get("msg", "Invalid value")
        messages.append(f"{loc}: {msg}" if loc else msg)
        sanitized_errors.append(
            {
                "loc": list(loc_raw) if isinstance(loc_raw, (list, tuple)) else [str(loc_raw)],
                "msg": str(msg),
                "type": str(err.get("type", "value_error")),
            }
        )
    friendly_msg = "; ".join(messages) if messages else "Invalid request data."
    correlation_id = correlation_id_var.get("")
    trace_id = get_current_trace_id()
    resp_headers = {"X-Trace-ID": trace_id} if trace_id else None
    return JSONResponse(
        status_code=422,
        content={
            "detail": friendly_msg,
            "errors": jsonable_encoder(sanitized_errors),
            "correlation_id": correlation_id,
            "trace_id": trace_id,
        },
        headers=resp_headers,
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    accept = request.headers.get("accept", "")
    if exc.status_code == 404 and MIME_TEXT_HTML in accept and os.path.exists("static/404.html"):
        return FileResponse("static/404.html", status_code=404)
    correlation_id = correlation_id_var.get("")
    trace_id = get_current_trace_id()
    merged_headers = dict(getattr(exc, "headers", None) or {})
    if trace_id:
        merged_headers["X-Trace-ID"] = trace_id
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "correlation_id": correlation_id,
            "trace_id": trace_id,
        },
        headers=merged_headers or None,
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    correlation_id = correlation_id_var.get("")
    trace_id = get_current_trace_id()
    logger.error(
        f"Unhandled application exception: {exc}",
        exc_info=exc,
        extra={"correlation_id": correlation_id, "trace_id": trace_id}
    )
    accept = request.headers.get("accept", "")
    if MIME_TEXT_HTML in accept and os.path.exists("static/500.html"):
        err_headers = {"X-Correlation-ID": correlation_id}
        if trace_id:
            err_headers["X-Trace-ID"] = trace_id
        return FileResponse(
            "static/500.html",
            status_code=500,
            headers=err_headers,
        )
    resp_headers = {"X-Trace-ID": trace_id} if trace_id else None
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal server error occurred.",
            "correlation_id": correlation_id,
            "trace_id": trace_id,
        },
        headers=resp_headers,
    )

@app.get("/robots.txt", response_class=FileResponse)
def read_robots():
    return FileResponse("static/robots.txt", media_type="text/plain")

@app.get("/sitemap.xml", response_class=FileResponse)
def read_sitemap():
    return FileResponse("static/sitemap.xml", media_type="application/xml")

@app.get("/")
def read_root(request: Request):
    accept = request.headers.get("accept", "")
    if "application/json" in accept and MIME_TEXT_HTML not in accept:
        return {
            "status": "ONLINE",
            "service": "AML Platform Ingestion Gateway",
            "version": "1.0.0"
        }
    return FileResponse("static/landing.html")

@app.get("/landing", response_class=FileResponse)
def read_landing():
    return FileResponse("static/landing.html")

SENTINEL_ASSET_VERSION = "20261125-cp1"
_TOPBAR_PARTIAL_PATH = "static/partials/topbar.html"
_WORKSPACE_HTML_CACHE: dict[tuple, tuple[str, str]] = {}


def _build_head_assets_snippet() -> str:
    return (
        f'<link rel="stylesheet" href="/static/style.css?v={SENTINEL_ASSET_VERSION}">\n'
        f'  <script src="/static/api-client.js?v={SENTINEL_ASSET_VERSION}"></script>\n'
        f'  <script src="/static/sentinel-query.js?v={SENTINEL_ASSET_VERSION}"></script>\n'
        f'  <script src="/static/sentinel-shell.js?v={SENTINEL_ASSET_VERSION}" defer></script>'
    )


def _render_workspace_page(
    static_file_path: str,
    active_nav: Optional[str] = None,
    header_class: str = "header-nav",
) -> tuple[str, str]:
    """
    Server-side composition of ONE shared topbar partial (`static/partials/topbar.html`)
    and unified head assets into each workspace page, cached by `(page_mtime, partial_mtime)`.
    Returns `(rendered_html, strong_etag)`.
    """
    import hashlib

    page_mtime = os.path.getmtime(static_file_path)
    partial_mtime = os.path.getmtime(_TOPBAR_PARTIAL_PATH) if os.path.exists(_TOPBAR_PARTIAL_PATH) else 0.0
    cache_key = (static_file_path, active_nav or "", header_class, SENTINEL_ASSET_VERSION, page_mtime, partial_mtime)

    cached = _WORKSPACE_HTML_CACHE.get(cache_key)
    if cached is not None:
        return cached

    with open(static_file_path, "r", encoding="utf-8") as fh:
        page_html = fh.read()

    if "<!-- @SENTINEL_HEAD_ASSETS -->" in page_html:
        page_html = page_html.replace("<!-- @SENTINEL_HEAD_ASSETS -->", _build_head_assets_snippet(), 1)

    if "<!-- @SENTINEL_TOPBAR -->" in page_html and os.path.exists(_TOPBAR_PARTIAL_PATH):
        with open(_TOPBAR_PARTIAL_PATH, "r", encoding="utf-8") as pfh:
            topbar_html = pfh.read()

        active_key = (active_nav or "").strip().lower()
        replacements = {
            "{{HEADER_CLASS}}": header_class,
            "{{ACTIVE_OVERVIEW}}": " active" if active_key == "overview" else "",
            "{{ARIA_OVERVIEW}}": ' aria-current="page"' if active_key == "overview" else "",
            "{{ACTIVE_TRIAGE}}": " active" if active_key == "triage" else "",
            "{{ARIA_TRIAGE}}": ' aria-current="page"' if active_key == "triage" else "",
            "{{ACTIVE_INVESTIGATIONS}}": " active" if active_key == "investigations" else "",
            "{{ARIA_INVESTIGATIONS}}": ' aria-current="page"' if active_key == "investigations" else "",
            "{{ACTIVE_NETWORK}}": " active" if active_key == "network" else "",
            "{{ARIA_NETWORK}}": ' aria-current="page"' if active_key == "network" else "",
        }
        for token, val in replacements.items():
            topbar_html = topbar_html.replace(token, val)

        page_html = page_html.replace("<!-- @SENTINEL_TOPBAR -->", topbar_html.strip(), 1)

    etag = f'"{hashlib.sha256(page_html.encode("utf-8")).hexdigest()[:24]}"'

    # Keep cache bounded if files are edited repeatedly during dev reloads
    if len(_WORKSPACE_HTML_CACHE) > 64:
        _WORKSPACE_HTML_CACHE.clear()
    _WORKSPACE_HTML_CACHE[cache_key] = (page_html, etag)
    return page_html, etag


def _serve_authenticated_page(
    request: Request,
    static_file_path: str,
    active_nav: Optional[str] = None,
    header_class: str = "header-nav",
):
    """
    Server-side cryptographic cookie authentication guard for all HTML workspace routes (S-9).
    Verifies JWT signature via decode_jwt_with_rotation() and enforces type == 'access'.
    Composes the single shared topbar component and enforces strict HTML revalidation
    (`Cache-Control: private, no-cache, must-revalidate`) so browsers never serve stale page HTML.
    """
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_303_SEE_OTHER)

    try:
        from services.secrets_manager import decode_jwt_with_rotation
        payload = decode_jwt_with_rotation(token)
        if not payload or payload.get("type") != "access":
            return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_303_SEE_OTHER)
    except Exception:
        return RedirectResponse(url=LOGIN_ROUTE, status_code=status.HTTP_303_SEE_OTHER)

    rendered_html, etag = _render_workspace_page(
        static_file_path,
        active_nav=active_nav,
        header_class=header_class,
    )
    headers = {
        "Cache-Control": "private, no-cache, must-revalidate",
        "CDN-Cache-Control": "no-store",
        "Pragma": "no-cache",
        "ETag": etag,
    }
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)
    return HTMLResponse(content=rendered_html, headers=headers)


@app.get("/dashboard")
def read_dashboard(request: Request):
    """Server-side cookie authentication guard for compliance dashboard."""
    return _serve_authenticated_page(request, "static/index.html", active_nav="investigations", header_class="topbar")

@app.get(LOGIN_ROUTE, response_class=FileResponse)
def read_login():
    return FileResponse("static/login.html")

@app.get("/rfi/{token}", response_class=FileResponse)
def read_external_rfi_portal(token: str):
    """Public white-label Customer/RM RFI upload portal (token-gated via /api/v1/rfi/public/{token})."""
    return FileResponse("static/rfi-portal.html")

@app.get("/alerts/triage")
@app.get("/triage")
def read_triage(request: Request):
    """Server-side cookie authentication guard for Alert Triage Inbox."""
    return _serve_authenticated_page(request, "static/triage.html", active_nav="triage", header_class="triage-nav")

@app.get("/admin/rules")
@app.get("/rules-admin")
def read_rules_admin(request: Request):
    """Server-side cookie authentication guard for Rule Builder & Tuner."""
    return _serve_authenticated_page(request, "static/rules-admin.html", active_nav=None, header_class="rules-nav")

@app.get("/admin/users")
@app.get("/users-admin")
def read_users_admin(request: Request):
    """Server-side cookie authentication guard for User & Permissions Governance."""
    return _serve_authenticated_page(request, "static/users-admin.html", active_nav=None, header_class="users-nav")

@app.get("/sar/draft/{id}")
@app.get("/sar/drafts/{id}")
@app.get("/sar/editor")
def read_sar_editor(request: Request, id: str = None):
    """Server-side cookie authentication guard for SAR Draft Editor."""
    return _serve_authenticated_page(request, "static/sar-editor.html", active_nav=None, header_class="header-nav")

@app.get("/sar/queue")
@app.get("/sar/filings")
def read_sar_queue(request: Request):
    """Server-side cookie authentication guard for MLRO SAR Filing Queue."""
    return _serve_authenticated_page(request, "static/sar-queue.html", active_nav=None, header_class="header-nav")

@app.get("/customers/{id}")
@app.get("/customers")
def read_customer_360(request: Request, id: str = None):
    """Server-side cookie authentication guard for Customer 360 Dossier."""
    return _serve_authenticated_page(request, "static/customer-360.html", active_nav=None, header_class="header-nav")

@app.get("/network/{account_id}")
@app.get("/network")
def read_network_graph(request: Request, account_id: str = None):
    """Server-side cookie authentication guard for Network Graph Visualizer."""
    return _serve_authenticated_page(request, "static/network.html", active_nav="network", header_class="header-nav")

@app.get("/dashboard/executive")
@app.get("/executive")
def read_executive_dashboard(request: Request):
    """Server-side cookie authentication guard for Executive Compliance Dashboard."""
    return _serve_authenticated_page(request, "static/executive-dashboard.html", active_nav="overview", header_class="header-nav")

@app.get("/audit/logs")
@app.get("/audit")
def read_audit_vault(request: Request):
    """Server-side cookie authentication guard for Audit Log Vault."""
    return _serve_authenticated_page(request, "static/audit-vault.html", active_nav=None, header_class="header-nav")

@app.get("/admin/health")
@app.get("/health-admin")
def read_system_health(request: Request):
    """Server-side cookie authentication guard for Admin System Health."""
    return _serve_authenticated_page(request, "static/system-health.html", active_nav=None, header_class="header-nav")

@app.get("/ml/governance")
@app.get("/admin/ml-governance")
@app.get("/audit/model-reports")
def read_ml_governance(request: Request):
    """Server-side cookie authentication guard for ML Governance & Model Validation."""
    return _serve_authenticated_page(request, "static/ml-governance.html", active_nav=None, header_class="header-nav")

@app.get("/settings/risk-appetite")
@app.get("/risk-appetite")
def read_risk_appetite(request: Request):
    """Server-side cookie authentication guard for Institutional Risk Appetite Settings."""
    return _serve_authenticated_page(request, "static/risk-appetite.html", active_nav=None, header_class="header-nav")


@app.get("/compliance/ops")
@app.get("/ops")
def read_compliance_ops(request: Request):
    """Server-side cookie authentication guard for Compliance Operations Hub."""
    return _serve_authenticated_page(request, "static/compliance-ops.html", active_nav=None, header_class="navbar")



