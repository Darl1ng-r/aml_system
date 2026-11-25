"""
IAM Microservice Application (Hardened Monolith Adapter)
========================================================
Maintains full security parity with `main.py` (fixes P1-09):
  - OpenAPI / Swagger disabled in hardened environments (production / prod / staging)
  - Full middleware stack: TrustedProxy, CorrelationId, SecurityHeaders, CORS (explicit headers),
    RequestBodySizeLimit, CSRFProtection
  - Shared sanitized exception handlers (strips Pydantic `input`, adds `correlation_id`)
  - Fail-closed Vault bootstrap in hardened environments
  - Non-disclosing health probes (`/health/live`, `/health/ready`, plus `/health/liveness`,
    `/health/readiness` compatibility aliases) with explicit `acquire(timeout=2.0)`
"""

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from config import settings
from observability.logging import setup_json_logging
from observability.middleware import CorrelationIdMiddleware, correlation_id_var
from routers import auth, jwks
from services.body_limit import RequestBodySizeLimitMiddleware
from services.csrf import CSRFProtectionMiddleware
from services.security_headers import SecurityHeadersMiddleware
from services.trusted_proxy import TrustedProxyMiddleware

logger = logging.getLogger(__name__)


@asynccontextmanager
async def iam_lifespan(app: FastAPI):
    """Lifecycle manager for the IAM microservice."""
    setup_json_logging(level=logging.INFO)
    logger.info("Bootstrapping IAM Microservice...")

    is_hardened = getattr(settings, "is_hardened", settings.is_production)

    # 0. Bootstrap Vault secrets (fail-closed in hardened environments)
    try:
        from services.vault_loader import VaultSecretsLoader
        await VaultSecretsLoader.bootstrap()
        logger.info("IAM Vault secrets loaded successfully.")
    except Exception as e:
        if is_hardened:
            logger.critical("IAM Vault secrets bootstrap failed in hardened environment: %s", e)
            raise
        logger.warning("IAM Vault secrets bootstrap skipped/offline: %s", e)

    from database.postgres import init_db_pool, close_db_pool
    from database.redis_db import get_redis_client, get_async_redis_client, close_redis_client
    from services.http_client import close_http_client

    allow_offline = bool(getattr(settings, "allow_offline_dev", False)) and not is_hardened

    try:
        await init_db_pool()
        logger.info("IAM PostgreSQL pool initialized.")
    except Exception:
        logger.exception("IAM PostgreSQL pool init failed")
        if not allow_offline:
            raise

    try:
        get_redis_client()
        await get_async_redis_client()
        logger.info("IAM Redis client connected.")
    except Exception as e:
        logger.warning("IAM Redis client init failed: %s", e)
        if not allow_offline:
            raise

    yield

    logger.info("Shutting down IAM Microservice connections...")
    for closer in (close_http_client, close_db_pool, close_redis_client):
        try:
            await closer()
        except Exception:
            pass
    try:
        from services.vault_loader import VaultSecretsLoader
        await VaultSecretsLoader.shutdown()
    except Exception:
        pass


_is_hardened = getattr(settings, "is_hardened", settings.is_production)

iam_app = FastAPI(
    title="AML IAM Microservice",
    description="Identity, RBAC, Multi-Factor Authentication & JWKS Authority",
    version="1.0.0",
    lifespan=iam_lifespan,
    docs_url=None if _is_hardened else "/docs",
    redoc_url=None if _is_hardened else "/redoc",
    openapi_url=None if _is_hardened else "/openapi.json",
)

# Middleware stack matching main.py (LIFO order)
iam_app.add_middleware(CSRFProtectionMiddleware)
iam_app.add_middleware(RequestBodySizeLimitMiddleware)

allowed_origins_raw = getattr(settings, "allowed_origins", "http://localhost:3000")
allowed_origins = [o.strip() for o in allowed_origins_raw.split(",") if o.strip()]
iam_app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins or ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-CSRF-Protection",
        "X-Requested-With",
        "Idempotency-Key",
        "X-Client-Mode",
        "X-API-Key",
        "Accept",
    ],
)
iam_app.add_middleware(SecurityHeadersMiddleware)
iam_app.add_middleware(CorrelationIdMiddleware)
iam_app.add_middleware(TrustedProxyMiddleware)


@iam_app.exception_handler(RequestValidationError)
async def iam_validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    sanitized = [
        {
            "loc": list(err.get("loc", [])),
            "msg": str(err.get("msg", "Invalid value")),
            "type": str(err.get("type", "value_error")),
        }
        for err in errors
    ]
    return JSONResponse(
        status_code=422,
        content={
            "detail": "; ".join(e["msg"] for e in sanitized) or "Invalid request data.",
            "errors": jsonable_encoder(sanitized),
            "correlation_id": correlation_id_var.get(""),
        },
    )


@iam_app.exception_handler(StarletteHTTPException)
async def iam_http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "correlation_id": correlation_id_var.get("")},
        headers=getattr(exc, "headers", None),
    )


@iam_app.exception_handler(Exception)
async def iam_global_exception_handler(request: Request, exc: Exception):
    cid = correlation_id_var.get("")
    logger.error("Unhandled IAM exception: %s", exc, exc_info=exc, extra={"correlation_id": cid})
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred.", "correlation_id": cid},
    )


iam_app.include_router(jwks.router)
iam_app.include_router(auth.router)


@iam_app.get("/health/live", tags=["Health"])
@iam_app.get("/health/liveness", tags=["Health"])
async def liveness():
    """Liveness probe: verifies the process is responsive."""
    return {"status": "UP", "service": "iam-service"}


@iam_app.get("/health/ready", tags=["Health"])
@iam_app.get("/health/readiness", tags=["Health"])
async def readiness():
    """Readiness probe: verifies PostgreSQL and Redis without disclosing raw error strings."""
    from database.postgres import get_db_pool
    from database.redis_db import get_async_redis_client

    checks: Dict[str, Any] = {"postgres": False, "redis": False}
    try:
        pool = await get_db_pool()
        if pool:
            async with pool.acquire(timeout=2.0) as conn:
                res = await conn.fetchval("SELECT 1;")
                checks["postgres"] = (res == 1)
    except Exception as e:
        logger.warning("IAM readiness PostgreSQL probe failed: %s", e)

    try:
        redis_client = await get_async_redis_client()
        if redis_client:
            pong = await asyncio.wait_for(redis_client.ping(), timeout=1.5)
            checks["redis"] = (pong is True)
    except Exception as e:
        logger.warning("IAM readiness Redis probe failed: %s", e)

    is_hardened = getattr(settings, "is_hardened", settings.is_production)
    is_ready = checks["postgres"] and (checks["redis"] if is_hardened else True)
    status_code = status.HTTP_200_OK if is_ready else status.HTTP_503_SERVICE_UNAVAILABLE
    return Response(
        content=json.dumps({"status": "UP" if is_ready else "DOWN", "checks": checks}),
        status_code=status_code,
        media_type="application/json",
    )


app = iam_app
