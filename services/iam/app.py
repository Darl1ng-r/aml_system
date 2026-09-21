"""
IAM Microservice Application
=============================
Standalone FastAPI microservice for Identity and Access Management (IAM).
Handles tenant provisioning, user registration/login, MFA, password rotation,
API keys, and public JWKS distribution for edge API gateways (Envoy/Kong).
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Response, status
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from observability.logging import setup_json_logging
from observability.middleware import CorrelationIdMiddleware
from routers import auth, jwks

logger = logging.getLogger(__name__)


@asynccontextmanager
async def iam_lifespan(app: FastAPI):
    """Lifecycle manager for the IAM microservice."""
    setup_json_logging(level=logging.INFO)
    logger.info("Bootstrapping IAM Microservice...")

    # 0. Bootstrap Vault secrets before loading cryptographic keys or DB passwords
    try:
        from services.vault_loader import VaultSecretsLoader
        await VaultSecretsLoader.bootstrap()
        logger.info("IAM Vault secrets loaded successfully.")
    except Exception as e:
        logger.warning(f"IAM Vault secrets bootstrap skipped/offline: {e}")

    from database.postgres import init_db_pool, close_db_pool
    from database.redis_db import get_redis_client, get_async_redis_client, close_redis_client

    allow_offline = getattr(settings, "allow_offline_dev", False)

    # 1. Connect PostgreSQL pool
    try:
        await init_db_pool()
        logger.info("IAM PostgreSQL pool initialized.")
    except Exception as e:
        logger.error(f"IAM PostgreSQL pool init failed: {e}")
        if not allow_offline:
            raise

    # 2. Connect Redis client (used for session & lockout tracking)
    try:
        get_redis_client()
        await get_async_redis_client()
        logger.info("IAM Redis client connected.")
    except Exception as e:
        logger.warning(f"IAM Redis client init failed: {e}")

    yield

    # Clean shutdown
    logger.info("Shutting down IAM Microservice connections...")
    try:
        await close_db_pool()
    except Exception:
        pass
    try:
        await close_redis_client()
    except Exception:
        pass


iam_app = FastAPI(
    title="AML IAM Microservice",
    description="Identity, RBAC, Multi-Factor Authentication & JWKS Authority",
    version="1.0.0",
    lifespan=iam_lifespan,
)

# Correlation ID tracing middleware
iam_app.add_middleware(CorrelationIdMiddleware)

# Allowed CORS origins
allowed_origins_raw = getattr(settings, "allowed_origins", "http://localhost:3000,http://localhost:8000")
allowed_origins = [o.strip() for o in allowed_origins_raw.split(",") if o.strip()]
iam_app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins or ["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

# Include Authentication & Public Key routers
iam_app.include_router(jwks.router)
iam_app.include_router(auth.router)


@iam_app.get("/health/liveness", tags=["Health"])
async def liveness():
    """Liveness probe: verifies the process is responsive."""
    return {"status": "UP", "service": "iam-service"}


@iam_app.get("/health/readiness", tags=["Health"])
async def readiness():
    """Readiness probe: verifies PostgreSQL and Redis connections."""
    from database.postgres import get_db_pool
    from database.redis_db import get_async_redis_client

    checks: Dict[str, Any] = {"postgres": False, "redis": False}
    try:
        pool = await get_db_pool()
        if pool:
            async with pool.acquire() as conn:
                res = await conn.fetchval("SELECT 1;")
                checks["postgres"] = (res == 1)
    except Exception as e:
        checks["postgres_error"] = str(e)

    try:
        redis_client = await get_async_redis_client()
        if redis_client:
            pong = await redis_client.ping()
            checks["redis"] = (pong is True)
    except Exception as e:
        checks["redis_error"] = str(e)

    is_ready = checks.get("postgres", False)
    status_code = status.HTTP_200_OK if is_ready else status.HTTP_503_SERVICE_UNAVAILABLE
    return Response(
        content=f'{{"status": "{"UP" if is_ready else "DOWN"}", "checks": {checks}}}',
        status_code=status_code,
        media_type="application/json",
    )


# Standard alias for ASGI servers (uvicorn services.iam.app:app)
app = iam_app
