"""
Hardened Health Check Endpoints
================================
Provides secure, topology-masked health endpoints:

  - ``/health/live`` (Shallow Liveness):
      Publicly accessible for Kubernetes liveness probes. Returns 200 OK.

  - ``/health`` (Deep Readiness & Topology Protection):
      Pings backing services (PostgreSQL, Redis, Neo4j, Elasticsearch).
      - Unauthenticated callers (e.g. public / standard K8s readiness probes):
        Returns minimal 200 (healthy) or 503 (degraded) WITHOUT revealing service names,
        latencies, or exception trace details.
      - Authenticated callers (valid Bearer JWT or matching X-Health-Token):
        Returns full detailed component breakdown for monitoring & internal diagnostics.
"""

import logging
import os
import time
from typing import Optional

from fastapi import APIRouter, Header, Request, Depends
from fastapi.responses import JSONResponse
from config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Health"])


def is_authenticated_health_request(
    authorization: Optional[str] = Header(None),
    x_health_token: Optional[str] = Header(None),
) -> bool:
    """
    Validates whether the health request contains proper diagnostic clearance.
    Clearance granted via:
      1. Matching X-Health-Token header (matching HEALTH_CHECK_SECRET env var)
      2. Valid Bearer JWT access token
    """
    health_secret = os.getenv("HEALTH_CHECK_SECRET")
    if health_secret and x_health_token == health_secret:
        return True

    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        try:
            from services.secrets_manager import decode_jwt_with_rotation

            decode_jwt_with_rotation(token, algorithm=settings.jwt_algorithm)
            return True
        except Exception:
            pass

    return False


@router.get("/health/live")
async def liveness():
    """Lightweight liveness probe — returns 200 if process is running."""
    return {"status": "alive"}


@router.get("/health/ready")
async def readiness_probe():
    """
    Decoupled readiness probe for Kubernetes.
    Verifies that the web process is running and can acquire a database connection,
    preventing cascading failure when secondary/asynchronous datastores (Neo4j, ES)
    are temporarily restarting or syncing.
    """
    try:
        from database.postgres import db_pool
        if db_pool is None:
            return JSONResponse(content={"status": "not_ready", "reason": "db_pool_uninitialized"}, status_code=503)
        async with db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"status": "ready"}
    except Exception as e:
        logger.warning(f"Readiness probe failed: {e}")
        return JSONResponse(content={"status": "not_ready"}, status_code=503)


@router.get("/health")
async def readiness(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_health_token: Optional[str] = Header(None),
):
    """
    Deep readiness probe with topology-masking defense.

    - Unauthenticated requests: Returns HTTP 200 or 503 with minimal status string only.
    - Authenticated requests: Returns detailed service topology metrics & latencies.
    """
    authenticated = is_authenticated_health_request(authorization, x_health_token)
    checks: dict[str, dict] = {}
    all_healthy = True

    # ── PostgreSQL ────────────────────────────────────────────────────────
    try:
        from database.postgres import db_pool

        t0 = time.monotonic()
        if db_pool is None:
            raise RuntimeError("Connection pool not initialised")
        async with db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        checks["postgres"] = {"status": "ok", "latency_ms": latency_ms}
    except Exception as e:
        checks["postgres"] = {"status": "error", "detail": str(e)}
        all_healthy = False

    # ── Redis ─────────────────────────────────────────────────────────────
    try:
        from database.redis_db import get_async_redis_client

        t0 = time.monotonic()
        redis_client = await get_async_redis_client()
        await redis_client.ping()
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        checks["redis"] = {"status": "ok", "latency_ms": latency_ms}
    except Exception as e:
        checks["redis"] = {"status": "error", "detail": str(e)}
        all_healthy = False

    # ── Neo4j ─────────────────────────────────────────────────────────────
    try:
        from database.neo4j_db import get_async_neo4j_driver

        t0 = time.monotonic()
        driver = await get_async_neo4j_driver()
        async with driver.session() as session:
            await session.run("RETURN 1")
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        checks["neo4j"] = {"status": "ok", "latency_ms": latency_ms}
    except Exception as e:
        checks["neo4j"] = {"status": "error", "detail": str(e)}
        all_healthy = False

    # ── Elasticsearch ─────────────────────────────────────────────────────
    try:
        from database.elasticsearch_db import get_async_elasticsearch_client

        t0 = time.monotonic()
        es = await get_async_elasticsearch_client()
        await es.info()
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        checks["elasticsearch"] = {"status": "ok", "latency_ms": latency_ms}
    except Exception as e:
        checks["elasticsearch"] = {"status": "error", "detail": str(e)}
        all_healthy = False

    status_code = 200 if all_healthy else 503

    if authenticated:
        # Full diagnostic report for internal authorized callers / monitoring dashboards
        body = {
            "status": "healthy" if all_healthy else "degraded",
            "checks": checks,
        }
    else:
        # Masked, non-disclosing response for public / unauthenticated readiness probes
        body = {
            "status": "healthy" if all_healthy else "degraded"
        }

    return JSONResponse(content=body, status_code=status_code)
