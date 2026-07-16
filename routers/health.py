"""
Health Check Endpoints
=======================
Provides ``/health`` (deep) and ``/health/live`` (shallow) endpoints
referenced by the Kubernetes liveness and readiness probes in fastapi-app.yaml.

Deep check (readiness):
    Pings PostgreSQL, Redis, Neo4j, and Elasticsearch.
    Returns 200 if all dependencies are reachable, 503 otherwise.

Shallow check (liveness):
    Always returns 200 — proves the process is alive and accepting HTTP.
"""

import logging
import time

from fastapi import APIRouter
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Health"])


@router.get("/health/live")
async def liveness():
    """Lightweight liveness probe — always 200 if the process is running."""
    return {"status": "alive"}


@router.get("/health")
async def readiness():
    """
    Deep readiness probe — verifies every backing service is reachable.

    Returns 200 when healthy, 503 when any dependency is down.
    """
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
        info = await es.info()
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        checks["elasticsearch"] = {"status": "ok", "latency_ms": latency_ms}
    except Exception as e:
        checks["elasticsearch"] = {"status": "error", "detail": str(e)}
        all_healthy = False

    status_code = 200 if all_healthy else 503
    body = {
        "status": "healthy" if all_healthy else "degraded",
        "checks": checks,
    }
    return JSONResponse(content=body, status_code=status_code)
