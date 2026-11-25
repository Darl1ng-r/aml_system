"""
Hardened Health Check Endpoints
================================
Provides secure, topology-masked, timeout-bounded health endpoints:
  - `/health/live`: Lightweight liveness probe (200 OK).
  - `/health/ready`: Decoupled K8s readiness probe with explicit acquire(timeout=2.0)
    plus Tier-1 Redis verification in hardened environments; returns opaque status.
  - `/health`: Deep readiness probe rate-limited & cached (5s TTL) to prevent DoS;
    respects `enable_neo4j` / `enable_elasticsearch` flags; restricts diagnostic
    breakdown to `X-Health-Token` or revoked-checked `SUPER_ADMIN` JWT and NEVER
    exposes raw `str(e)` driver errors (fixes P1-06, P2-03, P2-17, P2-22).
"""

import asyncio
import hmac
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse

from config import settings
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

SQL_PING_QUERY = "SELECT 1"

router = APIRouter(tags=["Health"])

# Short 5s cache for deep /health checks to prevent unauthenticated DB/Redis ping amplification
_HEALTH_CACHE_TTL_SECONDS = 5.0
_health_cache_ts: float = 0.0
_health_cache_result: Optional[tuple[bool, dict[str, dict[str, Any]]]] = None


async def is_authenticated_health_request(
    authorization: Optional[str] = Header(None),
    x_health_token: Optional[str] = Header(None),
) -> bool:
    """
    Validates diagnostic clearance for `/health`:
      1. Constant-time match against HEALTH_CHECK_SECRET via X-Health-Token
      2. Active (non-revoked) SUPER_ADMIN access JWT (strictly `type == 'access'`)
    """
    health_secret = os.getenv("HEALTH_CHECK_SECRET")
    if health_secret and x_health_token and hmac.compare_digest(x_health_token, health_secret):
        return True

    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        try:
            from services.secrets_manager import decode_jwt_with_rotation
            from services.auth import _is_jti_revoked, _verify_token_version

            payload = decode_jwt_with_rotation(token, algorithm=settings.jwt_algorithm)
            if payload.get("type") != "access":
                return False
            role = str(payload.get("role", "")).upper()
            if role != "SUPER_ADMIN":
                return False
            jti = payload.get("jti")
            if jti and await _is_jti_revoked(str(jti)):
                return False
            uid = payload.get("id") or payload.get("sub")
            tv = payload.get("token_version")
            if uid and tv is not None and not await _verify_token_version(str(uid), int(tv)):
                return False
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
    Checks PostgreSQL (with 2s acquire timeout) and, in hardened environments,
    Tier-1 Redis (1.5s timeout). Never exposes internal pool/driver details.
    """
    try:
        from database.postgres import db_pool
        if db_pool is None:
            return JSONResponse(content={"status": "not_ready"}, status_code=503)
        async with db_pool.acquire(timeout=2.0) as conn:
            await asyncio.wait_for(conn.fetchval(SQL_PING_QUERY), timeout=2.0)

        if getattr(settings, "is_hardened", settings.is_production):
            from database.redis_db import get_async_redis_client
            redis_client = await get_async_redis_client()
            if redis_client is None:
                return JSONResponse(content={"status": "not_ready"}, status_code=503)
            pong = await asyncio.wait_for(redis_client.ping(), timeout=1.5)
            if pong is not True:
                return JSONResponse(content={"status": "not_ready"}, status_code=503)

        return {"status": "ready"}
    except Exception as e:
        logger.warning("Readiness probe failed: %s", e)
        return JSONResponse(content={"status": "not_ready"}, status_code=503)


async def _run_deep_health_checks() -> tuple[bool, dict[str, dict[str, Any]]]:
    global _health_cache_ts, _health_cache_result
    now = time.monotonic()
    if _health_cache_result is not None and (now - _health_cache_ts) < _HEALTH_CACHE_TTL_SECONDS:
        return _health_cache_result

    checks: dict[str, dict[str, Any]] = {}
    all_healthy = True

    # ── PostgreSQL ────────────────────────────────────────────────────────
    try:
        from database.postgres import db_pool

        t0 = time.monotonic()
        if db_pool is None:
            raise RuntimeError("Connection pool not initialised")
        async with db_pool.acquire(timeout=2.0) as conn:
            await asyncio.wait_for(conn.fetchval(SQL_PING_QUERY), timeout=2.0)
        checks["postgres"] = {"status": "ok", "latency_ms": round((time.monotonic() - t0) * 1000, 1)}
    except Exception as e:
        logger.warning("Health check PostgreSQL failed: %s", e)
        checks["postgres"] = {"status": "error", "detail": "Service unavailable"}
        all_healthy = False

    # ── Redis ─────────────────────────────────────────────────────────────
    try:
        from database.redis_db import get_async_redis_client

        t0 = time.monotonic()
        redis_client = await get_async_redis_client()
        await asyncio.wait_for(redis_client.ping(), timeout=1.5)
        checks["redis"] = {"status": "ok", "latency_ms": round((time.monotonic() - t0) * 1000, 1)}
    except Exception as e:
        logger.warning("Health check Redis failed: %s", e)
        checks["redis"] = {"status": "error", "detail": "Service unavailable"}
        all_healthy = False

    # ── Neo4j (only checked when enabled — fixes P2-22) ───────────────────
    if getattr(settings, "enable_neo4j", False):
        try:
            from database.neo4j_db import get_async_neo4j_driver

            t0 = time.monotonic()
            driver = await get_async_neo4j_driver()
            async with driver.session() as session:
                await asyncio.wait_for(session.run("RETURN 1"), timeout=2.0)
            checks["neo4j"] = {"status": "ok", "latency_ms": round((time.monotonic() - t0) * 1000, 1)}
        except Exception as e:
            logger.warning("Health check Neo4j failed: %s", e)
            checks["neo4j"] = {"status": "error", "detail": "Service unavailable"}
            all_healthy = False
    else:
        checks["neo4j"] = {"status": "disabled"}

    # ── Elasticsearch (only checked when enabled — fixes P2-22) ───────────
    if getattr(settings, "enable_elasticsearch", False):
        try:
            from database.elasticsearch_db import get_async_elasticsearch_client

            t0 = time.monotonic()
            es = await get_async_elasticsearch_client()
            await asyncio.wait_for(es.info(), timeout=2.0)
            checks["elasticsearch"] = {"status": "ok", "latency_ms": round((time.monotonic() - t0) * 1000, 1)}
        except Exception as e:
            logger.warning("Health check Elasticsearch failed: %s", e)
            checks["elasticsearch"] = {"status": "error", "detail": "Service unavailable"}
            all_healthy = False
    else:
        checks["elasticsearch"] = {"status": "disabled"}

    _health_cache_result = (all_healthy, checks)
    _health_cache_ts = now
    return all_healthy, checks


@router.get("/health")
async def readiness(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_health_token: Optional[str] = Header(None),
    _rate_limit=Depends(RateLimiter(limit=20, window=60, ip_only=True)),
):
    """Deep readiness probe with rate limiting, 5s cache, and topology masking."""
    authenticated = await is_authenticated_health_request(authorization, x_health_token)
    all_healthy, checks = await _run_deep_health_checks()
    status_code = 200 if all_healthy else 503

    if authenticated:
        body: dict[str, Any] = {
            "status": "healthy" if all_healthy else "degraded",
            "checks": checks,
        }
    else:
        body = {"status": "healthy" if all_healthy else "degraded"}

    return JSONResponse(content=body, status_code=status_code)


@router.get("/api/v1/health/system")
async def get_system_topology_health(
    current_user: dict = Depends(RoleChecker(["ADMIN", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """
    Exposes institutional component health, pool utilization, and latencies
    for the Admin System Health command center without leaking raw driver exceptions.
    """
    is_super_admin = str(current_user.get("role", "")).upper() == "SUPER_ADMIN"
    services: dict[str, Any] = {}

    # 1. PostgreSQL
    try:
        from database.postgres import db_pool
        t0 = time.monotonic()
        if db_pool:
            async with db_pool.acquire(timeout=2.0) as conn:
                await asyncio.wait_for(conn.fetchval(SQL_PING_QUERY), timeout=2.0)
            pool_size = (
                db_pool.get_size()
                if callable(getattr(db_pool, "get_size", None))
                else getattr(db_pool, "_size", None)
            )
            free_conns = (
                db_pool.get_idle_size()
                if callable(getattr(db_pool, "get_idle_size", None))
                else getattr(db_pool, "_free", None)
            )
            services["postgres"] = {
                "status": "UP",
                "latency_ms": round((time.monotonic() - t0) * 1000, 1),
                "pool_size": pool_size,
                "free_connections": free_conns,
            }
        else:
            services["postgres"] = {"status": "DEGRADED", "detail": "Pool not initialized"}
    except Exception as e:
        logger.warning("System topology PostgreSQL probe failed: %s", e)
        services["postgres"] = {"status": "DOWN", "error": "Service check failed"}

    # 2. Redis
    try:
        from database.redis_db import get_async_redis_client
        t0 = time.monotonic()
        redis_client = await get_async_redis_client()
        if redis_client:
            await asyncio.wait_for(redis_client.ping(), timeout=1.5)
            services["redis"] = {
                "status": "UP",
                "latency_ms": round((time.monotonic() - t0) * 1000, 1),
                "cluster_mode": False,
            }
        else:
            services["redis"] = {"status": "DOWN", "detail": "Client unavailable"}
    except Exception as e:
        logger.warning("System topology Redis probe failed: %s", e)
        services["redis"] = {"status": "DOWN", "error": "Service check failed"}

    # 3. Elasticsearch
    if getattr(settings, "enable_elasticsearch", False):
        try:
            from database.elasticsearch_db import get_async_elasticsearch_client
            t0 = time.monotonic()
            es = await get_async_elasticsearch_client()
            if es:
                info = await asyncio.wait_for(es.info(), timeout=2.0)
                services["elasticsearch"] = {
                    "status": "UP",
                    "latency_ms": round((time.monotonic() - t0) * 1000, 1),
                    "version": info.get("version", {}).get("number", "8.x") if is_super_admin else "managed",
                }
            else:
                services["elasticsearch"] = {"status": "DEGRADED"}
        except Exception as e:
            logger.warning("System topology Elasticsearch probe failed: %s", e)
            services["elasticsearch"] = {"status": "DOWN", "error": "Service check failed"}
    else:
        services["elasticsearch"] = {"status": "DISABLED"}

    # 4. Neo4j
    if getattr(settings, "enable_neo4j", False):
        try:
            from database.neo4j_db import get_async_neo4j_driver
            t0 = time.monotonic()
            driver = await get_async_neo4j_driver()
            if driver:
                async with driver.session() as s:
                    await asyncio.wait_for(s.run("RETURN 1"), timeout=2.0)
                services["neo4j"] = {
                    "status": "UP",
                    "latency_ms": round((time.monotonic() - t0) * 1000, 1),
                }
            else:
                services["neo4j"] = {"status": "DEGRADED"}
        except Exception as e:
            logger.warning("System topology Neo4j probe failed: %s", e)
            services["neo4j"] = {"status": "DOWN", "error": "Service check failed"}
    else:
        services["neo4j"] = {"status": "DISABLED"}

    # 5. Redpanda / Kafka Messaging Bus (live TCP reachability probe)
    from config import KAFKA_BOOTSTRAP_SERVERS, TRANSACTIONS_TOPIC
    try:
        t0 = time.monotonic()
        first_broker = str(KAFKA_BOOTSTRAP_SERVERS).split(",")[0].strip()
        host, port_str = (first_broker.rsplit(":", 1) if ":" in first_broker else (first_broker, "9092"))
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port_str)), timeout=1.5)
        writer.close()
        await writer.wait_closed()
        rp_info = {
            "status": "UP",
            "latency_ms": round((time.monotonic() - t0) * 1000, 1),
            "default_topic": TRANSACTIONS_TOPIC,
            "mode": "STREAMING_AIOKAFKA",
        }
        if is_super_admin:
            rp_info["bootstrap_servers"] = KAFKA_BOOTSTRAP_SERVERS
        services["redpanda"] = rp_info
    except Exception as e:
        logger.warning("System topology Redpanda probe failed: %s", e)
        rp_err = {
            "status": "DOWN",
            "default_topic": TRANSACTIONS_TOPIC,
            "error": "Broker unreachable",
        }
        if is_super_admin:
            rp_err["bootstrap_servers"] = KAFKA_BOOTSTRAP_SERVERS
        services["redpanda"] = rp_err

    all_up = all(s.get("status") in {"UP", "DISABLED"} for s in services.values())
    return {
        "system_status": "OPERATIONAL" if all_up else "DEGRADED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": services,
    }


@router.get("/api/v1/admin/queue-health")
async def get_queue_health(
    current_user: dict = Depends(RoleChecker(["ADMIN", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Returns tenant-scoped streaming queue & outbox telemetry without leaking raw exceptions."""
    from database.postgres import get_async_db_conn
    from config import TRANSACTIONS_TOPIC, KAFKA_BOOTSTRAP_SERVERS

    tenant_id = enforce_tenant_data_scope(current_user)
    is_super_admin = str(current_user.get("role", "")).upper() == "SUPER_ADMIN"

    pending_outbox = 0
    outbox_error = None
    tx_rate_per_sec = 0.0
    alert_rate_per_sec = 0.0
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            pending_outbox = await conn.fetchval(
                "SELECT COUNT(*) FROM transactional_outbox WHERE tenant_id = $1::uuid AND status IN ('PENDING', 'PROCESSING');",
                str(tenant_id),
            )
            if pending_outbox is None:
                pending_outbox = 0
            try:
                published_60s = await conn.fetchval(
                    """
                    SELECT COUNT(*) FROM transactional_outbox
                    WHERE tenant_id = $1::uuid AND status = 'PUBLISHED' AND updated_at >= NOW() - INTERVAL '60 seconds';
                    """,
                    str(tenant_id),
                )
                if isinstance(published_60s, (int, float)):
                    tx_rate_per_sec = round(float(published_60s) / 60.0, 2)
                alerts_60s = await conn.fetchval(
                    "SELECT COUNT(*) FROM alerts WHERE tenant_id = $1::uuid AND created_at >= NOW() - INTERVAL '60 seconds';",
                    str(tenant_id),
                )
                if isinstance(alerts_60s, (int, float)):
                    alert_rate_per_sec = round(float(alerts_60s) / 60.0, 2)
            except Exception:
                pass
    except Exception as exc:
        logger.exception("Failed to query queue health from transactional_outbox")
        if getattr(settings, "is_hardened", settings.is_production):
            outbox_error = "Queue telemetry database unavailable."
        else:
            outbox_error = str(exc)[:200]
        pending_outbox = -1

    broker_reachable = False
    try:
        first_broker = str(KAFKA_BOOTSTRAP_SERVERS).split(",")[0].strip()
        host, port_str = (first_broker.rsplit(":", 1) if ":" in first_broker else (first_broker, "9092"))
        _r, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port_str)), timeout=1.0)
        writer.close()
        await writer.wait_closed()
        broker_reachable = True
    except Exception:
        broker_reachable = False

    cg_status = "HEALTHY" if broker_reachable else "BROKER_UNREACHABLE"
    topics = [
        {
            "topic": TRANSACTIONS_TOPIC if is_super_admin else "transactions.scored",
            "partitions": 3,
            "replication_factor": 1,
            "broker_reachable": broker_reachable,
            "consumer_groups": [
                {
                    "group_id": "aml_scoring_workers" if is_super_admin else "scoring",
                    "total_lag": max(0, pending_outbox) if pending_outbox >= 0 else None,
                    "status": cg_status,
                    "messages_per_sec": tx_rate_per_sec,
                }
            ],
        },
        {
            "topic": "aml.alerts.created" if is_super_admin else "alerts.created",
            "partitions": 3,
            "replication_factor": 1,
            "broker_reachable": broker_reachable,
            "consumer_groups": [
                {
                    "group_id": "aml_alert_dispatchers" if is_super_admin else "dispatchers",
                    "total_lag": 0 if broker_reachable else None,
                    "status": cg_status,
                    "messages_per_sec": alert_rate_per_sec,
                }
            ],
        },
    ]

    if outbox_error:
        system_status = "DEGRADED"
    elif pending_outbox >= 1000:
        system_status = "BACKPRESSURE_DETECTED"
    else:
        system_status = "HEALTHY"

    res: dict[str, Any] = {
        "status": system_status,
        "pending_outbox_events": pending_outbox if pending_outbox >= 0 else None,
        "kafka_topics": topics,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    if outbox_error:
        res["error"] = outbox_error
    return res
