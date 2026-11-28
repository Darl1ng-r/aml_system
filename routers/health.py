"""
Hardened Health Check Endpoints
================================
Thin HTTP controller for liveness, event-loop-aware readiness, deep cached
health probes, system topology, and streaming queue telemetry.
All PostgreSQL queries live in `repositories/ops_repo.py`.
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
from repositories.ops_repo import fetch_queue_health_counts_repo, ping_postgres_pool_repo
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Health"])

_HEALTH_CACHE_TTL_SECONDS = 5.0
_health_cache_ts: float = 0.0
_health_cache_result: Optional[tuple[bool, dict[str, dict[str, Any]]]] = None
_server_draining: bool = False


def mark_server_draining() -> None:
    """Marks the worker as draining so /health/ready immediately returns 503 during graceful shutdown."""
    global _server_draining
    _server_draining = True


def reset_server_draining() -> None:
    """Clears the draining flag on startup (and between test runs)."""
    global _server_draining
    _server_draining = False


def is_server_draining() -> bool:
    """Returns True once SIGTERM / lifespan shutdown has initiated graceful draining."""
    return _server_draining


async def is_authenticated_health_request(
    authorization: Optional[str] = Header(None),
    x_health_token: Optional[str] = Header(None),
) -> bool:
    health_secret = os.getenv("HEALTH_CHECK_SECRET")
    if health_secret and x_health_token and hmac.compare_digest(x_health_token, health_secret):
        return True

    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        try:
            from services.auth import _is_jti_revoked, _verify_token_version
            from services.secrets_manager import decode_jwt_with_rotation

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
    """Decoupled readiness probe failing fast (503) during graceful drain, event-loop saturation, or DB/Redis outage."""
    if _server_draining:
        return JSONResponse(content={"status": "draining"}, status_code=503)

    try:
        from observability.event_loop_monitor import (
            is_event_loop_saturated,
            probe_event_loop_lag_seconds,
        )

        if is_event_loop_saturated(max_lag_seconds=0.5):
            logger.warning("Readiness probe failed fast: asyncio event loop saturated.")
            return JSONResponse(content={"status": "not_ready"}, status_code=503)

        live_lag = await probe_event_loop_lag_seconds()
        if live_lag >= 0.5:
            logger.warning("Readiness probe failed fast: event loop tick lag %.1fms >= 500ms.", live_lag * 1000.0)
            return JSONResponse(content={"status": "not_ready"}, status_code=503)

        await ping_postgres_pool_repo(timeout=2.0)

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

    try:
        from observability.event_loop_monitor import get_event_loop_health, is_event_loop_saturated

        loop_diag = get_event_loop_health()
        saturated = is_event_loop_saturated(max_lag_seconds=0.5)
        checks["event_loop"] = {
            "status": "degraded" if saturated else "ok",
            **loop_diag,
        }
        if saturated:
            all_healthy = False
    except Exception:
        pass

    try:
        pg_stats = await ping_postgres_pool_repo(timeout=2.0)
        checks["postgres"] = {"status": "ok", "latency_ms": pg_stats["latency_ms"]}
    except Exception as e:
        logger.warning("Health check PostgreSQL failed: %s", e)
        checks["postgres"] = {"status": "error", "detail": "Service unavailable"}
        all_healthy = False

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
    """Exposes institutional component health, pool utilization, and latencies."""
    is_super_admin = str(current_user.get("role", "")).upper() == "SUPER_ADMIN"
    services: dict[str, Any] = {}

    try:
        import database.postgres as _pg

        if _pg.db_pool:
            pg_stats = await ping_postgres_pool_repo(timeout=2.0)
            services["postgres"] = {
                "status": "UP",
                "latency_ms": pg_stats["latency_ms"],
                "pool_size": pg_stats["pool_size"],
                "free_connections": pg_stats["free_connections"],
            }
        else:
            services["postgres"] = {"status": "DEGRADED", "detail": "Pool not initialized"}
    except Exception as e:
        logger.warning("System topology PostgreSQL probe failed: %s", e)
        services["postgres"] = {"status": "DOWN", "error": "Service check failed"}

    try:
        from database.redis_db import get_async_redis_client

        t0 = time.monotonic()
        redis_client = await get_async_redis_client()
        if redis_client:
            await asyncio.wait_for(redis_client.ping(), timeout=1.5)
            services["redis"] = {
                "status": "UP",
                "role": "state_noeviction",
                "latency_ms": round((time.monotonic() - t0) * 1000, 1),
                "cluster_mode": False,
            }
        else:
            services["redis"] = {"status": "DOWN", "detail": "Client unavailable"}
    except Exception as e:
        logger.warning("System topology Redis probe failed: %s", e)
        services["redis"] = {"status": "DOWN", "error": "Service check failed"}

    try:
        from database.redis_db import get_async_cache_redis_client

        t0 = time.monotonic()
        cache_client = await get_async_cache_redis_client()
        if cache_client:
            await asyncio.wait_for(cache_client.ping(), timeout=0.5)
            services["redis_cache"] = {
                "status": "UP",
                "role": "cache_allkeys_lfu",
                "latency_ms": round((time.monotonic() - t0) * 1000, 1),
            }
        else:
            services["redis_cache"] = {"status": "DEGRADED", "detail": "Fail-open to PostgreSQL"}
    except Exception as e:
        logger.warning("System topology Cache Redis probe failed: %s", e)
        services["redis_cache"] = {"status": "DEGRADED", "detail": "Fail-open to PostgreSQL"}

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

    from config import KAFKA_BOOTSTRAP_SERVERS, TRANSACTIONS_TOPIC

    try:
        t0 = time.monotonic()
        first_broker = str(KAFKA_BOOTSTRAP_SERVERS).split(",")[0].strip()
        host, port_str = first_broker.rsplit(":", 1) if ":" in first_broker else (first_broker, "9092")
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

    from observability.load_shedding import get_load_shedding_snapshot
    from observability.storage_monitor import get_storage_health_snapshot

    storage_snap = get_storage_health_snapshot()
    load_shedding_snap = get_load_shedding_snapshot()
    # redis_cache is intentionally fail-open; core system health depends on primary DB/state/enabled services
    all_up = all(
        s.get("status") in {"UP", "DISABLED"}
        for name, s in services.items()
        if name != "redis_cache"
    )
    return {
        "system_status": "OPERATIONAL" if all_up else "DEGRADED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "deployment_cell_id": getattr(settings, "deployment_cell_id", "cell-us-east-1"),
        "deployment_region": getattr(settings, "deployment_region", "us-east-1"),
        "services": services,
        "storage_telemetry": storage_snap,
        "load_shedding": load_shedding_snap,
    }


@router.get("/api/v1/admin/queue-health")
async def get_queue_health(
    current_user: dict = Depends(RoleChecker(["ADMIN", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Returns tenant-scoped streaming queue & outbox telemetry without leaking raw exceptions."""
    from config import KAFKA_BOOTSTRAP_SERVERS, TRANSACTIONS_TOPIC

    tenant_id = enforce_tenant_data_scope(current_user)
    is_super_admin = str(current_user.get("role", "")).upper() == "SUPER_ADMIN"

    pending_outbox = 0
    outbox_error = None
    tx_rate_per_sec = 0.0
    alert_rate_per_sec = 0.0
    try:
        pending_outbox, tx_rate_per_sec, alert_rate_per_sec = await fetch_queue_health_counts_repo(
            tenant_id=str(tenant_id),
        )
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
        host, port_str = first_broker.rsplit(":", 1) if ":" in first_broker else (first_broker, "9092")
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
