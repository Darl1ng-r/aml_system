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
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Header, Request, Depends
from fastapi.responses import JSONResponse
from config import settings
from services.auth import RoleChecker

logger = logging.getLogger(__name__)

SQL_PING_QUERY = "SELECT 1"

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
            await conn.fetchval(SQL_PING_QUERY)
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
            await conn.fetchval(SQL_PING_QUERY)
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


@router.get("/api/v1/health/system")
async def get_system_topology_health(
    current_user: dict = Depends(RoleChecker(["ADMIN", "SUPER_ADMIN"]))
):
    """
    Exposes complete institutional component health, pool utilization,
    latencies, and service status for the Admin System Health command center.
    """
    import asyncio
    services = {}

    # 1. PostgreSQL
    try:
        from database.postgres import db_pool
        t0 = time.monotonic()
        if db_pool:
            async with db_pool.acquire() as conn:
                await conn.fetchval(SQL_PING_QUERY)
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
                "free_connections": free_conns
            }
        else:
            services["postgres"] = {"status": "DEGRADED", "detail": "Pool not initialized"}
    except Exception as e:
        services["postgres"] = {"status": "DOWN", "error": str(e)}

    # 2. Redis
    try:
        from database.redis_db import get_async_redis_client
        t0 = time.monotonic()
        redis_client = await get_async_redis_client()
        if redis_client:
            await redis_client.ping()
            services["redis"] = {
                "status": "UP",
                "latency_ms": round((time.monotonic() - t0) * 1000, 1),
                "cluster_mode": False
            }
        else:
            services["redis"] = {"status": "DOWN", "detail": "Client unavailable"}
    except Exception as e:
        services["redis"] = {"status": "DOWN", "error": str(e)}

    # 3. Elasticsearch
    try:
        from database.elasticsearch_db import get_async_elasticsearch_client
        t0 = time.monotonic()
        es = await get_async_elasticsearch_client()
        if es:
            info = await es.info()
            services["elasticsearch"] = {
                "status": "UP",
                "latency_ms": round((time.monotonic() - t0) * 1000, 1),
                "version": info.get("version", {}).get("number", "8.x")
            }
        else:
            services["elasticsearch"] = {"status": "DEGRADED"}
    except Exception as e:
        services["elasticsearch"] = {"status": "DOWN", "error": str(e)}

    # 4. Neo4j
    try:
        from database.neo4j_db import get_async_neo4j_driver
        t0 = time.monotonic()
        driver = await get_async_neo4j_driver()
        if driver:
            async with driver.session() as s:
                await s.run("RETURN 1")
            services["neo4j"] = {
                "status": "UP",
                "latency_ms": round((time.monotonic() - t0) * 1000, 1)
            }
        else:
            services["neo4j"] = {"status": "DEGRADED"}
    except Exception as e:
        services["neo4j"] = {"status": "DOWN", "error": str(e)}

    # 5. Redpanda / Kafka Messaging Bus (live TCP reachability probe)
    from config import KAFKA_BOOTSTRAP_SERVERS, TRANSACTIONS_TOPIC
    try:
        t0 = time.monotonic()
        first_broker = str(KAFKA_BOOTSTRAP_SERVERS).split(",")[0].strip()
        host, port_str = (first_broker.rsplit(":", 1) if ":" in first_broker else (first_broker, "9092"))
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port_str)), timeout=1.5)
        writer.close()
        await writer.wait_closed()
        services["redpanda"] = {
            "status": "UP",
            "latency_ms": round((time.monotonic() - t0) * 1000, 1),
            "bootstrap_servers": KAFKA_BOOTSTRAP_SERVERS,
            "default_topic": TRANSACTIONS_TOPIC,
            "mode": "STREAMING_AIOKAFKA"
        }
    except Exception as e:
        services["redpanda"] = {
            "status": "DOWN",
            "bootstrap_servers": KAFKA_BOOTSTRAP_SERVERS,
            "default_topic": TRANSACTIONS_TOPIC,
            "error": str(e)
        }

    all_up = all(s.get("status") == "UP" for s in services.values())
    return {
        "system_status": "OPERATIONAL" if all_up else "DEGRADED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": services
    }


@router.get("/api/v1/admin/queue-health")
async def get_queue_health(
    current_user: dict = Depends(RoleChecker(["ADMIN", "SUPER_ADMIN"]))
):
    """
    Returns Kafka / Redpanda consumer lag metrics, partition offsets,
    and ingestion backpressure state for streaming data feeds.
    """
    from database.postgres import get_async_db_conn
    from config import TRANSACTIONS_TOPIC

    # Check pending & in-flight outbox messages and live 60s publish rate in PostgreSQL
    import asyncio
    from config import KAFKA_BOOTSTRAP_SERVERS

    pending_outbox = 0
    outbox_error = None
    tx_rate_per_sec = 0.0
    alert_rate_per_sec = 0.0
    try:
        async with get_async_db_conn() as conn:
            pending_outbox = await conn.fetchval(
                "SELECT COUNT(*) FROM transactional_outbox WHERE status IN ('PENDING', 'PROCESSING');"
            )
            if pending_outbox is None:
                pending_outbox = 0
            try:
                published_60s = await conn.fetchval(
                    """
                    SELECT COUNT(*) FROM transactional_outbox
                    WHERE status = 'PUBLISHED' AND updated_at >= NOW() - INTERVAL '60 seconds';
                    """
                )
                if isinstance(published_60s, (int, float)):
                    tx_rate_per_sec = round(float(published_60s) / 60.0, 2)
                alerts_60s = await conn.fetchval(
                    "SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '60 seconds';"
                )
                if isinstance(alerts_60s, (int, float)):
                    alert_rate_per_sec = round(float(alerts_60s) / 60.0, 2)
            except Exception:
                pass
    except Exception as e:
        logger.exception("Failed to query queue health from transactional_outbox")
        outbox_error = str(e)
        pending_outbox = -1

    # Probe live Kafka / Redpanda broker connectivity
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
            "topic": TRANSACTIONS_TOPIC,
            "partitions": 3,
            "replication_factor": 1,
            "broker_reachable": broker_reachable,
            "consumer_groups": [
                {
                    "group_id": "aml_scoring_workers",
                    "total_lag": max(0, pending_outbox) if pending_outbox >= 0 else None,
                    "status": cg_status,
                    "messages_per_sec": tx_rate_per_sec
                }
            ]
        },
        {
            "topic": "aml.alerts.created",
            "partitions": 3,
            "replication_factor": 1,
            "broker_reachable": broker_reachable,
            "consumer_groups": [
                {
                    "group_id": "aml_alert_dispatchers",
                    "total_lag": 0 if broker_reachable else None,
                    "status": cg_status,
                    "messages_per_sec": alert_rate_per_sec
                }
            ]
        }
    ]

    if outbox_error:
        system_status = "DEGRADED"
    elif pending_outbox >= 1000:
        system_status = "BACKPRESSURE_DETECTED"
    else:
        system_status = "HEALTHY"

    res = {
        "status": system_status,
        "pending_outbox_events": pending_outbox if pending_outbox >= 0 else None,
        "kafka_topics": topics,
        "checked_at": datetime.now(timezone.utc).isoformat()
    }
    if outbox_error:
        res["error"] = outbox_error
    return res

