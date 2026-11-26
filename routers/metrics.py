"""
Dashboard Analytics & Real-Time WebSocket Streaming Router
============================================================
Thin HTTP + WebSocket controller for live dashboard KPIs, executive metrics,
and tenant-isolated WebSocket event streams.
All PostgreSQL SQL lives in `repositories/analytics_repo.py`.
"""

import asyncio
import json
import logging
import uuid as _ws_uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect

from database.postgres import get_async_db_read_conn
from repositories.analytics_repo import (
    fetch_dashboard_metrics_repo,
    fetch_executive_analytics_tx as _fetch_executive_analytics,
    fetch_executive_counts_tx as _fetch_executive_counts,
    fetch_executive_metrics_repo,
    fetch_executive_sla_breaches_tx as _fetch_executive_sla_breaches,
)
from services.auth import RoleChecker, enforce_tenant_data_scope, get_current_user
from services.http_cache import build_conditional_json_response
from services.rate_limiter import RateLimiter, _check_local_rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Analytics & Real-Time Streaming"])


# ── WebSocket Manager ──────────────────────────────────────────────────────────

class ConnectionManager:
    """Manages active WebSocket connections with tenant partitioning and Redis Pub/Sub."""

    def __init__(self):
        self.active_connections: dict[WebSocket, dict] = {}

    async def connect(
        self,
        websocket: WebSocket,
        tenant_id: str = "00000000-0000-0000-0000-000000000001",
        role: str = "ANALYST",
    ):
        await websocket.accept()
        self.active_connections[websocket] = {
            "tenant_id": str(tenant_id),
            "role": role,
        }
        logger.info(
            "WebSocket client connected (tenant=%s, role=%s). Active connections on this pod: %s",
            tenant_id,
            role,
            len(self.active_connections),
        )

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            del self.active_connections[websocket]
            logger.info("WebSocket client disconnected. Remaining on this pod: %s", len(self.active_connections))

    async def _send_local(self, message: dict, target_tenant_id: str | None = None):
        if not self.active_connections:
            return
        payload = json.dumps(message)
        target = target_tenant_id or message.get("tenant_id")
        is_global = message.get("is_system_broadcast", False)
        disconnected = []

        for connection, info in self.active_connections.items():
            is_overseer = info.get("role") in ["SUPER_ADMIN", "GLOBAL_AUDITOR"]
            if target:
                if info.get("tenant_id") != str(target) and not is_overseer:
                    continue
            elif not is_global and not is_overseer:
                continue

            try:
                await asyncio.wait_for(connection.send_text(payload), timeout=2.0)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)

    async def broadcast(self, message: dict, target_tenant_id: str | None = None):
        await self._send_local(message, target_tenant_id)
        try:
            from database.redis_db import get_async_redis_client

            redis = await get_async_redis_client()
            if redis:
                envelope = {
                    "message": message,
                    "target_tenant_id": target_tenant_id or message.get("tenant_id"),
                    "sender_instance_id": _WS_INSTANCE_ID,
                }
                await redis.publish("aml:events:broadcast", json.dumps(envelope))
        except Exception as e:
            logger.debug("Redis Pub/Sub broadcast skipped/non-fatal: %s", e)


_WS_INSTANCE_ID = str(_ws_uuid.uuid4())
ws_manager = ConnectionManager()


async def start_redis_ws_listener(ws_mgr: ConnectionManager, shutdown_event: asyncio.Event | None = None):
    """Background listener consuming Redis Pub/Sub events with jittered reconnect recovery (P2-23)."""
    from database.redis_db import get_async_redis_pubsub_client
    from services.http_client import full_jitter_backoff

    attempt = 0
    while shutdown_event is None or not shutdown_event.is_set():
        redis = None
        pubsub = None
        try:
            redis = await get_async_redis_pubsub_client()
            if not redis:
                await asyncio.sleep(full_jitter_backoff(2.0, attempt, cap=30.0))
                attempt += 1
                continue
            pubsub = redis.pubsub()
            await pubsub.subscribe("aml:events:broadcast")
            logger.info("Subscribed to distributed Redis WebSocket channel 'aml:events:broadcast'")
            attempt = 0

            while shutdown_event is None or not shutdown_event.is_set():
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg.get("type") == "message":
                    data = json.loads(msg["data"])
                    if data.get("sender_instance_id") == _WS_INSTANCE_ID:
                        continue
                    await ws_mgr._send_local(data.get("message", {}), data.get("target_tenant_id"))
                await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("Redis WebSocket listener disconnected (%s); reconnecting with jittered backoff.", e)
            await asyncio.sleep(full_jitter_backoff(1.0, attempt, cap=30.0))
            attempt += 1
        finally:
            if pubsub is not None:
                try:
                    await pubsub.close()
                except Exception:
                    pass
            if redis is not None:
                try:
                    await redis.aclose()
                except Exception:
                    pass


def _determine_risk_tier(active: int) -> str:
    if active >= 4:
        return "Critical"
    if active >= 2:
        return "High"
    return "Normal"


# ── Analytics API Endpoints ───────────────────────────────────────────────────

@router.get("/api/v1/metrics/dashboard")
async def get_dashboard_metrics(
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Computes dynamic dashboard KPIs, 7-day trends, category breakdown, and analyst leaderboard."""
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        payload = await fetch_dashboard_metrics_repo(
            tenant_id=tenant_id,
            determine_risk_tier_fn=_determine_risk_tier,
            read_conn_factory=get_async_db_read_conn,
        )
        return build_conditional_json_response(request, payload)
    except Exception:
        logger.exception("Dashboard metrics query failed")
        raise HTTPException(status_code=500, detail="Failed to load dashboard analytics.")


@router.get("/api/v1/metrics/executive")
async def get_executive_metrics(
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["ANALYST", "AUDITOR", "MLRO", "ADMIN", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Computes executive compliance KPIs, SLA breach trackers, and SAR throughput (30s Redis cached)."""
    tenant_id = enforce_tenant_data_scope(current_user)
    cache_key = f"metrics:executive:{tenant_id}"
    redis = None
    try:
        from database.redis_db import get_async_redis_client

        redis = await get_async_redis_client()
        if redis:
            cached = await redis.get(cache_key)
            if cached:
                return build_conditional_json_response(request, json.loads(cached))
    except Exception:
        redis = None

    try:
        payload = await fetch_executive_metrics_repo(
            tenant_id=tenant_id,
            counts_fn=_fetch_executive_counts,
            sla_fn=_fetch_executive_sla_breaches,
            analytics_fn=_fetch_executive_analytics,
            read_conn_factory=get_async_db_read_conn,
        )
        if redis:
            try:
                await redis.set(cache_key, json.dumps(payload), ex=30)
            except Exception:
                pass
        return build_conditional_json_response(request, payload)
    except Exception:
        logger.exception("Failed to calculate executive compliance metrics")
        raise HTTPException(status_code=500, detail="Failed to calculate executive compliance metrics.")


MAX_WS_CONNECTIONS_PER_USER = 10
MAX_WS_CONNECTIONS_PER_IP = 25


def _is_ws_origin_allowed(websocket: WebSocket) -> bool:
    from config import settings

    headers = getattr(websocket, "headers", None)
    raw_origin = headers.get("origin") if headers is not None else None
    origin = raw_origin.strip().lower().rstrip("/") if isinstance(raw_origin, str) else ""
    if not origin:
        cookies = getattr(websocket, "cookies", None) or {}
        has_cookie = isinstance(cookies, dict) and bool(cookies.get("access_token"))
        return not (settings.is_production and has_cookie)

    raw_host = headers.get("host") if headers is not None else None
    host = raw_host.strip().lower() if isinstance(raw_host, str) else ""
    if host and origin in (f"http://{host}", f"https://{host}"):
        return True

    allowed = {o.strip().lower().rstrip("/") for o in settings.allowed_origins.split(",") if o.strip()}
    return origin in allowed


async def _authenticate_ws_connection(
    websocket: WebSocket,
    ticket: str | None,
    token: str | None,
) -> tuple[str, str, str] | None:
    from config import settings
    from services.auth import _verify_token_version
    from services.secrets_manager import decode_jwt_with_rotation

    if ticket:
        try:
            from database.redis_db import get_async_redis_client

            redis = await get_async_redis_client()
            if redis:
                key = f"ws:ticket:{ticket}"
                raw = await (redis.getdel(key) if hasattr(redis, "getdel") else redis.get(key))
                if raw and not hasattr(redis, "getdel"):
                    await redis.delete(key)
                if raw:
                    tdata = json.loads(raw)
                    uid, tid, role = tdata.get("user_id"), tdata.get("tenant_id"), tdata.get("role")
                    if uid and tid and role:
                        return str(uid), str(tid), str(role)
        except Exception as err:
            logger.warning("WebSocket ticket auth failed: %s", err)
        return None

    if token and settings.is_production:
        return None

    auth_token = websocket.cookies.get("access_token") or token
    if not auth_token:
        return None

    try:
        payload = decode_jwt_with_rotation(auth_token, algorithm=settings.jwt_algorithm)
        if payload.get("type") != "access":
            return None
        user_id = payload.get("id") or payload.get("user_id") or payload.get("sub")
        tenant_id = payload.get("tenant_id")
        role = payload.get("role")
        token_version = payload.get("token_version")
        if not user_id or not tenant_id or not role:
            return None
        await _verify_token_version(str(user_id), token_version, tenant_id=str(tenant_id), jti=payload.get("jti"))
        return str(user_id), str(tenant_id), str(role)
    except Exception:
        return None


@router.websocket("/ws/live-stream")
async def websocket_live_stream(websocket: WebSocket, ticket: str | None = None, token: str | None = None):
    """WebSocket connection handler pushing real-time tenant-isolated events."""
    from services.trusted_proxy import get_trusted_client_ip

    peer_ip = get_trusted_client_ip(websocket)
    ws_allowed, _ = _check_local_rate_limit(f"ws_connect:{peer_ip}", limit=30, window=60)
    if not ws_allowed:
        await websocket.close(code=1008, reason="Too many WebSocket connection attempts")
        return

    if not _is_ws_origin_allowed(websocket):
        await websocket.close(code=1008, reason="Origin not permitted")
        return

    cookies = getattr(websocket, "cookies", None) or {}
    cookie_token = cookies.get("access_token") if isinstance(cookies, dict) else None
    if not ticket and not token and not cookie_token:
        await websocket.close(code=1008, reason="Missing authentication token")
        return

    identity = await _authenticate_ws_connection(websocket, ticket=ticket, token=token)
    if not identity:
        await websocket.close(code=1008, reason="Invalid, revoked, or missing authentication credentials")
        return

    user_id, tenant_id, role = identity

    user_conns = sum(1 for info in ws_manager.active_connections.values() if info.get("user_id") == user_id)
    ip_conns = sum(1 for info in ws_manager.active_connections.values() if info.get("peer_ip") == peer_ip)
    if user_conns >= MAX_WS_CONNECTIONS_PER_USER or ip_conns >= MAX_WS_CONNECTIONS_PER_IP:
        await websocket.close(code=1008, reason="WebSocket connection limit exceeded")
        return

    await ws_manager.connect(websocket, tenant_id=tenant_id, role=role)
    if websocket in ws_manager.active_connections:
        ws_manager.active_connections[websocket]["user_id"] = user_id
        ws_manager.active_connections[websocket]["peer_ip"] = peer_ip
    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=65.0)
                if data == "ping":
                    await websocket.send_text(json.dumps({"event": "pong"}))
            except asyncio.TimeoutError:
                logger.info("WebSocket idle timeout exceeded (65s); closing connection cleanly.")
                await websocket.close(code=1000, reason="Idle timeout")
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("WebSocket connection error: %s", e)
    finally:
        ws_manager.disconnect(websocket)
