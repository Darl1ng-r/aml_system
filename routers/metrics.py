"""
Dashboard Analytics & Real-Time WebSocket Streaming Router
============================================================
Provides live PostgreSQL analytics endpoints and WebSocket streaming feeds:

  - GET /api/v1/metrics/dashboard:
      Computes real-time KPI metrics, 7-day daily alert trends, category
      distribution breakdown, and live analyst workload leaderboard from PostgreSQL.

  - WebSocket /ws/live-stream:
      Real-time event pipe pushing live transaction ingestion events, newly
      triggered alerts, and case resolution updates directly to dashboard client charts.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import List, Any

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, HTTPException
from database.postgres import get_async_db_read_conn
from services.auth import get_current_user, RoleChecker, enforce_tenant_data_scope

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Analytics & Real-Time Streaming"])


# ── WebSocket Manager ──────────────────────────────────────────────────────────
class ConnectionManager:
    """
    Manages active WebSocket dashboard connections with tenant partitioning
    and a distributed Redis Pub/Sub backplane for horizontal multi-pod replicas.
    """

    def __init__(self):
        # Maps WebSocket instance -> {"tenant_id": str, "role": str}
        self.active_connections: dict[WebSocket, dict] = {}

    async def connect(
        self,
        websocket: WebSocket,
        tenant_id: str = "00000000-0000-0000-0000-000000000001",
        role: str = "ANALYST"
    ):
        await websocket.accept()
        self.active_connections[websocket] = {
            "tenant_id": str(tenant_id),
            "role": role
        }
        logger.info(
            f"WebSocket client connected (tenant={tenant_id}, role={role}). "
            f"Active connections on this pod: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            del self.active_connections[websocket]
            logger.info(f"WebSocket client disconnected. Remaining on this pod: {len(self.active_connections)}")

    async def _send_local(self, message: dict, target_tenant_id: str | None = None):
        """Dispatches message only to authorized local connections (tenant-scoped or global roles)."""
        if not self.active_connections:
            return
        payload = json.dumps(message)
        target = target_tenant_id or message.get("tenant_id")
        is_global = message.get("is_system_broadcast", False)
        disconnected = []

        for connection, info in self.active_connections.items():
            # Enforce Tenant Isolation:
            # If target tenant is set, only broadcast to connections from that tenant
            # or global compliance overseers (SUPER_ADMIN, GLOBAL_AUDITOR).
            # If no target tenant is set and not an explicit global broadcast, do NOT leak to tenant-scoped users.
            is_overseer = info.get("role") in ["SUPER_ADMIN", "GLOBAL_AUDITOR"]
            if target:
                if info.get("tenant_id") != str(target) and not is_overseer:
                    continue
            elif not is_global and not is_overseer:
                # Omitted target tenant on non-system message: fail closed for tenant analysts
                continue

            try:
                await asyncio.wait_for(connection.send_text(payload), timeout=2.0)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)

    async def broadcast(self, message: dict, target_tenant_id: str | None = None):
        """
        Broadcasts message to authorized local sockets and publishes to Redis Pub/Sub
        for distribution across other horizontal worker processes and pods.
        """
        # 1. Deliver to local clients connected to this pod
        await self._send_local(message, target_tenant_id)

        # 2. Publish to Redis Pub/Sub channel for inter-pod distribution
        try:
            from database.redis_db import get_async_redis_client
            redis = await get_async_redis_client()
            if redis:
                envelope = {
                    "message": message,
                    "target_tenant_id": target_tenant_id or message.get("tenant_id"),
                    "sender_instance_id": _WS_INSTANCE_ID
                }
                await redis.publish("aml:events:broadcast", json.dumps(envelope))
        except Exception as e:
            logger.debug(f"Redis Pub/Sub broadcast skipped/non-fatal: {e}")


import uuid as _ws_uuid
_WS_INSTANCE_ID = str(_ws_uuid.uuid4())
ws_manager = ConnectionManager()


async def start_redis_ws_listener(ws_mgr: ConnectionManager, shutdown_event: asyncio.Event | None = None):
    """Background listener consuming Redis Pub/Sub events published by other pods/workers."""
    from database.redis_db import get_async_redis_pubsub_client
    redis = None
    try:
        redis = await get_async_redis_pubsub_client()
        if not redis:
            return
        pubsub = redis.pubsub()
        await pubsub.subscribe("aml:events:broadcast")
        logger.info("Subscribed to distributed Redis WebSocket channel 'aml:events:broadcast'")

        while shutdown_event is None or not shutdown_event.is_set():
            try:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg.get("type") == "message":
                    data = json.loads(msg["data"])
                    # Discard if this pod/worker instance was the original sender (UUID-safe across K8s pods)
                    if data.get("sender_instance_id") == _WS_INSTANCE_ID:
                        continue
                    await ws_mgr._send_local(data.get("message", {}), data.get("target_tenant_id"))
                await asyncio.sleep(0.05)
            except asyncio.CancelledError:
                raise
            except Exception as loop_err:
                logger.debug(f"Redis WS listener error: {loop_err}")
                await asyncio.sleep(1.0)
    except Exception as e:
        logger.warning(f"Failed to start Redis WebSocket listener (standalone fallback active): {e}")
    finally:
        if redis:
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


# ── Analytics API Endpoint ────────────────────────────────────────────────────
@router.get("/api/v1/metrics/dashboard")
async def get_dashboard_metrics(
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"]))
):
    """
    Computes dynamic, non-hardcoded dashboard metrics directly from PostgreSQL:
      - Active cases & critical pending counts
      - 7-day daily alert frequency trend
      - Alert category distribution breakdown
      - Live analyst workload leaderboard
    """
    tenant_id = enforce_tenant_data_scope(current_user)

    try:
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
            # 1. KPI Counts
            active_cases = await conn.fetchval(
                "SELECT COUNT(*) FROM alerts WHERE status = 'OPEN';"
            )
            critical_cases = await conn.fetchval(
                "SELECT COUNT(*) FROM alerts WHERE status = 'OPEN' AND threat_level = 'CRITICAL';"
            )

            # 2. 7-Day Daily Trend Data
            trend_rows = await conn.fetch(
                """
                SELECT DATE(created_at) as day, COUNT(*) as count
                FROM alerts
                WHERE created_at >= NOW() - INTERVAL '7 days'
                GROUP BY DATE(created_at)
                ORDER BY day ASC;
                """
            )
            days_map = { (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%a"): 0 for i in reversed(range(7)) }
            for row in trend_rows:
                day_name = row["day"].strftime("%a")
                if day_name in days_map:
                    days_map[day_name] = int(row["count"])

            # 3. Category Distribution Breakdown
            cat_rows = await conn.fetch(
                """
                SELECT rule_name, COUNT(*) as count
                FROM alerts
                GROUP BY rule_name
                ORDER BY count DESC;
                """
            )
            categories = [
                {"category": row["rule_name"], "count": int(row["count"])}
                for row in cat_rows
            ]

            # 4. Analyst Workload Leaderboard
            leaderboard_rows = await conn.fetch(
                """
                SELECT u.username,
                       COUNT(a.id) FILTER (WHERE a.status = 'OPEN') as active_cases,
                       COUNT(a.id) FILTER (WHERE a.status LIKE 'CLOSED%') as resolved_cases,
                       COUNT(a.id) as total_cases
                FROM users u
                LEFT JOIN alerts a ON u.id = a.assigned_officer_id
                GROUP BY u.username
                ORDER BY active_cases DESC;
                """
            )
            analysts = []
            for row in leaderboard_rows:
                active = int(row["active_cases"])
                resolved = int(row["resolved_cases"])
                total = int(row["total_cases"])
                res_rate = round((resolved / total * 100), 1) if total > 0 else 100.0
                analysts.append({
                    "username": row["username"],
                    "active_cases": active,
                    "resolution_rate": f"{res_rate}%",
                    "risk_tier": _determine_risk_tier(active)
                })

            # 1b. Real Resolution Time & Escalation Rate (replaces static Executive Modal KPIs)
            avg_res_hours = 0.0
            escalation_rate = 0.0
            try:
                raw_avg = await conn.fetchval(
                    """
                    SELECT AVG(EXTRACT(EPOCH FROM (updated_at - created_at)) / 3600.0)
                    FROM alerts
                    WHERE status LIKE 'CLOSED%' AND updated_at IS NOT NULL AND created_at IS NOT NULL AND updated_at >= created_at;
                    """
                )
                if isinstance(raw_avg, (int, float)):
                    avg_res_hours = round(float(raw_avg), 1)
                total_alerts_all = await conn.fetchval("SELECT COUNT(*) FROM alerts;")
                escalated_alerts = await conn.fetchval(
                    "SELECT COUNT(*) FROM alerts WHERE status IN ('ESCALATED', 'CLOSED_SAR');"
                )
                if isinstance(total_alerts_all, (int, float)) and total_alerts_all > 0 and isinstance(escalated_alerts, (int, float)):
                    escalation_rate = round((float(escalated_alerts) / float(total_alerts_all)) * 100.0, 1)
            except Exception:
                pass

            return {
                "active_cases": active_cases or 0,
                "critical_cases": critical_cases or 0,
                "avg_resolution_hours": avg_res_hours,
                "escalation_rate": escalation_rate,
                "daily_trend": {
                    "labels": list(days_map.keys()),
                    "data": list(days_map.values())
                },
                "category_distribution": categories,
                "analyst_leaderboard": analysts
            }
    except Exception as e:
        logger.exception("Dashboard metrics query failed")
        raise HTTPException(status_code=500, detail=f"Failed to load analytics: {str(e)}")


async def _fetch_executive_counts(conn: Any) -> dict:
    alerts_24h = await conn.fetchval(
        "SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '24 hours';"
    )
    open_alerts = await conn.fetchval(
        "SELECT COUNT(*) FROM alerts WHERE status IN ('NEW', 'IN_REVIEW', 'ESCALATED', 'OPEN');"
    )
    open_cases = await conn.fetchval(
        "SELECT COUNT(*) FROM cases WHERE status IN ('OPEN', 'INVESTIGATING', 'PENDING_EDD', 'PENDING_SAR');"
    )
    sars_mtd = await conn.fetchval(
        """
        SELECT COUNT(*) FROM sar_drafts
        WHERE status IN ('APPROVED', 'FILED')
          AND created_at >= DATE_TRUNC('month', NOW());
        """
    )
    total_closed = await conn.fetchval(
        "SELECT COUNT(*) FROM alerts WHERE status LIKE 'CLOSED%';"
    )
    fps_closed = await conn.fetchval(
        "SELECT COUNT(*) FROM alerts WHERE status = 'CLOSED_FALSE_POSITIVE';"
    )
    median_triage = await conn.fetchval(
        """
        SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (
            ORDER BY EXTRACT(EPOCH FROM (COALESCE(res.resolved_at, a.fincen_submitted_at) - a.created_at)) / 3600.0
        )
        FROM alerts a
        LEFT JOIN LATERAL (
            SELECT MAX(al.occurred_at) AS resolved_at
            FROM audit_log al
            WHERE al.resource_id = a.id::text
              AND al.action IN ('CLOSE_FALSE_POSITIVE', 'RESOLVE_ALERT', 'FINCEN_SAR_FILED', 'UPDATE_ALERT')
        ) res ON TRUE
        WHERE a.status LIKE 'CLOSED%'
          AND a.created_at IS NOT NULL
          AND COALESCE(res.resolved_at, a.fincen_submitted_at) IS NOT NULL
          AND COALESCE(res.resolved_at, a.fincen_submitted_at) >= a.created_at;
        """
    )

    t_closed = int(total_closed or 0)
    f_closed = int(fps_closed or 0)
    fp_rate = round((f_closed / t_closed * 100), 1) if t_closed > 0 else 0.0
    median_hours = round(float(median_triage), 1) if median_triage is not None else 0.0

    return {
        "alerts_24h": int(alerts_24h or 0),
        "open_alerts": int(open_alerts or 0),
        "open_cases": int(open_cases or 0),
        "sars_filed_mtd": int(sars_mtd or 0),
        "false_positive_rate": f"{fp_rate}%",
        "median_triage_hours": median_hours
    }


async def _fetch_executive_sla_breaches(conn: Any) -> dict:
    breach_24h = await conn.fetchval(
        """
        SELECT COUNT(*) FROM alerts
        WHERE status IN ('NEW', 'IN_REVIEW', 'ESCALATED', 'OPEN')
          AND created_at <= NOW() - INTERVAL '24 hours';
        """
    )
    breach_48h = await conn.fetchval(
        """
        SELECT COUNT(*) FROM alerts
        WHERE status IN ('NEW', 'IN_REVIEW', 'ESCALATED', 'OPEN')
          AND created_at <= NOW() - INTERVAL '48 hours';
        """
    )
    breach_72h = await conn.fetchval(
        """
        SELECT COUNT(*) FROM alerts
        WHERE status IN ('NEW', 'IN_REVIEW', 'ESCALATED', 'OPEN')
          AND created_at <= NOW() - INTERVAL '72 hours';
        """
    )

    breach_rows = await conn.fetch(
        """
        SELECT a.id, a.rule_name, a.threat_level, a.created_at,
               ROUND(EXTRACT(EPOCH FROM (NOW() - a.created_at)) / 3600.0, 1) as age_hours,
               COALESCE(u.username, 'UNASSIGNED') as assignee
        FROM alerts a
        LEFT JOIN users u ON a.assigned_officer_id = u.id
        WHERE a.status IN ('NEW', 'IN_REVIEW', 'ESCALATED', 'OPEN')
          AND a.created_at <= NOW() - INTERVAL '24 hours'
        ORDER BY a.created_at ASC
        LIMIT 10;
        """
    )
    breach_items = [
        {
            "alert_id": str(r["id"]),
            "rule_name": r["rule_name"],
            "threat_level": r["threat_level"],
            "age_hours": float(r["age_hours"]),
            "assignee": r["assignee"]
        }
        for r in breach_rows
    ]

    return {
        "breach_24h": int(breach_24h or 0),
        "breach_48h": int(breach_48h or 0),
        "breach_72h": int(breach_72h or 0),
        "items": breach_items
    }


async def _fetch_executive_analytics(conn: Any) -> tuple[list[dict], dict, list[dict]]:
    cat_rows = await conn.fetch(
        "SELECT rule_name, COUNT(*) as count FROM alerts GROUP BY rule_name ORDER BY count DESC LIMIT 8;"
    )
    typologies = [{"rule_name": r["rule_name"], "count": int(r["count"])} for r in cat_rows]

    trend_rows = await conn.fetch(
        """
        SELECT DATE(created_at) as day, COUNT(*) as count
        FROM alerts
        WHERE created_at >= NOW() - INTERVAL '7 days'
        GROUP BY DATE(created_at)
        ORDER BY day ASC;
        """
    )
    days_map = { (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%a"): 0 for i in reversed(range(7)) }
    for row in trend_rows:
        day_name = row["day"].strftime("%a")
        if day_name in days_map:
            days_map[day_name] = int(row["count"])

    leaderboard_rows = await conn.fetch(
        """
        SELECT u.username,
               COUNT(a.id) FILTER (WHERE a.status IN ('OPEN', 'IN_REVIEW', 'ESCALATED')) as active_cases,
               COUNT(a.id) FILTER (WHERE a.status LIKE 'CLOSED%') as resolved_cases,
               COUNT(a.id) as total_cases
        FROM users u
        LEFT JOIN alerts a ON u.id = a.assigned_officer_id
        GROUP BY u.username
        ORDER BY resolved_cases DESC
        LIMIT 10;
        """
    )
    analysts = []
    for row in leaderboard_rows:
        active = int(row["active_cases"])
        resolved = int(row["resolved_cases"])
        total = int(row["total_cases"])
        res_rate = round((resolved / total * 100), 1) if total > 0 else 100.0
        analysts.append({
            "username": row["username"],
            "active_cases": active,
            "resolved_cases": resolved,
            "resolution_rate": f"{res_rate}%"
        })

    return typologies, days_map, analysts


@router.get("/api/v1/metrics/executive")
async def get_executive_metrics(
    current_user: dict = Depends(RoleChecker(["ANALYST", "AUDITOR", "MLRO", "ADMIN", "SUPER_ADMIN"]))
):
    """
    Computes executive compliance KPIs, SLA breach trackers, SAR filing throughput,
    and institutional efficiency metrics for MLRO & Compliance Leadership.
    Backed by a 30s tenant-scoped Redis cache to prevent heavy aggregate scan storms.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    cache_key = f"metrics:executive:{tenant_id}"
    redis = None
    try:
        from database.redis_db import get_async_redis_client
        redis = await get_async_redis_client()
        if redis:
            cached = await redis.get(cache_key)
            if cached:
                return json.loads(cached)
    except Exception:
        redis = None

    try:
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
            kpis = await _fetch_executive_counts(conn)
            sla_breaches = await _fetch_executive_sla_breaches(conn)
            typologies, days_map, analysts = await _fetch_executive_analytics(conn)

            payload = {
                "kpis": kpis,
                "sla_breaches": sla_breaches,
                "typologies": typologies,
                "daily_trend": {
                    "labels": list(days_map.keys()),
                    "data": list(days_map.values())
                },
                "leaderboard": analysts
            }
            if redis:
                try:
                    await redis.set(cache_key, json.dumps(payload), ex=30)
                except Exception:
                    pass
            return payload
    except Exception as e:
        logger.exception("Failed to calculate executive compliance metrics")
        raise HTTPException(status_code=500, detail=f"Executive metrics failed: {str(e)}")



# ── Real-Time WebSocket Endpoint ──────────────────────────────────────────────
@router.websocket("/ws/live-stream")
async def websocket_live_stream(websocket: WebSocket, token: str | None = None):
    """
    WebSocket connection handler pushing real-time events to connected clients.
    Authenticates via query parameter `?token=<JWT>` or HttpOnly cookie `access_token`.
    """
    auth_token = token or websocket.cookies.get("access_token")
    if not auth_token:
        await websocket.close(code=1008, reason="Missing authentication token")
        return

    try:
        from services.secrets_manager import decode_jwt_with_rotation
        from config import settings
        payload = decode_jwt_with_rotation(auth_token, algorithm=settings.jwt_algorithm)
        tenant_id = str(payload.get("tenant_id", "00000000-0000-0000-0000-000000000001"))
        role = payload.get("role", "ANALYST")
    except Exception:
        await websocket.close(code=1008, reason="Invalid or expired authentication token")
        return

    await ws_manager.connect(websocket, tenant_id=tenant_id, role=role)
    try:
        while True:
            # Keep-alive loop reading client heartbeats with 65s idle timeout
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
        logger.warning(f"WebSocket connection error: {e}")
    finally:
        ws_manager.disconnect(websocket)
