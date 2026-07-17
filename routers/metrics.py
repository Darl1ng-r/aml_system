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
from datetime import datetime, timezone, timedelta
from typing import List

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, HTTPException
from database.postgres import get_async_db_read_conn
from services.auth import get_current_user, RoleChecker, enforce_tenant_data_scope

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Analytics & Real-Time Streaming"])


# ── WebSocket Manager ──────────────────────────────────────────────────────────
class ConnectionManager:
    """Manages active WebSocket dashboard connections and broadcasts real-time events."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Remaining: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
        payload = json.dumps(message)
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)


ws_manager = ConnectionManager()


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
                    "risk_tier": "Critical" if active >= 4 else ("High" if active >= 2 else "Normal")
                })

            return {
                "active_cases": active_cases or 0,
                "critical_cases": critical_cases or 0,
                "daily_trend": {
                    "labels": list(days_map.keys()),
                    "data": list(days_map.values())
                },
                "category_distribution": categories,
                "analyst_leaderboard": analysts
            }
    except Exception as e:
        logger.error(f"Dashboard metrics query failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to load analytics: {str(e)}")


# ── Real-Time WebSocket Endpoint ──────────────────────────────────────────────
@router.websocket("/ws/live-stream")
async def websocket_live_stream(websocket: WebSocket, token: str | None = None):
    """
    WebSocket connection handler pushing real-time events to connected clients.
    Requires token authentication via query parameter `?token=<JWT>`.
    """
    if not token:
        await websocket.close(code=1008, reason="Missing authentication token")
        return

    try:
        from services.secrets_manager import decode_jwt_with_rotation
        from config import settings
        decode_jwt_with_rotation(token, algorithm=settings.jwt_algorithm)
    except Exception:
        await websocket.close(code=1008, reason="Invalid or expired authentication token")
        return

    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep-alive loop reading client heartbeats
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"event": "pong"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket connection error: {e}")
        ws_manager.disconnect(websocket)
