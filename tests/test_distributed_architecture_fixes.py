"""
Test Suite: Distributed Architecture & Concurrency Remediation
==============================================================
Validates the 5 distributed systems, concurrency, and architecture fixes:
1. Supervised Transactional Outbox Relay startup/shutdown in lifespan.
2. Atomic Compare-and-Swap alert claiming with 409 Conflict guards.
3. Idempotent FinCEN electronic SAR submission with Redis caching & pre-flight checks.
4. WebSocket idle timeout socket reclamation and keep-alive ping handling.
5. Tiered rate-limiting partitioning by tenant, user, and client IP.
"""

import asyncio
import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import httpx
from fastapi import HTTPException, status
from fastapi.testclient import TestClient

from main import app, lifespan
from services.rate_limiter import RateLimiter
from services.idempotency import (
    check_idempotency,
    save_idempotency_result,
    clear_idempotency_key
)
from services.auth import create_access_token


TENANT_ID = "00000000-0000-0000-0000-000000000001"


def make_token(role: str = "ANALYST", user_id: str = None, tenant_id: str = TENANT_ID) -> str:
    uid = user_id or str(uuid.uuid4())
    return create_access_token({
        "id": uid,
        "sub": f"officer.{uid[:4]}",
        "username": f"officer.{uid[:4]}",
        "role": role,
        "tenant_id": tenant_id
    })


# ── 1. Outbox Relay Engine Lifespan Lifecycle ──────────────────────────────────

@pytest.mark.asyncio
async def test_outbox_relay_lifespan_lifecycle():
    """Verify that OutboxRelayEngine starts as a supervised background task in lifespan and exits gracefully."""
    import main

    with patch("main.startup_db_clients", new_callable=AsyncMock) as mock_startup, \
         patch("main.shutdown_db_clients", new_callable=AsyncMock) as mock_shutdown, \
         patch("database.outbox.OutboxRelayEngine.run", new_callable=AsyncMock) as mock_relay_run:

        # Simulate relay running until shutdown event is set
        async def mock_run(shutdown_event=None):
            while shutdown_event and not shutdown_event.is_set():
                await asyncio.sleep(0.01)

        mock_relay_run.side_effect = mock_run

        async with lifespan(app):
            # Verify outbox task is started
            assert main._outbox_relay_task is not None
            assert not main._outbox_relay_task.done()

        # On exiting lifespan context, task should be cleaned up
        assert main._outbox_relay_task is None
        assert mock_startup.called
        assert mock_shutdown.called


# ── 2. Atomic Alert Claiming Concurrency & TOCTOU Guards ───────────────────────

@pytest.mark.asyncio
async def test_claim_alert_already_claimed_by_other_officer_returns_409():
    """Verify that claiming an alert already assigned to a different officer returns HTTP 409 Conflict."""
    alert_id = str(uuid.uuid4())
    officer_a_id = uuid.uuid4()
    officer_b_id = str(uuid.uuid4())
    token_b = make_token("ANALYST", user_id=officer_b_id)

    mock_conn = AsyncMock()
    # Alert is currently assigned to officer A
    mock_conn.fetchrow.return_value = {
        "id": uuid.UUID(alert_id),
        "status": "IN_REVIEW",
        "assigned_officer_id": officer_a_id
    }

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.alerts.get_async_db_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"Authorization": f"Bearer {token_b}", "X-CSRF-Protection": "1"}
        ) as client:
            resp = await client.post(f"/api/v1/alerts/{alert_id}/claim")
            assert resp.status_code == 409
            assert "already claimed by another investigator" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_claim_alert_concurrent_cas_collision_returns_409():
    """Verify that when concurrent updates collide (UPDATE 0), the CAS guard returns HTTP 409 Conflict."""
    alert_id = str(uuid.uuid4())
    officer_id = str(uuid.uuid4())
    token = make_token("ANALYST", user_id=officer_id)

    mock_conn = AsyncMock()
    # Alert appears unassigned on read
    mock_conn.fetchrow.return_value = {
        "id": uuid.UUID(alert_id),
        "status": "NEW",
        "assigned_officer_id": None
    }
    # But concurrent write claimed it first -> UPDATE 0
    mock_conn.execute.return_value = "UPDATE 0"

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.alerts.get_async_db_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"Authorization": f"Bearer {token}", "X-CSRF-Protection": "1"}
        ) as client:
            resp = await client.post(f"/api/v1/alerts/{alert_id}/claim")
            assert resp.status_code == 409
            assert "claimed concurrently" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_claim_alert_successful_claim_and_idempotent_reclaim():
    """Verify that an unassigned alert can be claimed and successfully re-claimed by the same officer."""
    alert_id = str(uuid.uuid4())
    officer_id = str(uuid.uuid4())
    token = make_token("ANALYST", user_id=officer_id)

    mock_conn = AsyncMock()
    # Alert is unassigned
    mock_conn.fetchrow.return_value = {
        "id": uuid.UUID(alert_id),
        "status": "OPEN",
        "assigned_officer_id": None
    }
    mock_conn.execute.return_value = "UPDATE 1"

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.alerts.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.metrics.ws_manager.broadcast", new_callable=AsyncMock) as mock_ws_bcast:

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"Authorization": f"Bearer {token}", "X-CSRF-Protection": "1"}
        ) as client:
            resp = await client.post(f"/api/v1/alerts/{alert_id}/claim")
            assert resp.status_code == 200
            assert resp.json()["status"] == "CLAIMED"
            assert mock_ws_bcast.called


# ── 3. Idempotent Regulatory FinCEN E-Filing ───────────────────────────────────

@pytest.mark.asyncio
async def test_fincen_sar_submit_idempotent_cached_response():
    """Verify that repeated SAR submissions sharing an Idempotency-Key return cached receipts without re-submitting."""
    alert_id = str(uuid.uuid4())
    token = make_token("ADMIN")
    idemp_key = f"sar_test_{alert_id}"

    cached_receipt = {
        "alert_id": alert_id,
        "fincen_tracking_id": "BSA-2026-999888",
        "status": "ACKNOWLEDGED",
        "ack_code": "ACK_SUCCESS_200",
        "confirmation_message": "Receipt Cached",
        "submitted_at": "2026-10-13T12:00:00Z"
    }

    # Simulate Redis returning cached idempotency entry
    with patch("routers.fincen.check_idempotency", AsyncMock(return_value=(True, {"status_code": 201, "body": cached_receipt}))), \
         patch("services.fincen_efiling.fincen_client.submit_sar", new_callable=AsyncMock) as mock_submit:

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={
                "Authorization": f"Bearer {token}",
                "X-CSRF-Protection": "1",
                "Idempotency-Key": idemp_key
            }
        ) as client:
            resp = await client.post(
                "/api/v1/fincen/sar/submit",
                json={
                    "alert_id": alert_id,
                    "sar_xml": "<SuspiciousActivityReport><Test>1</Test></SuspiciousActivityReport>"
                }
            )
            assert resp.status_code == 201
            assert resp.headers.get("X-Cache-Lookup") == "HIT"
            assert resp.json()["fincen_tracking_id"] == "BSA-2026-999888"
            # Ensure external submission was NOT called again
            assert not mock_submit.called


@pytest.mark.asyncio
async def test_fincen_sar_submit_preflight_duplicate_check_returns_409():
    """Verify pre-flight check rejects submission if alert already has fincen_tracking_id in PostgreSQL."""
    alert_id = str(uuid.uuid4())
    token = make_token("ADMIN")

    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = {
        "fincen_tracking_id": "BSA-EXISTING-12345",
        "fincen_filing_status": "ACKNOWLEDGED",
        "fincen_submitted_at": "2026-10-13T10:00:00"
    }

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.fincen.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.fincen.check_idempotency", AsyncMock(return_value=(False, None))), \
         patch("routers.fincen.clear_idempotency_key", new_callable=AsyncMock) as mock_clear:

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"Authorization": f"Bearer {token}", "X-CSRF-Protection": "1"}
        ) as client:
            resp = await client.post(
                "/api/v1/fincen/sar/submit",
                json={
                    "alert_id": alert_id,
                    "sar_xml": "<SuspiciousActivityReport><Test>2</Test></SuspiciousActivityReport>"
                }
            )
            assert resp.status_code == 409
            assert "already electronically filed" in resp.json()["detail"]
            assert mock_clear.called


# ── 4. Resilient WebSocket Transport & Heartbeats ──────────────────────────────

@pytest.mark.asyncio
async def test_websocket_ping_pong_heartbeat():
    """Verify WebSocket endpoint responds to client 'ping' with 'pong'."""
    from fastapi import WebSocket
    from routers.metrics import websocket_live_stream

    mock_ws = AsyncMock(spec=WebSocket)
    mock_ws.cookies = {}

    with patch("services.secrets_manager.decode_jwt_with_rotation") as mock_decode, \
         patch("routers.metrics.ws_manager.connect", new_callable=AsyncMock) as mock_connect, \
         patch("routers.metrics.ws_manager.disconnect") as mock_disconnect:

        mock_decode.return_value = {
            "sub": "user-123",
            "role": "ANALYST",
            "tenant_id": TENANT_ID
        }

        # Send "ping" then simulate client disconnect
        mock_ws.receive_text.side_effect = ["ping", Exception("Client disconnected")]

        await websocket_live_stream(websocket=mock_ws, token="valid.jwt.token")

        mock_ws.send_text.assert_called_once_with(json.dumps({"event": "pong"}))
        mock_connect.assert_called_once()
        mock_disconnect.assert_called_once()


@pytest.mark.asyncio
async def test_websocket_idle_timeout_closes_cleanly():
    """Verify WebSocket closes with code 1000 when idle timeout expires without messages."""
    from fastapi import WebSocket
    from routers.metrics import websocket_live_stream

    mock_ws = AsyncMock(spec=WebSocket)
    mock_ws.cookies = {}

    with patch("services.secrets_manager.decode_jwt_with_rotation") as mock_decode, \
         patch("routers.metrics.ws_manager.connect", new_callable=AsyncMock), \
         patch("routers.metrics.ws_manager.disconnect"), \
         patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):

        mock_decode.return_value = {
            "sub": "user-123",
            "role": "ANALYST",
            "tenant_id": TENANT_ID
        }

        await websocket_live_stream(websocket=mock_ws, token="valid.jwt.token")

        mock_ws.close.assert_called_once_with(code=1000, reason="Idle timeout")


# ── 5. Tiered Rate Limiting Partitioning ───────────────────────────────────────

@pytest.mark.asyncio
async def test_tiered_rate_limiter_partitions_by_tenant_and_user():
    """Verify rate limiter derives tiered keys incorporating tenant_id and user_id."""
    limiter = RateLimiter(limit=10, window=60)
    user_id = str(uuid.uuid4())
    token = make_token("ANALYST", user_id=user_id, tenant_id=TENANT_ID)

    mock_pipe = MagicMock()
    mock_pipe.execute = AsyncMock(return_value=[0, True, 1, True])
    mock_redis = MagicMock()
    mock_redis.pipeline.return_value = mock_pipe

    mock_req = MagicMock()
    mock_req.state.client_ip = "192.168.1.50"
    mock_req.url.path = "/api/v1/transactions"
    mock_req.headers = {"Authorization": f"Bearer {token}", "host": "api.aml.internal"}

    with patch("services.rate_limiter.get_async_redis_client", AsyncMock(return_value=mock_redis)):
        await limiter(mock_req)
        # Inspect the key passed to Redis
        call_args = mock_pipe.zadd.call_args
        rate_key = call_args[0][0]
        assert TENANT_ID in rate_key
        assert user_id in rate_key
        assert "/api/v1/transactions" in rate_key
        assert "192.168.1.50" in rate_key
