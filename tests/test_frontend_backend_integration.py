"""
Frontend-Backend Integration & Data Authenticity Test Suite
============================================================
Verifies:
  - POST /api/v1/alerts/{id}/escalate persists escalation in PostgreSQL
  - GET /api/v1/alerts/{id}/details returns authentic KYC, 30d timeline, and prior alerts
  - GET /api/v1/alerts supports server-side search and severity filters
  - WebSocket /ws/live-stream accepts token parameter and cookie fallback, rejects when missing
"""

import pytest
import uuid
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import WebSocket
from main import app
from routers.metrics import websocket_live_stream


@pytest.fixture
def mock_analyst():
    return {
        "id": "11111111-1111-1111-1111-111111111111",
        "username": "analyst.test",
        "role": "ANALYST",
        "tenant_id": "00000000-0000-0000-0000-000000000001"
    }


# ── 1. Alert Escalation Endpoint Tests ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_escalate_alert_success(mock_analyst):
    from routers.alerts import escalate_alert, AlertEscalate

    alert_id = str(uuid.uuid4())
    mock_conn = AsyncMock()
    mock_conn.execute.return_value = "UPDATE 1"

    with patch("routers.alerts.get_async_db_conn") as mock_get_conn, \
         patch("routers.metrics.ws_manager.broadcast", new_callable=AsyncMock) as mock_broadcast, \
         patch("observability.logging.log_audit_event") as mock_audit:
        
        mock_get_conn.return_value.__aenter__.return_value = mock_conn

        payload = AlertEscalate(justification="Suspicious cross-border structuring.")
        result = await escalate_alert(id=alert_id, payload=payload, current_user=mock_analyst)

        assert result["status"] == "ESCALATED"
        assert result["alert_id"] == alert_id
        mock_conn.execute.assert_called_once()
        mock_broadcast.assert_called_once()


@pytest.mark.asyncio
async def test_escalate_alert_invalid_uuid(mock_analyst):
    from routers.alerts import escalate_alert
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        await escalate_alert(id="not-a-valid-uuid", payload=None, current_user=mock_analyst)

    assert exc_info.value.status_code == 400
    assert "Invalid alert ID format" in exc_info.value.detail


@pytest.mark.asyncio
async def test_escalate_alert_not_found(mock_analyst):
    from routers.alerts import escalate_alert
    from fastapi import HTTPException

    alert_id = str(uuid.uuid4())
    mock_conn = AsyncMock()
    mock_conn.execute.return_value = "UPDATE 0"

    with patch("routers.alerts.get_async_db_conn") as mock_get_conn:
        mock_get_conn.return_value.__aenter__.return_value = mock_conn

        with pytest.raises(HTTPException) as exc_info:
            await escalate_alert(id=alert_id, payload=None, current_user=mock_analyst)

        assert exc_info.value.status_code == 404
        assert "Alert not found" in exc_info.value.detail


# ── 2. Enriched Alert Details Endpoint Tests ───────────────────────────────────

@pytest.mark.asyncio
async def test_get_alert_details_success(mock_analyst):
    from routers.alerts import get_alert_details
    from datetime import datetime, timezone

    alert_id = str(uuid.uuid4())
    txn_id = str(uuid.uuid4())
    sender_id = str(uuid.uuid4())

    now = datetime.now(timezone.utc)

    mock_row = {
        "id": alert_id,
        "rule_name": "STRUCTURING_THRESHOLD",
        "threat_level": "CRITICAL",
        "ai_risk_score": 0.93,
        "explainability_payload": '{"attributions": {"velocity": 0.45}}',
        "status": "OPEN",
        "created_at": now,
        "assignee": "analyst.test",
        "txn_id": txn_id,
        "amount": 9500.00,
        "currency": "USD",
        "txn_time": now,
        "country": "KY",
        "channel": "SWIFT",
        "merchant": None,
        "device": None,
        "sender_id": sender_id,
        "sender_account": "ACC-4821",
        "sender_name": "Tobias M. Varga",
        "sender_bic": "CHASUS33",
        "sender_risk_score": 0.85,
        "sender_risk_tier": "HIGH",
        "sender_created_at": now,
        "receiver_id": str(uuid.uuid4()),
        "receiver_account": "ACC-9921",
        "receiver_name": "Harlow Kane Ltd",
        "receiver_bic": "BARCGB22"
    }

    mock_tx_history = [
        {
            "id": txn_id,
            "amount": 9500.00,
            "currency": "USD",
            "timestamp": now,
            "country": "KY",
            "channel": "SWIFT",
            "status": "PENDING"
        }
    ]

    mock_prior_alerts = [
        {
            "id": str(uuid.uuid4()),
            "rule_name": "RAPID_MOVEMENT",
            "threat_level": "HIGH",
            "status": "CLOSED_SAR",
            "created_at": now
        }
    ]

    mock_conn = AsyncMock()
    mock_conn.fetchrow.side_effect = [
        mock_row,  # main alert query
        {"kyc_risk_tier": "HIGH", "jurisdiction_risk_score": 0.88, "avg_amount": 8000.0, "monthly_frequency": 5} # profile
    ]
    mock_conn.fetch.side_effect = [
        mock_tx_history,   # trailing 30-day txns
        mock_prior_alerts  # prior alerts
    ]

    with patch("routers.alerts.get_async_db_read_conn") as mock_get_conn:
        mock_get_conn.return_value.__aenter__.return_value = mock_conn

        details = await get_alert_details(id=alert_id, current_user=mock_analyst)

        assert details["alert_id"] == alert_id
        assert details["entity"]["name"] == "Tobias M. Varga"
        assert details["entity"]["account_number"] == "ACC-4821"
        assert details["entity"]["risk_tier"] == "HIGH"
        assert len(details["timeline_30d"]) == 1
        assert details["timeline_30d"][0]["is_flagged"] is True
        assert len(details["prior_alerts"]) == 1
        assert details["prior_alerts"][0]["rule_name"] == "RAPID_MOVEMENT"


# ── 3. List Alerts Filter & Search Tests ───────────────────────────────────────

@pytest.mark.asyncio
async def test_list_alerts_with_search_and_severity(mock_analyst):
    from routers.alerts import list_alerts
    from fastapi import Response
    from datetime import datetime, timezone

    mock_conn = AsyncMock()
    mock_conn.fetchval.return_value = 1
    mock_conn.fetch.return_value = [
        (
            str(uuid.uuid4()), "LARGE_TRANSACTION", "CRITICAL", 0.95, None, "OPEN",
            datetime.now(timezone.utc), 50000.0, "USD", datetime.now(timezone.utc),
            "ACC-1001", "ACC-2002", "analyst.test",
            "Alice Corp", "Bob LLC", "CRITICAL", datetime.now(timezone.utc),
            "Wire", "US"
        )
    ]

    response = Response()
    with patch("routers.alerts.get_async_db_read_conn") as mock_get_conn:
        mock_get_conn.return_value.__aenter__.return_value = mock_conn

        alerts = await list_alerts(
            response=response,
            page=1,
            limit=10,
            search="Alice",
            severity="CRITICAL",
            current_user=mock_analyst
        )

        assert len(alerts) == 1
        assert alerts[0]["transaction"]["sender_name"] == "Alice Corp"
        assert response.headers["X-Total-Count"] == "1"
        # Verify SQL query executed with search & severity WHERE clauses
        count_sql = mock_conn.fetchval.call_args[0][0]
        assert "a.threat_level = $2" in count_sql
        assert "s.owner_name ILIKE" in count_sql


# ── 4. WebSocket Authentication Dual-Support Tests ─────────────────────────────

@pytest.mark.asyncio
async def test_websocket_accepts_token_param():
    mock_ws = AsyncMock(spec=WebSocket)
    mock_ws.cookies = {}

    with patch("services.secrets_manager.decode_jwt_with_rotation") as mock_decode, \
         patch("routers.metrics.ws_manager.connect", new_callable=AsyncMock) as mock_connect:

        mock_decode.return_value = {
            "sub": "user-123",
            "role": "ANALYST",
            "tenant_id": "00000000-0000-0000-0000-000000000001"
        }

        # Simulate client connecting and then disconnecting immediately
        mock_ws.receive_text.side_effect = Exception("Client disconnected")

        await websocket_live_stream(websocket=mock_ws, token="valid.jwt.token")

        mock_decode.assert_called_once_with("valid.jwt.token", algorithm=mock_decode.call_args[1]["algorithm"])
        mock_connect.assert_called_once()


@pytest.mark.asyncio
async def test_websocket_accepts_cookie_when_token_param_missing():
    mock_ws = AsyncMock(spec=WebSocket)
    mock_ws.cookies = {"access_token": "cookie.jwt.token"}

    with patch("services.secrets_manager.decode_jwt_with_rotation") as mock_decode, \
         patch("routers.metrics.ws_manager.connect", new_callable=AsyncMock) as mock_connect:

        mock_decode.return_value = {
            "sub": "user-123",
            "role": "ANALYST",
            "tenant_id": "00000000-0000-0000-0000-000000000001"
        }

        mock_ws.receive_text.side_effect = Exception("Client disconnected")

        # token is None, but cookie exists
        await websocket_live_stream(websocket=mock_ws, token=None)

        mock_decode.assert_called_once_with("cookie.jwt.token", algorithm=mock_decode.call_args[1]["algorithm"])
        mock_connect.assert_called_once()


@pytest.mark.asyncio
async def test_websocket_rejects_when_both_missing():
    mock_ws = AsyncMock(spec=WebSocket)
    mock_ws.cookies = {}

    await websocket_live_stream(websocket=mock_ws, token=None)

    mock_ws.close.assert_called_once_with(code=1008, reason="Missing authentication token")
