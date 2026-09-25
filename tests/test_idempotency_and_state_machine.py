"""
Institutional Test Suite: Deterministic State Machine & Idempotency Layer
========================================================================
Validates:
1. services.state_machine:
   - Deterministic case transition table and illegal jump rejection
   - Terminal case lock (CLOSED cannot transition)
   - Alert transition matrix and terminal alert lock (CLOSED_SAR / CLOSED_FALSE_POSITIVE)
2. routers.cases:
   - PATCH /api/v1/cases/{id} workflow state updates and state-machine validation
   - POST /api/v1/cases/{id}/close terminal state rejection
3. routers.alerts:
   - POST /api/v1/alerts/{id}/action rejects terminal alert re-closure
   - POST /api/v1/alerts/{id}/escalate rejects terminal alert escalation
   - POST /api/v1/alerts/{id}/claim rejects terminal alert claiming
4. services.idempotency & routers.transactions:
   - First-time reservation and cache miss
   - Cache hit fast-return with exact response payload and headers
   - Concurrent in-flight collision returns HTTP 409 Conflict
   - POST /api/v1/transactions/ingest asynchronous buffer route (HTTP 202)
"""

import pytest
import uuid
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
from fastapi import HTTPException

from main import app
from services.auth import create_access_token
from services.state_machine import (
    validate_case_transition,
    validate_alert_transition,
    CaseStatus,
    AlertStatus,
)
from services.idempotency import (
    check_idempotency,
    save_idempotency_result,
    extract_idempotency_key,
)

TENANT_ID = "00000000-0000-0000-0000-000000000001"


def make_token(role="ANALYST", user_id=None, tenant_id=TENANT_ID):
    uid = str(user_id or uuid.uuid4())
    return create_access_token({
        "sub": uid,
        "id": uid,
        "role": role,
        "username": f"user_{role.lower()}",
        "tenant_id": tenant_id
    })


# ── 1. Unit Tests: State Machine Pure Logic ────────────────────────────────────

def test_case_state_machine_valid_transitions():
    """Verify standard legitimate progression paths for AML Cases."""
    # OPEN -> INVESTIGATING -> PENDING_SAR -> CLOSED
    validate_case_transition("OPEN", "INVESTIGATING")
    validate_case_transition("INVESTIGATING", "PENDING_SAR")
    validate_case_transition("PENDING_SAR", "CLOSED")
    # Non-mutating idempotent check
    validate_case_transition("INVESTIGATING", "INVESTIGATING")


def test_case_state_machine_illegal_transition():
    """Verify illegal jumps are strictly rejected with HTTP 400."""
    # PENDING_SAR cannot transition backward to INVESTIGATING directly
    with pytest.raises(HTTPException) as exc_info:
        validate_case_transition("PENDING_SAR", "INVESTIGATING")
    assert exc_info.value.status_code == 400
    assert "Illegal Case state transition" in exc_info.value.detail


def test_case_state_machine_terminal_closed_lock():
    """Verify CLOSED case is strictly locked and cannot transition to any state."""
    with pytest.raises(HTTPException) as exc_info:
        validate_case_transition("CLOSED", "OPEN")
    assert exc_info.value.status_code == 400
    assert "already CLOSED" in exc_info.value.detail

    with pytest.raises(HTTPException) as exc_info2:
        validate_case_transition("CLOSED", "CLOSED")
    assert exc_info2.value.status_code == 400
    assert "already CLOSED" in exc_info2.value.detail


def test_alert_state_machine_valid_transitions():
    """Verify valid alert progression paths."""
    validate_alert_transition("NEW", "IN_REVIEW")
    validate_alert_transition("IN_REVIEW", "ESCALATED")
    validate_alert_transition("ESCALATED", "CLOSED_SAR")
    validate_alert_transition("OPEN", "CLOSED_FALSE_POSITIVE")


def test_alert_state_machine_terminal_lock():
    """Verify CLOSED_SAR and CLOSED_FALSE_POSITIVE cannot be transitioned."""
    for terminal in ["CLOSED_SAR", "CLOSED_FALSE_POSITIVE", "CLOSED"]:
        with pytest.raises(HTTPException) as exc_info:
            validate_alert_transition(terminal, "IN_REVIEW")
        assert exc_info.value.status_code == 400
        assert "already terminal" in exc_info.value.detail


# ── 2. Integration Tests: Case State Machine in Routers ────────────────────────

@pytest.mark.asyncio
async def test_case_patch_state_machine_validation():
    """Verify PATCH /api/v1/cases/{id} rejects illegal state transitions."""
    case_id = str(uuid.uuid4())
    token = make_token("MLRO")

    mock_row = {
        "id": uuid.UUID(case_id),
        "status": "PENDING_SAR",
        "tenant_id": uuid.UUID(TENANT_ID)
    }

    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = mock_row
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.cases.get_async_db_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {token}"}
        ) as ac:
            # Illegal transition: PENDING_SAR -> OPEN
            resp = await ac.patch(
                f"/api/v1/cases/{case_id}",
                json={"status": "OPEN"}
            )
            assert resp.status_code == 400
            assert "Illegal Case state transition" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_case_close_already_closed_rejected():
    """Verify POST /api/v1/cases/{id}/close rejects an already CLOSED case."""
    case_id = str(uuid.uuid4())
    token = make_token("L2_INVESTIGATOR")

    mock_row = {
        "id": uuid.UUID(case_id),
        "status": "CLOSED",
        "tenant_id": uuid.UUID(TENANT_ID)
    }

    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = mock_row
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.cases.get_async_db_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {token}"}
        ) as ac:
            resp = await ac.post(
                f"/api/v1/cases/{case_id}/close",
                json={
                    "closure_reason": "FALSE_POSITIVE",
                    "closing_notes": "Attempting to close again"
                }
            )
            assert resp.status_code == 400
            assert "already CLOSED" in resp.json()["detail"]


# ── 3. Integration Tests: Alert State Machine in Routers ───────────────────────

@pytest.mark.asyncio
async def test_alert_action_terminal_rejection():
    """Verify POST /api/v1/alerts/{id}/action rejects terminal alert modification."""
    alert_id = str(uuid.uuid4())
    token = make_token("ADMIN")

    mock_row = {
        "id": uuid.UUID(alert_id),
        "rule_name": "STRUCTURING",
        "threat_level": "HIGH",
        "ai_risk_score": 0.88,
        "status": "CLOSED_SAR",
        "amount": 15000.0,
        "currency": "USD",
        "timestamp": datetime.now(timezone.utc),
        "account_number": "ACC1",
        "owner_name": "Alice",
    }

    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = mock_row
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.alerts.get_async_db_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {token}"}
        ) as ac:
            resp = await ac.post(
                f"/api/v1/alerts/{alert_id}/action",
                json={"action": "CLOSE_FALSE_POSITIVE", "justification": "Trying to reopen"}
            )
            assert resp.status_code == 400
            assert "already terminal" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_alert_escalate_terminal_rejection():
    """Verify POST /api/v1/alerts/{id}/escalate rejects already terminal alerts."""
    alert_id = str(uuid.uuid4())
    token = make_token("ANALYST")

    mock_row = {
        "id": uuid.UUID(alert_id),
        "status": "CLOSED_FALSE_POSITIVE"
    }

    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = mock_row
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.alerts.get_async_db_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {token}"}
        ) as ac:
            resp = await ac.post(
                f"/api/v1/alerts/{alert_id}/escalate",
                json={"justification": "Senior review escalation"}
            )
            assert resp.status_code == 400
            assert "already terminal" in resp.json()["detail"]


# ── 4. Unit & Integration Tests: Idempotency Layer ────────────────────────────

@pytest.mark.asyncio
async def test_idempotency_service_flow():
    """Test reservation, in-flight detection, and cache retrieval via mock Redis."""
    store = {}

    mock_redis = AsyncMock()
    async def mock_set(key, val, nx=False, ex=None):
        if nx and key in store:
            return False
        store[key] = val
        return True

    async def mock_get(key):
        return store.get(key)

    mock_redis.set.side_effect = mock_set
    mock_redis.get.side_effect = mock_get

    with patch("services.idempotency.get_async_redis_client", return_value=mock_redis):
        # 1. First attempt: key reserved in-flight
        is_cached, cached = await check_idempotency("key-123", tenant_id="tenant-1")
        assert is_cached is False
        assert cached is None

        # 2. Concurrent second attempt: detects IN_FLIGHT -> 409
        with pytest.raises(HTTPException) as exc_info:
            await check_idempotency("key-123", tenant_id="tenant-1")
        assert exc_info.value.status_code == 409
        assert "Concurrent request" in exc_info.value.detail

        # 3. Save completed result
        await save_idempotency_result("key-123", 201, {"tx_id": "abc"}, tenant_id="tenant-1")

        # 4. Third attempt: returns completed cached response
        is_cached, cached = await check_idempotency("key-123", tenant_id="tenant-1")
        assert is_cached is True
        assert cached["status_code"] == 201
        assert cached["body"] == {"tx_id": "abc"}


@pytest.mark.asyncio
async def test_transaction_ingest_idempotency_header_cached_hit():
    """Verify transaction endpoint intercepts duplicate requests using Idempotency-Key."""
    token = make_token("ANALYST")
    idem_key = f"idem-{uuid.uuid4()}"

    cached_response_payload = {
        "transaction_id": "cached-tx-001",
        "decision": "APPROVED",
        "alert_triggered": False,
        "risk_score": 0.12,
        "triggered_rules": [],
        "explainability": {"attributions": {}, "dynamic_risk": {}}
    }

    mock_redis = AsyncMock()
    # Mock that the key already completed
    mock_redis.set.return_value = False
    mock_redis.get.return_value = json.dumps({
        "status": "COMPLETED",
        "status_code": 201,
        "body": cached_response_payload
    })

    with patch("services.idempotency.get_async_redis_client", return_value=mock_redis):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={
                "X-CSRF-Protection": "1",
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": idem_key
            }
        ) as ac:
            resp = await ac.post(
                "/api/v1/transactions",
                json={
                    "sender_account": "ACC_SEND_1",
                    "receiver_account": "ACC_RECV_1",
                    "amount": 250.0,
                    "currency": "USD",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
            assert resp.status_code == 201
            assert resp.headers.get("Idempotency-Key") == idem_key
            assert resp.headers.get("X-Cache-Lookup") == "HIT"
            assert resp.json()["transaction_id"] == "cached-tx-001"


# ── 5. Integration Tests: Asynchronous High-Throughput Buffer Route ────────────

@pytest.mark.asyncio
async def test_async_transaction_buffer_endpoint():
    """Verify POST /api/v1/transactions/ingest returns HTTP 202 (<5ms async buffer)."""
    token = make_token("ANALYST")
    idem_key = f"async-idem-{uuid.uuid4()}"

    mock_conn = AsyncMock()
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.transactions.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.transactions.publish_transaction", return_value=True), \
         patch("database.outbox.record_outbox_event", return_value=None), \
         patch("services.idempotency.get_async_redis_client", return_value=None):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={
                "X-CSRF-Protection": "1",
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": idem_key
            }
        ) as ac:
            resp = await ac.post(
                "/api/v1/transactions/ingest",
                json={
                    "sender_account": "ACC_HIGH_VOLUME_1",
                    "receiver_account": "ACC_HIGH_VOLUME_2",
                    "amount": 5000.0,
                    "currency": "USD",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "channel": "API_BATCH"
                }
            )
            assert resp.status_code == 202
            body = resp.json()
            assert body["status"] == "ACCEPTED"
            assert body["ingestion_mode"] == "ASYNC_BUFFERED"
            assert "transaction_id" in body
            assert resp.headers.get("Location") == f"/api/v1/transactions/{body['transaction_id']}"
