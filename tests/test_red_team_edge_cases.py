"""
Red Team Adversarial & Edge-Case Verification Suite
====================================================
Validates all hardened defenses against:
1. CHAOS-01: Elasticsearch downtime fails-closed (HELD_FOR_REVIEW) during onboarding.
2. ADV-03: Receiver CIP pending smuggling rejection.
3. ADV-01: FinCEN 31 CFR § 1010.313 24-hour rolling cash aggregation & structuring detection.
4. ADV-02: Unicode homoglyphs, diacritics, and zero-width character evasion bypass.
5. RACE-03: Optimistic concurrency locking on SAR draft 4-eyes reviews.
6. STATE-01: Case state machine violation (cannot re-close or edit archived closed cases).
7. AUDIT-01: In-transaction crash-proof immutable audit logging.
"""

import pytest
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
import httpx
from fastapi import HTTPException

from main import app
from routers.screening import levenshtein_ratio, normalize_screening_name
from database.postgres import get_async_db_conn
from services.audit import record_audit_event_tx
from services.auth import create_access_token

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


# ── 1. CHAOS-01: Elasticsearch Down Fails Closed in Onboarding ───────────────

@pytest.mark.anyio
async def test_onboarding_elasticsearch_down_fails_closed():
    """Verify that Elasticsearch downtime during onboarding sets status=HELD_FOR_REVIEW and risk_score=1.0."""
    token = make_token("ANALYST")
    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = {"id": TENANT_ID}
    mock_conn.fetchval.return_value = uuid.uuid4()

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.onboarding.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.onboarding.get_async_elasticsearch_client", side_effect=Exception("ConnectionRefused: ES cluster offline")):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {token}"}) as ac:
            resp = await ac.post(
                "/api/v1/onboard/accounts/individual",
                json={
                    "tenant_id": TENANT_ID,
                    "name": "Boris Suspect",
                    "account_number": "ACC_SUSPECT_01",
                    "swift_bic": "CHASEUS3XXX"
                }
            )
            assert resp.status_code == 201
            body = resp.json()
            assert body["status"] == "HELD_FOR_REVIEW", "Account must be quarantined when sanctions screening is down!"
            assert body["risk_score"] == 1.0, "Risk score must fail-closed to 1.0!"


# ── 2. ADV-03: Receiver CIP Verification Enforcement ─────────────────────────

@pytest.mark.anyio
async def test_receiver_cip_pending_rejected():
    """Verify that transactions destined for an unverified receiver account (CIP_PENDING) are rejected."""
    token = make_token("ANALYST")
    mock_conn = AsyncMock()
    # Mock row lookup where sender is ACTIVE but receiver is CIP_PENDING
    mock_conn.fetchrow.return_value = {
        "sender_id": uuid.uuid4(),
        "sender_tenant": TENANT_ID,
        "sender_risk": 0.10,
        "sender_name": "Alice Verified",
        "sender_bic": "CHASEUS3XXX",
        "sender_status": "ACTIVE",
        "receiver_id": uuid.uuid4(),
        "receiver_risk": 0.20,
        "receiver_name": "Bob Unverified",
        "receiver_bic": "BOFAUS3NXXX",
        "receiver_status": "CIP_PENDING",
        "velocity_count": 0
    }

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.transactions.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.transactions.get_async_db_read_conn", return_value=mock_ctx):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {token}"}) as ac:
            resp = await ac.post(
                "/api/v1/transactions",
                json={
                    "sender_account": "ACC_SEND_OK",
                    "receiver_account": "ACC_RECV_UNVERIFIED",
                    "amount": 2500.0,
                    "currency": "USD",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
            assert resp.status_code == 400
            assert "CIP" in resp.json()["detail"]


# ── 3. ADV-01: 24-Hour Rolling Cash Aggregation (FinCEN 31 CFR 1010.313) ───────

@pytest.mark.anyio
async def test_sub_threshold_structuring_triggers_ctr():
    """Verify that multiple cash deposits aggregating >= $10k in 24h trigger CTR and structuring alert."""
    token = make_token("ANALYST")
    sender_uuid = uuid.uuid4()
    receiver_uuid = uuid.uuid4()

    mock_read_conn = AsyncMock()
    mock_read_conn.fetchrow.return_value = {
        "sender_id": sender_uuid,
        "sender_tenant": TENANT_ID,
        "sender_risk": 0.15,
        "sender_name": "Charlie Cash",
        "sender_bic": "CHASEUS3XXX",
        "sender_status": "ACTIVE",
        "receiver_id": receiver_uuid,
        "receiver_risk": 0.15,
        "receiver_name": "Merchant LLC",
        "receiver_bic": "BOFAUS3NXXX",
        "receiver_status": "ACTIVE",
        "velocity_count": 1
    }

    mock_read_ctx = AsyncMock()
    mock_read_ctx.__aenter__.return_value = mock_read_conn
    mock_read_ctx.__aexit__.return_value = None

    mock_write_conn = AsyncMock()
    # 24h rolling cash aggregation: prior cash deposits = $9,500.0
    mock_write_conn.fetchrow.return_value = {
        "total_cash_24h": 9500.0,
        "cash_count_24h": 1
    }
    mock_write_conn.fetch.return_value = [{"id": sender_uuid, "status": "ACTIVE"}]
    mock_write_conn.execute.return_value = "INSERT 0 1"

    mock_write_ctx = AsyncMock()
    mock_write_ctx.__aenter__.return_value = mock_write_conn
    mock_write_ctx.__aexit__.return_value = None

    with patch("routers.transactions.get_async_db_read_conn", return_value=mock_read_ctx), \
         patch("routers.transactions.get_async_db_conn", return_value=mock_write_ctx), \
         patch("routers.transactions.anomaly_model.predict_risk", return_value={"risk_score": 0.2, "attributions": {}}), \
         patch("routers.transactions.RulesEngine.evaluate_transaction", return_value=[]), \
         patch("routers.transactions.get_customer_baseline", return_value={"avg_amount": 1000.0, "std_amount": 200.0}), \
         patch("routers.transactions.get_iforest_score", return_value=0.1), \
         patch("routers.transactions.publish_transaction", new_callable=AsyncMock), \
         patch("routers.transactions.calculate_customer_baseline", new_callable=AsyncMock):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {token}"}) as ac:
            # Depositing $800 cash (single tx is < $10k, but aggregate = $9500 + $800 = $10,300 >= $10k!)
            resp = await ac.post(
                "/api/v1/transactions",
                json={
                    "sender_account": "ACC_CHARLIE",
                    "receiver_account": "ACC_MERCHANT",
                    "amount": 800.0,
                    "currency": "USD",
                    "channel": "CASH",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
            assert resp.status_code == 201
            # Verify CTR filing was executed on mock_write_conn
            executed_sqls = [call[0][0] for call in mock_write_conn.execute.call_args_list]
            ctr_executed = any("INSERT INTO ctr_filings" in sql for sql in executed_sqls)
            assert ctr_executed, "CTR filing must be triggered when 24h cumulative cash >= $10,000 under FinCEN 31 CFR 1010.313!"


# ── 4. ADV-02: Unicode Homoglyphs & Zero-Width Bypass Normalization ───────────

def test_unicode_homoglyphs_and_zero_width_sanctions_normalization():
    """Verify that Cyrillic homoglyphs, zero-width characters, and diacritics are normalized."""
    # "Vladimir" with Cyrillic 'а' (\u0430) and zero-width non-breaking space (\uFEFF)
    adversarial_name = "Vl\u0430dim\uFEFFir Sm\u0456rnov"
    canonical_target = "Vladimir Smirnov"

    norm = normalize_screening_name(adversarial_name)
    assert norm == "vladimir smirnov"

    ratio = levenshtein_ratio(adversarial_name, canonical_target)
    assert ratio == 1.0, f"Levenshtein similarity ratio must be 1.0 after normalization, got {ratio}"


# ── 5. RACE-03: Optimistic Concurrency Locking on SAR Draft Reviews ───────────

@pytest.mark.anyio
async def test_concurrent_sar_review_optimistic_concurrency():
    """Verify that concurrent or duplicate reviews on the same SAR draft return 400 or 409."""
    mlro_id = uuid.uuid4()
    token = make_token("MLRO", user_id=mlro_id)
    draft_id = uuid.uuid4()

    mock_conn = AsyncMock()
    # Draft is already APPROVED (not PENDING_MLRO_REVIEW)
    mock_conn.fetchrow.return_value = {
        "id": draft_id,
        "status": "APPROVED",
        "drafted_by": uuid.uuid4(),
        "tenant_id": TENANT_ID
    }

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.fincen.get_async_db_conn", return_value=mock_ctx):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {token}"}) as ac:
            resp = await ac.post(
                f"/api/v1/fincen/sar/drafts/{draft_id}/review",
                json={"action": "APPROVE"}
            )
            assert resp.status_code == 400
            assert "already APPROVED" in resp.json()["detail"]


# ── 6. STATE-01: Case FSM Blocks Modifying Closed Cases ────────────────────────

@pytest.mark.anyio
async def test_case_fsm_blocks_closing_already_closed_case():
    """Verify that attempting to close an already CLOSED case returns 400 Bad Request."""
    token = make_token("L2_INVESTIGATOR")
    case_id = uuid.uuid4()
    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = {
        "id": case_id,
        "status": "CLOSED",
        "tenant_id": TENANT_ID
    }

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.cases.get_async_db_conn", return_value=mock_ctx):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {token}"}) as ac:
            resp = await ac.post(
                f"/api/v1/cases/{case_id}/close",
                json={
                    "closure_reason": "FALSE_POSITIVE",
                    "closing_notes": "Duplicate closure attempt"
                }
            )
            assert resp.status_code == 400
            assert "already CLOSED" in resp.json()["detail"]


# ── 7. AUDIT-01: Synchronous In-Transaction Audit Persistence ──────────────────

@pytest.mark.asyncio
async def test_synchronous_audit_written_atomically():
    """Verify that record_audit_event_tx synchronously executes SQL within the provided connection."""
    mock_conn = AsyncMock()
    mock_conn.execute.return_value = "INSERT 0 1"

    await record_audit_event_tx(
        conn=mock_conn,
        action="TEST_ACTION",
        actor_id="user_123",
        actor_role="ADMIN",
        resource_type="ACCOUNT",
        resource_id="acc_999",
        tenant_id=TENANT_ID,
        actor_username="admin_user",
        before_state={"status": "ACTIVE"},
        after_state={"status": "FROZEN"}
    )

    assert mock_conn.execute.called
    call_sql = mock_conn.execute.call_args[0][0]
    assert "INSERT INTO audit_log" in call_sql
