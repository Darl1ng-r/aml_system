"""
P1 High-Impact UX & Intelligence Multipliers — Verification Test Suite
=======================================================================
Validates all 6 P1 deliverables:
  P1-1: Entity-Centric Case Auto-Correlation & Alert Grouping
  P1-2: Historical Rule Backtesting (Read Replica) & Champion-Challenger Shadow Mode
  P1-3: Global Cmd+K Search API & Extended Bulk Triage Actions with RBAC Separation
  P1-4: Automated Notification & SLA Escalation Engine with 12h Deduplication
  P1-5: Perpetual KYC (pKYC) Delta Rescreening & Independent QA Four-Eyes Sampling (SoD)
  P1-6: Shared Shell Auto-Mount, Responsive Tablet/Mobile Breakpoints & Frontend Hygiene
"""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import ASGITransport

from main import app
from services.auth import create_access_token
from services.case_correlation import correlate_alert_to_entity_case, higher_priority
from services.notifications import run_sla_escalation_sweep
from services.pkyc_and_qa import run_pkyc_delta_rescreen
from services.rule_backtest import evaluate_rule_on_tx_row, evaluate_shadow_rules

TENANT_ID = "00000000-0000-0000-0000-000000000001"


def _make_token(role: str = "MLRO", username: str = "elena.mlro") -> str:
    return create_access_token({
        "sub": str(uuid.uuid4()),
        "id": str(uuid.uuid4()),
        "username": username,
        "role": role,
        "tenant_id": TENANT_ID,
    })


# ── P1-1: Entity-Centric Case Auto-Correlation & Alert Grouping ────────────────
@pytest.mark.anyio
async def test_p1_1_case_auto_correlation_merges_and_upgrades_priority():
    assert higher_priority("MEDIUM", "CRITICAL") == "CRITICAL"
    assert higher_priority("CRITICAL", "LOW") == "CRITICAL"

    subj_id = uuid.uuid4()
    existing_case_id = uuid.uuid4()
    alert_2_id = uuid.uuid4()

    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value={
        "id": existing_case_id,
        "case_number": "CASE-2026-ENT001",
        "priority": "MEDIUM",
        "status": "OPEN",
    })
    mock_conn.execute = AsyncMock()
    mock_conn.fetchval = AsyncMock(return_value=2)

    res = await correlate_alert_to_entity_case(
        conn=mock_conn,
        tenant_id=TENANT_ID,
        alert_id=alert_2_id,
        subject_account_id=subj_id,
        title="Second Alert for Entity",
        priority="CRITICAL",
        actor_username="analyst.jane",
    )

    assert res["correlated"] is True
    assert res["case_id"] == str(existing_case_id)
    assert res["priority"] == "CRITICAL"
    assert res["linked_alert_count"] == 2
    # Verify priority upgrade UPDATE was executed
    executed_sql = " ".join(str(c.args[0]) for c in mock_conn.execute.call_args_list)
    assert "UPDATE cases SET priority = $1" in executed_sql
    assert "INSERT INTO case_alerts" in executed_sql


@pytest.mark.anyio
async def test_p1_1_alerts_grouped_by_entity_endpoint():
    token = _make_token(role="L1_ANALYST", username="l1.triage")
    subj_id = uuid.uuid4()

    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=[
        {
            "subject_account_id": subj_id,
            "account_number": "DE8937040044",
            "owner_name": "Shell Holdings Ltd",
            "alert_count": 4,
            "max_risk_score": 0.94,
            "total_exposure_usd": 48500.0,
            "alert_ids": [str(uuid.uuid4()), str(uuid.uuid4())],
            "rules_fired": ["STRUCTURING_SMURFING", "LARGE_TRANSACTION"],
            "latest_alert_at": datetime.now(timezone.utc),
            "active_case_id": None,
        }
    ])
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    transport = ASGITransport(app=app)
    with patch("routers.alerts.get_async_db_read_conn", return_value=mock_ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get(
                "/api/v1/alerts/grouped-by-entity",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res.status_code == 200
            body = res.json()
            assert body["total_entities"] == 1
            assert body["entities"][0]["alert_count"] == 4
            assert body["entities"][0]["total_exposure_usd"] == 48500.0


# ── P1-2: Historical Rule Backtesting & Champion-Challenger Shadow Mode ────────
def test_p1_2_evaluate_rule_on_tx_row_logic():
    hit, _ = evaluate_rule_on_tx_row("LARGE_TRANSACTION", {"threshold": 10000.0}, {"amount_base_usd": 12500.0})
    assert hit is True
    hit_low, _ = evaluate_rule_on_tx_row("LARGE_TRANSACTION", {"threshold": 15000.0}, {"amount_base_usd": 12500.0})
    assert hit_low is False


@pytest.mark.anyio
async def test_p1_2_rule_backtest_endpoint_computes_delta_and_avoided_fps():
    token = _make_token(role="ADMIN", username="rule.admin")
    now = datetime.now(timezone.utc)

    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value={"enabled": True, "config": {"threshold": 10000.0}})
    mock_conn.fetch = AsyncMock(return_value=[
        {
            "id": uuid.uuid4(),
            "sender_account_id": uuid.uuid4(),
            "amount": 11500.0,
            "amount_base_usd": 11500.0,
            "currency": "USD",
            "country": "US",
            "channel": "WIRE",
            "timestamp": now - timedelta(days=2),
            "historical_alert_status": "CLOSED_FALSE_POSITIVE",
        },
        {
            "id": uuid.uuid4(),
            "sender_account_id": uuid.uuid4(),
            "amount": 25000.0,
            "amount_base_usd": 25000.0,
            "currency": "USD",
            "country": "US",
            "channel": "WIRE",
            "timestamp": now - timedelta(days=1),
            "historical_alert_status": "CLOSED_SAR",
        },
    ])
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    transport = ASGITransport(app=app)
    with patch("services.rule_backtest.get_async_db_read_conn", return_value=mock_ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post(
                "/api/v1/rules/LARGE_TRANSACTION/backtest",
                headers={"Authorization": f"Bearer {token}", "X-CSRF-Protection": "1"},
                json={"candidate_config": {"threshold": 15000.0}, "lookback_days": 30},
            )
            assert res.status_code == 200
            body = res.json()
            assert body["champion_hits"] == 2
            assert body["challenger_hits"] == 1
            assert body["delta_hits"] == -1
            assert body["avoided_false_positives"] == 1
            assert body["captured_historical_sars"] == 1
            assert body["missed_historical_sars"] == 0


@pytest.mark.anyio
async def test_p1_2_shadow_rule_evaluation_persists_silently():
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=[
        {
            "rule_name": "LARGE_TRANSACTION",
            "version": 3,
            "mode": "SHADOW",
            "config": {"threshold": 5000.0},
            "shadow_config": {"threshold": 5000.0},
        }
    ])
    mock_conn.execute = AsyncMock()

    hits = await evaluate_shadow_rules(
        conn=mock_conn,
        tenant_id=TENANT_ID,
        transaction_id=uuid.uuid4(),
        sender_account_id=uuid.uuid4(),
        amount_base_usd=7500.0,
        country="US",
        channel="WIRE",
    )
    assert hits == ["LARGE_TRANSACTION"]
    assert mock_conn.execute.call_count == 1
    assert "INSERT INTO rule_shadow_hits" in mock_conn.execute.call_args.args[0]


# ── P1-3: Global Cmd+K Search & Bulk Triage RBAC Separation ────────────────────
@pytest.mark.anyio
async def test_p1_3_global_search_and_bulk_triage_rbac():
    l1_token = _make_token(role="L1_ANALYST", username="l1.sarah")
    alert_1 = str(uuid.uuid4())

    # 1. Global Cmd+K search endpoint
    mock_search_conn = AsyncMock()
    mock_search_conn.fetch = AsyncMock(side_effect=[
        [{"id": uuid.uuid4(), "account_number": "ACC-999", "owner_name": "Acme Corp", "swift_bic": "CHASUS33", "status": "ACTIVE", "risk_score": 0.85}],
        [{"id": uuid.uuid4(), "case_number": "CASE-2026-001", "title": "Acme Ring", "status": "OPEN", "priority": "HIGH"}],
        [],
        [],
    ])
    search_ctx = AsyncMock()
    search_ctx.__aenter__.return_value = mock_search_conn
    search_ctx.__aexit__.return_value = None

    transport = ASGITransport(app=app)
    with patch("routers.search.get_async_db_read_conn", return_value=search_ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/v1/search/global?q=Acme", headers={"Authorization": f"Bearer {l1_token}"})
            assert res.status_code == 200
            body = res.json()
            assert body["total"] == 2
            assert len(body["accounts"]) == 1
            assert len(body["cases"]) == 1

    # 2. L1_ANALYST CAN bulk CLAIM alerts
    mock_bulk_conn = AsyncMock()
    mock_bulk_conn.fetch = AsyncMock(return_value=[{"id": uuid.UUID(alert_1)}])
    bulk_ctx = AsyncMock()
    bulk_ctx.__aenter__.return_value = mock_bulk_conn
    bulk_ctx.__aexit__.return_value = None

    with patch("routers.alerts.get_async_db_conn", return_value=bulk_ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res_claim = await ac.post(
                "/api/v1/alerts/bulk-action",
                headers={
                    "Authorization": f"Bearer {l1_token}",
                    "X-CSRF-Protection": "1",
                    "Idempotency-Key": str(uuid.uuid4()),
                },
                json={"alert_ids": [alert_1], "action": "CLAIM", "justification": "Claiming triage batch"},
            )
            assert res_claim.status_code == 200
            assert res_claim.json()["processed_count"] == 1

            # 3. L1_ANALYST MUST be blocked (403) from bulk CLOSE_SAR
            res_close = await ac.post(
                "/api/v1/alerts/bulk-action",
                headers={"Authorization": f"Bearer {l1_token}", "X-CSRF-Protection": "1"},
                json={"alert_ids": [alert_1], "action": "CLOSE_SAR", "justification": "Unauthorized closure"},
            )
            assert res_close.status_code == 403


# ── P1-4: Automated Notification & SLA Escalation Engine ───────────────────────
@pytest.mark.anyio
async def test_p1_4_sla_escalation_sweep_and_deduplication():
    alert_id = uuid.uuid4()
    sar_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(side_effect=[
        [{"id": alert_id, "rule_name": "SANCTIONS_HIT", "threat_level": "CRITICAL", "status": "OPEN", "created_at": now - timedelta(hours=30)}],
        [{"id": sar_id, "alert_id": alert_id, "status": "PENDING_MLRO_REVIEW", "statutory_deadline_at": now + timedelta(days=2)}],
    ])
    # First alert not yet notified (None -> creates id); SAR already notified (1 -> deduplicated!)
    mock_conn.fetchval = AsyncMock(side_effect=[None, uuid.uuid4(), 1])
    mock_conn.execute = AsyncMock()

    with patch("services.notifications.enqueue_webhook_event_tx", AsyncMock()) as mock_wh:
        res = await run_sla_escalation_sweep(conn=mock_conn, tenant_id=TENANT_ID)
        assert res["alert_sla_escalations"] == 1
        assert res["sar_deadline_escalations"] == 0  # Deduplicated!
        assert res["total_notifications_created"] == 1
        assert mock_wh.call_count == 1


# ── P1-5: Perpetual KYC (pKYC) Delta Rescreening & QA Four-Eyes Sampling ───────
@pytest.mark.anyio
async def test_p1_5_pkyc_delta_rescreen_flags_newly_sanctioned_account():
    acc_id = uuid.uuid4()
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=[
        {
            "id": acc_id,
            "account_number": "ACC-PKYC-001",
            "owner_name": "Vladimir Smirnov",
            "risk_score": 0.10,
            "status": "ACTIVE",
            "pkyc_material_change_flag": False,
        }
    ])
    mock_conn.execute = AsyncMock()
    mock_conn.fetchval = AsyncMock(side_effect=[
        uuid.uuid4(),  # INSERT alerts RETURNING id
        None,          # dedup check for notification
        uuid.uuid4(),  # INSERT notifications RETURNING id
        uuid.uuid4(),  # INSERT pkyc_rescreen_runs RETURNING id
    ])

    with patch("services.pkyc_and_qa.perform_sanctions_search", AsyncMock(return_value={"match_found": True, "source_list": "OFAC SDN"})), \
         patch("services.pkyc_and_qa.perform_pep_search", AsyncMock(return_value={"match_found": False})):
        res = await run_pkyc_delta_rescreen(conn=mock_conn, tenant_id=TENANT_ID, triggered_by="mlro.elena")
        assert res["accounts_scanned"] == 1
        assert res["material_changes_found"] == 1
        assert res["alerts_generated"] == 1
        assert res["flagged_accounts"][0]["reason"] == "PKYC_SANCTIONS_DELTA_HIT"


@pytest.mark.anyio
async def test_p1_5_qa_four_eyes_enforces_sod_and_reopens_failed_dismissal():
    review_id = uuid.uuid4()
    alert_id = uuid.uuid4()

    # Case 1: Original analyst attempts to QA their own dismissal -> 403 SoD violation
    same_analyst_token = _make_token(role="MLRO", username="analyst.bob")
    mock_conn_sod = AsyncMock()
    mock_conn_sod.fetchrow = AsyncMock(return_value={
        "id": review_id,
        "alert_id": alert_id,
        "status": "PENDING",
        "original_analyst_username": "analyst.bob",
    })
    ctx_sod = AsyncMock()
    ctx_sod.__aenter__.return_value = mock_conn_sod
    ctx_sod.__aexit__.return_value = None

    transport = ASGITransport(app=app)
    with patch("routers.qa.get_async_db_conn", return_value=ctx_sod):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res_sod = await ac.post(
                f"/api/v1/qa/{review_id}/review",
                headers={"Authorization": f"Bearer {same_analyst_token}", "X-CSRF-Protection": "1"},
                json={"decision": "PASSED", "notes": "Self-approving my own closure"},
            )
            assert res_sod.status_code == 403
            assert "Segregation of Duties" in res_sod.json()["detail"]

    # Case 2: Independent QA reviewer fails dismissal -> reopens alert to OPEN
    qa_token = _make_token(role="QA_REVIEWER", username="qa.claire")
    mock_conn_fail = AsyncMock()
    mock_conn_fail.fetchrow = AsyncMock(return_value={
        "id": review_id,
        "alert_id": alert_id,
        "status": "PENDING",
        "original_analyst_username": "analyst.bob",
    })
    mock_conn_fail.execute = AsyncMock()
    mock_conn_fail.fetchval = AsyncMock(return_value=uuid.uuid4())
    ctx_fail = AsyncMock()
    ctx_fail.__aenter__.return_value = mock_conn_fail
    ctx_fail.__aexit__.return_value = None

    with patch("routers.qa.get_async_db_conn", return_value=ctx_fail):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res_fail = await ac.post(
                f"/api/v1/qa/{review_id}/review",
                headers={"Authorization": f"Bearer {qa_token}", "X-CSRF-Protection": "1"},
                json={"decision": "FAILED_REOPENED", "notes": "Structuring evidence overlooked; reopen immediately."},
            )
            assert res_fail.status_code == 200
            body = res_fail.json()
            assert body["status"] == "FAILED_REOPENED"
            assert body["reopened"] is True
            executed_sql = " ".join(str(c.args[0]) for c in mock_conn_fail.execute.call_args_list)
            assert "UPDATE alerts SET status = 'OPEN'" in executed_sql


# ── P1-6: Shared Shell, Cmd+K, Notification Bell & Responsive CSS Integrity ────
def test_p1_6_frontend_shell_and_responsive_breakpoints_present():
    with open("static/api-client.js", "r", encoding="utf-8") as f:
        api_client = f.read()
    assert "sentinel-shell.js" in api_client

    with open("static/sentinel-shell.js", "r", encoding="utf-8") as f:
        shell_js = f.read()
    assert "/api/v1/search/global" in shell_js
    assert "/api/v1/notifications" in shell_js
    assert "setConnectionState" in shell_js
    assert "alert(" not in shell_js and "confirm(" not in shell_js and "prompt(" not in shell_js

    with open("static/style.css", "r", encoding="utf-8") as f:
        css = f.read()
    assert "@media (max-width: 1024px)" in css
    assert "@media (max-width: 768px)" in css
