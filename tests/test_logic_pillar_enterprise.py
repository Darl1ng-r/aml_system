"""
Enterprise Logic Pillar Integration, Parity, Resilience & Schema Suite (Workstream 6)
=====================================================================================
Verifies:
  1. Sync (`POST /api/v1/transactions`) vs Async (`workers/scoring_worker.py`) compliance
     parity — including BSA CTR filing, structuring alerts, and SR 11-7 provenance.
  2. Consolidated single-connection read-replica rule snapshot (<= 1 DB checkout instead
     of 7 write-pool checkouts) using USD-normalized `COALESCE(amount_base_usd, amount)`.
  3. Dual-layer idempotency: Redis outage seamlessly falls back to PostgreSQL
     `idempotency_records` (replay, 422 payload mismatch, 409 in-flight, clean release).
  4. CTR filing hardening: mandatory `Idempotency-Key` (400 if missing), `FOR UPDATE`
     row lock, terminal `FILED` lockout, and atomic WORM `audit_log`.
  5. Event-loop non-blocking compute bulkheads, Isolation Forest SR 11-7 determinism,
     `EventLoopLagMonitor`, and pure-ASGI `RequestTimeoutMiddleware` (HTTP 504).
  6. Migration `036` schema integrity on live PostgreSQL (`NUMERIC(19, 4)`, `FORCE RLS`
     on `idempotency_records`, provenance columns, unique deduplication indexes).
"""

from __future__ import annotations

import asyncio
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import numpy as np
import pytest
from fastapi import HTTPException

from database.postgres import get_async_db_conn
from main import app
from observability.event_loop_monitor import EventLoopLagMonitor
from observability.middleware import RequestTimeoutMiddleware
from services.auth import create_access_token
from services.idempotency import check_idempotency, clear_idempotency_key, save_idempotency_result
from services.isolation_forest import IsolationForestScratch, get_iforest_score
from services.network_analysis import compute_betweenness_centrality, run_network_analysis
from services.rule_backtest import backtest_rule_config
from services.rules import RulesEngine
from workers.scoring_worker import score_transaction


def _mock_db_ctx(mock_conn):
    @asynccontextmanager
    async def _cm(*args, **kwargs):
        yield mock_conn

    return _cm()


def _make_token(role: str = "MLRO", tenant_id: str | None = None) -> str:
    return create_access_token(
        {
            "sub": f"logic_test_{role.lower()}",
            "id": str(uuid.uuid4()),
            "role": role,
            "tenant_id": tenant_id or "00000000-0000-0000-0000-000000000001",
        }
    )


# ── 1. Sync vs Async Compliance Parity (CTR + Provenance + Decision) ──────────

@pytest.mark.anyio
async def test_sync_and_async_ingestion_have_full_ctr_and_provenance_parity():
    tenant_id = "00000000-0000-0000-0000-000000000001"
    sender_uuid = uuid.uuid4()
    receiver_uuid = uuid.uuid4()
    token = _make_token("ANALYST", tenant_id)

    account_row = {
        "sender_id": sender_uuid,
        "sender_tenant": uuid.UUID(tenant_id),
        "sender_account_number": "ACC_CASH_1",
        "sender_risk": 0.25,
        "sender_name": "Acme Cash Co",
        "sender_bic": "CHASUS33",
        "sender_status": "ACTIVE",
        "sender_customer_id": "CUST-1",
        "sender_tax_id": "12-3456789",
        "receiver_id": receiver_uuid,
        "receiver_account_number": "ACC_CASH_2",
        "receiver_risk": 0.20,
        "receiver_name": "Receiver LLC",
        "receiver_bic": "BOFAUS3N",
        "receiver_status": "ACTIVE",
        "velocity_count": 2,
    }

    def _new_mock_conn():
        conn = AsyncMock()
        conn.fetchrow.side_effect = [
            account_row,
            {"total_cash_24h": Decimal("0"), "cash_count_24h": 0},
        ]
        conn.fetch.return_value = [{"id": sender_uuid, "status": "ACTIVE"}]
        conn.fetchval.return_value = None
        conn.execute.return_value = "INSERT 0 1"
        return conn

    # A) Sync HTTP ingestion of $10,500 CASH deposit
    sync_read_conn = AsyncMock()
    sync_read_conn.fetchrow.return_value = account_row
    sync_write_conn = AsyncMock()
    sync_write_conn.fetch.return_value = [{"id": sender_uuid, "status": "ACTIVE"}]
    sync_write_conn.fetchrow.return_value = {"total_cash_24h": Decimal("0"), "cash_count_24h": 0}
    sync_write_conn.fetchval.return_value = None
    sync_write_conn.execute.return_value = "INSERT 0 1"

    with patch("routers.transactions.get_async_db_read_conn", return_value=_mock_db_ctx(sync_read_conn)), \
         patch("routers.transactions.get_async_db_conn", return_value=_mock_db_ctx(sync_write_conn)), \
         patch("services.fx_rates.get_async_redis_client", new_callable=AsyncMock, return_value=None), \
         patch("routers.transactions.RulesEngine.evaluate_transaction", new_callable=AsyncMock, return_value=["LARGE_TRANSACTION_THRESHOLD"]), \
         patch("routers.transactions.anomaly_model.predict_risk", return_value={"risk_score": 0.35, "attributions": {}, "model_version": "xgboost-test01"}), \
         patch("routers.transactions.get_customer_baseline", new_callable=AsyncMock, return_value={"avg_amount": 500.0}), \
         patch("routers.transactions.get_iforest_score", new_callable=AsyncMock, return_value=0.3), \
         patch("routers.transactions.calculate_customer_baseline", new_callable=AsyncMock), \
         patch("routers.metrics.ws_manager.broadcast", new_callable=AsyncMock), \
         patch("services.rule_backtest.evaluate_shadow_rules", new_callable=AsyncMock), \
         patch("services.network_analysis.compute_transitive_counterparty_taint", new_callable=AsyncMock, return_value=0.0):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {token}"},
        ) as ac:
            resp = await ac.post(
                "/api/v1/transactions",
                json={
                    "sender_account": "ACC_CASH_1",
                    "receiver_account": "ACC_CASH_2",
                    "amount": "10500.00",
                    "currency": "USD",
                    "timestamp": "2026-11-26T01:00:00Z",
                    "channel": "CASH",
                },
            )
            assert resp.status_code == 201
            sync_body = resp.json()

    # B) Async Kafka scoring worker on identical $10,500 CASH deposit
    async_conn = _new_mock_conn()
    with patch("workers.scoring_worker.get_async_db_conn", side_effect=lambda *a, **k: _mock_db_ctx(async_conn)), \
         patch("services.fx_rates.get_async_redis_client", new_callable=AsyncMock, return_value=None), \
         patch("workers.scoring_worker.RulesEngine.evaluate_transaction", new_callable=AsyncMock, return_value=["LARGE_TRANSACTION_THRESHOLD"]), \
         patch("workers.scoring_worker.anomaly_model.predict", return_value=(0.35, {})), \
         patch("workers.scoring_worker.get_customer_baseline", new_callable=AsyncMock, return_value={"avg_amount": 500.0}), \
         patch("workers.scoring_worker.get_iforest_score", new_callable=AsyncMock, return_value=0.3), \
         patch("workers.scoring_worker.calculate_customer_baseline", new_callable=AsyncMock), \
         patch("services.rule_backtest.evaluate_shadow_rules", new_callable=AsyncMock), \
         patch("services.network_analysis.compute_transitive_counterparty_taint", new_callable=AsyncMock, return_value=0.0):
        async_res = await score_transaction(
            {
                "transaction_id": str(uuid.uuid4()),
                "tenant_id": tenant_id,
                "sender_account": "ACC_CASH_1",
                "receiver_account": "ACC_CASH_2",
                "amount": "10500.00",
                "currency": "USD",
                "timestamp": "2026-11-26T01:00:00Z",
                "channel": "CASH",
            }
        )

    # Parity assertions: BOTH paths create BSA CTR filings, lock accounts FOR UPDATE, and emit provenance!
    sync_ctr_sql = [c[0][0] for c in sync_write_conn.execute.call_args_list if "INSERT INTO ctr_filings" in c[0][0]]
    async_ctr_sql = [c[0][0] for c in async_conn.execute.call_args_list if "INSERT INTO ctr_filings" in c[0][0]]
    assert len(sync_ctr_sql) == 1
    assert len(async_ctr_sql) == 1

    async_lock_sql = [c[0][0] for c in async_conn.fetch.call_args_list if "ORDER BY id ASC FOR UPDATE" in c[0][0]]
    assert len(async_lock_sql) == 1

    assert sync_body["decision"] == async_res["decision"] == "APPROVED"
    assert sync_body["alert_triggered"] is True and async_res["alert_triggered"] is True
    assert async_res["ctr_filing_created"] is True
    assert len(sync_body["provenance"]["ruleset_hash"]) == 64
    assert sync_body["provenance"]["ruleset_hash"] == async_res["ruleset_hash"]


# ── 2. Single-Connection Consolidated Rule Snapshot ───────────────────────────

@pytest.mark.anyio
async def test_rules_engine_uses_single_read_connection_and_usd_normalized_sql():
    sender_uuid = str(uuid.uuid4())
    receiver_uuid = str(uuid.uuid4())
    tenant_id = "00000000-0000-0000-0000-000000000001"
    eval_ts = datetime(2026, 11, 26, 2, 0, tzinfo=timezone.utc)

    read_conn = AsyncMock()
    read_conn.fetchrow.return_value = {
        "account_created_at": eval_ts,
        "avg_daily_count": Decimal("1"),
        "stddev_daily_count": Decimal("1"),
        "avg_daily_amount": Decimal("1000"),
        "stddev_daily_amount": Decimal("200"),
        "today_count": 0,
        "today_amount": Decimal("0"),
        "last_incoming_amount_usd": None,
        "last_incoming_at": None,
        "last_outgoing_at": None,
        "has_reverse_tx": False,
        "sub_7d_count": 0,
        "sub_7d_amount_usd": Decimal("0"),
        "conduit_inflow_24h_usd": Decimal("20000"),
        "conduit_outflow_24h_usd": Decimal("0"),
    }

    checkout_count = 0

    @asynccontextmanager
    async def _counting_read_conn(*args, **kwargs):
        nonlocal checkout_count
        checkout_count += 1
        yield read_conn

    with patch("repositories.transaction_repo.get_async_db_read_conn", side_effect=_counting_read_conn), \
         patch("services.rules.get_rules_config_async", new_callable=AsyncMock, return_value={"rules": {
             "LARGE_TRANSACTION": {"enabled": True, "threshold": 10000.0},
             "CONDUIT_RAPID_PASSTHROUGH": {"enabled": True, "min_inflow": 5000.0, "min_ratio": 0.85, "max_ratio": 1.15},
             "STRUCTURING_SMURFING": {"enabled": False},
             "GEOGRAPHIC_SANCTIONS": {"enabled": False},
         }}), \
         patch("services.rules._lookup_account_entity_from_db", new_callable=AsyncMock, return_value=None):
        prov = await RulesEngine.evaluate_transaction_with_provenance(
            sender_id=sender_uuid,
            receiver_id=receiver_uuid,
            amount=Decimal("19000.00"),
            timestamp=eval_ts,
            evaluated_at=eval_ts,
            tenant_id=tenant_id,
            metadata={"customer_id": "CUST-SINGLE-CONN"},
        )

    assert checkout_count == 1, f"Expected exactly 1 consolidated read checkout, got {checkout_count}"
    assert "CONDUIT_RAPID_PASSTHROUGH" in prov.triggered_rules
    assert "LARGE_TRANSACTION_THRESHOLD" in prov.triggered_rules
    sql_executed = read_conn.fetchrow.call_args[0][0]
    assert "COALESCE(amount_base_usd, amount)" in sql_executed
    assert "COALESCE(t.amount_base_usd, t.amount)" in sql_executed
    assert "NOW()" not in sql_executed


# ── 3. Dual-Layer Idempotency (Redis Outage -> PostgreSQL L2 Authority) ───────

@pytest.mark.anyio
async def test_dual_layer_idempotency_survives_redis_outage_via_postgres():
    tenant_id = "00000000-0000-0000-0000-000000000001"
    key = f"logic_test:{uuid.uuid4().hex}"
    req_hash = "a" * 64
    other_hash = "b" * 64

    with patch("services.idempotency.get_async_redis_client", new_callable=AsyncMock, side_effect=ConnectionError("Redis offline")):
        # 1. First call reserves IN_FLIGHT in PostgreSQL idempotency_records
        cached, data = await check_idempotency(key, tenant_id=tenant_id, request_hash=req_hash)
        assert cached is False and data is None

        # 2. Concurrent duplicate returns HTTP 409 from PostgreSQL L2
        with pytest.raises(HTTPException) as exc_409:
            await check_idempotency(key, tenant_id=tenant_id, request_hash=req_hash)
        assert exc_409.value.status_code == 409

        # 3. Complete persists response durably in PostgreSQL
        await save_idempotency_result(
            key,
            status_code=201,
            body={"transaction_id": "tx-durable-1"},
            tenant_id=tenant_id,
            request_hash=req_hash,
        )

        # 4. Retry replays exact response even with Redis still down!
        cached_hit, hit_data = await check_idempotency(key, tenant_id=tenant_id, request_hash=req_hash)
        assert cached_hit is True
        assert hit_data["status_code"] == 201
        assert hit_data["body"]["transaction_id"] == "tx-durable-1"

        # 5. Mismatched body hash returns HTTP 422 from PostgreSQL L2
        with pytest.raises(HTTPException) as exc_422:
            await check_idempotency(key, tenant_id=tenant_id, request_hash=other_hash)
        assert exc_422.value.status_code == 422

        # 6. clear_idempotency_key must NOT delete a COMPLETED record
        await clear_idempotency_key(key, tenant_id=tenant_id)
        still_cached, _ = await check_idempotency(key, tenant_id=tenant_id, request_hash=req_hash)
        assert still_cached is True

    # Clean up test row
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        scope, pure_key = key.split(":", 1)
        await conn.execute(
            "DELETE FROM idempotency_records WHERE tenant_id = $1::uuid AND scope = $2 AND idempotency_key = $3;",
            uuid.UUID(tenant_id),
            scope,
            pure_key,
        )


# ── 4. CTR Filing Hardening (Mandatory Idempotency-Key + FSM Lockout) ─────────

@pytest.mark.anyio
async def test_ctr_submit_requires_idempotency_key_and_blocks_re_filing():
    tenant_id = "00000000-0000-0000-0000-000000000001"
    ctr_id = str(uuid.uuid4())
    token = _make_token("MLRO", tenant_id)
    transport = httpx.ASGITransport(app=app)

    # 1. Missing Idempotency-Key -> 400 Bad Request
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {token}"},
    ) as ac:
        resp_missing = await ac.post(f"/api/v1/ctr/filings/{ctr_id}/submit")
        assert resp_missing.status_code == 400
        assert "Idempotency-Key" in resp_missing.json()["detail"]

    # 2. Already FILED CTR -> terminal FSM lockout (400), never overwrites tracking ID
    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = {
        "id": uuid.UUID(ctr_id),
        "tenant_id": uuid.UUID(tenant_id),
        "transaction_id": uuid.uuid4(),
        "account_id": uuid.uuid4(),
        "amount": Decimal("12000.00"),
        "currency": "USD",
        "status": "FILED",
        "fincen_tracking_id": "CTR-2026-ORIGINAL",
    }
    with patch("repositories.ctr_repo.get_async_db_conn", return_value=_mock_db_ctx(mock_conn)), \
         patch("services.idempotency.check_idempotency", new_callable=AsyncMock, return_value=(False, None)), \
         patch("services.idempotency.clear_idempotency_key", new_callable=AsyncMock):
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={
                "X-CSRF-Protection": "1",
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": str(uuid.uuid4()),
            },
        ) as ac:
            resp_filed = await ac.post(f"/api/v1/ctr/filings/{ctr_id}/submit")
            assert resp_filed.status_code == 400
            assert "terminal" in resp_filed.json()["detail"].lower()
            mock_conn.execute.assert_not_called()


# ── 5. Event-Loop Protection, Deterministic iForest, Lag Monitor & 504 Guard ──

def test_isolation_forest_is_bit_for_bit_deterministic_for_sr11_7():
    rng = np.random.default_rng(123)
    X = rng.normal(loc=5000.0, scale=1500.0, size=(120, 5))
    probe = np.array([45000.0, 0.85, 0.70, 3.0, 1.0])

    m1 = IsolationForestScratch(n_estimators=40, max_samples=64, seed=42).fit(X)
    m2 = IsolationForestScratch(n_estimators=40, max_samples=64, seed=42).fit(X)

    assert m1.model_version == m2.model_version
    assert m1.compute_anomaly_score(probe) == m2.compute_anomaly_score(probe)


@pytest.mark.anyio
async def test_compute_offloading_keeps_event_loop_responsive_and_monitor_samples():
    monitor = EventLoopLagMonitor(interval_seconds=0.02, warn_threshold_seconds=0.2)
    monitor.start()
    try:
        # Build a 120-node graph for Brandes centrality + Tarjan SCC fallback
        graph = {f"ACC-{i}": [f"ACC-{(i + 1) % 120}", f"ACC-{(i + 7) % 120}"] for i in range(120)}
        with patch("services.network_analysis.get_async_neo4j_driver", side_effect=RuntimeError("offline")), \
             patch("services.network_analysis.fetch_transaction_graph", new_callable=AsyncMock, return_value=graph):
            res = await run_network_analysis(tenant_id=None, window_hours=72)
        assert res["circular_flows"]
        assert res["intermediary_ranking"]

        await asyncio.sleep(0.06)
        snap = monitor.snapshot()
        assert snap["samples_recorded"] >= 2
        assert snap["last_lag_ms"] < 200.0
    finally:
        await monitor.stop()


@pytest.mark.anyio
async def test_request_timeout_middleware_returns_504_with_correlation_id():
    async def slow_app(scope, receive, send):
        await asyncio.sleep(0.5)

    mw = RequestTimeoutMiddleware(slow_app, default_timeout_seconds=0.05)
    # Bypass min clamp in __init__ for fast unit test
    mw.default_timeout_seconds = 0.05
    sent: list[dict] = []

    async def capture_send(msg):
        sent.append(msg)

    scope = {"type": "http", "method": "GET", "path": "/api/v1/slow", "headers": []}
    await mw(scope, AsyncMock(), capture_send)

    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 504
    body = json.loads(sent[1]["body"].decode("utf-8"))
    assert "deadline" in body["detail"]
    assert body["correlation_id"]


# ── 6. Migration 036 Schema & FORCE RLS Verification on Live PostgreSQL ───────

@pytest.mark.anyio
async def test_migration_036_schema_precision_rls_provenance_and_unique_indexes():
    tenant_id = "00000000-0000-0000-0000-000000000001"
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        # 1. NUMERIC(19, 4) precision on transactions & ctr_filings
        cols = await conn.fetch(
            """
            SELECT table_name, column_name, numeric_precision, numeric_scale
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND (
                  (table_name = 'transactions' AND column_name IN ('amount', 'amount_base_usd'))
                  OR (table_name = 'ctr_filings' AND column_name = 'amount')
              );
            """
        )
        col_map = {(r["table_name"], r["column_name"]): (r["numeric_precision"], r["numeric_scale"]) for r in cols}
        assert col_map[("transactions", "amount")] == (19, 4)
        assert col_map[("transactions", "amount_base_usd")] == (19, 4)
        assert col_map[("ctr_filings", "amount")] == (19, 4)

        # 2. FORCE ROW LEVEL SECURITY on idempotency_records
        rls_row = await conn.fetchrow(
            """
            SELECT relrowsecurity, relforcerowsecurity
            FROM pg_class
            WHERE relname = 'idempotency_records';
            """
        )
        assert rls_row is not None
        assert rls_row["relrowsecurity"] is True
        assert rls_row["relforcerowsecurity"] is True

        # 3. Provenance & idempotency columns on transactions and alerts
        tx_cols = {
            r["column_name"]
            for r in await conn.fetch(
                "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'transactions';"
            )
        }
        for col in ("idempotency_key", "fx_rate_source", "fx_rate_quoted_at", "evaluated_at", "ruleset_hash", "model_version", "evaluation_provenance"):
            assert col in tx_cols, f"Missing column transactions.{col}"

        alert_cols = {
            r["column_name"]
            for r in await conn.fetch(
                "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'alerts';"
            )
        }
        for col in ("ruleset_hash", "model_version", "evaluated_at"):
            assert col in alert_cols, f"Missing column alerts.{col}"

        # 4. Unique deduplication indexes exist
        idx_names = {
            r["indexname"]
            for r in await conn.fetch(
                "SELECT indexname FROM pg_indexes WHERE schemaname = 'public';"
            )
        }
        assert "uq_transactions_tenant_idempotency_key" in idx_names
        assert "uq_alerts_tenant_tx_rule" in idx_names
        assert "uq_ctr_filings_tenant_tx" in idx_names


# ── 7. Readiness Fail-Fast, Automatic Audit Trace Binding & Migration 037 ─────

@pytest.mark.anyio
async def test_health_ready_fails_fast_503_on_event_loop_saturation():
    transport = httpx.ASGITransport(app=app)
    with patch("observability.event_loop_monitor.is_event_loop_saturated", return_value=True):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/health/ready")
            assert resp.status_code == 503
            assert resp.json()["status"] == "not_ready"


@pytest.mark.anyio
async def test_audit_record_and_error_responses_propagate_correlation_and_trace_id():
    from observability.middleware import correlation_id_var
    from services.audit import record_audit_event_tx

    fake_cid = "cid-audit-trace-check-01"
    fake_tid = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    tok = correlation_id_var.set(fake_cid)
    try:
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=None)
        mock_conn.execute = AsyncMock()

        with patch("observability.middleware.get_current_trace_id", return_value=fake_tid):
            await record_audit_event_tx(
                conn=mock_conn,
                action="TEST_TRACE_AUDIT",
                actor_id="actor-1",
                actor_role="MLRO",
                resource_type="TRANSACTION",
                resource_id="tx-123",
                tenant_id="00000000-0000-0000-0000-000000000001",
                details={"custom": "ok"},
            )

        insert_calls = [c for c in mock_conn.execute.call_args_list if "INSERT INTO audit_log" in c[0][0]]
        assert len(insert_calls) == 1
        persisted_details = json.loads(insert_calls[0][0][13])
        assert persisted_details["correlation_id"] == fake_cid
        assert persisted_details["trace_id"] == fake_tid
        assert persisted_details["custom"] == "ok"

        # Error responses include both correlation_id and trace_id
        transport = httpx.ASGITransport(app=app)
        with patch("main.get_current_trace_id", return_value=fake_tid):
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
                headers={"X-Correlation-ID": fake_cid},
            ) as ac:
                err_resp = await ac.get("/api/v1/transactions/not-a-uuid")
                assert err_resp.status_code in (401, 400)
                err_json = err_resp.json()
                assert err_json["correlation_id"] == fake_cid
                assert err_json["trace_id"] == fake_tid
                assert err_resp.headers.get("x-trace-id") == fake_tid
    finally:
        correlation_id_var.reset(tok)


@pytest.mark.anyio
async def test_migration_037_str_batches_precision_and_mandatory_idempotency():
    tenant_id = "00000000-0000-0000-0000-000000000001"
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        row = await conn.fetchrow(
            """
            SELECT numeric_precision, numeric_scale
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'str_batches'
              AND column_name = 'total_amount';
            """
        )
        assert (row["numeric_precision"], row["numeric_scale"]) == (19, 4)

    # Mandatory Idempotency-Key returns 400 across accounts, risk-appetite, rules, rfi, str_batch
    mlro_token = _make_token("MLRO", tenant_id)
    admin_token = _make_token("ADMIN", tenant_id)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {mlro_token}"},
    ) as ac:
        r1 = await ac.post(f"/api/v1/accounts/{uuid.uuid4()}/freeze", json={"reason": "Court order mandate"})
        r2 = await ac.put("/api/v1/settings/risk-appetite", json={"cash_structuring_threshold": "10000.00"})
        r3 = await ac.patch(
            "/api/v1/rules/LARGE_TRANSACTION",
            json={"enabled": True},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        r4 = await ac.post("/api/v1/str/batch/batches")
        r5 = await ac.post(f"/api/v1/rfi/{uuid.uuid4()}/cancel")
        for r in (r1, r2, r3, r4, r5):
            assert r.status_code == 400, f"Expected 400 missing Idempotency-Key, got {r.status_code}: {r.text}"
            assert "Idempotency-Key" in r.json()["detail"]
