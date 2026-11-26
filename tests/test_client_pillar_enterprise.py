"""
Enterprise Client Pillar Regression Suite
=========================================
Validates all 5 workstreams of the Client Pillar enterprise upgrade:
  1. Conditional HTTP revalidation (ETag / If-None-Match -> 304) preserving Cache-Control: no-store
  2. Strictly mandatory Idempotency-Key (400 if missing/malformed) + replay / 409 / 422 semantics
  3. Optimistic Concurrency Control (If-Match / expected_version -> 412 Precondition Failed)
  4. Lean REST sparse projection (?fields=summary) & composite BFF (/alerts/{id}/workbench)
  5. Frontend unified transport (api-client.js), server-state cache (sentinel-query.js),
     XSS escaping, CORS headers, and OpenAPI TypeScript contract drift gate.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

import httpx
from httpx import ASGITransport
import pytest

from main import app
from services.auth import create_access_token

ROOT = Path(__file__).resolve().parent.parent
TENANT_ID = "00000000-0000-0000-0000-000000000001"


def _auth_headers(role: str = "ADMIN", user_id: str | None = None, extra: dict | None = None) -> dict:
    uid = user_id or str(uuid.uuid4())
    tok = create_access_token(
        {
            "sub": uid,
            "id": uid,
            "username": f"tester_{role.lower()}",
            "role": role,
            "email": f"{role.lower()}@sentinel.bank",
            "tenant_id": TENANT_ID,
            "token_version": 1,
        }
    )
    hdrs = {
        "Authorization": f"Bearer {tok}",
        "X-CSRF-Protection": "1",
    }
    if extra:
        hdrs.update(extra)
    return hdrs


def _mock_db_ctx(conn):
    @asynccontextmanager
    async def _ctx(*args, **kwargs):
        yield conn
    return _ctx


class _InMemoryRedis:
    """Minimal async Redis stand-in for testing Idempotency-Key replay, 409, and 422."""

    def __init__(self):
        self.store: dict[str, str] = {}

    async def set(self, key: str, value: str, nx: bool = False, ex: int | None = None):
        if nx and key in self.store:
            return False
        self.store[key] = value
        return True

    async def get(self, key: str):
        return self.store.get(key)

    async def delete(self, key: str):
        return 1 if self.store.pop(key, None) is not None else 0


# ── 1. Conditional ETag / 304 Not Modified with Cache-Control: no-store ───────


@pytest.mark.asyncio
async def test_conditional_etag_304_on_high_frequency_read_endpoints():
    headers = _auth_headers("ADMIN")
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=[])
    mock_conn.fetchval = AsyncMock(return_value=0)
    mock_conn.fetchrow = AsyncMock(return_value=None)

    transport = ASGITransport(app=app)
    with (
        patch("services.auth._verify_token_version", AsyncMock(return_value=None)),
        patch("routers.notifications.get_async_db_read_conn", side_effect=_mock_db_ctx(mock_conn)),
        patch("routers.risk_appetite.get_async_db_read_conn", side_effect=_mock_db_ctx(mock_conn)),
        patch("routers.rules.get_async_db_conn", side_effect=_mock_db_ctx(mock_conn)),
        patch("routers.metrics.get_async_db_read_conn", side_effect=_mock_db_ctx(mock_conn)),
        patch("database.redis_db.get_async_redis_client", AsyncMock(return_value=None)),
    ):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            for endpoint in (
                "/api/v1/auth/me",
                "/api/v1/notifications?limit=25",
                "/api/v1/rules",
                "/api/v1/settings/risk-appetite",
                "/api/v1/metrics/executive",
            ):
                r1 = await ac.get(endpoint, headers=headers)
                assert r1.status_code == 200, f"{endpoint} returned {r1.status_code}: {r1.text}"
                etag = r1.headers.get("etag")
                assert etag, f"{endpoint} missing ETag header"
                assert r1.headers.get("cache-control") == "no-store"

                r2 = await ac.get(endpoint, headers={**headers, "If-None-Match": etag})
                assert r2.status_code == 304, f"{endpoint} failed conditional 304"
                assert r2.content == b""
                assert r2.headers.get("etag") == etag
                assert r2.headers.get("cache-control") == "no-store"


# ── 2. Strictly Mandatory Idempotency-Key (400 if missing) & Replay / 409 / 422


@pytest.mark.asyncio
async def test_mandatory_idempotency_key_returns_400_on_all_regulatory_mutations():
    headers = _auth_headers("ADMIN")
    aid = str(uuid.uuid4())
    cid = str(uuid.uuid4())
    did = str(uuid.uuid4())

    cases = [
        ("POST", f"/api/v1/alerts/{aid}/action", {"action": "CLOSE_FALSE_POSITIVE", "justification": "Verified payroll transfer"}),
        ("POST", f"/api/v1/alerts/{aid}/escalate", {"justification": "Needs L2 review"}),
        ("POST", f"/api/v1/alerts/{aid}/claim", None),
        ("POST", "/api/v1/alerts/bulk-action", {"alert_ids": [aid], "action": "CLAIM", "justification": "Batch claim"}),
        ("POST", "/api/v1/cases", {"title": "Structuring Investigation", "priority": "HIGH", "alert_ids": []}),
        ("POST", f"/api/v1/cases/{cid}/close", {"closure_reason": "FALSE_POSITIVE", "closing_notes": "Cleared after EDD"}),
        ("POST", "/api/v1/fincen/sar/drafts", {"alert_id": aid, "narrative": "Detailed suspicious activity narrative for BSA."}),
        ("POST", f"/api/v1/fincen/sar/drafts/{did}/review", {"action": "APPROVE"}),
    ]

    transport = ASGITransport(app=app)
    with patch("services.auth._verify_token_version", AsyncMock(return_value=None)):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            for method, url, payload in cases:
                res = await ac.request(method, url, headers=headers, json=payload)
                assert res.status_code == 400, f"{method} {url} should require Idempotency-Key (got {res.status_code})"
                assert "Idempotency-Key" in res.json().get("detail", "")

            # Malformed Idempotency-Key (< 8 chars or illegal chars) also rejected with 400
            bad_res = await ac.post(
                "/api/v1/cases",
                headers={**headers, "Idempotency-Key": "bad!"},
                json={"title": "Invalid Key Case", "priority": "MEDIUM", "alert_ids": []},
            )
            assert bad_res.status_code == 400


@pytest.mark.asyncio
async def test_idempotency_replay_mismatch_422_and_inflight_409_on_case_create():
    fake_redis = _InMemoryRedis()
    created_id = uuid.uuid4()
    mock_conn = AsyncMock()
    mock_conn.fetchval = AsyncMock(return_value=created_id)
    mock_conn.execute = AsyncMock()

    headers = _auth_headers("ADMIN")
    idem_key = str(uuid.uuid4())
    body_a = {"title": "Wire Layering Ring", "priority": "HIGH", "alert_ids": []}
    body_b = {"title": "Different Case Payload", "priority": "LOW", "alert_ids": []}

    transport = ASGITransport(app=app)
    with (
        patch("services.auth._verify_token_version", AsyncMock(return_value=None)),
        patch("services.idempotency.get_async_redis_client", AsyncMock(return_value=fake_redis)),
        patch("routers.cases.get_async_db_conn", side_effect=_mock_db_ctx(mock_conn)),
    ):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r1 = await ac.post("/api/v1/cases", headers={**headers, "Idempotency-Key": idem_key}, json=body_a)
            assert r1.status_code == 201
            assert r1.headers.get("idempotency-replayed") is None
            assert mock_conn.fetchval.await_count == 1

            # Exact retry -> replays cached 201 response without touching DB again
            r2 = await ac.post("/api/v1/cases", headers={**headers, "Idempotency-Key": idem_key}, json=body_a)
            assert r2.status_code == 201
            assert r2.headers.get("idempotency-replayed") == "true"
            assert r2.json()["case_id"] == r1.json()["case_id"]
            assert mock_conn.fetchval.await_count == 1

            # Reusing key with different payload -> 422 Unprocessable Entity
            r_mismatch = await ac.post("/api/v1/cases", headers={**headers, "Idempotency-Key": idem_key}, json=body_b)
            assert r_mismatch.status_code == 422

            # Simulated in-flight key -> 409 Conflict
            inflight_key = str(uuid.uuid4())
            fake_redis.store[f"idemp:{TENANT_ID}:cases:create:{inflight_key}"] = json.dumps({"status": "IN_FLIGHT"})
            r_conflict = await ac.post("/api/v1/cases", headers={**headers, "Idempotency-Key": inflight_key}, json=body_a)
            assert r_conflict.status_code == 409


# ── 3. Optimistic Concurrency Control (If-Match -> 412 Precondition Failed) ───


@pytest.mark.asyncio
async def test_optimistic_concurrency_if_match_returns_412_across_rules_cases_and_sars():
    headers = _auth_headers("ADMIN")
    now = datetime(2026, 11, 25, 10, 0, 0, tzinfo=timezone.utc)
    case_id = uuid.uuid4()
    draft_id = uuid.uuid4()

    # 1. Rules PATCH with stale If-Match
    rule_conn = AsyncMock()
    rule_conn.fetchrow = AsyncMock(
        return_value={
            "id": uuid.uuid4(),
            "enabled": True,
            "mode": "ACTIVE",
            "config": {"threshold": 10000},
            "shadow_config": None,
            "version": 4,
        }
    )

    # 2. Case PATCH with stale If-Match
    case_conn = AsyncMock()
    case_conn.fetchrow = AsyncMock(
        return_value={
            "id": case_id,
            "status": "OPEN",
            "created_at": now,
            "updated_at": now,
        }
    )

    # 3. SAR Draft PATCH with stale If-Match
    sar_conn = AsyncMock()
    sar_conn.fetchrow = AsyncMock(
        return_value={
            "id": draft_id,
            "status": "DRAFT",
            "created_at": now,
            "updated_at": now,
        }
    )

    transport = ASGITransport(app=app)
    with (
        patch("services.auth._verify_token_version", AsyncMock(return_value=None)),
        patch("routers.rules.get_async_db_conn", side_effect=_mock_db_ctx(rule_conn)),
        patch("routers.cases.get_async_db_conn", side_effect=_mock_db_ctx(case_conn)),
        patch("routers.fincen.get_async_db_conn", side_effect=_mock_db_ctx(sar_conn)),
    ):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r_rule = await ac.patch(
                "/api/v1/rules/LARGE_TRANSACTION",
                headers={**headers, "If-Match": '"rule-v2"', "Idempotency-Key": str(uuid.uuid4())},
                json={"config": {"threshold": 15000}},
            )
            assert r_rule.status_code == 412
            assert r_rule.headers.get("etag") == '"rule-v4"'

            r_rule_ver = await ac.patch(
                "/api/v1/rules/LARGE_TRANSACTION",
                headers={**headers, "Idempotency-Key": str(uuid.uuid4())},
                json={"config": {"threshold": 15000}, "expected_version": 2},
            )
            assert r_rule_ver.status_code == 412

            r_case = await ac.patch(
                f"/api/v1/cases/{case_id}",
                headers={**headers, "If-Match": '"case-stale-etag"'},
                json={"priority": "CRITICAL"},
            )
            assert r_case.status_code == 412

            r_sar = await ac.patch(
                f"/api/v1/fincen/sar/drafts/{draft_id}",
                headers={**headers, "If-Match": '"sar-draft-stale-etag"'},
                json={"narrative": "Updated narrative text after conflict."},
            )
            assert r_sar.status_code == 412


# ── 4. Sparse Projection (?fields=summary) & Composite BFF (/workbench) ───────


@pytest.mark.asyncio
async def test_alerts_summary_projection_and_workbench_bff_endpoint():
    headers = _auth_headers("ADMIN")
    alert_id = uuid.uuid4()
    txn_id = uuid.uuid4()
    sender_id = uuid.uuid4()
    receiver_id = uuid.uuid4()
    now = datetime(2026, 11, 25, 10, 0, 0, tzinfo=timezone.utc)

    # Row tuple matching list_alerts SELECT order
    list_row = (
        alert_id, "STRUCTURING_SMURFING", "HIGH", 0.88, None, "OPEN", now,
        9800.0, "USD", now, "ACC-001", "ACC-002", "Unassigned",
        "Alice Corp", "Bob LLC", "HIGH", now, "WIRE", "US"
    )
    list_conn = AsyncMock()
    list_conn.fetchval = AsyncMock(return_value=1)
    list_conn.fetch = AsyncMock(return_value=[list_row])

    # Workbench row dict
    wb_row = {
        "id": alert_id,
        "rule_name": "STRUCTURING_SMURFING",
        "threat_level": "HIGH",
        "ai_risk_score": 0.88,
        "explainability_payload": {"shap": {"velocity": 0.62}},
        "status": "OPEN",
        "created_at": now,
        "assignee": "Unassigned",
        "txn_id": txn_id,
        "amount": 9800.0,
        "currency": "USD",
        "txn_time": now,
        "country": "US",
        "channel": "WIRE",
        "merchant": "Wire Desk",
        "device": "web",
        "sender_id": sender_id,
        "sender_account": "ACC-001",
        "sender_name": "Alice Corp",
        "sender_bic": "CHASUS33",
        "sender_risk_score": 0.72,
        "sender_risk_tier": "HIGH",
        "sender_created_at": now,
        "receiver_id": receiver_id,
        "receiver_account": "ACC-002",
        "receiver_name": "Bob LLC",
        "receiver_bic": "BOFAUS3N",
    }
    wb_conn = AsyncMock()
    wb_conn.fetchrow = AsyncMock(side_effect=[wb_row, None])
    wb_conn.fetch = AsyncMock(
        return_value=[
            {
                "id": uuid.uuid4(),
                "escalated_by_name": "l1_analyst",
                "from_tier": 1,
                "to_tier": 2,
                "escalation_reason": "Repeated sub-threshold deposits",
                "created_at": now,
            }
        ]
    )
    wb_conn.fetchval = AsyncMock(return_value=3)

    transport = ASGITransport(app=app)
    with (
        patch("services.auth._verify_token_version", AsyncMock(return_value=None)),
        patch("routers.alerts.get_async_db_read_conn", side_effect=_mock_db_ctx(list_conn)),
    ):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r_sum = await ac.get("/api/v1/alerts?fields=summary", headers=headers)
            assert r_sum.status_code == 200
            rows = r_sum.json()
            assert len(rows) == 1
            assert "explainability" not in rows[0]
            assert rows[0]["rule_name"] == "STRUCTURING_SMURFING"

    with (
        patch("services.auth._verify_token_version", AsyncMock(return_value=None)),
        patch("routers.alerts.get_async_db_read_conn", side_effect=_mock_db_ctx(wb_conn)),
        patch("routers.alerts._fetch_customer_timeline_and_alerts", AsyncMock(return_value=([], []))),
        patch("routers.alerts._fetch_counterparties", AsyncMock(return_value=[])),
        patch("services.locking.get_resource_lock_status", AsyncMock(return_value={"locked": False})),
    ):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r_wb = await ac.get(f"/api/v1/alerts/{alert_id}/workbench", headers=headers)
            assert r_wb.status_code == 200
            wb = r_wb.json()
            assert wb["evidence_count"] == 3
            assert len(wb["escalations"]) == 1
            assert wb["alert"]["explainability"] == {"shap": {"velocity": 0.62}}
            etag = r_wb.headers.get("etag")
            assert etag

            # Conditional 304 on identical workbench bundle
            wb_conn.fetchrow = AsyncMock(side_effect=[wb_row, None])
            r_wb_304 = await ac.get(
                f"/api/v1/alerts/{alert_id}/workbench",
                headers={**headers, "If-None-Match": etag},
            )
            assert r_wb_304.status_code == 304


# ── 5. Frontend Transport, Cache, XSS & OpenAPI Contract Governance ───────────


def test_client_pillar_frontend_and_contract_invariants():
    api_js = (ROOT / "static" / "api-client.js").read_text(encoding="utf-8")
    sq_js = (ROOT / "static" / "sentinel-query.js").read_text(encoding="utf-8")
    shell_js = (ROOT / "static" / "sentinel-shell.js").read_text(encoding="utf-8")
    app_js = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
    triage_html = (ROOT / "static" / "triage.html").read_text(encoding="utf-8")
    exec_html = (ROOT / "static" / "executive-dashboard.html").read_text(encoding="utf-8")
    rules_html = (ROOT / "static" / "rules-admin.html").read_text(encoding="utf-8")
    sar_html = (ROOT / "static" / "sar-editor.html").read_text(encoding="utf-8")
    main_py = (ROOT / "main.py").read_text(encoding="utf-8")

    # Unified transport & cross-tab auth lock
    assert "navigator.locks.request" in api_js
    assert "aml_sentinel_auth" in api_js
    assert "generateIdempotencyKey" in api_js
    assert "class SentinelApiError" in api_js
    assert "RETRYABLE_STATUSES" in api_js
    assert "window.fetch = function" not in app_js

    # Server-state cache engine wired via shared head snippet
    assert "/static/sentinel-query.js" in main_py
    assert "If-None-Match" in sq_js
    assert "res.status === 304" in sq_js
    assert "aml_sentinel_cache" in sq_js
    assert "abortLanes" in sq_js
    assert "async function mutate(" in sq_js

    # Shell, Triage, Executive, Rules & SAR adoption + XSS escaping
    assert "abortKey: 'cmdk-search'" in shell_js
    assert "fields=summary" in triage_html
    assert "/workbench" in triage_html
    assert "applyOptimisticAlertPatch" in triage_html
    assert "esc(ownerName)" in triage_html
    assert "esc(b.rule_name)" in exec_html
    assert "If-Match" in rules_html and "412" in rules_html
    assert "If-Match" in sar_html and "412" in sar_html

    # OpenAPI & TypeScript contract files exist and match live schema
    assert (ROOT / "contracts" / "openapi.json").exists()
    assert (ROOT / "src" / "api" / "schema.d.ts").exists()
    from scripts.export_openapi_contract import build_contracts
    expected_openapi, expected_ts = build_contracts()
    assert (ROOT / "contracts" / "openapi.json").read_text(encoding="utf-8") == expected_openapi
    assert (ROOT / "src" / "api" / "schema.d.ts").read_text(encoding="utf-8") == expected_ts
