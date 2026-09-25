"""
Phase 2: Advanced Investigation Tools — End-to-End Verification Suite
======================================================================
Validates all Phase 2 deliverables across:
- Round-tripping & shell company typologies (Tasks 2.7 & 2.8)
- EU UNODC goAML XML export format (Task 2.9)
- SAR Draft Editor & MLRO Filing Queue lifecycle (Tasks 2.1 & 2.2)
- Customer 360 Dossier aggregation (Task 2.3)
- Executive Compliance Metrics & SLA breach indicators (Task 2.5)
- Immutable Audit Log Vault query & forensic export (Task 2.6)
- System Topology & Queue Lag Telemetry (Task 2.10)
- Ongoing CDD Re-screening engine (Task 2.11)
- Frontend authentication guards for Phase 2 routes
"""

import uuid
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest

from main import app
from services.rules import RulesEngine
from services.goaml import generate_goaml_xml
from services.auth import create_access_token


@pytest.fixture
def analyst_token():
    return create_access_token({
        "sub": "analyst@bank.com",
        "username": "sarah.analyst",
        "role": "L2_INVESTIGATOR",
        "id": "11111111-1111-1111-1111-111111111111",
        "tenant_id": "00000000-0000-0000-0000-000000000001"
    })


@pytest.fixture
def mlro_token():
    return create_access_token({
        "sub": "mlro@bank.com",
        "username": "compliance.mlro",
        "role": "MLRO",
        "id": "22222222-2222-2222-2222-222222222222",
        "tenant_id": "00000000-0000-0000-0000-000000000001"
    })


@pytest.fixture
def admin_token():
    return create_access_token({
        "sub": "admin@bank.com",
        "username": "sysadmin",
        "role": "ADMIN",
        "id": "33333333-3333-3333-3333-333333333333",
        "tenant_id": "00000000-0000-0000-0000-000000000001"
    })


@pytest.fixture
def auditor_token():
    return create_access_token({
        "sub": "auditor@bank.com",
        "username": "inspector.auditor",
        "role": "AUDITOR",
        "id": "44444444-4444-4444-4444-444444444444",
        "tenant_id": "00000000-0000-0000-0000-000000000001"
    })



# ── 1. AML Typologies: Round-Tripping & Shell Company Detection ───────────────

@pytest.mark.anyio
async def test_round_trip_detection_rule():
    """Verify ROUND_TRIP_DETECTION rule fires when reverse transaction occurs within window."""
    mock_conn = AsyncMock()
    # Mock finding a matching reverse transaction
    mock_conn.fetchval.return_value = 1

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("services.rules.get_async_db_conn", return_value=mock_ctx):
        triggered = await RulesEngine.evaluate_transaction(
            sender_id="acc-101",
            receiver_id="acc-202",
            amount=25000.0,
            timestamp=datetime.now(timezone.utc)
        )
        assert "ROUND_TRIP_DETECTION" in triggered


@pytest.mark.anyio
async def test_newly_incorporated_high_value_rule():
    """Verify NEWLY_INCORPORATED_HIGH_VALUE fires for newly created account transacting >= $50,000."""
    account_uuid = uuid.uuid4()
    mock_conn = AsyncMock()
    # Mock account creation date = 5 days ago (< 90 days threshold)
    created_at = datetime.now(timezone.utc)
    mock_conn.fetchval.return_value = created_at

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("services.rules.get_async_db_conn", return_value=mock_ctx):
        triggered = await RulesEngine.evaluate_transaction(
            sender_id=str(account_uuid),
            receiver_id="acc-counterparty",
            amount=75000.0,
            timestamp=datetime.now(timezone.utc)
        )
        assert "NEWLY_INCORPORATED_HIGH_VALUE" in triggered


# ── 2. EU UNODC goAML XML Export Schema ───────────────────────────────────────

def test_generate_goaml_xml_schema_validity():
    """Verify generate_goaml_xml constructs a valid UNODC goAML schema with required tags."""
    alert_tuple = (
        uuid.uuid4(),
        "ROUND_TRIP_DETECTION",
        "CRITICAL",
        0.92,
        45000.0,
        "EUR",
        datetime.now(timezone.utc),
        "DE89370400440532013000",
        "Apex Trade GmbH",
        "CY91280039201938210392",
        "Vortex Capital Limassol"
    )
    narrative = "Pass-through layering identified. Funds returned to originator within 48 hours."

    xml_str = generate_goaml_xml(alert_tuple, narrative, report_code="STR")
    assert isinstance(xml_str, str)
    assert "<report" in xml_str

    root = ET.fromstring(xml_str)
    assert root.tag == "report"
    assert root.attrib.get("schemaVersion") == "5.0.0"
    assert root.find("report_code").text == "STR"
    assert root.find("rentity_id").text == "AML-SENTINEL-FIU"
    assert "ROUND_TRIP_DETECTION" in root.find("reason").text

    txn = root.find("transaction")
    assert txn is not None
    assert txn.find("amount_local").text == "45000.00"

    from_client = txn.find("t_from_my_client")
    assert from_client is not None
    assert from_client.find("from_account/account_name").text == "Apex Trade GmbH"


# ── 3. SAR Draft Editor & MLRO Filing Queue Endpoints ─────────────────────────

@pytest.mark.anyio
async def test_sar_draft_lifecycle_and_xml_preview(analyst_token, mlro_token):
    """Verify SAR draft update, XML preview (FinCEN & goAML), and MLRO queue retrieval."""
    draft_id = uuid.uuid4()
    alert_id = uuid.uuid4()

    mock_draft = {
        "id": draft_id,
        "alert_id": alert_id,
        "case_id": None,
        "status": "PENDING_MLRO_REVIEW",
        "drafted_by": uuid.uuid4(),
        "drafted_by_username": "sarah.analyst",
        "narrative": "Suspicious rapid movement of funds across offshore accounts.",
        "xml_payload": "<test/>",
        "reviewed_by_username": None,
        "rejection_reason": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "rule_name": "RAPID_MOVEMENT_FUNDS",
        "threat_level": "HIGH",
        "ai_risk_score": 0.88,
        "amount": 35000.0,
        "currency": "USD",
        "sender_account_id": "ACC-001",
        "receiver_account_id": "ACC-002"
    }

    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = mock_draft
    mock_conn.fetch.return_value = [mock_draft]
    mock_conn.execute.return_value = "UPDATE 1"

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.fincen.get_async_db_conn", return_value=mock_ctx), \
         patch("database.postgres.get_async_db_conn", return_value=mock_ctx), \
         patch("database.postgres.get_async_db_read_conn", return_value=mock_ctx):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            # 1. GET /api/v1/fincen/sar/drafts/{id}
            headers = {"Authorization": f"Bearer {analyst_token}", "X-CSRF-Protection": "1"}
            res_get = await ac.get(f"/api/v1/fincen/sar/drafts/{draft_id}", headers=headers)
            assert res_get.status_code == 200
            assert res_get.json()["draft_id"] == str(draft_id)

            # 2. POST /api/v1/fincen/sar/preview for goAML
            res_prev = await ac.post(
                "/api/v1/fincen/sar/preview",
                headers=headers,
                json={
                    "alert_id": str(alert_id),
                    "narrative": "Detailed structuring investigation narrative.",
                    "format": "GOAML"
                }
            )
            assert res_prev.status_code == 200
            assert res_prev.json()["format"] == "GOAML"
            assert "<report" in res_prev.json()["xml"]

            # 3. GET /api/v1/fincen/sar/drafts (MLRO queue)
            headers_mlro = {"Authorization": f"Bearer {mlro_token}", "X-CSRF-Protection": "1"}
            res_queue = await ac.get("/api/v1/fincen/sar/drafts", headers=headers_mlro)
            assert res_queue.status_code == 200
            assert len(res_queue.json()) >= 1


# ── 4. Customer 360 Dossier ───────────────────────────────────────────────────

@pytest.mark.anyio
async def test_customer_360_dossier_aggregation(analyst_token):
    """Verify GET /api/v1/customers/{id}/dossier returns consolidated KYC, risk, and UBO tree."""
    customer_id = uuid.uuid4()

    mock_account = {
        "id": customer_id,
        "account_number": "DE8937040044",
        "swift_bic": "DEUTDEDDFXX",
        "owner_name": "Acme Holdings International",
        "status": "ACTIVE",
        "risk_score": 0.82,
        "risk_category": "HIGH",
        "created_at": datetime.now(timezone.utc),
        "frozen_reason": None,
        "freezing_order_ref": None,
        "frozen_at": None
    }

    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = mock_account
    mock_conn.fetch.return_value = []

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    # Mock Neo4j driver
    mock_session = AsyncMock()
    mock_res = AsyncMock()
    mock_res.data.return_value = [
        {"name": "Elena Rostova", "tax_id": "CY99182301", "percentage": 60.0}
    ]
    mock_session.run.return_value = mock_res
    mock_driver = MagicMock()
    mock_driver.session.return_value.__aenter__.return_value = mock_session
    mock_driver.session.return_value.__aexit__.return_value = None

    with patch("routers.customers.get_async_db_read_conn", return_value=mock_ctx), \
         patch("routers.customers.get_async_neo4j_driver", new_callable=AsyncMock) as mock_get_neo4j:
        mock_get_neo4j.return_value = mock_driver

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            headers = {"Authorization": f"Bearer {analyst_token}", "X-CSRF-Protection": "1"}
            res = await ac.get(f"/api/v1/customers/{customer_id}/dossier", headers=headers)
            assert res.status_code == 200
            dossier = res.json()
            assert dossier["account_number"] == "DE8937040044"
            assert dossier["risk_tier"] == "HIGH"
            assert len(dossier["ubos"]) == 1
            assert dossier["ubos"][0]["name"] == "Elena Rostova"


# ── 5. Executive Compliance Metrics ───────────────────────────────────────────

@pytest.mark.anyio
async def test_executive_compliance_metrics(mlro_token):
    """Verify GET /api/v1/metrics/executive computes SLA breach counts and KPI rates."""
    mock_conn = AsyncMock()
    mock_conn.fetchval.side_effect = [
        42,   # alerts_24h
        15,   # open_alerts
        5,    # open_cases
        8,    # sars_filed_mtd
        100,  # total_closed
        12,   # fps_closed
        3,    # breach_24h
        1,    # breach_48h
        0     # breach_72h
    ]
    mock_conn.fetch.side_effect = [
        [],  # breach_rows
        [{"rule_name": "STRUCTURING_SMURFING", "count": 18}],  # cat_rows
        [{"day": datetime.now(timezone.utc), "count": 10}],     # trend_rows
        []   # leaderboard_rows
    ]

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.metrics.get_async_db_read_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            headers = {"Authorization": f"Bearer {mlro_token}", "X-CSRF-Protection": "1"}
            res = await ac.get("/api/v1/metrics/executive", headers=headers)
            assert res.status_code == 200
            data = res.json()
            assert data["kpis"]["alerts_24h"] == 42
            assert data["sla_breaches"]["breach_24h"] == 3


# ── 6. Immutable Audit Log Vault ──────────────────────────────────────────────

@pytest.mark.anyio
async def test_audit_log_vault_query_and_export(auditor_token):
    """Verify GET /api/v1/audit/logs and GET /api/v1/audit/logs/export."""
    mock_conn = AsyncMock()
    mock_conn.fetchval.return_value = 1
    mock_conn.fetch.return_value = [
        {
            "id": uuid.uuid4(),
            "created_at": datetime.now(timezone.utc),
            "actor_id": "auditor_user",
            "actor_username": "auditor.jones",
            "actor_role": "AUDITOR",
            "actor_ip": "127.0.0.1",
            "actor_user_agent": "Mozilla/5.0",
            "session_id": "sess_123",
            "action": "UPDATE_RULE",
            "resource_type": "RULE",
            "resource_id": "LARGE_TRANSACTION",
            "before_state": None,
            "after_state": None,
            "details": {"threshold": 12000.0}
        }
    ]

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.audit.get_async_db_read_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            headers = {"Authorization": f"Bearer {auditor_token}", "X-CSRF-Protection": "1"}

            # 1. Query logs
            res_query = await ac.get("/api/v1/audit/logs?limit=10", headers=headers)
            assert res_query.status_code == 200
            assert len(res_query.json()["items"]) >= 1

            # 2. Export CSV
            res_csv = await ac.get("/api/v1/audit/logs/export?format=csv", headers=headers)
            assert res_csv.status_code == 200
            assert "text/csv" in res_csv.headers["content-type"]
            assert "X-Audit-Checksum-SHA256" in res_csv.headers


# ── 7. System Health & Queue Lag Telemetry ────────────────────────────────────

@pytest.mark.anyio
async def test_system_and_queue_health():
    """Verify GET /api/v1/health/system and GET /api/v1/admin/queue-health."""
    mock_pool = MagicMock()
    mock_pool._size = 10
    mock_pool._free = 8

    mock_conn = AsyncMock()
    mock_conn.fetchval.return_value = 1
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None
    mock_pool.acquire.return_value = mock_ctx

    with patch("database.postgres.db_pool", mock_pool), \
         patch("database.postgres.get_async_db_conn", return_value=mock_ctx):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            # 1. System health
            res_sys = await ac.get("/api/v1/health/system")
            assert res_sys.status_code == 200
            assert "services" in res_sys.json()

            # 2. Queue health
            res_q = await ac.get("/api/v1/admin/queue-health")
            assert res_q.status_code == 200
            assert res_q.json()["status"] == "HEALTHY"
            assert "kafka_topics" in res_q.json()


# ── 8. Ongoing CDD Re-Screening Trigger ───────────────────────────────────────

@pytest.mark.anyio
async def test_cdd_rescreen_trigger(admin_token):
    """Verify POST /api/v1/watchlist/rescreen initiates batch screening."""
    with patch("services.watchlist_sync.trigger_ongoing_cdd_rescreening", new_callable=AsyncMock) as mock_rescreen:
        mock_rescreen.return_value = {
            "status": "COMPLETED",
            "accounts_checked": 50,
            "hits_detected": 1,
            "escalated_accounts": [{"account_id": str(uuid.uuid4()), "owner_name": "Flagged Entity"}]
        }

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            headers = {"Authorization": f"Bearer {admin_token}", "X-CSRF-Protection": "1"}
            res = await ac.post("/api/v1/watchlist/rescreen", headers=headers)
            assert res.status_code == 200
            assert res.json()["hits_detected"] == 1


# ── 9. Phase 2 HTML Routes Redirect Unauthenticated Users ─────────────────────

@pytest.mark.parametrize("route", [
    "/sar/editor",
    "/sar/queue",
    "/customers",
    "/network",
    "/dashboard/executive",
    "/audit/logs",
    "/admin/health"
])
@pytest.mark.anyio
async def test_phase2_frontend_routes_redirect_unauthenticated(route):
    """Verify unauthenticated requests to Phase 2 pages are securely redirected to /login."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get(route, follow_redirects=False)
        assert res.status_code == 303
        assert res.headers["location"] == "/login"
