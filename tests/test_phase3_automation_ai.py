"""
Phase 3: Automation & AI Risk Scoring — End-to-End Verification Suite
======================================================================
Validates all Phase 3 deliverables across:
- Trade-Based Money Laundering (TBML) rule detection (Task 3.5)
- Crypto/Fiat & VASP Travel Rule Structuring rule (Task 3.6)
- Cryptographic WORM Hash Chain verification (Task 3.3)
- AI-Assisted SAR Narrative Generator (Task 3.4)
- SHAP Waterfall Explainability attribution breakdown (Task 3.2)
- Active Learning Retraining & Model Inventory (Task 3.1)
- Model Validation & Performance Reports (SR 11-7 / EU AI Act) (Task 3.7)
- SIEM / Splunk / Syslog Forwarder (Task 3.8)
- Dynamic Risk Appetite Settings (Task 3.9)
- Phase 3 Frontend route authentication redirects (Task 3.10)
"""

import uuid
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest

from main import app
from services.rules import RulesEngine
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


# ── 1. Trade-Based Money Laundering (TBML) Rule ───────────────────────────────

@pytest.mark.anyio
async def test_tbml_detection_rule():
    """Verify TRADE_BASED_ML_OVER_UNDER_INVOICING fires on abnormal commodity price variance."""
    now = datetime.now(timezone.utc)

    # 1. High price variance on high-risk commodity (Precious Metals, unit variance 45% > 35%)
    flagged = await RulesEngine.evaluate_transaction(
        sender_id="ACC-EXPORTER",
        receiver_id="ACC-IMPORTER",
        amount=150000.0,
        timestamp=now,
        metadata={
            "goods_category": "PRECIOUS_METALS",
            "unit_price_variance_pct": 45.0,
            "invoice_amount": 150000.0
        }
    )
    assert "TRADE_BASED_ML_OVER_UNDER_INVOICING" in flagged

    # 2. Normal variance on regular goods (Textiles, variance 5%) -> Not triggered
    clear = await RulesEngine.evaluate_transaction(
        sender_id="ACC-EXPORTER",
        receiver_id="ACC-IMPORTER",
        amount=5000.0,
        timestamp=now,
        metadata={
            "goods_category": "TEXTILES",
            "unit_price_variance_pct": 5.0,
            "invoice_amount": 5000.0
        }
    )
    assert "TRADE_BASED_ML_OVER_UNDER_INVOICING" not in clear


# ── 2. Crypto/Fiat & VASP Travel Rule Structuring ─────────────────────────────

@pytest.mark.anyio
async def test_crypto_fiat_vasp_structuring_rule():
    """Verify CRYPTO_FIAT_VASP_STRUCTURING flags Travel Rule threshold gaps and rapid conversions."""
    now = datetime.now(timezone.utc)

    # 1. Missing Travel Rule information on amount >= $1,000 via VASP
    flagged_gap = await RulesEngine.evaluate_transaction(
        sender_id="ACC-FIAT-01",
        receiver_id="ACC-VASP-GATEWAY",
        amount=2500.0,
        receiver_bic="VASPBTCUS33",
        timestamp=now,
        metadata={
            "is_vasp_transfer": True,
            "travel_rule_complete": False
        }
    )
    assert "CRYPTO_FIAT_VASP_STRUCTURING" in flagged_gap

    # 2. Rapid sequential conversions count >= 3
    flagged_rapid = await RulesEngine.evaluate_transaction(
        sender_id="ACC-FIAT-01",
        receiver_id="ACC-VASP-GATEWAY",
        amount=800.0,
        receiver_bic="VASPBTCUS33",
        timestamp=now,
        metadata={
            "is_vasp_transfer": True,
            "travel_rule_complete": True,
            "rapid_conversion_count": 4
        }
    )
    assert "CRYPTO_FIAT_VASP_STRUCTURING" in flagged_rapid


# ── 3. Cryptographic WORM Hash Chain Verification ─────────────────────────────

@pytest.mark.anyio
async def test_cryptographic_audit_hash_chain_verification(auditor_token):
    """Verify GET /api/v1/audit/verify-chain traverses SHA-256 chain and validates zero tampering."""
    mock_conn = AsyncMock()
    mock_conn.fetch.return_value = [
        {
            "id": uuid.uuid4(),
            "created_at": datetime.now(timezone.utc),
            "actor_id": "auditor_user",
            "action": "CONFIG_UPDATE",
            "resource_type": "RULE",
            "resource_id": "LARGE_TX",
            "details": {"threshold": 12000.0}
        },
        {
            "id": uuid.uuid4(),
            "created_at": datetime.now(timezone.utc),
            "actor_id": "mlro_user",
            "action": "APPROVE_SAR",
            "resource_type": "SAR",
            "resource_id": "SAR-001",
            "details": {"status": "FILED"}
        }
    ]

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.audit.get_async_db_read_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            headers = {"Authorization": f"Bearer {auditor_token}", "X-CSRF-Protection": "1"}
            res = await ac.get("/api/v1/audit/verify-chain", headers=headers)
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "VALID"
            assert data["verified_records"] == 2
            assert data["tampered"] is False
            assert "genesis_hash" in data
            assert "chain_head" in data


# ── 4. AI-Assisted SAR Narrative Generator ─────────────────────────────────────

@pytest.mark.anyio
async def test_ai_sar_narrative_generation(analyst_token):
    """Verify POST /api/v1/fincen/sar/generate-narrative synthesizes a 5-part FinCEN narrative."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        headers = {"Authorization": f"Bearer {analyst_token}", "X-CSRF-Protection": "1"}
        payload = {
            "subject_name": "Global Logistics Trading GmbH",
            "account_number": "DE89370400440532013000",
            "counterparty_name": "Offshore Capital Holding LLC",
            "counterparty_account": "CY991823019482019401",
            "amount": 75000.0,
            "currency": "EUR",
            "typologies": ["ROUND_TRIP_DETECTION", "RAPID_MOVEMENT_FUNDS"]
        }
        res = await ac.post("/api/v1/fincen/sar/generate-narrative", headers=headers, json=payload)
        assert res.status_code == 200
        data = res.json()
        narrative = data["narrative"]

        # Conforms to FinCEN Guidance 5 parts
        assert "PART I: SUBJECT IDENTIFICATION" in narrative
        assert "PART II: SUMMARY OF SUSPICIOUS ACTIVITY" in narrative
        assert "PART III: SUSPICIOUS TYPOLOGY" in narrative
        assert "PART IV: COUNTERPARTY" in narrative
        assert "PART V: CONCLUSION & DISPOSITION" in narrative
        assert data["word_count"] > 100
        assert data["character_count"] > 500


# ── 5. SHAP Waterfall Explainability ──────────────────────────────────────────

@pytest.mark.anyio
async def test_shap_waterfall_explainability(analyst_token):
    """Verify GET /api/v1/ml/explain/{alert_id} provides feature attributions."""
    alert_id = uuid.uuid4()
    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = {
        "id": alert_id,
        "rule_name": "STRUCTURING_SMURFING",
        "threat_level": "CRITICAL",
        "ai_risk_score": 0.94,
        "explainability_payload": json.dumps({
            "attributions": {
                "velocity_deviation": 0.35,
                "transaction_amount": 0.25,
                "customer_tenure": -0.05
            }
        }),
        "amount": 9500.0,
        "currency": "USD"
    }

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.ml_feedback.get_async_db_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            headers = {"Authorization": f"Bearer {analyst_token}", "X-CSRF-Protection": "1"}
            res = await ac.get(f"/api/v1/ml/explain/{alert_id}", headers=headers)
            assert res.status_code == 200
            data = res.json()
            assert data["alert_id"] == str(alert_id)
            assert len(data["waterfall_steps"]) >= 3
            assert "plain_english_summary" in data
            assert data["top_risk_driver"] != ""


# ── 6. ML Model Registry & SR 11-7 Validation Report ──────────────────────────

@pytest.mark.anyio
async def test_ml_models_and_sr11_7_validation(mlro_token):
    """Verify GET /api/v1/ml/models and GET /api/v1/ml/reports."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        headers = {"Authorization": f"Bearer {mlro_token}", "X-CSRF-Protection": "1"}

        # 1. Models Registry
        res_models = await ac.get("/api/v1/ml/models", headers=headers)
        assert res_models.status_code == 200
        assert len(res_models.json()["models"]) >= 3

        # 2. SR 11-7 Model Validation Report
        res_rep = await ac.get("/api/v1/ml/reports", headers=headers)
        assert res_rep.status_code == 200
        rep = res_rep.json()
        assert "SR 11-7" in rep["framework"]
        assert rep["performance_metrics"]["accuracy"] > 0.90
        assert "confusion_matrix" in rep
        assert rep["drift_analysis"]["status"] == "STABLE_NO_DRIFT"


# ── 7. SIEM / Splunk Forwarder ────────────────────────────────────────────────

@pytest.mark.anyio
async def test_siem_forwarder_integration(admin_token):
    """Verify SIEM forwarder status, config update, and test probe dispatch."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        headers = {"Authorization": f"Bearer {admin_token}", "X-CSRF-Protection": "1"}

        # 1. GET status
        res_stat = await ac.get("/api/v1/admin/siem/status", headers=headers)
        assert res_stat.status_code == 200
        assert "enabled" in res_stat.json()

        # 2. PUT config
        res_cfg = await ac.put(
            "/api/v1/admin/siem/config",
            headers=headers,
            json={
                "enabled": True,
                "destination_url": "http://127.0.0.1:8088/services/collector/event",
                "auth_token": "TEST-SPLUNK-TOKEN",
                "format": "SPLUNK_HEC"
            }
        )
        assert res_cfg.status_code == 200
        assert res_cfg.json()["status"] == "UPDATED"

        # 3. POST test probe
        res_test = await ac.post("/api/v1/admin/siem/test", headers=headers, json={})
        assert res_test.status_code == 200
        assert "target_url" in res_test.json()


# ── 8. Dynamic Institutional Risk Appetite Lifecycle ─────────────────────────

@pytest.mark.anyio
async def test_risk_appetite_settings_lifecycle(mlro_token):
    """Verify GET and PUT /api/v1/settings/risk-appetite."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        headers = {"Authorization": f"Bearer {mlro_token}", "X-CSRF-Protection": "1"}

        # 1. GET defaults
        res_get = await ac.get("/api/v1/settings/risk-appetite", headers=headers)
        assert res_get.status_code == 200
        data = res_get.json()
        assert data["jurisdiction_risk_multiplier"] >= 1.0

        # 2. PUT update
        res_put = await ac.put(
            "/api/v1/settings/risk-appetite",
            headers=headers,
            json={
                "jurisdiction_risk_multiplier": 1.8,
                "high_risk_jurisdictions": ["RU", "IR", "KP", "SY", "MM"],
                "pep_sanctions_auto_escalate": True,
                "cash_structuring_threshold": 9500.0,
                "crypto_travel_rule_threshold": 1000.0,
                "max_velocity_deviation_zscore": 2.8,
                "sar_filing_sla_hours": 48,
                "edd_mandatory_score_threshold": 0.82,
                "round_trip_window_hours": 48
            }
        )
        assert res_put.status_code == 200
        updated = res_put.json()["settings"]
        assert updated["sar_filing_sla_hours"] == 48
        assert updated["edd_mandatory_score_threshold"] == 0.82


# ── 9. Phase 3 HTML Routes Redirect Unauthenticated Users ─────────────────────

@pytest.mark.parametrize("route", [
    "/ml/governance",
    "/audit/model-reports",
    "/settings/risk-appetite"
])
@pytest.mark.anyio
async def test_phase3_frontend_routes_redirect_unauthenticated(route):
    """Verify unauthenticated requests to Phase 3 pages are securely redirected to /login."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get(route, follow_redirects=False)
        assert res.status_code == 303
        assert res.headers["location"] == "/login"
