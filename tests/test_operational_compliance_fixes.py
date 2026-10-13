"""
Unit & Integration Tests for Operational Compliance Fixes
==========================================================
Verifies the 4 non-negotiable compliance fixes required by the veteran BSA/AML audit:
  1. UCC Article 4A / Reg CC: Decoupling Transaction Surveillance from Payment Clearing
  2. Customer-Level Entity Aggregation (TIN / Beneficial Owner Scoping for Smurfing)
  3. Entity-Level False Positive Whitelisting (Four-Eyes Adjudication)
  4. Automated FinCEN 5-Part SAR Narrative Synthesis
"""

import json
import uuid
import pytest
import httpx
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from main import app
from services.auth import create_access_token
from services.rules import RulesEngine
from services.whitelisting import add_to_whitelist, is_entity_whitelisted, clear_local_whitelist_cache
from services.sar_narrative import synthesize_5part_narrative, generate_sar_narrative

TENANT_ID = "00000000-0000-0000-0000-000000000001"


def make_token(role: str = "ANALYST", user_id: uuid.UUID = None, tenant_id: str = TENANT_ID) -> str:
    uid = user_id or uuid.uuid4()
    return create_access_token(
        data={"sub": f"user-{uid}", "role": role, "user_id": str(uid), "tenant_id": tenant_id},
        expires_delta=timedelta(minutes=30)
    )


# ══════════════════════════════════════════════════════════════════════════════
# FIX 1: Decouple Transaction Surveillance from Payment Clearing (UCC 4A / Reg CC)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.anyio
async def test_behavioral_alert_allows_payment_to_settle_approved():
    """
    Under UCC Article 4A and Reg CC, behavioral AML anomalies (structuring, velocity spikes,
    ML risk scores >= 0.75) must settle as APPROVED/COMPLETED in-flight to prevent paralyzed
    legitimate commerce and federal tipping-off (31 U.S.C. 5318(g)(2)), while still raising
    an investigative alert in the investigator queue.
    """
    token = make_token("ANALYST")
    sender_uuid = uuid.uuid4()
    receiver_uuid = uuid.uuid4()

    mock_read_conn = AsyncMock()
    mock_read_conn.fetchrow.return_value = {
        "sender_id": sender_uuid,
        "sender_tenant": TENANT_ID,
        "sender_risk": 0.35,
        "sender_name": "Commercial Corp",
        "sender_bic": "BOFAUS3NXXX",
        "sender_status": "ACTIVE",
        "receiver_id": receiver_uuid,
        "receiver_risk": 0.20,
        "receiver_name": "Supplier LLC",
        "receiver_bic": "CHASEUS3XXX",
        "receiver_status": "ACTIVE",
        "velocity_count": 5
    }

    mock_read_ctx = AsyncMock()
    mock_read_ctx.__aenter__.return_value = mock_read_conn
    mock_read_ctx.__aexit__.return_value = None

    mock_write_conn = AsyncMock()
    mock_write_conn.fetch.return_value = [{"id": sender_uuid, "status": "ACTIVE"}]
    mock_write_conn.execute.return_value = "INSERT 0 1"

    mock_write_ctx = AsyncMock()
    mock_write_ctx.__aenter__.return_value = mock_write_conn
    mock_write_ctx.__aexit__.return_value = None

    # Simulate a transaction triggering behavioral anomaly: ML score = 0.88 + STRUCTURING
    with patch("routers.transactions.get_async_db_read_conn", return_value=mock_read_ctx), \
         patch("routers.transactions.get_async_db_conn", return_value=mock_write_ctx), \
         patch("routers.transactions.anomaly_model.predict_risk", return_value={"risk_score": 0.88, "attributions": {"amount": 0.9}}), \
         patch("routers.transactions.RulesEngine.evaluate_transaction", return_value=["STRUCTURING_VELOCITY_24H"]), \
         patch("routers.transactions.get_customer_baseline", return_value={"avg_amount": 1000.0, "std_amount": 200.0}), \
         patch("routers.transactions.get_iforest_score", return_value=0.85), \
         patch("routers.transactions.publish_transaction", new_callable=AsyncMock), \
         patch("routers.transactions.calculate_customer_baseline", new_callable=AsyncMock):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {token}"}) as ac:
            resp = await ac.post(
                "/api/v1/transactions",
                json={
                    "sender_account": "ACC_SEND_COMMERCIAL",
                    "receiver_account": "ACC_RECV_SUPPLIER",
                    "amount": 9500.0,
                    "currency": "USD",
                    "channel": "WIRE",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )

            assert resp.status_code == 201
            body = resp.json()
            # Non-negotiable requirement: Payment settles as APPROVED despite alert
            assert body["decision"] == "APPROVED", "Behavioral anomaly must settle as APPROVED to prevent tipping off!"
            assert body["alert_triggered"] is True, "Investigative alert must still be triggered!"
            assert "STRUCTURING_VELOCITY_24H" in body["triggered_rules"]

            # Verify the written status in DB is COMPLETED (not HELD)
            inserted_calls = [str(call) for call in mock_write_conn.execute.call_args_list]
            assert any("COMPLETED" in call for call in inserted_calls)


@pytest.mark.anyio
async def test_hard_sanctions_hit_holds_transaction():
    """
    Direct hard sanctions match (OFAC / SANCTIONS_HIT) must freeze the transaction as HELD.
    """
    token = make_token("ANALYST")
    sender_uuid = uuid.uuid4()
    receiver_uuid = uuid.uuid4()

    mock_read_conn = AsyncMock()
    mock_read_conn.fetchrow.return_value = {
        "sender_id": sender_uuid,
        "sender_tenant": TENANT_ID,
        "sender_risk": 0.99,
        "sender_name": "Target SDN Corp",
        "sender_bic": "BOFAUS3NXXX",
        "sender_status": "ACTIVE",
        "receiver_id": receiver_uuid,
        "receiver_risk": 0.20,
        "receiver_name": "Supplier LLC",
        "receiver_bic": "CHASEUS3XXX",
        "receiver_status": "ACTIVE",
        "velocity_count": 1
    }

    mock_read_ctx = AsyncMock()
    mock_read_ctx.__aenter__.return_value = mock_read_conn
    mock_read_ctx.__aexit__.return_value = None

    mock_write_conn = AsyncMock()
    mock_write_conn.fetch.return_value = [{"id": sender_uuid, "status": "ACTIVE"}]
    mock_write_conn.execute.return_value = "INSERT 0 1"

    mock_write_ctx = AsyncMock()
    mock_write_ctx.__aenter__.return_value = mock_write_conn
    mock_write_ctx.__aexit__.return_value = None

    # Simulate direct sanctions match
    with patch("routers.transactions.get_async_db_read_conn", return_value=mock_read_ctx), \
         patch("routers.transactions.get_async_db_conn", return_value=mock_write_ctx), \
         patch("routers.transactions.anomaly_model.predict_risk", return_value={"risk_score": 0.99, "attributions": {}}), \
         patch("routers.transactions.RulesEngine.evaluate_transaction", return_value=["SANCTIONS_HIT"]), \
         patch("routers.transactions.get_customer_baseline", return_value={}), \
         patch("routers.transactions.get_iforest_score", return_value=0.5), \
         patch("routers.transactions.publish_transaction", new_callable=AsyncMock), \
         patch("routers.transactions.calculate_customer_baseline", new_callable=AsyncMock):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {token}"}) as ac:
            resp = await ac.post(
                "/api/v1/transactions",
                json={
                    "sender_account": "ACC_SDN",
                    "receiver_account": "ACC_RECV",
                    "amount": 5000.0,
                    "currency": "USD",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )

            assert resp.status_code == 201
            body = resp.json()
            assert body["decision"] == "HELD"
            assert body["alert_triggered"] is True
            assert "SANCTIONS_HIT" in body["triggered_rules"]


# ══════════════════════════════════════════════════════════════════════════════
# FIX 2: Customer-Level Entity Aggregation (TIN / Beneficial Owner Scoping)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.anyio
async def test_entity_level_multi_account_structuring_aggregation():
    """
    A smurf splitting $21,000 across multiple accounts under the same beneficial owner/customer_id
    ($7,000 from account 1, $7,000 from account 2, $7,000 from account 3) must trigger
    STRUCTURING_VELOCITY_24H via entity-level sliding window aggregation in Redis.
    """
    customer_entity_id = f"cust-entity-{uuid.uuid4().hex[:8]}"
    acc_1 = str(uuid.uuid4())
    acc_2 = str(uuid.uuid4())

    mock_redis = MagicMock()
    pipe = AsyncMock()
    pipe.__aenter__.return_value = pipe
    pipe.__aexit__.return_value = None
    mock_redis.pipeline.return_value = pipe

    # Account 2 has no prior txs, but Entity sliding window has prior $7000 from Account 1
    pipe.execute.return_value = [
        0,                             # zremrangebyscore account
        [],                            # zrange account (empty)
        1,                             # zadd account
        1,                             # expire account
        0,                             # zremrangebyscore entity
        [(f"7000.0:{time_sec}:nonce1", time_sec)] if (time_sec := 1700000000) else [], # zrange entity
        1,                             # zadd entity
        1                              # expire entity
    ]

    with patch("services.rules.get_async_redis_client", return_value=mock_redis), \
         patch("services.rules.get_async_db_conn") as mock_db:
        mock_conn = AsyncMock()
        mock_conn.fetchrow.return_value = None
        mock_db.return_value.__aenter__.return_value = mock_conn

        # Account 2 now sends $7,000 (< $10,000 threshold individually, but entity aggregate = $14,000!)
        triggered = await RulesEngine.evaluate_transaction(
            sender_id=acc_2,
            receiver_id=str(uuid.uuid4()),
            amount=7000.0,
            metadata={"customer_id": customer_entity_id, "tax_id": "12-3456789"}
        )

        assert "STRUCTURING_VELOCITY_24H" in triggered, (
            "Entity-level aggregation must detect multi-account smurfing when aggregate exceeds $10k!"
        )


# ══════════════════════════════════════════════════════════════════════════════
# FIX 3: Entity-Level False Positive Whitelisting (Four-Eyes Resolution)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.anyio
async def test_entity_whitelist_suppresses_sanctions_alert():
    """
    A common name ("David Smith") cleared by compliance as FALSE_POSITIVE within its validity
    period must have its SANCTIONS_HIT alert suppressed.
    """
    clear_local_whitelist_cache()
    cleared_name = "David Smith"
    tenant = "00000000-0000-0000-0000-000000000001"

    # Add whitelist entry
    await add_to_whitelist(
        tenant_id=tenant,
        matched_entity_name=cleared_name,
        matched_rule="SANCTIONS_HIT",
        cleared_by="Senior AML Officer Jane",
        notes="Common name false positive, verified non-SDN identity."
    )

    # Verify is_entity_whitelisted resolves True
    assert await is_entity_whitelisted(tenant, cleared_name, "SANCTIONS_HIT") is True
    assert await is_entity_whitelisted(tenant, "Different Person", "SANCTIONS_HIT") is False

    # Mock Elasticsearch returning a fuzzy sanctions hit for "David Smith"
    mock_es = AsyncMock()
    with patch("services.rules.get_async_elasticsearch_client", return_value=mock_es), \
         patch("routers.screening.perform_sanctions_search", return_value={"match_found": True, "score": 0.88, "matched_name": "David Smith"}), \
         patch("services.rules.get_async_redis_client", return_value=AsyncMock()):

        # Rules engine evaluation
        rules = await RulesEngine.evaluate_transaction(
            sender_id=str(uuid.uuid4()),
            receiver_id=str(uuid.uuid4()),
            amount=500.0,
            sender_name=cleared_name,
            tenant_id=tenant
        )

        # Non-negotiable requirement: SANCTIONS_HIT must NOT be triggered
        assert "SANCTIONS_HIT" not in rules, "Whitelisted false positive must be suppressed!"


# ══════════════════════════════════════════════════════════════════════════════
# FIX 4: Automated FinCEN 5-Part SAR Narrative Synthesis
# ══════════════════════════════════════════════════════════════════════════════

def test_synthesize_5part_narrative_structure():
    """
    Verifies that synthesize_5part_narrative produces all 5 mandatory FinCEN sections.
    """
    subject = {
        "name": "Acme Import Corp",
        "account_number": "ACC-100293",
        "tax_id": "12-9876543",
        "onboarding_date": "2024-03-01",
        "risk_tier": "HIGH",
        "cip_status": "VERIFIED",
        "jurisdiction": "US"
    }
    activity = {
        "start_date": "2026-10-01",
        "end_date": "2026-10-02",
        "currency": "USD",
        "total_amount": 19500.0,
        "transaction_count": 2,
        "typologies": ["STRUCTURING_VELOCITY_24H", "JUST_BELOW_CTR_THRESHOLD"],
        "threat_level": "CRITICAL",
        "risk_score": 0.94
    }
    flow = {
        "sender_account": "ACC-100293",
        "sender_name": "Acme Import Corp",
        "sender_bic": "CHASEUS3XXX",
        "channel": "WIRE",
        "merchant": "Corporate Banking",
        "device": "Web API",
        "receiver_account": "ACC-998877",
        "receiver_name": "Offshore Holdings",
        "receiver_bic": "BARCGB22XXX",
        "country": "GB"
    }
    rationale = {
        "narrative_rationale": "Repetitive structured payments calibrated under $10,000 threshold.",
        "baseline_delta_pct": 340.0,
        "amount_zscore": 4.2,
        "pattern_description": "Multiple sub-threshold wire transfers destined for high-risk beneficiary.",
        "drivers": ["Velocity spike", "Cross-border conduit"]
    }
    disposition = {
        "analyst_id": "ANALYST-SEC-44",
        "case_ref": "CASE-SAR-9901"
    }

    narrative = synthesize_5part_narrative(subject, activity, flow, rationale, disposition)

    assert "PART I - SUBJECT IDENTIFICATION & KYC PROFILE:" in narrative
    assert "Acme Import Corp" in narrative
    assert "PART II - SUMMARY OF SUSPICIOUS ACTIVITY:" in narrative
    assert "19,500.00" in narrative
    assert "PART III - CHRONOLOGICAL FLOW OF FUNDS:" in narrative
    assert "ACC-100293" in narrative
    assert "PART IV - WHY THE ACTIVITY IS SUSPICIOUS" in narrative
    assert "340.0%" in narrative
    assert "PART V - DISPOSITION & CONTACT INFORMATION:" in narrative
    assert "ANALYST-SEC-44" in narrative


@pytest.mark.anyio
async def test_alert_narrative_endpoint():
    """
    Verifies GET /api/v1/alerts/{id}/narrative returns 200 with structured 5-part SAR text.
    """
    token = make_token("ANALYST")
    alert_id = str(uuid.uuid4())

    mock_row = {
        "alert_id": alert_id,
        "rule_name": "STRUCTURING_VELOCITY_24H",
        "threat_level": "CRITICAL",
        "ai_risk_score": 0.91,
        "explainability_payload": json.dumps({"dynamic_risk": {"amount_zscore": 3.4}}),
        "alert_status": "OPEN",
        "alert_created_at": datetime.now(timezone.utc),
        "tx_id": str(uuid.uuid4()),
        "amount": 9950.0,
        "currency": "USD",
        "tx_timestamp": datetime.now(timezone.utc),
        "country": "US",
        "merchant": "Online",
        "device": "Browser",
        "channel": "ACH",
        "sender_id": str(uuid.uuid4()),
        "sender_acc": "ACC_SEND_55",
        "sender_name": "Robert Vance",
        "sender_bic": "WFBIUS6SXXX",
        "sender_tier": "HIGH",
        "sender_created": datetime(2025, 2, 1, tzinfo=timezone.utc),
        "sender_status": "ACTIVE",
        "receiver_id": str(uuid.uuid4()),
        "receiver_acc": "ACC_RECV_66",
        "receiver_name": "Vance Refrigeration",
        "receiver_bic": "BOFAUS3NXXX",
        "receiver_tier": "STANDARD"
    }

    mock_db = AsyncMock()
    mock_db.fetchrow.return_value = mock_row
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_db
    mock_ctx.__aexit__.return_value = None

    with patch("database.postgres.get_async_db_read_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"Authorization": f"Bearer {token}"}) as ac:
            resp = await ac.get(f"/api/v1/alerts/{alert_id}/narrative")

            assert resp.status_code == 200
            data = resp.json()
            assert data["alert_id"] == alert_id
            assert "PART I" in data["narrative_text"]
            assert "PART V" in data["narrative_text"]
            assert "parts" in data
            assert "part_1_subject_profile" in data["parts"]
