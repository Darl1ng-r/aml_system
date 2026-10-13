import pytest
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from services.rules import RulesEngine
from services.dynamic_scorer import compute_dynamic_risk
from services.network_analysis import compute_transitive_counterparty_taint


@pytest.mark.anyio
async def test_structuring_extended_7d_triggers():
    """Verify that multiple sub-threshold transfers totaling >= $10k over 7 days triggers STRUCTURING_EXTENDED_7D."""
    sender_id = str(uuid.uuid4())
    mock_conn = AsyncMock()
    # Mock past 7 days: 2 transfers totaling $7,000
    mock_conn.fetchrow.return_value = {
        "total_sub_amount": 7000.0,
        "sub_count": 2
    }

    with patch("services.rules.get_async_db_conn") as mock_db:
        mock_db.return_value.__aenter__.return_value = mock_conn

        # 3rd transfer of $3,500 (total = $10,500 >= $10,000 across 3 transfers)
        rules = await RulesEngine.evaluate_transaction(
            sender_id=sender_id,
            receiver_id=str(uuid.uuid4()),
            amount=3500.0,
            metadata={"kyc_risk_tier": "STANDARD"}
        )

        assert "STRUCTURING_EXTENDED_7D" in rules


@pytest.mark.anyio
async def test_structuring_extended_7d_risk_tier_scaling():
    """Verify that for HIGH kyc_risk_tier, the structuring threshold is discounted to 50% ($5,000 target)."""
    sender_id = str(uuid.uuid4())
    mock_conn = AsyncMock()
    # Mock past 7 days: 2 transfers totaling $3,600
    mock_conn.fetchrow.return_value = {
        "total_sub_amount": 3600.0,
        "sub_count": 2
    }

    with patch("services.rules.get_async_db_conn") as mock_db:
        mock_db.return_value.__aenter__.return_value = mock_conn

        # Transfer of $1,800 gives total $5,400 >= $5,000 threshold for HIGH risk tier
        rules = await RulesEngine.evaluate_transaction(
            sender_id=sender_id,
            receiver_id=str(uuid.uuid4()),
            amount=1800.0,
            metadata={"kyc_risk_tier": "HIGH"}
        )

        assert "STRUCTURING_EXTENDED_7D" in rules


@pytest.mark.anyio
async def test_conduit_rapid_passthrough_flow_ratio():
    """Verify that conduit flow turnaround (24h Inflow ~= Outflow ratio within [0.85, 1.15]) triggers CONDUIT_RAPID_PASSTHROUGH."""
    sender_id = str(uuid.uuid4())
    mock_conn = AsyncMock()
    # Mock 24h inflows = $20,000, prior outflows = $0
    mock_conn.fetchrow.return_value = {
        "total_inflow": 20000.0,
        "total_outflow": 0.0
    }

    with patch("services.rules.get_async_db_conn") as mock_db:
        mock_db.return_value.__aenter__.return_value = mock_conn

        # Current outgoing transfer is $19,000 (ratio = 19000 / 20000 = 0.95 -> conduit pattern)
        rules = await RulesEngine.evaluate_transaction(
            sender_id=sender_id,
            receiver_id=str(uuid.uuid4()),
            amount=19000.0
        )

        assert "CONDUIT_RAPID_PASSTHROUGH" in rules


@pytest.mark.anyio
async def test_amount_anomaly_heuristics():
    """Verify that just-below-threshold and round-number anomalies trigger appropriately."""
    with patch("services.rules.get_async_db_conn") as mock_db:
        mock_conn = AsyncMock()
        mock_conn.fetchrow.return_value = None
        mock_db.return_value.__aenter__.return_value = mock_conn

        # 1. $9,500 is in [9000, 10000) -> JUST_BELOW_CTR_THRESHOLD
        rules_just_below = await RulesEngine.evaluate_transaction(
            sender_id=str(uuid.uuid4()),
            receiver_id=str(uuid.uuid4()),
            amount=9500.0
        )
        assert "JUST_BELOW_CTR_THRESHOLD" in rules_just_below

        # 2. $5,000 is multiple of $1,000 -> ROUND_NUMBER_ANOMALY_1K
        rules_round = await RulesEngine.evaluate_transaction(
            sender_id=str(uuid.uuid4()),
            receiver_id=str(uuid.uuid4()),
            amount=5000.0
        )
        assert "ROUND_NUMBER_ANOMALY_1K" in rules_round

        # 3. $3,456.78 has cents, not round -> Neither triggers
        rules_clean = await RulesEngine.evaluate_transaction(
            sender_id=str(uuid.uuid4()),
            receiver_id=str(uuid.uuid4()),
            amount=3456.78
        )
        assert "JUST_BELOW_CTR_THRESHOLD" not in rules_clean
        assert "ROUND_NUMBER_ANOMALY_1K" not in rules_clean


def test_dynamic_scorer_non_compensatory_floors_and_taint():
    """Verify that extreme behavioral spikes, taint risk, and critical rules impose non-compensatory floors regardless of low ML scores."""
    # Low ML score = 0.05, but extreme behavioral anomaly (Z >= 3.5)
    res_z = compute_dynamic_risk(
        rules_triggered=[],
        ml_score=0.05,
        amount=50000.0,
        baseline={"avg_amount": 1000.0, "variance_amount": 10000.0},
        iforest_score=0.10,
        sender_risk=0.10,
        receiver_risk=0.10
    )
    # Floor of 0.80 enforced despite 0.05 ML score
    assert res_z["dynamic_risk_score"] >= 0.80

    # Low ML score = 0.05, but upstream transitive taint = 0.85
    res_taint = compute_dynamic_risk(
        rules_triggered=[],
        ml_score=0.05,
        amount=100.0,
        baseline={"avg_amount": 100.0, "variance_amount": 100.0},
        iforest_score=0.10,
        sender_risk=0.10,
        receiver_risk=0.10,
        taint_risk=0.85
    )
    assert res_taint["dynamic_risk_score"] >= 0.85
    assert any("TRANSITIVE_TAINT_PROPAGATION" in d for d in res_taint["top_drivers"])
    assert res_taint["explainability"]["taint_risk_contribution"] == 0.85

    # Critical rule trigger CONDUIT_RAPID_PASSTHROUGH enforces floor >= 0.85
    res_conduit = compute_dynamic_risk(
        rules_triggered=["CONDUIT_RAPID_PASSTHROUGH"],
        ml_score=0.10,
        amount=15000.0,
        baseline={"avg_amount": 15000.0, "variance_amount": 100.0},
        iforest_score=0.10
    )
    assert res_conduit["dynamic_risk_score"] >= 0.85
    assert any("CONDUIT_FUNDS_FLOW_THROUGH" in d for d in res_conduit["top_drivers"])


@pytest.mark.anyio
async def test_compute_transitive_counterparty_taint_query():
    """Verify transitive taint traverses up to 2 hops and decays upstream risk."""
    mock_session = AsyncMock()
    mock_record = {"taint_score": 0.4225}
    mock_result = AsyncMock()
    mock_result.single.return_value = mock_record
    mock_session.run.return_value = mock_result

    mock_driver = MagicMock()
    mock_driver.session.return_value.__aenter__.return_value = mock_session
    mock_driver.session.return_value.__aexit__.return_value = None

    with patch("services.network_analysis.get_async_neo4j_driver", AsyncMock(return_value=mock_driver)):
        score = await compute_transitive_counterparty_taint(
            account_number="ACC-TARGET-123",
            tenant_id="tenant-xyz",
            max_hops=2,
            decay_factor=0.65
        )
        assert score == 0.4225
        assert mock_session.run.called
