"""
Unit test verifying real feature processing in scoring_worker.py (GAP-14)
=========================================================================
"""

import pytest
from unittest.mock import patch, AsyncMock
from workers.scoring_worker import score_transaction

@pytest.mark.asyncio
async def test_scoring_worker_passes_real_features():
    test_event = {
        "transaction_id": "00000000-0000-0000-0000-000000000123",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "sender_id": "00000000-0000-0000-0000-000000000111",
        "receiver_id": "00000000-0000-0000-0000-000000000222",
        "amount": 75000.0,
        "currency": "USD",
        "sender_risk": 0.85,
        "receiver_risk": 0.65,
        "velocity_count": 9,
        "timestamp": "2026-09-14T03:15:00Z",
        "is_geo_risk": 1,
        "channel": "Wire"
    }

    with patch("workers.scoring_worker.RulesEngine.evaluate_transaction", new_callable=AsyncMock) as mock_rules, \
         patch("workers.scoring_worker.anomaly_model.predict") as mock_predict, \
         patch("workers.scoring_worker.get_customer_baseline", new_callable=AsyncMock) as mock_baseline, \
         patch("workers.scoring_worker.get_iforest_score", new_callable=AsyncMock) as mock_iforest, \
         patch("workers.scoring_worker.compute_dynamic_risk") as mock_dynamic, \
         patch("workers.scoring_worker.get_async_db_conn") as mock_db, \
         patch("workers.scoring_worker.calculate_customer_baseline", new_callable=AsyncMock):

        mock_rules.return_value = ["STRUCTURING"]
        mock_predict.return_value = (0.88, {"amount_log": 0.4})
        mock_baseline.return_value = {"jurisdiction_risk_score": 0.8}
        mock_iforest.return_value = 0.75
        mock_dynamic.return_value = {
            "dynamic_risk_score": 0.92,
            "explainability": {"reason": "High risk test"}
        }

        # Mock DB connection
        mock_conn = AsyncMock()
        mock_db.return_value.__aenter__.return_value = mock_conn

        await score_transaction(test_event)

        # Verify anomaly_model.predict received real features, NOT hardcoded 0.2/1/12/0
        assert mock_predict.called
        passed_features = mock_predict.call_args[0][0]
        assert passed_features["amount"] == 75000.0
        assert passed_features["sender_risk"] == 0.85
        assert passed_features["receiver_risk"] == 0.65
        assert passed_features["velocity_24h"] == 9
        assert passed_features["hour_of_day"] == 3
        assert passed_features["is_geographic_risk"] == 1

        # Verify iforest also received real features
        assert mock_iforest.called
        iforest_kwargs = mock_iforest.call_args[1]
        assert iforest_kwargs["amount"] == 75000.0
        assert iforest_kwargs["sender_risk"] == 0.85
        assert iforest_kwargs["receiver_risk"] == 0.65
        assert iforest_kwargs["hour"] == 3
        assert iforest_kwargs["is_geo"] == 1
