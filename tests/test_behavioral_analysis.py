import pytest
import numpy as np
from services.isolation_forest import IsolationForestScratch
from services.dynamic_scorer import compute_dynamic_risk
from database.postgres import get_async_db_conn


def test_custom_isolation_forest_algorithm():
    """Verify custom Isolation Forest fits and scores outlier points higher than normal points."""
    np.random.seed(42)
    X = np.random.normal(loc=100.0, scale=10.0, size=(100, 2))
    outlier = np.array([[1000.0, 1000.0]])
    X_train = np.vstack([X, outlier])

    forest = IsolationForestScratch(n_estimators=50, max_samples=256)
    forest.fit(X_train)

    normal_score = forest.compute_anomaly_score(np.array([100.0, 100.0]))
    outlier_score = forest.compute_anomaly_score(np.array([1000.0, 1000.0]))

    assert outlier_score > normal_score
    assert outlier_score > 0.55


def test_dynamic_risk_scorer_blends():
    """Verify dynamic risk scoring blends rules, baseline Z-scores, and ML scores correctly."""
    mock_baseline = {
        "avg_amount": 103.0,
        "std_amount": 7.5,
        "median_amount": 102.5,
        "unique_receivers_count": 1,
        "unique_receiver_countries_count": 2,
        "top_countries": ["DE"],
        "top_merchants": ["Amazon"],
        "top_devices": ["iPhone"],
        "top_channels": ["MOBILE"]
    }

    # Normal transaction ($105 vs mean $103)
    normal_res = compute_dynamic_risk(
        rules_triggered=[],
        ml_score=0.12,
        amount=105.0,
        baseline=mock_baseline,
        iforest_score=0.45
    )

    # Anomaly transaction ($250 vs mean $103)
    outlier_res = compute_dynamic_risk(
        rules_triggered=[],
        ml_score=0.20,
        amount=250.0,
        baseline=mock_baseline,
        iforest_score=0.72
    )

    assert outlier_res["dynamic_risk_score"] > normal_res["dynamic_risk_score"]
    assert outlier_res["explainability"]["baseline_zscore_contribution"] > 0.20


@pytest.mark.anyio
async def test_integration_behavioral_baseline():
    """Integration test verifying customer baseline calculation when DB is available."""
    try:
        async with get_async_db_conn() as conn:
            row = await conn.fetchrow("SELECT id FROM accounts LIMIT 1;")
            if not row:
                pytest.skip("No accounts in PostgreSQL database.")
            account_id = str(row["id"])
    except Exception as e:
        pytest.skip(f"PostgreSQL database connection unavailable: {e}")

    from services.behavioral import calculate_customer_baseline
    baseline = await calculate_customer_baseline(account_id)
    assert "avg_amount" in baseline
    assert "unique_receivers_count" in baseline
