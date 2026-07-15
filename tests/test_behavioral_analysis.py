import asyncio
import asyncpg
import numpy as np
import os
import sys
from datetime import datetime, timedelta, timezone

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.postgres import init_db_pool, close_db_pool, get_async_db_conn
from services.behavioral import calculate_customer_baseline, get_customer_baseline
from services.isolation_forest import IsolationForestScratch, get_iforest_score, retrain_system_iforest
from services.dynamic_scorer import compute_dynamic_risk

async def execute_db(query, *args):
    async with get_async_db_conn() as conn:
        return await conn.execute(query, *args)

async def fetchval_db(query, *args):
    async with get_async_db_conn() as conn:
        return await conn.fetchval(query, *args)

async def setup_test_data():
    print("Seeding test data for behavioral verification...")
    # Clear old data
    await execute_db("DELETE FROM transactions;")
    await execute_db("DELETE FROM customer_profiles;")
    await execute_db("DELETE FROM accounts WHERE account_number IN ('BEHAVIOR_ACC_1', 'BEHAVIOR_ACC_2');")
    
    tenant_id = await fetchval_db("SELECT id FROM tenants LIMIT 1;")
    if not tenant_id:
        tenant_id = await fetchval_db("INSERT INTO tenants (name) VALUES ('Test Tenant') RETURNING id;")
        
    sender_id = await fetchval_db(
        "INSERT INTO accounts (tenant_id, account_number, swift_bic, owner_name, risk_score) VALUES ($1, $2, $3, $4, $5) RETURNING id;",
        tenant_id, "BEHAVIOR_ACC_1", "DBANKDE1XXX", "Alice Schmidt", 0.10
    )
    receiver_id = await fetchval_db(
        "INSERT INTO accounts (tenant_id, account_number, swift_bic, owner_name, risk_score) VALUES ($1, $2, $3, $4, $5) RETURNING id;",
        tenant_id, "BEHAVIOR_ACC_2", "CHASEUS3XXX", "Bob Jones", 0.15
    )
    
    # Seed 10 transactions with standard patterns:
    # Amounts: 100, 110, 95, 105, 100, 115, 90, 100, 105, 110 (mean = 103, std = ~7.5)
    # Countries: DE, DE, DE, US, DE, US, DE, US, DE, DE
    # Merchants: Amazon, Amazon, Netflix, Amazon, Netflix, Netflix, Amazon, Amazon, Netflix, Amazon
    # Devices: iPhone, iPhone, iPhone, Macbook, iPhone, Macbook, iPhone, iPhone, iPhone, Macbook
    # Channels: MOBILE, MOBILE, MOBILE, WEB, MOBILE, WEB, MOBILE, MOBILE, MOBILE, WEB
    amounts = [100.0, 110.0, 95.0, 105.0, 100.0, 115.0, 90.0, 100.0, 105.0, 110.0]
    countries = ["DE", "DE", "DE", "US", "DE", "US", "DE", "US", "DE", "DE"]
    merchants = ["Amazon", "Amazon", "Netflix", "Amazon", "Netflix", "Netflix", "Amazon", "Amazon", "Netflix", "Amazon"]
    devices = ["iPhone", "iPhone", "iPhone", "Macbook", "iPhone", "Macbook", "iPhone", "iPhone", "iPhone", "Macbook"]
    channels = ["MOBILE", "MOBILE", "MOBILE", "WEB", "MOBILE", "WEB", "MOBILE", "MOBILE", "MOBILE", "WEB"]
    
    base_time = datetime.now(timezone.utc) - timedelta(days=5)
    for i in range(10):
        tx_time = base_time + timedelta(hours=i * 2)
        await execute_db(
            """
            INSERT INTO transactions (id, tenant_id, sender_account_id, receiver_account_id, amount, currency, status, timestamp, country, merchant, device, channel)
            VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, 'COMPLETED', $6, $7, $8, $9, $10);
            """,
            tenant_id, sender_id, receiver_id, amounts[i], "USD", tx_time,
            countries[i], merchants[i], devices[i], channels[i]
        )
        
    return sender_id, receiver_id

async def run_tests():
    print("Initializing pools...")
    await init_db_pool()
    
    sender_id, receiver_id = await setup_test_data()
    
    # Test 1: Baseline Calculation
    print("\n--- Test 1: Baseline Calculation ---")
    baseline = await calculate_customer_baseline(str(sender_id))
    print("Baseline result:")
    for k, v in baseline.items():
        print(f"  {k}: {v}")
        
    assert abs(baseline["avg_amount"] - 103.0) < 0.1
    assert abs(baseline["median_amount"] - 102.5) < 0.1
    assert baseline["unique_receivers_count"] == 1
    assert baseline["unique_receiver_countries_count"] == 2
    assert "DE" in baseline["top_countries"]
    assert "Amazon" in baseline["top_merchants"]
    assert "iPhone" in baseline["top_devices"]
    assert "MOBILE" in baseline["top_channels"]
    
    # Test 2: Custom Isolation Forest Algorithm
    print("\n--- Test 2: Custom Isolation Forest ---")
    # Generate random training dataset
    np.random.seed(42)
    X = np.random.normal(loc=100.0, scale=10.0, size=(100, 2))
    # Add outlier at [1000, 1000]
    outlier = np.array([[1000.0, 1000.0]])
    X_train = np.vstack([X, outlier])
    
    forest = IsolationForestScratch(n_estimators=50, max_samples=256)
    forest.fit(X_train)
    
    normal_score = forest.compute_anomaly_score(np.array([100.0, 100.0]))
    outlier_score = forest.compute_anomaly_score(np.array([1000.0, 1000.0]))
    
    print(f"Normal point score: {normal_score:.4f}")
    print(f"Outlier point score: {outlier_score:.4f}")
    # Outlier must have significantly higher anomaly score than normal point
    assert outlier_score > normal_score
    assert outlier_score > 0.55
    
    # Test 3: System-wide Isolation Forest Wrapper Retraining
    print("\n--- Test 3: Retraining System-wide Forest ---")
    await retrain_system_iforest()
    score = await get_iforest_score(amount=500.0, sender_risk=0.10, receiver_risk=0.15, hour=12, is_geo=0)
    print(f"Score for transaction in retrained forest: {score:.4f}")
    assert 0.0 <= score <= 1.0

    # Test 4: Dynamic Risk Scorer Blend
    print("\n--- Test 4: Dynamic Scorer Blends ---")
    # Scenario A: Normal transaction (Amount = 105, similar to baseline mean = 103, std = 7.4)
    normal_res = compute_dynamic_risk(
        rules_triggered=[],
        ml_score=0.12,
        amount=105.0,
        baseline=baseline,
        iforest_score=0.45
    )
    print(f"Normal transaction dynamic risk details: {normal_res}")
    
    # Scenario B: High Amount Deviation transaction (Amount = 250 -> Z-score > 15)
    outlier_res = compute_dynamic_risk(
        rules_triggered=[],
        ml_score=0.20,
        amount=250.0,
        baseline=baseline,
        iforest_score=0.72
    )
    print(f"Outlier transaction dynamic risk details: {outlier_res}")
    
    assert outlier_res["dynamic_risk_score"] > normal_res["dynamic_risk_score"]
    assert outlier_res["explainability"]["baseline_zscore_contribution"] > 0.25 # Z-score contribution close to max weight (0.30)
    
    # Cleanup test data
    await execute_db("DELETE FROM transactions;")
    await execute_db("DELETE FROM customer_profiles;")
    await execute_db("DELETE FROM accounts WHERE account_number IN ('BEHAVIOR_ACC_1', 'BEHAVIOR_ACC_2');")
    
    await close_db_pool()
    print("\n=== ALL BEHAVIORAL VERIFICATION TESTS PASSED SUCCESSFULLY! ===")

if __name__ == "__main__":
    asyncio.run(run_tests())
