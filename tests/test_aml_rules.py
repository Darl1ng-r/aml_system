import asyncio
import asyncpg
import time
import os
import sys
from datetime import datetime, timedelta, timezone

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD,
    SANCTIONS_INDEX
)
from services.rules import RulesEngine, get_rules_config
from database.postgres import init_db_pool, close_db_pool, get_async_db_conn
from database.redis_db import get_async_redis_client
from database.elasticsearch_db import get_async_elasticsearch_client

async def execute_db(query, *args):
    async with get_async_db_conn() as conn:
        return await conn.execute(query, *args)

async def fetchval_db(query, *args):
    async with get_async_db_conn() as conn:
        return await conn.fetchval(query, *args)

async def setup_test_accounts():
    print("Setting up test accounts for rules verification...")
    # Delete test artifacts
    await execute_db("DELETE FROM transactions;")
    await execute_db("DELETE FROM accounts WHERE account_number IN ('TEST_ACC_DE', 'TEST_ACC_RU', 'TEST_ACC_US', 'TEST_ACC_IR', 'TEST_DORMANT');")
    
    tenant_id = await fetchval_db("SELECT id FROM tenants LIMIT 1;")
    if not tenant_id:
        tenant_id = await fetchval_db("INSERT INTO tenants (name) VALUES ('Test Tenant') RETURNING id;")
    
    # 1. German Account (Normal)
    de_id = await fetchval_db(
        "INSERT INTO accounts (tenant_id, account_number, swift_bic, owner_name, risk_score) VALUES ($1, $2, $3, $4, $5) RETURNING id;",
        tenant_id, "TEST_ACC_DE", "DBANKDE1XXX", "Alice Schmidt", 0.10
    )
    # 2. US Account (Normal)
    us_id = await fetchval_db(
        "INSERT INTO accounts (tenant_id, account_number, swift_bic, owner_name, risk_score) VALUES ($1, $2, $3, $4, $5) RETURNING id;",
        tenant_id, "TEST_ACC_US", "CHASEUS3XXX", "Bob Jones", 0.15
    )
    # 3. Russian Account (High Risk Geographic)
    ru_id = await fetchval_db(
        "INSERT INTO accounts (tenant_id, account_number, swift_bic, owner_name, risk_score) VALUES ($1, $2, $3, $4, $5) RETURNING id;",
        tenant_id, "TEST_ACC_RU", "SBERRU88XXX", "Vladimir Smirnov", 0.90
    )
    # 4. Iranian Account (High Risk Geographic)
    ir_id = await fetchval_db(
        "INSERT INTO accounts (tenant_id, account_number, swift_bic, owner_name, risk_score) VALUES ($1, $2, $3, $4, $5) RETURNING id;",
        tenant_id, "TEST_ACC_IR", "MELIIR22XXX", "Reza Rezaei", 0.95
    )
    # 5. Dormant Account
    dormant_id = await fetchval_db(
        "INSERT INTO accounts (tenant_id, account_number, swift_bic, owner_name, risk_score, created_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id;",
        tenant_id, "TEST_DORMANT", "DBANKDE1XXX", "Dormant Owner", 0.10, datetime.now(timezone.utc) - timedelta(days=120)
    )
    
    return {
        "tenant_id": tenant_id,
        "DE": de_id,
        "US": us_id,
        "RU": ru_id,
        "IR": ir_id,
        "DORMANT": dormant_id
    }

async def run_tests():
    print("Initializing DB pools...")
    await init_db_pool()
    
    accs = await setup_test_accounts()
    
    # Fetch current config
    config = get_rules_config()
    print(f"Loaded rules configuration: {list(config['rules'].keys())}")
    
    # Test 1: Large Transaction Threshold
    print("\n--- Test 1: Large Transaction Threshold ---")
    triggered = await RulesEngine.evaluate_transaction(
        sender_id=str(accs["DE"]),
        receiver_id=str(accs["US"]),
        amount=15000.0, # above 10000 threshold
        sender_name="Alice Schmidt",
        sender_bic="DBANKDE1XXX",
        receiver_name="Bob Jones",
        receiver_bic="CHASEUS3XXX"
    )
    print(f"Triggered: {triggered}")
    assert "LARGE_TRANSACTION_THRESHOLD" in triggered
    
    # Test 2: Structuring (Smurfing)
    print("\n--- Test 2: Structuring ---")
    # Clear Redis key first
    r = await get_async_redis_client()
    await r.delete(f"acc:velocity:{accs['DE']}")
    
    # Send 1st small transaction ($4000)
    triggered1 = await RulesEngine.evaluate_transaction(
        sender_id=str(accs["DE"]),
        receiver_id=str(accs["US"]),
        amount=4000.0,
        sender_name="Alice Schmidt",
        sender_bic="DBANKDE1XXX",
        receiver_name="Bob Jones",
        receiver_bic="CHASEUS3XXX"
    )
    # Send 2nd transaction ($6500) -> total $10500 (>= 10000) and both under 10000.
    triggered2 = await RulesEngine.evaluate_transaction(
        sender_id=str(accs["DE"]),
        receiver_id=str(accs["US"]),
        amount=6500.0,
        sender_name="Alice Schmidt",
        sender_bic="DBANKDE1XXX",
        receiver_name="Bob Jones",
        receiver_bic="CHASEUS3XXX"
    )
    print(f"Tx 1 triggered: {triggered1}")
    print(f"Tx 2 triggered: {triggered2}")
    assert "STRUCTURING_VELOCITY_24H" in triggered2
    
    # Test 3: Geographic Risk (SWIFT Country check)
    print("\n--- Test 3: Geographic Risk ---")
    # Sender RU Swift BIC: SBERRU88XXX (Country RU is in high_risk_countries)
    triggered_geo = await RulesEngine.evaluate_transaction(
        sender_id=str(accs["RU"]),
        receiver_id=str(accs["US"]),
        amount=100.0,
        sender_name="Vladimir Smirnov",
        sender_bic="SBERRU88XXX",
        receiver_name="Bob Jones",
        receiver_bic="CHASEUS3XXX"
    )
    print(f"Triggered for RU sender: {triggered_geo}")
    assert "GEOGRAPHIC_RISK" in triggered_geo
    
    # Test 4: Sanctions Screening (Fuzzy Metaphone Match)
    print("\n--- Test 4: Sanctions screening fuzzy match ---")
    # Vladimir Smirnov matches "Wladimir Smirnow" seeded in Elasticsearch
    triggered_sanctions = await RulesEngine.evaluate_transaction(
        sender_id=str(accs["DE"]),
        receiver_id=str(accs["US"]),
        amount=100.0,
        sender_name="Vladimir Smirnov", # Sender matches sanctions
        sender_bic="DBANKDE1XXX",
        receiver_name="Bob Jones",
        receiver_bic="CHASEUS3XXX"
    )
    print(f"Triggered for sanctions name: {triggered_sanctions}")
    assert "SANCTIONS_HIT" in triggered_sanctions

    # Test 5: Rapid Movement of Funds
    print("\n--- Test 5: Rapid Movement of Funds ---")
    # To simulate rapid movement, we need an incoming completed transaction first.
    # Let's insert a completed transaction from US to DE of $5,000.
    await execute_db(
        """
        INSERT INTO transactions (id, tenant_id, sender_account_id, receiver_account_id, amount, currency, status, timestamp)
        VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, 'COMPLETED', NOW() - INTERVAL '2 minutes');
        """,
        accs["tenant_id"], accs["US"], accs["DE"], 5000.0, "USD"
    )
    # Now evaluate DE sending $4,800 to US (96% of the incoming amount, within 10-min window)
    triggered_rapid = await RulesEngine.evaluate_transaction(
        sender_id=str(accs["DE"]),
        receiver_id=str(accs["US"]),
        amount=4800.0,
        sender_name="Alice Schmidt",
        sender_bic="DBANKDE1XXX",
        receiver_name="Bob Jones",
        receiver_bic="CHASEUS3XXX",
        timestamp=datetime.now(timezone.utc)
    )
    print(f"Triggered for rapid fund movement: {triggered_rapid}")
    assert "RAPID_MOVEMENT_FUNDS" in triggered_rapid
    
    # Test 6: Dormant Account Activation
    print("\n--- Test 6: Dormant Account Activation ---")
    # Dormant account has no transaction history and created_at is 120 days ago.
    # Sudden transfer of $60,000 (>= 50000 threshold)
    triggered_dormant = await RulesEngine.evaluate_transaction(
        sender_id=str(accs["DORMANT"]),
        receiver_id=str(accs["US"]),
        amount=60000.0,
        sender_name="Dormant Owner",
        sender_bic="DBANKDE1XXX",
        receiver_name="Bob Jones",
        receiver_bic="CHASEUS3XXX"
    )
    print(f"Triggered for dormant account: {triggered_dormant}")
    assert "DORMANT_ACCOUNT_ACTIVATION" in triggered_dormant

    # Test 7: Velocity Spike (Z-score deviation)
    print("\n--- Test 7: Velocity Spike (Z-score deviation) ---")
    # Insert historical transactions for the last 5 days: average 1 transaction per day, amount $500
    for i in range(1, 6):
        await execute_db(
            """
            INSERT INTO transactions (id, tenant_id, sender_account_id, receiver_account_id, amount, currency, status, timestamp)
            VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, 'COMPLETED', NOW() - $6 * INTERVAL '1 day');
            """,
            accs["tenant_id"], accs["DE"], accs["US"], 500.0, "USD", i
        )
        
    # Today we make 10 transactions in quick succession.
    for i in range(9):
        await execute_db(
            """
            INSERT INTO transactions (id, tenant_id, sender_account_id, receiver_account_id, amount, currency, status, timestamp)
            VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, 'COMPLETED', NOW());
            """,
            accs["tenant_id"], accs["DE"], accs["US"], 500.0, "USD"
        )
        
    triggered_velocity = await RulesEngine.evaluate_transaction(
        sender_id=str(accs["DE"]),
        receiver_id=str(accs["US"]),
        amount=500.0,
        sender_name="Alice Schmidt",
        sender_bic="DBANKDE1XXX",
        receiver_name="Bob Jones",
        receiver_bic="CHASEUS3XXX"
    )
    print(f"Triggered for velocity spike: {triggered_velocity}")
    assert "VELOCITY_MONITORING_SPIKE" in triggered_velocity

    # Cleanup test accounts
    await execute_db("DELETE FROM transactions;")
    await execute_db("DELETE FROM accounts WHERE account_number IN ('TEST_ACC_DE', 'TEST_ACC_RU', 'TEST_ACC_US', 'TEST_ACC_IR', 'TEST_DORMANT');")

    await close_db_pool()
    print("\n=== ALL AML RULES TESTS PASSED SUCCESSFULLY! ===")

if __name__ == "__main__":
    asyncio.run(run_tests())
