import urllib.request
import urllib.error
import urllib.parse
import json
import time
import sys
import os

# Add parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_URL = "http://localhost:8000"

TOKEN = None

def make_request(url: str, method: str = "GET", data: dict = None, is_form: bool = False) -> dict:
    global TOKEN
    if is_form and data:
        req_data = urllib.parse.urlencode(data).encode('utf-8')
    else:
        req_data = json.dumps(data).encode('utf-8') if data else None
        
    req = urllib.request.Request(url, data=req_data, method=method)
    if is_form:
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    else:
        req.add_header('Content-Type', 'application/json')
        
    if TOKEN:
        req.add_header('Authorization', f'Bearer {TOKEN}')
        
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        print(f"HTTP Error {e.code} for {method} {url}: {body}")
        raise e
    except Exception as e:
        print(f"Connection failed for {method} {url}: {e}")
        raise e

def test_onboarding_and_screening():
    global TOKEN
    print("\n--- 1. Testing KYC Sanctions Screening & Onboarding ---")
    
    # Authenticate via signup or login
    print("Attempting to authenticate compliance analyst user sarah_jenkins...")
    signup_payload = {
        "username": "sarah_jenkins",
        "password": "password123",
        "role": "ANALYST"
    }
    try:
        signup_res = make_request(f"{BASE_URL}/api/v1/auth/signup", "POST", signup_payload)
        TOKEN = signup_res["access_token"]
        print("Signup successful!")
    except Exception:
        print("Signup failed or user already exists. Attempting login fallback...")
        login_payload = {
            "username": "sarah_jenkins",
            "password": "password123"
        }
        login_res = make_request(f"{BASE_URL}/api/v1/auth/login", "POST", login_payload, is_form=True)
        TOKEN = login_res["access_token"]
        print("Login fallback successful!")
    
    # Sanctions Search (Fuzzy Match: Vladimir Smirnov vs Wladimir Smirnow)
    print("Testing fuzzy screening search...")
    search_payload = {
        "name": "Vladimir Smirnov",
        "threshold": 0.70
    }
    res = make_request(f"{BASE_URL}/api/v1/screening/search", "POST", search_payload)
    print(f"Screening Result: {json.dumps(res, indent=2)}")
    assert res["match_found"] is True
    assert "Wladimir Smirnow" in res["matched_entry"]["name"]

    # Individual Onboarding
    # Let's find the tenant_id first from DB or assume a seed
    # Since we dropped and recreated tables, let's fetch the seeded tenant ID
    from database.postgres import get_db_cursor
    with get_db_cursor() as cur:
        cur.execute("SELECT id FROM tenants LIMIT 1;")
        tenant_id = str(cur.fetchone()[0])
        
        # Also clean up accounts from previous tests if any
        cur.execute("DELETE FROM alerts;")
        cur.execute("DELETE FROM transactions;")
        cur.execute("DELETE FROM accounts WHERE account_number IN ('DE12345', 'US54321', 'CORP999');")
    
    print(f"Onboarding individual Alice Schmidt under Tenant {tenant_id}...")
    alice_payload = {
        "tenant_id": tenant_id,
        "account_number": "DE12345",
        "swift_bic": "DBANKDEFXXX",
        "name": "Alice Schmidt",
        "date_of_birth": "1990-01-01"
    }
    alice_res = make_request(f"{BASE_URL}/api/v1/onboard/individual", "POST", alice_payload)
    print(f"Alice Onboarded: {json.dumps(alice_res, indent=2)}")
    assert alice_res["status"] == "APPROVED"

    print(f"Onboarding individual Bob Jones...")
    bob_payload = {
        "tenant_id": tenant_id,
        "account_number": "US54321",
        "swift_bic": "CHASEUS3XXX",
        "name": "Bob Jones",
        "date_of_birth": "1985-05-05"
    }
    bob_res = make_request(f"{BASE_URL}/api/v1/onboard/individual", "POST", bob_payload)
    print(f"Bob Onboarded: {json.dumps(bob_res, indent=2)}")

    print("\n--- 2. Testing KYB Corporate Onboarding (Neo4j UBO graph mapping) ---")
    corp_payload = {
        "tenant_id": tenant_id,
        "company_name": "ACME Holdings Ltd",
        "registration_number": "REG-888999",
        "account_number": "CORP999",
        "swift_bic": "BARCGB22XXX",
        "ubos": [
            {"name": "Alice Schmidt", "tax_id": "TAX-ALICE", "ownership_percentage": 60.0},
            {"name": "Bob Jones", "tax_id": "TAX-BOB", "ownership_percentage": 40.0}
        ]
    }
    corp_res = make_request(f"{BASE_URL}/api/v1/onboard/corporate", "POST", corp_payload)
    print(f"Corporate Onboarded: {json.dumps(corp_res, indent=2)}")
    assert corp_res["status"] == "APPROVED"
    assert corp_res["ubo_count"] == 2

def test_transactions_monitoring():
    print("\n--- 3. Testing Real-time Synchronous Transaction Scoring ---")
    
    # Tx 1: Normal transaction ($1,500) -> Should be APPROVED
    print("Submitting normal transaction ($1,500)...")
    tx_normal = {
        "sender_account": "DE12345",
        "receiver_account": "US54321",
        "amount": 1500.00,
        "currency": "USD",
        "timestamp": "2026-07-13T12:00:00Z"
    }
    res_normal = make_request(f"{BASE_URL}/api/v1/transactions", "POST", tx_normal)
    print(f"Normal Tx Result: {json.dumps(res_normal, indent=2)}")
    assert res_normal["decision"] == "APPROVED"

    # Tx 2: Large transaction ($12,000) -> Should trigger LARGE_TRANSACTION_THRESHOLD and be HELD
    print("Submitting large transaction ($12,000)...")
    tx_large = {
        "sender_account": "DE12345",
        "receiver_account": "US54321",
        "amount": 12000.00,
        "currency": "USD",
        "timestamp": "2026-07-13T12:05:00Z"
    }
    res_large = make_request(f"{BASE_URL}/api/v1/transactions", "POST", tx_large)
    print(f"Large Tx Result: {json.dumps(res_large, indent=2)}")
    assert res_large["decision"] == "HELD"
    assert "LARGE_TRANSACTION_THRESHOLD" in res_large["triggered_rules"]
    assert "attributions" in res_large["explainability"]

    # Tx 3 & 4: Structuring velocity rule check
    # Submit multiple transactions just under the threshold within a 24h window
    print("Submitting structuring transaction 1 ($5,000)...")
    tx_struct1 = {
        "sender_account": "DE12345",
        "receiver_account": "US54321",
        "amount": 5000.00,
        "currency": "USD",
        "timestamp": "2026-07-13T12:10:00Z"
    }
    make_request(f"{BASE_URL}/api/v1/transactions", "POST", tx_struct1)
    
    print("Submitting structuring transaction 2 ($6,000) -> Should trigger STRUCTURING_VELOCITY_24H and HELD...")
    tx_struct2 = {
        "sender_account": "DE12345",
        "receiver_account": "US54321",
        "amount": 6000.00,
        "currency": "USD",
        "timestamp": "2026-07-13T12:15:00Z"
    }
    res_struct = make_request(f"{BASE_URL}/api/v1/transactions", "POST", tx_struct2)
    print(f"Structuring Tx Result: {json.dumps(res_struct, indent=2)}")
    assert res_struct["decision"] == "HELD"
    assert "STRUCTURING_VELOCITY_24H" in res_struct["triggered_rules"]

def test_alert_management():
    print("\n--- 4. Testing Case & Alert Resolution + SAR Generation ---")
    
    # List alerts
    alerts = make_request(f"{BASE_URL}/api/v1/alerts")
    print(f"Fetched {len(alerts)} alerts from case management.")
    assert len(alerts) > 0
    
    # Select the first alert and file a SAR
    alert_id = alerts[0]["alert_id"]
    print(f"Resolving alert {alert_id} with CLOSE_SAR and generating XML report...")
    
    action_payload = {
        "action": "CLOSE_SAR",
        "justification": "Alert confirmed structuring pattern and threshold evasion.",
        "sar_xml_generate": True
    }
    resolve_res = make_request(f"{BASE_URL}/api/v1/alerts/{alert_id}/action", "POST", action_payload)
    print(f"Resolve Result Status: {resolve_res['status']}")
    print("\nGenerated SAR XML Regulatory Report:")
    print(resolve_res["sar_xml"])
    
    assert resolve_res["status"] == "CLOSED_SAR"
    assert resolve_res["sar_xml"] is not None

def test_graph_sync_verification():
    print("\n--- 5. Verifying Neo4j Async Graph Synchronization ---")
    print("Sleeping for 6 seconds to let the polling graph sync worker update the Neo4j database...")
    time.sleep(6)
    
    from database.neo4j_db import get_neo4j_driver
    driver = get_neo4j_driver()
    
    # Query Neo4j to assert account and transactions exist
    query = """
    MATCH (s:Account)-[t:TRANSFERS_TO]->(r:Account)
    RETURN s.account_number AS sender, r.account_number AS receiver, t.amount AS amount
    LIMIT 5;
    """
    with driver.session() as session:
        result = session.run(query)
        records = list(result)
        print(f"Fetched {len(records)} transaction edges from Neo4j:")
        for rec in records:
            print(f"  {rec['sender']} -[TRANSFERS_TO {rec['amount']}]-> {rec['receiver']}")
        
        assert len(records) > 0

if __name__ == "__main__":
    print("Starting End-to-End AML Platform Flow Verification...")
    
    # Make sure FastAPI app is running
    try:
        make_request(BASE_URL)
        print("FastAPI server is running.")
    except Exception:
        print(f"FastAPI server is offline at {BASE_URL}. Please start the server first!")
        sys.exit(1)
        
    try:
        test_onboarding_and_screening()
        test_transactions_monitoring()
        test_alert_management()
        test_graph_sync_verification()
        print("\n=== ALL E2E VERIFICATION TESTS PASSED SUCCESSFULLY! ===")
    except Exception as e:
        print(f"\n E2E verification test failure: {e}")
        sys.exit(1)
