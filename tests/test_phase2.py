import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
import yaml
from main import app
from services.auth import create_access_token, create_refresh_token, hash_password
from services.network_analysis import run_network_analysis, tarjan_scc, compute_betweenness_centrality

@pytest.mark.anyio
async def test_refresh_token_rotation():
    """
    Verify Refresh Token Rotation:
    1. A valid refresh token generates a new access token and a new rotated refresh token.
    2. The old refresh token is blacklisted/revoked in Redis.
    3. Attempting to replay/reuse the old refresh token immediately fails with HTTP 401.
    4. The new rotated refresh token can be used for the subsequent refresh.
    """
    initial_refresh_token = create_refresh_token({
        "sub": "user-uuid-1234",
        "role": "ANALYST",
        "username": "compliance_analyst",
        "tenant_id": "00000000-0000-0000-0000-000000000001"
    })

    # In-memory mock Redis to simulate token denylist
    redis_store = {}

    mock_redis = AsyncMock()
    async def mock_get(key):
        return redis_store.get(key)
    async def mock_setex(key, ttl, val):
        redis_store[key] = val

    mock_redis.get = mock_get
    mock_redis.setex = mock_setex

    with patch("database.redis_db.get_async_redis_client", return_value=mock_redis):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            # Step 1: First refresh exchange
            resp1 = await ac.post("/api/v1/auth/refresh", json={"refresh_token": initial_refresh_token})
            assert resp1.status_code == 200, f"Refresh failed: {resp1.text}"
            data1 = resp1.json()
            assert "access_token" in data1
            assert "refresh_token" in data1
            new_refresh_token = data1["refresh_token"]
            assert new_refresh_token != initial_refresh_token

            # Step 2: Attempt to replay the old initial_refresh_token (must fail 401)
            resp_replay = await ac.post("/api/v1/auth/refresh", json={"refresh_token": initial_refresh_token})
            assert resp_replay.status_code == 401

            # Step 3: Rotate again using the new token (must succeed)
            resp2 = await ac.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh_token})
            assert resp2.status_code == 200
            data2 = resp2.json()
            assert data2["refresh_token"] != new_refresh_token

@pytest.mark.anyio
async def test_auth_cookie_lifecycle():
    """
    Verify that /login attaches HttpOnly cookies and /logout clears them.
    """
    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = {
        "id": "11111111-1111-1111-1111-111111111111",
        "role": "ANALYST",
        "password_hash": hash_password("ValidPassword2026!"),
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "is_active": True
    }
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    mock_redis = AsyncMock()
    mock_redis.setex = AsyncMock()

    with patch("database.postgres.get_async_db_conn", return_value=mock_ctx), \
         patch("database.redis_db.get_async_redis_client", return_value=mock_redis):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            # Login
            login_resp = await ac.post(
                "/api/v1/auth/login",
                data={"username": "officer@aml.com", "password": "ValidPassword2026!"}
            )
            assert login_resp.status_code == 200
            cookies = login_resp.cookies
            assert "access_token" in cookies
            assert "refresh_token" in cookies
            refresh_cookie_val = cookies["refresh_token"]

            # Logout clears cookies
            logout_resp = await ac.post(
                "/api/v1/auth/logout",
                json={"refresh_token": refresh_cookie_val}
            )
            assert logout_resp.status_code == 200
            # Check delete-cookie response headers
            set_cookie_headers = logout_resp.headers.get_list("set-cookie")
            assert any("access_token=\"\";" in h or "access_token=;" in h or "Max-Age=0" in h for h in set_cookie_headers)

@pytest.mark.anyio
async def test_transaction_cross_tenant_rejection():
    """
    Verify that an ANALYST from Tenant A attempting to ingest a transaction
    for an account belonging to Tenant B is rejected with HTTP 403 Forbidden.
    """
    # Mock user token for Tenant 1
    analyst_token = create_access_token({
        "sub": "analyst-1",
        "role": "ANALYST",
        "username": "analyst_tenant1",
        "tenant_id": "11111111-1111-1111-1111-111111111111"
    })

    # Account lookup returns sender belonging to Tenant 2
    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = {
        "sender_id": "account-sender-id",
        "sender_tenant": "22222222-2222-2222-2222-222222222222", # Different Tenant!
        "sender_risk": 0.2,
        "sender_name": "Alice Corp",
        "sender_bic": "CHASUS33",
        "receiver_id": "account-recv-id",
        "receiver_risk": 0.1,
        "receiver_name": "Bob Ltd",
        "receiver_bic": "BOFAUS3N",
        "velocity_count": 1
    }
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.transactions.get_async_db_read_conn", return_value=mock_ctx), \
         patch("database.redis_db.get_async_redis_client", return_value=AsyncMock()):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post(
                "/api/v1/transactions",
                json={
                    "sender_account": "ACC_TENANT_2",
                    "receiver_account": "ACC_RECV_1",
                    "amount": 5000.0,
                    "currency": "USD",
                    "timestamp": "2026-09-09T10:00:00Z"
                },
                headers={"Authorization": f"Bearer {analyst_token}"}
            )
            assert resp.status_code == 403
            assert "restricted to your assigned tenant" in resp.text

@pytest.mark.anyio
async def test_network_analysis_resilience():
    """
    Verify run_network_analysis returns properly formed dictionary structure
    even when Neo4j is offline or returning empty graphs.
    """
    with patch("database.neo4j_db.get_async_neo4j_driver", side_effect=Exception("Neo4j offline")):
        res = await run_network_analysis()
        assert isinstance(res, dict)
        assert "circular_flows" in res
        assert "fan_in_alerts" in res
        assert "fan_out_alerts" in res
        assert "intermediary_ranking" in res

def test_kubernetes_sync_worker_manifest():
    """Verify that sync-worker.yaml is a valid Kubernetes deployment manifest."""
    with open("deployments/kubernetes/sync-worker.yaml", "r") as f:
        docs = list(yaml.safe_load_all(f))
    assert len(docs) >= 1
    dep = docs[0]
    assert dep["kind"] == "Deployment"
    assert dep["metadata"]["name"] == "aml-sync-worker"
    container = dep["spec"]["template"]["spec"]["containers"][0]
    assert container["command"] == ["python", "scripts/sync_worker.py"]
