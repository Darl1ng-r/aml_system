import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
import json
import time
from services.mfa import generate_totp_secret, generate_totp_code
from main import app
from services.auth import create_access_token, hash_password
from services.rate_limiter import RateLimiter
from fastapi import Request


class InMemoryRedis:
    """Lightweight in-memory Redis mock for testing lockout and replay behavior."""
    def __init__(self):
        self.store = {}
        self.ttls = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, val):
        self.store[key] = str(val)

    async def setex(self, key, seconds, val):
        self.store[key] = str(val)
        self.ttls[key] = seconds

    async def incr(self, key):
        val = int(self.store.get(key, 0)) + 1
        self.store[key] = str(val)
        return val

    async def expire(self, key, seconds):
        self.ttls[key] = seconds
        return True

    async def ttl(self, key):
        return self.ttls.get(key, 900)

    async def delete(self, *keys):
        for k in keys:
            self.store.pop(k, None)
            self.ttls.pop(k, None)


@pytest.mark.anyio
async def test_cookie_based_authentication_get_me():
    """Verify dual token resolution: GET /api/v1/auth/me works via HttpOnly access_token cookie."""
    token = create_access_token({
        "sub": "22222222-2222-2222-2222-222222222222",
        "role": "COMPLIANCE_OFFICER",
        "username": "compliance_lead",
        "email": "lead@aml.com",
        "tenant_id": "00000000-0000-0000-0000-000000000001"
    })

    transport = httpx.ASGITransport(app=app)
    # 1. Successful authentication via cookie only (no Authorization header)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", cookies={"access_token": token}) as ac:
        response = await ac.get("/api/v1/auth/me")
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "compliance_lead"
        assert data["role"] == "COMPLIANCE_OFFICER"
        assert data["tenant_id"] == "00000000-0000-0000-0000-000000000001"

    # 2. Rejection with invalid cookie
    async with httpx.AsyncClient(transport=transport, base_url="http://test", cookies={"access_token": "malformed.jwt.token"}) as ac:
        bad_response = await ac.get("/api/v1/auth/me")
        assert bad_response.status_code == 401

    # 3. Rejection with missing credentials
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        empty_response = await ac.get("/api/v1/auth/me")
        assert empty_response.status_code == 401


@pytest.mark.anyio
async def test_account_lockout_trigger_and_reset():
    """Verify brute-force defense: 5 failed logins lock the account with HTTP 423."""
    mock_redis = InMemoryRedis()

    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = {
        "id": "33333333-3333-3333-3333-333333333333",
        "role": "ANALYST",
        "password_hash": hash_password("ValidPassword2026!"),
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "is_active": True
    }
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("database.redis_db.get_async_redis_client", AsyncMock(return_value=mock_redis)), \
         patch("database.postgres.get_async_db_conn", return_value=mock_ctx):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            target_user = "target_analyst@aml.com"

            # Attempts 1 to 4: Fail with 401 Unauthorized
            for attempt in range(1, 5):
                res = await ac.post(
                    "/api/v1/auth/login",
                    data={"username": target_user, "password": f"WrongAttempt{attempt}!"}
                )
                assert res.status_code == 401, f"Attempt {attempt} should return 401"

            # Attempt 5: Threshold reached -> returns HTTP 423 Locked
            res5 = await ac.post(
                "/api/v1/auth/login",
                data={"username": target_user, "password": "WrongAttempt5!"}
            )
            assert res5.status_code == 423
            assert "temporarily locked" in res5.json()["detail"].lower()

            # Attempt 6 while locked: Immediately blocked by check_account_lockout
            res6 = await ac.post(
                "/api/v1/auth/login",
                data={"username": target_user, "password": "ValidPassword2026!"}
            )
            assert res6.status_code == 423

            # Reset lockout and verify successful login
            await mock_redis.delete(f"failed_logins:lockout:{target_user}", f"failed_logins:{target_user}")
            res_success = await ac.post(
                "/api/v1/auth/login",
                data={"username": target_user, "password": "ValidPassword2026!"}
            )
            assert res_success.status_code == 200
            assert "access_token" in res_success.json()


@pytest.mark.anyio
async def test_totp_anti_replay_defense():
    """Verify MFA anti-replay defense: Consumed TOTP codes are blocked on reuse within window."""
    mock_redis = InMemoryRedis()
    totp_secret = generate_totp_secret()
    user_id = "44444444-4444-4444-4444-4444-444444444444"

    # Pre-seed valid MFA ticket
    ticket_id = "test_ticket_12345"
    ticket_payload = {
        "user_id": user_id,
        "role": "ANALYST",
        "username": "totp_user",
        "email": "totp_user@aml.com",
        "tenant_id": "00000000-0000-0000-0000-000000000001"
    }
    await mock_redis.set(f"mfa:ticket:{ticket_id}", json.dumps(ticket_payload))

    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = {
        "mfa_secret": totp_secret,
        "recovery_codes": "[]"
    }
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    valid_totp_code = generate_totp_code(totp_secret)

    with patch("database.redis_db.get_async_redis_client", AsyncMock(return_value=mock_redis)), \
         patch("database.postgres.get_async_db_conn", return_value=mock_ctx):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            # 1. First verification with code succeeds
            res1 = await ac.post(
                "/api/v1/auth/mfa/verify",
                json={"mfa_ticket": ticket_id, "code": valid_totp_code}
            )
            assert res1.status_code == 200
            assert "access_token" in res1.json()

            # Seed a second ticket to simulate an attacker capturing & replaying the code
            ticket_replay = "replay_ticket_99999"
            await mock_redis.set(f"mfa:ticket:{ticket_replay}", json.dumps(ticket_payload))

            # 2. Immediate replay of the same code fails with 401
            res_replay = await ac.post(
                "/api/v1/auth/mfa/verify",
                json={"mfa_ticket": ticket_replay, "code": valid_totp_code}
            )
            assert res_replay.status_code == 401
            assert "already used" in res_replay.json()["detail"].lower()


@pytest.mark.anyio
async def test_signup_error_sanitization():
    """Verify information disclosure defense: internal database/schema exceptions are sanitized."""
    mock_conn = AsyncMock()
    # Simulate Postgres UniqueViolation exception
    mock_conn.execute.side_effect = Exception('duplicate key value violates unique constraint "users_username_key"')
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("database.postgres.get_async_db_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(
                "/api/v1/auth/signup",
                json={"username": "duplicate_officer", "password": "Password123!"}
            )
            assert response.status_code == 400
            detail = response.json()["detail"]
            assert "unique constraint" not in detail.lower()
            assert "users_username_key" not in detail
            assert detail == "Username already registered or invalid registration data"


@pytest.mark.anyio
async def test_rate_limiter_forwarded_for_resolution():
    """Verify reverse-proxy IP handling: RateLimiter isolates client IP from X-Forwarded-For."""
    mock_pipe = MagicMock()
    mock_pipe.execute = AsyncMock(return_value=[None, None, 1, None])
    
    mock_redis = AsyncMock()
    mock_redis.pipeline = MagicMock(return_value=mock_pipe)

    rate_limiter = RateLimiter(limit=10, window=60)

    # Build mock request with X-Forwarded-For header
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/alerts",
        "headers": [
            (b"x-forwarded-for", b"203.0.113.195, 70.41.3.18, 150.172.238.178"),
            (b"host", b"test")
        ],
        "client": ("127.0.0.1", 5000)
    }
    request = Request(scope)

    with patch("services.rate_limiter.get_async_redis_client", AsyncMock(return_value=mock_redis)):
        await rate_limiter(request)

        # Inspect pipeline calls to confirm key contains client IP '203.0.113.195' and not proxy '127.0.0.1'
        called_key = mock_pipe.zremrangebyscore.call_args[0][0]
        assert "203.0.113.195" in called_key
        assert "127.0.0.1" not in called_key


@pytest.mark.anyio
async def test_jwks_endpoint_and_rsa_keys():
    """Verify /.well-known/jwks.json returns RFC 7517 compliant RSA public key set."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get("/.well-known/jwks.json")
        assert res.status_code == 200
        data = res.json()
        assert "keys" in data
        assert len(data["keys"]) > 0
        jwk = data["keys"][0]
        assert jwk["kty"] == "RSA"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"
        assert "n" in jwk
        assert "e" in jwk
        assert "kid" in jwk


@pytest.mark.anyio
async def test_csrf_protection_middleware_enforcement():
    """Verify CSRFProtectionMiddleware blocks cookie-based state-changing requests without custom header."""
    transport = httpx.ASGITransport(app=app)
    # 1. State-changing POST with cookie session and NO X-CSRF-Protection header -> 403 Forbidden
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        cookies={"access_token": "dummy_token"}
    ) as ac:
        res_blocked = await ac.post("/api/v1/auth/logout", json={})
        assert res_blocked.status_code == 403
        assert "CSRF protection error" in res_blocked.json()["detail"]

    # 2. State-changing POST with cookie session and valid X-CSRF-Protection: 1 header -> Allowed past middleware
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        cookies={"access_token": "dummy_token"},
        headers={"X-CSRF-Protection": "1"}
    ) as ac:
        res_allowed = await ac.post("/api/v1/auth/logout", json={})
        # Passes CSRF middleware (response status is 200 logout success, not 403)
        assert res_allowed.status_code == 200


@pytest.mark.anyio
async def test_active_session_revocation_via_token_version():
    """Verify session revocation increments token_version and invalidates outstanding tokens."""
    user_id = "55555555-5555-5555-5555-555555555555"
    token_v1 = create_access_token({
        "sub": user_id,
        "role": "ANALYST",
        "username": "revoked_user",
        "email": "revoked@aml.com",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "token_version": 1
    })

    mock_conn = AsyncMock()
    # Initial state: user has token_version=1
    mock_conn.fetchrow.return_value = {
        "id": user_id,
        "token_version": 2
    }
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    mock_redis = InMemoryRedis()
    await mock_redis.set(f"user:token_version:{user_id}", "2")

    with patch("database.postgres.get_async_db_conn", return_value=mock_ctx), \
         patch("database.redis_db.get_async_redis_client", AsyncMock(return_value=mock_redis)):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"Authorization": f"Bearer {token_v1}"}
        ) as ac:
            # Token with version 1 is compared against Redis token_version=2 -> 401 Unauthorized
            res = await ac.get("/api/v1/auth/me")
            assert res.status_code == 401
            assert res.json()["detail"] == "Could not validate credentials"
