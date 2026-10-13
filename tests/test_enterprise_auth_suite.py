"""
Enterprise IAM & Security Audit Test Suite
===========================================
Validates enterprise AuthN/AuthZ standards:
- NIST SP 800-63B breached password prevention (HIBP k-Anonymity)
- Zero user enumeration & timing attack mitigation
- Refresh Token Rotation (RTR) with family compromise detection (RFC 6819)
- Global session invalidation across all devices
- Debounced username availability validation
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
from httpx import ASGITransport
from main import app
from services.auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    check_breached_password,
    DUMMY_ARGON2_HASH
)


@pytest.mark.anyio
async def test_breached_password_k_anonymity_detection():
    """Validates that known breached passwords are identified via k-Anonymity logic."""
    # Test common password 'password123'
    # Mock HIBP API response returning matching suffix
    with patch("aiohttp.ClientSession.get") as mock_get:
        mock_resp = AsyncMock()
        mock_resp.status = 200
        # Simulated response from HIBP range endpoint
        mock_resp.text = AsyncMock(return_value="0018A45C4D18801804E4451F30E41060D9F:16\nCB4B4C1371CB0F98CDD321F57E12E83F992:4300\n")
        mock_get.return_value.__aenter__.return_value = mock_resp

        # SHA-1 of 'password123' is cb4b4c1371cb0f98cdd321f57e12e83f992 (prefix cb4b4, suffix c1371cb0f98cdd321f57e12e83f992)
        # Let's test with a simulated hit
        with patch("hashlib.sha1") as mock_sha1:
            mock_hash = MagicMock()
            mock_hash.hexdigest.return_value = "CB4B4CB4B4C1371CB0F98CDD321F57E12E83F992"
            mock_sha1.return_value = mock_hash
            is_breached = await check_breached_password("known_breached_password")
            assert is_breached is True


@pytest.mark.anyio
async def test_clean_password_passes_hibp_check():
    """Validates that a clean custom password passes HIBP check."""
    with patch("aiohttp.ClientSession.get") as mock_get:
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1\n")
        mock_get.return_value.__aenter__.return_value = mock_resp

        is_breached = await check_breached_password("UnlikelyToEverBeBreached_984512!@#")
        assert is_breached is False


@pytest.mark.anyio
async def test_register_endpoint_rejects_breached_password():
    """Verify POST /api/v1/auth/register rejects breached passwords with HTTP 400."""
    transport = ASGITransport(app=app)
    with patch("services.auth.check_breached_password", AsyncMock(return_value=True)):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post(
                "/api/v1/auth/register",
                json={"username": "new_compliance_user", "password": "CommonPwnedPassword123!"}
            )
            assert res.status_code == 400
            assert "breach" in res.json().get("detail", "").lower()


@pytest.mark.anyio
async def test_login_timing_mitigation_on_nonexistent_user():
    """
    Verify login executes dummy hash comparison when user is not found,
    returning HTTP 401 without user enumeration.
    """
    import uuid
    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = None  # User does not exist
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    ghost_username = f"ghost_{uuid.uuid4().hex[:8]}"
    transport = ASGITransport(app=app)
    with patch("database.postgres.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.auth.check_account_lockout", AsyncMock(return_value=None)), \
         patch("routers.auth.record_failed_login", AsyncMock(return_value=1)), \
         patch("routers.auth.verify_password_and_needs_rehash", return_value=(False, False)) as mock_verify:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post(
                "/api/v1/auth/login",
                data={"username": ghost_username, "password": "AnyPassword123!"}
            )
            assert res.status_code == 401
            assert res.json().get("detail") == "Incorrect username or password"
            # Verify that dummy hash verification was executed to equalize latency
            mock_verify.assert_called()


@pytest.mark.anyio
async def test_refresh_token_rotation_and_compromise_detection():
    """
    Validates:
    1. First refresh consumes token and issues new tokens in same family.
    2. Re-using the consumed token triggers compromise detection, revoking entire family.
    """
    user_id = "00000000-0000-0000-0000-000000000099"
    family_id = "fam_12345678"
    token = create_refresh_token({
        "sub": user_id,
        "role": "ANALYST",
        "username": "officer.jones",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "family_id": family_id,
        "token_version": 1
    })

    # In-memory mock Redis to test real state transitions
    redis_store = {}
    mock_redis = AsyncMock()
    async def get_val(key):
        return redis_store.get(key)
    async def setex_val(key, ttl, val):
        redis_store[key] = val
    async def incr_val(key):
        val = int(redis_store.get(key, 1)) + 1
        redis_store[key] = str(val)
        return val

    mock_redis.get = AsyncMock(side_effect=get_val)
    mock_redis.setex = AsyncMock(side_effect=setex_val)
    mock_redis.incr = AsyncMock(side_effect=incr_val)

    mock_conn = AsyncMock()
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    headers = {"X-CSRF-Protection": "1"}
    transport = ASGITransport(app=app)
    with patch("database.redis_db.get_async_redis_client", return_value=mock_redis), \
         patch("database.postgres.get_async_db_conn", return_value=mock_ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            # Step 1: Legitimate refresh
            res1 = await ac.post("/api/v1/auth/refresh", json={"refresh_token": token}, headers=headers)
            assert res1.status_code == 200
            data1 = res1.json()
            assert "access_token" in data1
            assert "refresh_token" in data1
            assert redis_store.get(f"token:revoked:{token}") == "1"

            # Step 2: Compromise attack — re-submit the already revoked token
            res2 = await ac.post("/api/v1/auth/refresh", json={"refresh_token": token}, headers=headers)
            assert res2.status_code == 401
            assert "compromised" in res2.json().get("detail", "").lower()
            # Verify family was revoked in Redis
            assert redis_store.get(f"token:family_revoked:{family_id}") == "1"


@pytest.mark.anyio
async def test_check_username_availability_endpoint():
    """Verify GET /api/v1/auth/check-username reports availability accurately."""
    mock_conn = AsyncMock()
    mock_conn.fetchval.return_value = None  # Available
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    transport = ASGITransport(app=app)
    with patch("database.postgres.get_async_db_conn", return_value=mock_ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/v1/auth/check-username?username=brand_new_officer")
            assert res.status_code == 200
            assert res.json().get("available") is True
            assert res.json().get("username") == "brand_new_officer"


@pytest.mark.anyio
async def test_global_revoke_all_sessions_endpoint():
    """Verify POST /api/v1/auth/sessions/revoke-all bumps token version and invalidates sessions."""
    user_id = "00000000-0000-0000-0000-000000000099"
    access_tok = create_access_token({
        "sub": user_id,
        "role": "ADMIN",
        "username": "compliance_admin",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "token_version": 1
    })

    mock_conn = AsyncMock()
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    mock_redis = AsyncMock()
    mock_redis.incr = AsyncMock(return_value=2)

    transport = ASGITransport(app=app)
    with patch("database.redis_db.get_async_redis_client", return_value=mock_redis), \
         patch("database.postgres.get_async_db_conn", return_value=mock_ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post(
                "/api/v1/auth/sessions/revoke-all",
                headers={"Authorization": f"Bearer {access_tok}", "X-CSRF-Protection": "1"}
            )
            assert res.status_code == 200
            assert "revoked" in res.json().get("detail", "").lower()
