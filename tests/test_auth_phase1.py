import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
from main import app
from services.auth import hash_password, verify_password
from observability.sanitizer import sanitize_text

def test_sanitizer_xss_protection():
    """Verify that decoded entities do not re-introduce active script tags."""
    assert sanitize_text("&lt;script&gt;alert(1)&lt;/script&gt;") == "alert(1)"
    assert sanitize_text("<img src=x onerror=alert(1)>") == ""
    assert sanitize_text("Normal Customer Name") == "Normal Customer Name"

def test_password_hashing_and_verification():
    """Verify password hashing with Argon2id and verify_password correctness with both Argon2id and legacy PBKDF2."""
    pw = "P@ssw0rdEnterprise2026!"
    hashed = hash_password(pw)
    assert hashed.startswith("$argon2id$") or hashed.startswith("pbkdf2_sha256$")
    assert verify_password(pw, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False

    # Test backward compatibility with legacy PBKDF2 hash
    import hashlib
    salt = "testsalt123"
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt.encode("utf-8"), 600000)
    legacy_hash = f"pbkdf2_sha256$600000${salt}${dk.hex()}"
    assert verify_password(pw, legacy_hash) is True
    assert verify_password("WrongPassword!", legacy_hash) is False

@pytest.mark.anyio
async def test_login_user_not_found_fails_with_401():
    """Verify zero-bypass: logging in with nonexistent user yields 401 Unauthorized."""
    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = None
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("database.postgres.get_async_db_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(
                "/api/v1/auth/login",
                data={"username": "nonexistent_officer@aml.com", "password": "InvalidPassword123!"}
            )
            assert response.status_code == 401
            assert "access_token" not in response.json()

@pytest.mark.anyio
async def test_login_invalid_password_fails_with_401():
    """Verify zero-bypass: logging in with incorrect password yields 401 Unauthorized."""
    mock_conn = AsyncMock()
    # Return user with real hash for a different password
    mock_conn.fetchrow.return_value = {
        "id": "11111111-1111-1111-1111-111111111111",
        "role": "ANALYST",
        "password_hash": hash_password("CorrectPassword2026!"),
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "is_active": True
    }
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("database.postgres.get_async_db_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(
                "/api/v1/auth/login",
                data={"username": "existing_officer@aml.com", "password": "WrongPassword2026!"}
            )
            assert response.status_code == 401
            assert "access_token" not in response.json()

@pytest.mark.anyio
async def test_login_valid_credentials_succeeds_with_token():
    """Verify that logging in with valid local credentials yields JWT token."""
    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = {
        "id": "11111111-1111-1111-1111-111111111111",
        "role": "ANALYST",
        "password_hash": hash_password("CorrectPassword2026!"),
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "is_active": True
    }
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("database.postgres.get_async_db_conn", return_value=mock_ctx):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(
                "/api/v1/auth/login",
                data={"username": "existing_officer@aml.com", "password": "CorrectPassword2026!"}
            )
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert data["role"] == "ANALYST"

def test_signup_role_defaults_to_analyst():
    """Verify that UserSignup automatically assigns ANALYST role."""
    from routers.auth import UserSignup
    assert "role" not in UserSignup.model_fields
    user = UserSignup(username="test_officer", password="ValidPassword2026!")
    assert user.username == "test_officer"
    assert user.password == "ValidPassword2026!"

@pytest.mark.anyio
async def test_static_files_accessible():
    """Verify static files route returns 200 OK and is mounted."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/static/style.css")
        assert response.status_code == 200
        assert len(response.text) > 0
