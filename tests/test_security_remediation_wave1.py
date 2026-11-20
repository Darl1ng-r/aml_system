"""
Wave 1 Security & Multi-Tenant Isolation Regression Tests (S-1 through S-12)
"""

import io
import uuid
import jwt
import pytest
import httpx
from httpx import ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch

from main import app
from config import settings
from services.auth import (
    create_access_token,
    create_refresh_token,
    RoleChecker,
    _verify_token_version,
    _verify_supabase_user,
)
from services.secrets_manager import (
    decode_jwt_with_rotation,
    get_or_create_rsa_keypair,
)
from services.siem_forwarder import validate_siem_destination_url
from services.encryption import encrypt_pii, decrypt_pii, DecryptionError
from services.rate_limiter import RateLimiter
from database.postgres import get_async_db_read_conn
from fastapi import HTTPException
from starlette.requests import Request


@pytest.mark.anyio
async def test_s1_public_signup_blocked_in_production():
    """S-1: Public /signup and /register must return 403 in production."""
    transport = ASGITransport(app=app)
    with patch.object(settings, "environment", "production"):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            for endpoint in ("/api/v1/auth/signup", "/api/v1/auth/register"):
                res = await ac.post(
                    endpoint,
                    json={"username": "attacker_user", "password": "UniqueSecurePassphrase!9271"},
                )
                assert res.status_code == 403, f"{endpoint} should be 403 in production"


@pytest.mark.anyio
async def test_s1_signup_enforces_hibp_check():
    """S-1: /signup (not just /register) must enforce HIBP breached password rejection."""
    transport = ASGITransport(app=app)
    with patch("services.auth.check_breached_password", AsyncMock(return_value=True)):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post(
                "/api/v1/auth/signup",
                json={"username": "hibp_test_user", "password": "CommonBreachedPassword123!"},
            )
            assert res.status_code == 400
            assert "breach" in res.json()["detail"].lower()


@pytest.mark.anyio
async def test_s2_refresh_token_rejected_as_access_token():
    """S-2: Refresh tokens must be rejected on API endpoints."""
    refresh = create_refresh_token({
        "sub": str(uuid.uuid4()),
        "role": "ADMIN",
        "username": "admin_user",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
    })
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        res_bearer = await ac.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {refresh}"},
        )
        assert res_bearer.status_code == 401

        res_cookie = await ac.get(
            "/api/v1/auth/me",
            cookies={"access_token": refresh},
        )
        assert res_cookie.status_code == 401


def test_s3_jwt_algorithm_confusion_blocked():
    """S-3: HS256 token signed using RSA public key PEM and alg=none must be rejected."""
    _, pub_pem = get_or_create_rsa_keypair()

    # Craft HS256 token signed with the RSA public key string (classic RS256->HS256 confusion)
    # Bypass PyJWT's own PEM guard by signing raw header/payload with HMAC-SHA256
    import base64
    import hashlib
    import hmac
    import json

    header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps({"sub": "forged", "role": "SUPER_ADMIN", "type": "access", "exp": 9999999999}).encode()
    ).rstrip(b"=").decode()
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = base64.urlsafe_b64encode(hmac.new(pub_pem.encode(), signing_input, hashlib.sha256).digest()).rstrip(b"=").decode()
    confused_token = f"{header_b64}.{payload_b64}.{sig}"

    with pytest.raises(jwt.PyJWTError):
        decode_jwt_with_rotation(confused_token)

    # Also verify alg=none is strictly rejected
    none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    none_token = f"{none_header}.{payload_b64}."
    with pytest.raises(jwt.PyJWTError):
        decode_jwt_with_rotation(none_token)


@pytest.mark.anyio
async def test_s4_token_version_falls_back_to_postgres_when_redis_down():
    """S-4: _verify_token_version must check PostgreSQL and reject revoked tokens when Redis fails."""
    uid = str(uuid.uuid4())
    mock_conn = AsyncMock()
    mock_conn.fetchval = AsyncMock(return_value=5)  # Revoked: DB version is 5 > token version 2
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("database.redis_db.get_async_redis_client", AsyncMock(side_effect=ConnectionError("Redis offline"))), \
         patch("services.auth.get_async_db_conn", return_value=mock_ctx):
        with pytest.raises(HTTPException) as exc:
            await _verify_token_version(uid, token_version=2, tenant_id="00000000-0000-0000-0000-000000000001")
        assert exc.value.status_code == 401


def test_s5_l1_analyst_excluded_from_analyst_privilege_escalation():
    """S-5: L1_ANALYST must NOT pass RoleChecker(['ANALYST'])."""
    checker = RoleChecker(["ANALYST"])
    assert "L1_ANALYST" not in checker.allowed_roles
    assert "L2_INVESTIGATOR" in checker.allowed_roles
    assert "MLRO" in checker.allowed_roles

    with pytest.raises(HTTPException) as exc:
        checker({"id": "u1", "role": "L1_ANALYST", "username": "tier1"})
    assert exc.value.status_code == 403


@pytest.mark.anyio
async def test_s6_evidence_upload_blocks_path_traversal_and_html():
    """S-6: Evidence Locker blocks path traversal filenames and active HTML/SVG MIME types."""
    token = create_access_token({
        "sub": str(uuid.uuid4()),
        "role": "L2_INVESTIGATOR",
        "username": "inv1",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
    })
    case_id = str(uuid.uuid4())
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        res_trav = await ac.post(
            f"/api/v1/cases/{case_id}/evidence",
            headers={"Authorization": f"Bearer {token}", "X-CSRF-Protection": "1"},
            files={"file": ("../../etc/passwd.pdf", io.BytesIO(b"%PDF-1.4"), "application/pdf")},
        )
        assert res_trav.status_code == 400
        assert "traversal" in res_trav.json()["detail"].lower()

        res_html = await ac.post(
            f"/api/v1/cases/{case_id}/evidence",
            headers={"Authorization": f"Bearer {token}", "X-CSRF-Protection": "1"},
            files={"file": ("xss.html", io.BytesIO(b"<script>alert(1)</script>"), "text/html")},
        )
        assert res_html.status_code == 400


def test_s7_siem_ssrf_private_and_metadata_urls_blocked():
    """S-7: SIEM URL validation blocks HTTP, localhost, private RFC1918, and cloud metadata IPs."""
    blocked_urls = [
        "http://splunk.example.com/hec",
        "https://localhost:8088/services/collector",
        "https://127.0.0.1:8088/services/collector",
        "https://169.254.169.254/latest/meta-data/",
        "https://10.0.0.5:8088/hec",
        "https://192.168.1.10/hec",
        "https://172.16.0.2/hec",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://aml-postgres-primary.aml-system.svc.cluster.local:5432/",
    ]
    for url in blocked_urls:
        with pytest.raises(ValueError):
            validate_siem_destination_url(url)

    # Public external HTTPS hostname should pass
    assert validate_siem_destination_url("https://siem.example.invalid/services/collector/event").startswith("https://")


@pytest.mark.anyio
async def test_s8_export_alerts_pdf_escapes_html_xss():
    """S-8: export_alerts_pdf must escape HTML/JS payloads in DB fields."""
    token = create_access_token({
        "sub": str(uuid.uuid4()),
        "role": "ADMIN",
        "username": "<b>admin</b>",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
    })
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=[{
        "id": uuid.uuid4(),
        "threat_level": "HIGH",
        "ai_risk_score": 0.92,
        "rule_name": "<script>alert('xss')</script>",
        "status": "OPEN",
        "created_at": None,
        "amount": 9500.0,
        "currency": "USD",
        "sender": "ACCT-1",
        "receiver": "ACCT-2",
        "assignee": "<img src=x onerror=alert(1)>",
    }])
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    transport = ASGITransport(app=app)
    with patch("routers.alerts.get_async_db_read_conn", return_value=mock_ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get(
                "/api/v1/alerts/export/pdf",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res.status_code == 200
            body = res.text
            assert "<script>alert('xss')</script>" not in body
            assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in body
            assert "<img src=x onerror=alert(1)>" not in body
            assert "&lt;b&gt;admin&lt;/b&gt;" in body


@pytest.mark.anyio
async def test_s9_all_workspace_html_routes_verify_jwt_signature():
    """S-9: Forged cookies like access_token=anything must redirect to /login on all workspace routes."""
    protected_pages = [
        "/dashboard",
        "/alerts/triage",
        "/admin/rules",
        "/admin/users",
        "/sar/queue",
        "/sar/editor",
        "/customers",
        "/network",
        "/dashboard/executive",
        "/audit/logs",
        "/admin/health",
        "/ml/governance",
        "/settings/risk-appetite",
        "/compliance/ops",
    ]
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as ac:
        for route in protected_pages:
            res = await ac.get(route, cookies={"access_token": "forged-not-a-valid-jwt"})
            assert res.status_code == 303, f"{route} failed to reject forged cookie"
            assert res.headers.get("location") == "/login"


@pytest.mark.anyio
async def test_s10_supabase_uses_app_metadata_not_user_metadata():
    """S-10: Supabase verification must ignore client-writable user_metadata and read app_metadata."""
    fake_resp = MagicMock()
    fake_resp.status = 200
    fake_resp.json = AsyncMock(return_value={
        "id": str(uuid.uuid4()),
        "email": "user@bank.com",
        "user_metadata": {"role": "SUPER_ADMIN", "tenant_id": "99999999-9999-9999-9999-999999999999"},
        "app_metadata": {"role": "L1_ANALYST", "tenant_id": "00000000-0000-0000-0000-000000000001"},
    })
    fake_resp.__aenter__ = AsyncMock(return_value=fake_resp)
    fake_resp.__aexit__ = AsyncMock(return_value=None)

    fake_session = MagicMock()
    fake_session.get = MagicMock(return_value=fake_resp)
    fake_session.__aenter__ = AsyncMock(return_value=fake_session)
    fake_session.__aexit__ = AsyncMock(return_value=None)

    cred_exc = HTTPException(status_code=401, detail="Unauthorized")
    with patch.object(settings, "supabase_url", "https://example.supabase.co"), \
         patch.object(settings, "supabase_key", "sb-real-key-123456"), \
         patch("aiohttp.ClientSession", return_value=fake_session):
        user = await _verify_supabase_user("some-jwt", cred_exc)
        assert user["role"] == "L1_ANALYST"
        assert user["tenant_id"] == "00000000-0000-0000-0000-000000000001"


@pytest.mark.anyio
async def test_s11_read_replica_rls_fails_closed():
    """S-11: get_async_db_read_conn must reject invalid tenant_id and set sentinel UUID on None."""
    mock_conn = AsyncMock()
    mock_tx = AsyncMock()
    mock_tx.__aenter__.return_value = None
    mock_tx.__aexit__.return_value = None
    mock_conn.transaction = MagicMock(return_value=mock_tx)

    mock_pool = MagicMock()
    mock_pool._loop = MagicMock()
    mock_pool._loop.is_closed.return_value = False
    mock_pool.acquire = AsyncMock(return_value=mock_conn)
    mock_pool.release = AsyncMock()

    with patch("database.postgres.db_pool", mock_pool), \
         patch("database.postgres.db_replica_pool", mock_pool):
        # 1. Invalid UUID raises ValueError
        with pytest.raises(ValueError, match="Invalid tenant_id"):
            async with get_async_db_read_conn(tenant_id="not-a-uuid"):
                pass

        # 2. Missing tenant_id sets fail-closed sentinel UUID
        mock_conn.execute.reset_mock()
        async with get_async_db_read_conn(tenant_id=None):
            pass
        mock_conn.execute.assert_awaited_once_with(
            "SELECT set_config('app.current_tenant_id', '00000000-0000-0000-0000-000000000000', true);"
        )


def test_s12_encryption_raises_on_tampered_ciphertext():
    """S-12: Tampered AES-256-GCM ciphertext must raise DecryptionError, never return raw ciphertext."""
    encrypted = encrypt_pii("123-45-6789")
    assert encrypted.startswith("enc:v1:")
    assert decrypt_pii(encrypted) == "123-45-6789"

    # Tamper with the ciphertext body
    tampered = encrypted[:-4] + ("AAAA" if not encrypted.endswith("AAAA") else "BBBB")
    with pytest.raises(DecryptionError):
        decrypt_pii(tampered)


@pytest.mark.anyio
async def test_s12_rate_limiter_fail_closed_in_production():
    """S-12: RateLimiter(fail_closed=True) raises 503 in production when Redis is down."""
    limiter = RateLimiter(limit=5, window=60, fail_closed=True)
    req = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/v1/auth/login",
        "headers": [(b"host", b"api.example.com")],
        "client": ("203.0.113.10", 12345),
    })
    with patch.object(settings, "environment", "production"), \
         patch("services.rate_limiter.get_async_redis_client", AsyncMock(side_effect=ConnectionError("down"))):
        with pytest.raises(HTTPException) as exc:
            await limiter(req)
        assert exc.value.status_code == 503
