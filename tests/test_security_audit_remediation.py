"""
Test Suite: Security Audit Remediation (Findings #3, #11, #14, #15, #16, #17, #20, #22, #23, #34)
================================================================================================
Validates all ruthless security audit fixes across middlewares, auth cookies,
headers, rate limiting, and parameter validation.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
from httpx import ASGITransport
from starlette.requests import Request
from starlette.responses import Response

from main import app
from services.trusted_proxy import get_trusted_client_ip
from services.rate_limiter import RateLimiter
from routers.auth import set_auth_cookies
import config


# ── 1. Finding #15 & #34: Right-to-Left XFF IP Traversal ─────────────────────
def test_right_to_left_xff_traversal_rejects_spoofed_prefixes():
    """
    Ensure get_trusted_client_ip parses X-Forwarded-For right-to-left.
    Attacker injects: '198.51.100.1 (spoofed), 203.0.113.5 (real client), 10.0.0.1 (trusted proxy)'
    The function MUST return '203.0.113.5' and NOT the spoofed '198.51.100.1'.
    """
    headers = {
        "x-forwarded-for": "198.51.100.1, 203.0.113.5, 10.0.0.1"
    }
    req = MagicMock(spec=Request)
    req.client.host = "127.0.0.1"  # Direct peer is trusted reverse proxy
    req.headers = headers

    resolved_ip = get_trusted_client_ip(req)
    assert resolved_ip == "203.0.113.5", f"Expected real client 203.0.113.5, got {resolved_ip}"


def test_untrusted_direct_peer_cannot_spoof_ip():
    """If direct peer is untrusted, XFF headers must be completely ignored."""
    headers = {
        "x-forwarded-for": "10.0.0.1, 127.0.0.1"
    }
    req = MagicMock(spec=Request)
    req.client.host = "203.0.113.99"  # Untrusted external IP
    req.headers = headers

    resolved_ip = get_trusted_client_ip(req)
    assert resolved_ip == "203.0.113.99"


# ── 2. Finding #14 & #34: Rate Limiter In-Process Fallback & Fail-Closed ──────
@pytest.mark.anyio
async def test_rate_limiter_in_process_fallback_when_redis_offline():
    """
    When Redis is offline/unreachable, RateLimiter falls back to in-process
    sliding window token bucket rather than failing open completely.
    """
    limiter = RateLimiter(limit=3, window=60, fail_closed=False)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/test-endpoint",
        "headers": [(b"host", b"test")],
        "client": ("198.51.100.50", 12345),
    }
    req = Request(scope)

    with patch("services.rate_limiter.get_async_redis_client", AsyncMock(side_effect=ConnectionError("Redis down"))):
        # 3 allowed requests
        await limiter(req)
        await limiter(req)
        await limiter(req)

        # 4th request must be rejected with 429 Too Many Requests
        with pytest.raises(Exception) as exc_info:
            await limiter(req)
        assert getattr(exc_info.value, "status_code", None) == 429


@pytest.mark.anyio
async def test_rate_limiter_fail_closed_on_sensitive_routes():
    """
    Sensitive routes with fail_closed=True must block requests if Redis is down
    and the in-process fallback bucket limit is exceeded.
    """
    limiter = RateLimiter(limit=2, window=60, fail_closed=True)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/auth/login",
        "headers": [(b"host", b"test")],
        "client": ("198.51.100.77", 12345),
    }
    req = Request(scope)

    with patch("services.rate_limiter.get_async_redis_client", AsyncMock(side_effect=ConnectionError("Redis down"))):
        await limiter(req)
        await limiter(req)
        with pytest.raises(Exception) as exc_info:
            await limiter(req)
        assert getattr(exc_info.value, "status_code", None) == 429


# ── 3. Finding #20 & #34: Server-Side Auth Guard on /dashboard ─────────────────
@pytest.mark.anyio
async def test_dashboard_unauthenticated_returns_303_redirect():
    """
    Direct navigation to /dashboard without valid session cookie must
    return HTTP 303 See Other redirecting to /login.
    """
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", follow_redirects=False) as ac:
        response = await ac.get("/dashboard")
        assert response.status_code == 303
        assert response.headers.get("location") == "/login"


# ── 4. Finding #22, #23 & #34: Security Response Headers ───────────────────────
@pytest.mark.anyio
async def test_security_headers_present_on_all_responses():
    """
    Verify CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
    and Permissions-Policy headers are enforced on responses.
    """
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/login")
        assert response.status_code == 200

        # Finding #22: Content-Security-Policy
        csp = response.headers.get("Content-Security-Policy")
        assert csp is not None
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp

        # Finding #23: Standard Security Headers
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert "strict-origin-when-cross-origin" in response.headers.get("Referrer-Policy", "")
        assert "geolocation=()" in response.headers.get("Permissions-Policy", "")


# ── 5. Finding #16 & #34: Metrics Endpoint Authentication Gate ────────────────
@pytest.mark.anyio
async def test_metrics_endpoint_unconditional_gate():
    """
    /metrics must require valid Bearer token whenever METRICS_SECRET is configured.
    """
    transport = ASGITransport(app=app)
    with patch.object(config.settings, "metrics_secret", "test_super_secret_metrics_token_2026"):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            # Unauthenticated request
            unauth_resp = await ac.get("/metrics")
            assert unauth_resp.status_code == 401

            # Invalid token
            bad_token_resp = await ac.get(
                "/metrics",
                headers={"Authorization": "Bearer invalid_token"}
            )
            assert bad_token_resp.status_code == 401

            # Valid token
            valid_resp = await ac.get(
                "/metrics",
                headers={"Authorization": "Bearer test_super_secret_metrics_token_2026"}
            )
            assert valid_resp.status_code == 200
            assert "http_requests_total" in valid_resp.text or "aml" in valid_resp.text or "# HELP" in valid_resp.text


# ── 6. Finding #17 & #34: Search Query Parameter Max Length ───────────────────
@pytest.mark.anyio
async def test_alerts_search_query_parameter_max_length():
    """
    Alerts search query exceeding 200 chars must be rejected with 422 Unprocessable Entity.
    """
    from services.auth import create_access_token
    token = create_access_token({
        "sub": "test_analyst",
        "username": "test_analyst",
        "role": "ANALYST",
        "tenant_id": "00000000-0000-0000-0000-000000000000"
    })
    headers = {
        "Authorization": f"Bearer {token}",
        "X-CSRF-Protection": "1"
    }

    transport = ASGITransport(app=app)
    oversized_search = "A" * 201
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(f"/api/v1/alerts?search={oversized_search}", headers=headers)
        assert resp.status_code == 422
        assert "search" in str(resp.json()).lower()


# ── 7. Finding #11 & #34: Cookie SameSite=strict ──────────────────────────────
def test_set_auth_cookies_enforces_samesite_strict():
    """
    set_auth_cookies must configure samesite='strict' to eliminate login CSRF.
    """
    response = Response()
    set_auth_cookies(
        response=response,
        access_token="test.access.token",
        refresh_token="test.refresh.token"
    )

    cookies = response.headers.getlist("set-cookie")
    assert len(cookies) == 2

    for cookie in cookies:
        cookie_lower = cookie.lower()
        assert "samesite=strict" in cookie_lower
        assert "httponly" in cookie_lower


# ── 8. Finding #3 & #34: Cluster-Safe User Sync ───────────────────────────────
def test_user_sync_module_has_no_in_memory_state():
    """
    Verify services.auth does NOT contain the legacy '_synced_users' in-memory set,
    guaranteeing that multiple pod replicas do not diverge on user synchronization state.
    """
    import services.auth as auth_mod
    assert not hasattr(auth_mod, "_synced_users"), "Legacy in-memory _synced_users set must be removed!"
