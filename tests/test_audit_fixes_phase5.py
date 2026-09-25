"""
Phase 5 Remediation & Security Hardening Tests
==============================================
Validates the following fixes:
1. UserProvision model instantiation and schema integrity (fixing missing Optional import)
2. CWE-290 IP address spoofing mitigation in TrustedProxyMiddleware via right-to-left traversal
3. RateLimiter path normalization (neutralizing trailing slash quota bypasses)
4. Sanitizer Trojan Source bidi override & nested script tag neutralization
5. docker-compose.yml loopback (127.0.0.1) port isolation
6. Sentry APM settings configuration and graceful initialization
"""

import ipaddress
import os
import re
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from starlette.requests import Request


# ── 1. UserProvision Model ────────────────────────────────────────────────────
def test_user_provision_model_instantiation():
    """Verify that UserProvision can be instantiated and validated without PydanticUserError."""
    from routers.auth import UserProvision

    user = UserProvision(
        username="compliance.officer@bank.com",
        password="SuperSecretPassword123!",
        role="AUDITOR",
        tenant_id="11111111-2222-3333-4444-555555555555"
    )
    assert user.username == "compliance.officer@bank.com"
    assert user.role == "AUDITOR"
    assert user.tenant_id == "11111111-2222-3333-4444-555555555555"

    # Verify default role and optional tenant_id
    default_user = UserProvision(
        username="analyst_user",
        password="ValidPassword2026!"
    )
    assert default_user.role == "ANALYST"
    assert default_user.tenant_id is None


# ── 2. CWE-290 IP Spoofing Neutralization ─────────────────────────────────────
def test_trusted_proxy_neutralizes_x_forwarded_for_spoofing():
    """
    Verifies that when behind a trusted proxy, get_trusted_client_ip traverses
    X-Forwarded-For right-to-left, discarding attacker-injected header prefixes.
    """
    from services.trusted_proxy import get_trusted_client_ip

    def make_mock_request(peer_ip: str, x_forwarded_for: str | None = None, x_real_ip: str | None = None):
        headers = {}
        if x_forwarded_for:
            headers["x-forwarded-for"] = x_forwarded_for
        if x_real_ip:
            headers["x-real-ip"] = x_real_ip
        req = MagicMock(spec=Request)
        req.client.host = peer_ip
        req.headers = headers
        return req

    # Scenario A: Valid request through trusted reverse proxy (RFC 7239 client IP extraction)
    req_trusted = make_mock_request("127.0.0.1", x_forwarded_for="203.0.113.195, 10.0.0.2")
    assert get_trusted_client_ip(req_trusted) == "203.0.113.195"

    # Scenario B: Direct untrusted peer spoofing headers (CWE-290 defense)
    req_untrusted = make_mock_request("198.51.100.99", x_forwarded_for="127.0.0.1, 10.0.0.1")
    assert get_trusted_client_ip(req_untrusted) == "198.51.100.99"

    # Scenario C: X-Real-IP resolution when behind trusted proxy
    req_real = make_mock_request("127.0.0.1", x_real_ip="198.51.100.42")
    assert get_trusted_client_ip(req_real) == "198.51.100.42"

    # Scenario D: Direct untrusted peer spoofing X-Real-IP (CWE-290 defense)
    req_untrusted_real = make_mock_request("198.51.100.99", x_real_ip="10.0.0.1")
    assert get_trusted_client_ip(req_untrusted_real) == "198.51.100.99"


# ── 3. RateLimiter Path Normalization ──────────────────────────────────────────
@pytest.mark.anyio
async def test_rate_limiter_path_normalization():
    """Verify that trailing slashes are stripped so keys are shared and cannot be bypassed."""
    from services.rate_limiter import RateLimiter

    limiter = RateLimiter(limit=10, window=60)
    
    mock_pipe = MagicMock()
    mock_pipe.execute = AsyncMock(return_value=[0, True, 1, True])
    mock_redis = MagicMock()
    mock_redis.pipeline.return_value = mock_pipe

    req1 = MagicMock(spec=Request)
    req1.client.host = "203.0.113.50"
    req1.url.path = "/api/v1/auth/login"
    req1.state = MagicMock()
    req1.state.client_ip = "203.0.113.50"

    req2 = MagicMock(spec=Request)
    req2.client.host = "203.0.113.50"
    req2.url.path = "/api/v1/auth/login/"
    req2.state = MagicMock()
    req2.state.client_ip = "203.0.113.50"

    keys_called = []
    def record_zadd(key, mapping):
        keys_called.append(key)

    mock_pipe.zadd.side_effect = record_zadd

    with patch("services.rate_limiter.get_async_redis_client", AsyncMock(return_value=mock_redis)):
        await limiter(req1)
        await limiter(req2)

    assert len(keys_called) == 2
    # Both calls must resolve to the identical normalized key
    assert keys_called[0] == keys_called[1]
    assert keys_called[0].startswith("rate_limit:/api/v1/auth/login:")


# ── 4. Sanitizer Unicode & Tag Hardening ──────────────────────────────────────
def test_sanitizer_trojan_source_and_nested_tags():
    """Verify Trojan Source bidi characters, zero-width chars, and nested tags are neutralized."""
    from observability.sanitizer import sanitize_text

    # Trojan Source RTL/LTR override characters
    trojan_input = "Admin\u202e\u2066User\u2069\u202c"
    assert sanitize_text(trojan_input) == "AdminUser"

    # Zero-width spaces
    zw_input = "evil\u200b\u200cpayload\ufeff"
    assert sanitize_text(zw_input) == "evilpayload"

    # Nested / recursive script tags designed to bypass single-pass regexes
    nested_script = "<<script>script>alert(1)</<script>script>"
    assert "<script" not in sanitize_text(nested_script).lower()
    assert sanitize_text(nested_script) == "alert(1)"

    # Clean legitimate strings remain intact
    assert sanitize_text("Standard AML Entity Name") == "Standard AML Entity Name"


# ── 5. Docker Compose Loopback Port Bindings ──────────────────────────────────
def test_docker_compose_loopback_port_bindings():
    """Verifies that all exposed host ports in docker-compose.yml are bound to 127.0.0.1."""
    import yaml

    with open("docker-compose.yml", "r", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)

    services = compose_data.get("services", {})
    unbound_ports = []

    for svc_name, svc_conf in services.items():
        ports = svc_conf.get("ports", [])
        for port_mapping in ports:
            # e.g., "127.0.0.1:8000:8000" or "8000:8000"
            if isinstance(port_mapping, str):
                parts = port_mapping.split(":")
                if len(parts) == 2:
                    # e.g. "8000:8000" -> not bound to loopback
                    unbound_ports.append(f"{svc_name}: {port_mapping}")
                elif len(parts) == 3:
                    host_ip = parts[0]
                    if host_ip != "127.0.0.1" and host_ip != "::1":
                        unbound_ports.append(f"{svc_name}: {port_mapping}")

    assert not unbound_ports, f"Found public/unbound ports in docker-compose.yml: {unbound_ports}"


# ── 6. Sentry Configuration ───────────────────────────────────────────────────
def test_sentry_settings_configuration():
    """Verify Sentry settings fields and defaults."""
    from config import Settings

    s = Settings(
        environment="production",
        postgres_password="secure_prod_password_123",
        aml_app_password="secure_prod_password_999",
        neo4j_password="secure_prod_password_456",
        elastic_password="secure_prod_password_789",
        internal_gateway_secret="secure_prod_internal_gateway_secret_999",
        sentry_dsn="https://public@sentry.io/12345"
    )
    assert s.sentry_dsn == "https://public@sentry.io/12345"
    assert s.sentry_traces_sample_rate == 0.1
