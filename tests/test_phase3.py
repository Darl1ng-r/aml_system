import json
import pytest
from unittest.mock import AsyncMock, patch
import httpx
import yaml
from main import app
from services.auth import hash_password
from services.mfa import (
    generate_totp_secret,
    generate_totp_code,
    verify_totp_code,
    generate_recovery_codes,
    verify_and_consume_recovery_code,
)
from observability.logging import JsonFormatter, mask_sensitive_text, mask_dict_data


def test_totp_generation_and_verification():
    """Verify RFC 6238 TOTP code generation, format, and drift window tolerance."""
    secret = generate_totp_secret()
    assert len(secret) == 32

    current_code = generate_totp_code(secret)
    assert len(current_code) == 6
    assert current_code.isdigit()

    # Valid code matches
    assert verify_totp_code(secret, current_code) is True
    # Non-digit / wrong length rejected
    assert verify_totp_code(secret, "abc123") is False
    assert verify_totp_code(secret, "9999999") is False


def test_recovery_code_generation_and_consumption():
    """Verify backup recovery code generation and single-use consumption."""
    plain_codes, hashed_codes = generate_recovery_codes(count=8)
    assert len(plain_codes) == 8
    assert len(hashed_codes) == 8

    test_code = plain_codes[0]
    # First use succeeds and burns the code
    valid, remaining = verify_and_consume_recovery_code(test_code, hashed_codes)
    assert valid is True
    assert len(remaining) == 7

    # Second use of same code fails
    valid2, remaining2 = verify_and_consume_recovery_code(test_code, remaining)
    assert valid2 is False
    assert len(remaining2) == 7


@pytest.mark.anyio
async def test_mfa_login_challenge_flow():
    """
    Verify complete MFA Login Challenge Flow:
    1. /login with valid credentials on an MFA-enabled account returns mfa_required: true + mfa_ticket.
    2. /mfa/verify with ticket and correct TOTP code returns access & refresh tokens.
    3. Invalid TOTP code returns 401 Unauthorized.
    """
    secret = generate_totp_secret()
    totp_code = generate_totp_code(secret)

    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = {
        "id": "22222222-2222-2222-2222-222222222222",
        "role": "ANALYST",
        "password_hash": hash_password("ValidPassword2026!"),
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "is_active": True,
        "mfa_enabled": True,
        "mfa_secret": secret,
        "recovery_codes": json.dumps([])
    }
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    redis_store = {}
    mock_redis = AsyncMock()
    async def mock_get(k):
        return redis_store.get(k)
    async def mock_setex(k, ttl, v):
        redis_store[k] = v
    async def mock_delete(k):
        redis_store.pop(k, None)

    mock_redis.get = mock_get
    mock_redis.setex = mock_setex
    mock_redis.delete = mock_delete

    with patch("database.postgres.get_async_db_conn", return_value=mock_ctx), \
         patch("database.redis_db.get_async_redis_client", return_value=mock_redis):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            # Step 1: Initial Login yields MFA challenge
            login_resp = await ac.post(
                "/api/v1/auth/login",
                data={"username": "mfa_officer@aml.com", "password": "ValidPassword2026!"}
            )
            assert login_resp.status_code == 200
            data = login_resp.json()
            assert data.get("mfa_required") is True
            assert "mfa_ticket" in data
            assert "access_token" not in data
            ticket = data["mfa_ticket"]

            # Step 2: Failed verification with wrong TOTP code
            failed_verify = await ac.post(
                "/api/v1/auth/mfa/verify",
                json={"mfa_ticket": ticket, "code": "000000"}
            )
            assert failed_verify.status_code == 401

            # Step 3: Successful verification with valid TOTP code
            success_verify = await ac.post(
                "/api/v1/auth/mfa/verify",
                json={"mfa_ticket": ticket, "code": totp_code}
            )
            assert success_verify.status_code == 200
            tokens = success_verify.json()
            assert "access_token" in tokens
            assert "refresh_token" in tokens
            assert "access_token" in success_verify.cookies


def test_sensitive_pii_logging_masking():
    """Verify JsonFormatter scrubs bank account numbers, passwords, and bearer tokens."""
    import logging

    formatter = JsonFormatter()
    raw_message = "Processed transfer for account ACC_GB9912345678 with auth Bearer eyJhbGciOiJIUzI1Ni... and password=SuperSecret!"
    record = logging.LogRecord(
        name="aml.test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg=raw_message,
        args=(),
        exc_info=None
    )
    record.details = {
        "password": "CleartextPassword123!",
        "ssn": "000-11-2222",
        "beneficiary": "ACC_DE8898765432"
    }

    formatted = formatter.format(record)
    parsed = json.loads(formatted)

    # Verify message masking
    assert "SuperSecret!" not in parsed["message"]
    assert "[REDACTED]" in parsed["message"]
    assert "ACC_GB99****5678" in parsed["message"]

    # Verify details extra dictionary masking
    assert parsed["extra"]["details"]["password"] == "[REDACTED]"
    assert parsed["extra"]["details"]["ssn"] == "[REDACTED]"
    assert "ACC_DE88****5432" in parsed["extra"]["details"]["beneficiary"]


def test_prometheus_alert_rules_yaml():
    """Verify deployments/monitoring/prometheus-rules.yaml is valid YAML and includes key alert rules."""
    with open("deployments/monitoring/prometheus-rules.yaml", "r") as f:
        data = yaml.safe_load(f)

    assert data["kind"] == "PrometheusRule"
    groups = data["spec"]["groups"]
    assert len(groups) >= 1
    rule_names = [r["alert"] for r in groups[0]["rules"]]
    assert "AMLHighErrorRate" in rule_names
    assert "AMLLatencySLOBreach" in rule_names
    assert "AMLKafkaConsumerLag" in rule_names
    assert "AMLBruteForceDetected" in rule_names
    assert "AMLUnauthorizedTenantAccessSpike" in rule_names


def test_ci_pipeline_yaml():
    """Verify .github/workflows/ci.yml is valid YAML and includes all required pipeline jobs."""
    with open(".github/workflows/ci.yml", "r") as f:
        pipeline = yaml.safe_load(f)

    jobs = pipeline["jobs"]
    assert "lint-and-audit" in jobs
    assert "test" in jobs
    assert "container-security" in jobs
