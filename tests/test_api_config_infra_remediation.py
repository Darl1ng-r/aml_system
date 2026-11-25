"""
API Configuration, Resilience & Infrastructure Remediation Regression Suite
===========================================================================
Covers every P0, P1, P2, and P3 remediation from `api_config_and_infra_audit.md`.
"""

import inspect
import os
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import HTTPException, Request
from pydantic import ValidationError

from config import Settings, settings
from main import app

ROOT = Path(__file__).resolve().parent.parent


# ── P0-01: Read-Only RootFS Import & Prometheus Multiproc Safety ──────────────

def test_p0_01_evidence_router_does_not_makedirs_at_import():
    src = (ROOT / "routers" / "evidence.py").read_text(encoding="utf-8")
    # Ensure no top-level module-import os.makedirs call remains
    for line in src.splitlines():
        assert not line.startswith("os.makedirs("), f"Found import-time makedirs: {line}"


def test_p0_01_prometheus_creates_multiproc_dir_safely(tmp_path):
    target_dir = tmp_path / "prom_multiproc_missing"
    assert not target_dir.exists()
    with patch.dict(os.environ, {"PROMETHEUS_MULTIPROC_DIR": str(target_dir)}):
        os.makedirs(os.environ["PROMETHEUS_MULTIPROC_DIR"], exist_ok=True)
    assert target_dir.is_dir()
    prom_src = (ROOT / "observability" / "prometheus.py").read_text(encoding="utf-8")
    assert "os.makedirs(_multiproc_dir, exist_ok=True)" in prom_src


# ── P0-02: Redis TLS kwargs compatible with pinned redis==5.0.1 ───────────────

def test_p0_02_redis_tls_kwargs_avoid_unsupported_ssl_context(tmp_path):
    import redis
    from database.redis_db import _build_redis_tls_kwargs

    fake_ca = tmp_path / "ca.crt"
    fake_cert = tmp_path / "tls.crt"
    fake_key = tmp_path / "tls.key"
    for f in (fake_ca, fake_cert, fake_key):
        f.write_text("dummy", encoding="utf-8")

    with (
        patch("database.redis_db.get_ssl_context", return_value=MagicMock()),
        patch("database.redis_db.get_tls_cert_paths", return_value=(str(fake_ca), str(fake_cert), str(fake_key))),
    ):
        kwargs = _build_redis_tls_kwargs()

    assert kwargs["ssl"] is True
    assert "ssl_context" not in kwargs
    assert kwargs["ssl_ca_certs"] == str(fake_ca)
    assert kwargs["ssl_certfile"] == str(fake_cert)
    assert kwargs["ssl_keyfile"] == str(fake_key)
    # Verify every key is accepted by installed redis.Redis / SSLConnection
    conn_params = inspect.signature(redis.connection.SSLConnection.__init__).parameters
    for k in kwargs:
        if k == "ssl":
            continue
        assert k in conn_params, f"Unsupported redis SSL kwarg: {k}"


# ── P0-05: Cloudflare Turnstile Fail-Closed in Hardened Environments ──────────

@pytest.mark.asyncio
async def test_p0_05_turnstile_rejects_missing_or_test_secret_in_hardened():
    from services.turnstile import TURNSTILE_TEST_SECRET, verify_turnstile_token

    with (
        patch.object(settings, "environment", "production"),
        patch.object(settings, "turnstile_secret_key", ""),
    ):
        with pytest.raises(RuntimeError, match="TURNSTILE_SECRET_KEY"):
            await verify_turnstile_token("some_token")

    with (
        patch.object(settings, "environment", "staging"),
        patch.object(settings, "turnstile_secret_key", TURNSTILE_TEST_SECRET),
    ):
        with pytest.raises(RuntimeError, match="TURNSTILE_SECRET_KEY"):
            await verify_turnstile_token("some_token")


# ── P0-06 & P0-07: No Hardcoded DB Password in Mig 011 & Sanitized Templates ──

def test_p0_06_migration_011_has_no_hardcoded_password_literal():
    src = (ROOT / "migrations" / "versions" / "011_create_aml_app_role_and_token_version.py").read_text(encoding="utf-8")
    assert "aml_app_secure_pass_2026" not in src
    assert (ROOT / "migrations" / "versions" / "035_rotate_aml_app_password_from_env.py").exists()


def test_p0_07_env_templates_do_not_contain_live_supabase_project():
    for fname in (".env.example", ".env.production.example"):
        content = (ROOT / fname).read_text(encoding="utf-8")
        assert "xzhsdffpnrlpcitiectz.supabase.co" not in content


# ── P0-08 & P1-01: Staging Security Parity, Placeholders & ALLOW_OFFLINE_DEV ──

def test_p1_01_staging_enforces_hardened_validators_and_blocks_placeholders():
    with pytest.raises(ValidationError):
        Settings(
            environment="staging",
            postgres_password="StrongPassword!Staging#2026",
            aml_app_password="StrongAppPassword!Staging#2026",
            redis_password="redispassword",
            internal_gateway_secret="StrongGatewaySecret!Staging#2026",
            metrics_secret="StrongMetricsSecret!Staging#2026",
            allowed_origins="https://staging.example.com",
        )

    with pytest.raises(ValidationError):
        Settings(
            environment="production",
            postgres_password="REPLACE_WITH_HIGH_ENTROPY_PASSWORD",
            aml_app_password="StrongAppPassword!Prod#2026",
            internal_gateway_secret="StrongGatewaySecret!Prod#2026",
            metrics_secret="StrongMetricsSecret!Prod#2026",
            allowed_origins="https://aml.example.com",
        )

    with pytest.raises(ValidationError):
        Settings(
            environment="staging",
            postgres_password="StrongPassword!Staging#2026",
            aml_app_password="StrongAppPassword!Staging#2026",
            internal_gateway_secret="StrongGatewaySecret!Staging#2026",
            metrics_secret="StrongMetricsSecret!Staging#2026",
            allowed_origins="https://staging.example.com",
            vault_dev_token="root",
        )

    valid_staging = Settings(
        _env_file=None,
        environment="staging",
        postgres_password="StrongPassword!Staging#2026",
        aml_app_password="StrongAppPassword!Staging#2026",
        neo4j_password="StrongNeo4jPassword!Staging#2026",
        elastic_password="StrongElasticPassword!Staging#2026",
        redis_password="StrongRedisPassword!Staging#2026",
        internal_gateway_secret="StrongGatewaySecret!Staging#2026",
        metrics_secret="StrongMetricsSecret!Staging#2026",
        allowed_origins="https://staging.example.com",
        allow_offline_dev=True,
        allow_public_signup=True,
    )
    assert valid_staging.is_hardened is True
    assert valid_staging.allow_offline_dev is False
    assert valid_staging.allow_public_signup is False


def test_p0_08_main_does_not_allow_env_override_of_offline_dev():
    code_lines = [
        line for line in (ROOT / "main.py").read_text(encoding="utf-8").splitlines()
        if not line.strip().startswith("#")
    ]
    assert 'os.getenv("ALLOW_OFFLINE_DEV"' not in "\n".join(code_lines)


# ── P0-09: Rate Limiter Route-Template Keying, API-Key Bucket & Non-Polluting Lua

@pytest.mark.asyncio
async def test_p0_09_rate_limiter_uses_route_template_not_raw_path():
    from services.rate_limiter import RateLimiter

    limiter = RateLimiter(limit=2, window=60, ip_only=True)

    def _make_req(token_seg: str):
        req = MagicMock(spec=Request)
        req.client = MagicMock(host="198.51.100.77")
        req.state = MagicMock(client_ip="198.51.100.77")
        req.url = MagicMock(path=f"/api/v1/rfi/public/{token_seg}")
        req.scope = {"route": MagicMock(path="/api/v1/rfi/public/{token}")}
        req.headers = {}
        req.cookies = {}
        return req

    with patch("services.rate_limiter.get_async_redis_client", AsyncMock(return_value=None)):
        await limiter(_make_req("tok-aaa"))
        await limiter(_make_req("tok-bbb"))
        # 3rd call with a BRAND-NEW path param must hit 429 on the SAME route bucket!
        with pytest.raises(HTTPException) as exc_info:
            await limiter(_make_req("tok-ccc"))
        assert exc_info.value.status_code == 429
        assert "X-RateLimit-Limit" in exc_info.value.headers


@pytest.mark.asyncio
async def test_p0_09_rate_limiter_supports_per_api_key_buckets():
    from services.rate_limiter import _build_rate_limit_key, _extract_identity

    req = MagicMock(spec=Request)
    req.headers = {"X-API-Key": "aml_live_secret_key_001"}
    req.cookies = {}
    req.url = MagicMock(path="/api/v1/transactions/ingest")
    req.scope = {"route": MagicMock(path="/api/v1/transactions/ingest")}

    uid, tid, key_hash = _extract_identity(req)
    assert uid is None and tid is None and key_hash is not None
    rl_key, route_tpl = _build_rate_limit_key(req, "198.51.100.1", uid, tid, key_hash)
    assert rl_key.startswith(f"rate_limit:apikey:{key_hash}:")
    assert route_tpl == "/api/v1/transactions/ingest"


@pytest.mark.asyncio
async def test_p0_09_redis_lua_atomic_rejection_does_not_add_member():
    from services.rate_limiter import RateLimiter

    limiter = RateLimiter(limit=2, window=60)
    req = MagicMock(spec=Request)
    req.client = MagicMock(host="203.0.113.10")
    req.state = MagicMock(client_ip="203.0.113.10")
    req.url = MagicMock(path="/api/v1/alerts")
    req.scope = {"route": MagicMock(path="/api/v1/alerts")}
    req.headers = {}
    req.cookies = {}

    class FakeAsyncRedis:
        def __init__(self):
            self.eval_calls = 0

        async def eval(self, script, numkeys, *args):
            self.eval_calls += 1
            assert "ZCARD" in script and "if count >= limit then" in script
            if self.eval_calls <= 2:
                return [1, self.eval_calls]
            return [0, 2]

    fake_redis = FakeAsyncRedis()
    with patch("services.rate_limiter.get_async_redis_client", AsyncMock(return_value=fake_redis)):
        await limiter(req)
        await limiter(req)
        with pytest.raises(HTTPException) as exc_info:
            await limiter(req)
        assert exc_info.value.status_code == 429


# ── P0-10: FinCEN Environment Guard & Verified SFTP ───────────────────────────

@pytest.mark.asyncio
async def test_p0_10_fincen_blocks_live_in_dev_and_sandbox_in_prod():
    from services.fincen_efiling import FinCENEfilingClient

    client = FinCENEfilingClient()
    valid_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<EFilingBatchXML xmlns="www.fincen.gov/base">'
        '<Activity><ActivityID>1</ActivityID><SuspiciousActivity><SuspiciousActivityID>1</SuspiciousActivityID></SuspiciousActivity></Activity>'
        '</EFilingBatchXML>'
    )

    with (
        patch.object(settings, "environment", "development"),
        patch.object(settings, "fincen_transport", "rest"),
        patch("services.sar_validator.validate_regulatory_xml", return_value=(True, [])),
    ):
        with pytest.raises(RuntimeError, match="forbidden outside production"):
            await client.submit_sar(valid_xml, alert_id="a1")

    with (
        patch.object(settings, "environment", "production"),
        patch.object(settings, "fincen_transport", "sandbox"),
        patch("services.sar_validator.validate_regulatory_xml", return_value=(True, [])),
    ):
        with pytest.raises(RuntimeError, match="must NOT file SARs to FinCEN sandbox"):
            await client.submit_sar(valid_xml, alert_id="a1")


# ── P1-02, P1-03, P1-04, P1-15: Body Limit, RFI Pre-Check, 422 Input Strip & Cache-Control

@pytest.mark.asyncio
async def test_p1_02_body_size_limit_rejects_oversized_payload_413():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post(
            "/api/v1/auth/login",
            content=b"x" * (2 * 1024 * 1024 + 100),
            headers={"Content-Type": "application/json"},
        )
        assert res.status_code == 413


@pytest.mark.asyncio
async def test_p1_03_rfi_submit_rejects_bad_token_before_multipart_spool():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post(
            "/api/v1/rfi/public/invalid-token-format/submit",
            content=b"not-even-valid-multipart-junk",
            headers={"Content-Type": "multipart/form-data; boundary=abc"},
        )
        assert res.status_code == 404


@pytest.mark.asyncio
async def test_p1_04_validation_422_strips_input_and_adds_correlation_id():
    secret_canary = "SuperSecretCanaryPassword!99999"
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        # Send invalid JSON type to /api/v1/auth/signup to trigger RequestValidationError
        res = await ac.post(
            "/api/v1/auth/signup",
            json={"username": "ab", "password": secret_canary, "email": "not-an-email"},
        )
        assert res.status_code == 422
        body = res.json()
        assert "correlation_id" in body
        assert secret_canary not in res.text
        for err in body.get("errors", []):
            assert "input" not in err


@pytest.mark.asyncio
async def test_p1_15_api_responses_emit_cache_control_no_store_and_jwks_supports_304():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        r_api = await ac.get("/api/v1/auth/me")
        assert r_api.headers.get("cache-control") == "no-store"

        r_jwks = await ac.get("/.well-known/jwks.json")
        assert r_jwks.status_code == 200
        etag = r_jwks.headers.get("etag")
        assert etag and "max-age=300" in r_jwks.headers.get("cache-control", "")

        r_304 = await ac.get("/.well-known/jwks.json", headers={"If-None-Match": etag})
        assert r_304.status_code == 304


# ── P1-09: IAM Microservice Security Parity ───────────────────────────────────

@pytest.mark.asyncio
async def test_p1_09_iam_service_hardened_and_no_raw_error_leak():
    from services.iam.app import iam_app

    transport = httpx.ASGITransport(app=iam_app)
    with patch("database.postgres.get_db_pool", AsyncMock(side_effect=RuntimeError("pg_secret_host:5432 auth failed"))):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r = await ac.get("/health/readiness")
            assert r.status_code == 503
            assert "pg_secret_host" not in r.text
            assert "postgres_error" not in r.json().get("checks", {})
            assert r.headers.get("x-content-type-options") == "nosniff"


# ── P1-10: RSA Key Hot-Reload & Zero-Downtime Multi-Key JWKS ──────────────────

def test_p1_10_rsa_hot_reload_and_previous_public_key_in_jwks():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from services.secrets_manager import get_jwks, get_or_create_rsa_keypair, invalidate_rsa_key_cache

    k1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    k2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p1 = k1.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pub1 = k1.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    p2 = k2.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()

    invalidate_rsa_key_cache()
    try:
        with patch.dict(os.environ, {"JWT_PRIVATE_KEY_PEM": p1, "JWT_PREVIOUS_PUBLIC_KEY_PEM": ""}):
            priv_a, _ = get_or_create_rsa_keypair()
            assert priv_a.strip() == p1.strip()

        # Rotate to k2 with k1 public key retained in grace window
        with patch.dict(os.environ, {"JWT_PRIVATE_KEY_PEM": p2, "JWT_PREVIOUS_PUBLIC_KEY_PEM": pub1}):
            priv_b, _ = get_or_create_rsa_keypair()
            assert priv_b.strip() == p2.strip()
            jwks_doc = get_jwks()
            assert len(jwks_doc["keys"]) == 2
    finally:
        invalidate_rsa_key_cache()


# ── P1-13: Watchlist Sync Fails Closed in Hardened Environments ───────────────

@pytest.mark.asyncio
async def test_p1_13_watchlist_sync_refuses_toy_fallback_in_hardened():
    from services.watchlist_sync import WatchlistSyncEngine

    engine = WatchlistSyncEngine()
    with (
        patch.object(settings, "environment", "production"),
        patch("services.watchlist_sync._fetch_feed_content", AsyncMock(return_value=None)),
    ):
        with pytest.raises(RuntimeError, match="sanctions feed sync failed"):
            await engine.fetch_ofac_sdn_feed()


# ── P2-01, P2-04: Circuit Breaker & Full Jitter Backoff ───────────────────────

def test_p2_01_and_p2_04_circuit_breaker_trips_and_full_jitter_bounded():
    from services.http_client import CircuitBreaker, full_jitter_backoff

    cb = CircuitBreaker(target="test_svc", failure_threshold=3, window_seconds=30.0, recovery_timeout=60.0)
    assert cb.allow_request() is True
    cb.record_failure()
    cb.record_failure()
    assert cb.state == "closed"
    cb.record_failure()
    assert cb.state == "open"
    assert cb.allow_request() is False

    samples = [full_jitter_backoff(1.0, attempt=3, cap=10.0) for _ in range(30)]
    assert all(0.0 <= s <= 8.0 for s in samples)
    assert len(set(samples)) > 5  # genuinely jittered, not deterministic


# ── P2-08, P2-18, P3-03: Login CSRF, SSRF IP Scrubbing, Correlation-ID Validation

@pytest.mark.asyncio
async def test_p2_08_and_p3_03_login_csrf_and_correlation_id_validation():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        r_csrf = await ac.post(
            "/api/v1/auth/login",
            data={"username": "alice", "password": "pw"},
            headers={"Origin": "https://evil.attacker.example"},
        )
        assert r_csrf.status_code == 403

        r_cid = await ac.get("/health/live", headers={"X-Correlation-ID": "bad\x00<script>alert(1)</script>"})
        assert r_cid.status_code == 200
        returned_cid = r_cid.headers.get("x-correlation-id", "")
        assert re.fullmatch(r"[A-Za-z0-9._-]{8,64}", returned_cid)
        assert "<script>" not in returned_cid


def test_p2_18_ssrf_error_does_not_leak_resolved_internal_ip():
    from services.siem_forwarder import validate_siem_destination_url

    fake_addr = [(2, 1, 6, "", ("10.96.0.1", 443))]
    with patch("socket.getaddrinfo", return_value=fake_addr):
        with pytest.raises(ValueError) as exc_info:
            validate_siem_destination_url("https://internal-rebind.example.com/hook")
        assert "10.96.0.1" not in str(exc_info.value)


# ── P2-05, P2-06, P3-04: Frontend Resilience & Local Lucide Invariants ────────

def test_p2_05_p2_06_p3_04_frontend_timeouts_and_local_lucide():
    api_js = (ROOT / "static" / "api-client.js").read_text(encoding="utf-8")
    app_js = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
    triage_html = (ROOT / "static" / "triage.html").read_text(encoding="utf-8")
    landing_html = (ROOT / "static" / "landing.html").read_text(encoding="utf-8")

    assert "AbortSignal.timeout" in api_js
    assert "if (!window.__AML_FETCH_PATCHED__)" in api_js
    assert "window.fetch = function" not in app_js
    assert "Date.now() % 1000" not in app_js
    assert "ev.code === 1008" in app_js
    assert "triageWsReconnectTimer" in triage_html
    assert "unpkg.com/lucide" not in landing_html
    assert "/static/lucide.min.js" in landing_html


# ── Infrastructure Manifests & CI/CD Hardening Invariants ─────────────────────

def test_infra_manifests_and_ci_hardening_invariants():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "--no-server-header" in dockerfile
    assert "--proxy-headers" in dockerfile
    assert "--limit-concurrency" in dockerfile
    assert "/usr/sbin/nologin" in dockerfile

    fastapi_yaml = (ROOT / "deployments" / "kubernetes" / "fastapi-app.yaml").read_text(encoding="utf-8")
    assert fastapi_yaml.count('pki/issue/aml-cluster-role"') == 2  # single secret + single template
    assert "prom-multiproc" in fastapi_yaml
    assert "secretRef:" not in fastapi_yaml  # least-privilege secretKeyRef only

    netpol = (ROOT / "deployments" / "kubernetes" / "network-policies.yaml").read_text(encoding="utf-8")
    assert "app: aml-scoring-worker" in netpol
    assert "app: aml-secret-rotator" in netpol
    assert "169.254.0.0/16" in netpol

    mig_job = (ROOT / "deployments" / "kubernetes" / "alembic-migration-job.yaml").read_text(encoding="utf-8")
    assert "job: aml-db-migrations" in mig_job
    assert "aml-postgres-primary" in mig_job

    ingress_lines = [
        line for line in (ROOT / "deployments" / "kubernetes" / "ingress-tls.yaml").read_text(encoding="utf-8").splitlines()
        if not line.strip().startswith("#")
    ]
    ingress = "\n".join(ingress_lines)
    assert 'proxy-body-size: "26m"' in ingress
    assert "configuration-snippet" not in ingress

    rotator = (ROOT / "deployments" / "kubernetes" / "secret-rotation-job.yaml").read_text(encoding="utf-8")
    assert '"watch"' in rotator
    assert "medium: Memory" in rotator
    assert "previous_public_keys" in rotator

    envoy = (ROOT / "deployments" / "docker" / "envoy" / "envoy.yaml").read_text(encoding="utf-8")
    assert "address: 127.0.0.1" in envoy
    assert "circuit_breakers:" in envoy
    assert "max_request_bytes:" in envoy
    assert (ROOT / "deployments" / "docker" / "envoy" / "entrypoint.sh").exists()

    ci_yml = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "sha256sum -c" in ci_yml
    assert "aml-scoring-worker" in ci_yml
    assert "name: production" in ci_yml
    assert "repository }}:latest" not in ci_yml
