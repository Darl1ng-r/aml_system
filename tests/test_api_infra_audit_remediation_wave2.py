"""
API & Infrastructure Security Audit Remediation Suite (Wave 2)
==============================================================
End-to-end verification tests for every finding remediated from the
Principal API Architect & Infrastructure Security audit:
  - HIGH-1: Locked-down zero-`unsafe-inline` / zero-CDN API CSP, exact
            SRI-pinned CDN URLs on HTML CSP, and per-request cryptographic
            CSP nonces stamped onto `<script>` tags in authenticated pages.
  - HIGH-2: Zero Starlette `BaseHTTPMiddleware` subclasses anywhere in the
            HTTP middleware stack (`TrustedProxyMiddleware`,
            `SecurityHeadersMiddleware`, `CSRFProtectionMiddleware` all pure ASGI).
  - MED-1:  Staging K8s Kustomize overlay isolates `EVIDENCE_S3_BUCKET`,
            `EVIDENCE_WORM_ENABLED`, and Vault `ExternalSecret` `secretStoreRef`.
  - MED-2:  `config.Settings` enforces HTTPS on `PUBLIC_BASE_URL` in hardened
            environments and forbids `ENABLE_TLS=false` in production (fail-secure True).
  - MED-3:  `services/watchlist_sync.py` routes live feed downloads through
            `request_with_resilience` (shared pool + circuit breaker + retries)
            with zero ad-hoc `httpx.AsyncClient` instantiation.
  - MED-4:  KEDA Prometheus trigger uses HTTPS + bearer `TriggerAuthentication`
            (`aml-prometheus-trigger-auth`); `docker-compose.yml` avoids
            `changeme_in_production` and CLI argv password exposure in healthchecks.
  - MED-5:  Error shielding on `routers/evidence.py` presign 503 + strict
            typed/bounded Pydantic validation on `routers/jobs.py` and `routers/rules.py`.
  - LOW-1:  Canonical error envelopes (`detail`, `correlation_id`, `trace_id`)
            from early pure-ASGI middlewares (`body_limit`, `csrf`).
  - LOW-2:  Unused `aiohttp` import removed from `routers/auth.py`.
  - Bonus:  `GET /api/v1/health/system` exposes `load_shedding` & `deployment_cell_id`;
            `GET /api/v1/reports/*` supports ETag / `304 Not Modified` with
            `Cache-Control: no-store` & `CDN-Cache-Control: no-store`;
            `deployments/monitoring/prometheus-slo-rules.yaml` defines burn-rate & resilience alerts.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import re
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import yaml
from pydantic import ValidationError
from starlette.middleware.base import BaseHTTPMiddleware

from main import app

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _make_auth_token(role: str = "ADMIN", tenant_id: str = "00000000-0000-0000-0000-000000000001") -> str:
    from services.auth import create_access_token

    return create_access_token(
        {
            "sub": f"audit-{role.lower()}",
            "id": str(uuid.uuid4()),
            "username": f"audit-{role.lower()}",
            "role": role,
            "tenant_id": tenant_id,
            "token_version": 1,
        }
    )


def _valid_prod_kwargs(**overrides):
    base = {
        "_env_file": None,
        "environment": "production",
        "postgres_password": "StrongProdPgPassword!2026#",
        "aml_app_password": "StrongProdAppPassword!2026#",
        "neo4j_password": "StrongProdNeoPassword!2026#",
        "elastic_password": "StrongProdEsPassword!2026#",
        "redis_password": "StrongProdRedisPassword!2026#",
        "internal_gateway_secret": "StrongProdGatewaySecret!2026#XYZ",
        "metrics_secret": "StrongProdMetricsSecret!2026#XYZ",
        "allowed_origins": "https://aml.example.com",
    }
    base.update(overrides)
    return base


# ── HIGH-1: Strict API CSP + Version-Pinned CDN + Per-Request HTML Nonce ─────
@pytest.mark.asyncio
async def test_high1_api_csp_has_zero_unsafe_inline_and_zero_cdns():
    """API/health/metrics routes must emit locked-down API_CSP with zero unsafe-inline or CDN origins."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        for path in ("/health/live", "/api/v1/health/system"):
            res = await ac.get(path)
            csp = res.headers.get("Content-Security-Policy", "")
            assert "default-src 'none'" in csp, f"Expected default-src 'none' on {path}, got: {csp}"
            assert "'unsafe-inline'" not in csp, f"Found unsafe-inline in API CSP on {path}: {csp}"
            assert "cdn.jsdelivr.net" not in csp
            assert "unpkg.com" not in csp
            assert "frame-ancestors 'none'" in csp
            assert "upgrade-insecure-requests" in csp


@pytest.mark.asyncio
async def test_high1_workspace_html_stamps_cryptographic_csp_nonce():
    """Authenticated workspace HTML pages must stamp a fresh per-request nonce on <script> tags and enforce script-src-elem."""
    token = _make_auth_token(role="ADMIN")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        r1 = await ac.get("/dashboard", cookies={"access_token": token})
        r2 = await ac.get("/dashboard", cookies={"access_token": token})
        assert r1.status_code == 200
        assert r2.status_code == 200

        csp1 = r1.headers.get("Content-Security-Policy", "")
        csp2 = r2.headers.get("Content-Security-Policy", "")

        m1 = re.search(r"script-src-elem 'self' 'nonce-([^']+)'", csp1)
        m2 = re.search(r"script-src-elem 'self' 'nonce-([^']+)'", csp2)
        assert m1 is not None, f"Missing nonce-enforced script-src-elem in CSP: {csp1}"
        assert m2 is not None, f"Missing nonce-enforced script-src-elem in CSP: {csp2}"
        assert m1.group(1) != m2.group(1), "CSP nonce must be cryptographically unique per request"
        assert f'nonce="{m1.group(1)}"' in r1.text

        # CDN origins must be pinned to exact SRI asset URLs, never root wildcard registries
        assert "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" in csp1
        assert "https://unpkg.com/vis-network@10.1.2/standalone/umd/vis-network.min.js" in csp1
        assert "worker-src 'self' blob:" in csp1
        assert "child-src 'none'" in csp1


# ── HIGH-2: Zero BaseHTTPMiddleware in Entire Stack ──────────────────────────
def test_high2_zero_base_http_middleware_in_app_stack():
    """Every middleware registered on FastAPI app must be pure ASGI (zero BaseHTTPMiddleware subclasses)."""
    from services.csrf import CSRFProtectionMiddleware
    from services.security_headers import SecurityHeadersMiddleware
    from services.trusted_proxy import TrustedProxyMiddleware

    for cls in (TrustedProxyMiddleware, SecurityHeadersMiddleware, CSRFProtectionMiddleware):
        assert not issubclass(cls, BaseHTTPMiddleware), f"{cls.__name__} must not subclass BaseHTTPMiddleware"
        assert callable(getattr(cls, "__call__", None))

    for mw in app.user_middleware:
        cls = mw.cls
        assert not (
            inspect.isclass(cls) and issubclass(cls, BaseHTTPMiddleware)
        ), f"Middleware {cls} still inherits from Starlette BaseHTTPMiddleware"


# ── MED-1: Staging K8s Overlay Isolation ─────────────────────────────────────
def test_med1_staging_overlay_isolates_s3_worm_and_vault_store():
    """Staging Kustomize overlay must never share production S3 bucket, WORM lock, or Vault ClusterSecretStore."""
    overlay_path = ROOT / "deployments" / "kubernetes" / "overlays" / "staging" / "kustomization.yaml"
    doc = yaml.safe_load(overlay_path.read_text(encoding="utf-8"))
    assert doc["namespace"] == "aml-system-staging"

    patches = doc.get("patches", [])
    cm_patch = next(p for p in patches if p["target"]["kind"] == "ConfigMap" and p["target"]["name"] == "aml-config")
    cm_ops = {op["path"]: op["value"] for op in yaml.safe_load(cm_patch["patch"])}
    assert cm_ops["/data/ENVIRONMENT"] == "staging"
    assert cm_ops["/data/EVIDENCE_S3_BUCKET"] == "aml-compliance-evidence-staging"
    assert cm_ops["/data/EVIDENCE_WORM_ENABLED"] == "false"
    assert cm_ops["/data/OUTBOUND_EGRESS_ENABLED"] == "false"

    es_patch = next(
        p for p in patches if p["target"]["kind"] == "ExternalSecret" and p["target"]["name"] == "aml-secrets"
    )
    es_ops = {op["path"]: op["value"] for op in yaml.safe_load(es_patch["patch"])}
    assert es_ops["/spec/secretStoreRef/name"] == "vault-backend-staging"


# ── MED-2: Config Hardened Validation (PUBLIC_BASE_URL + ENABLE_TLS) ─────────
def test_med2_config_enforces_https_public_base_url_and_prod_tls():
    """Hardened envs must reject non-HTTPS/loopback PUBLIC_BASE_URL and production must forbid ENABLE_TLS=false."""
    from config import Settings

    # 1. Plain HTTP PUBLIC_BASE_URL rejected in hardened mode
    with pytest.raises(ValidationError, match="PUBLIC_BASE_URL"):
        Settings(**_valid_prod_kwargs(public_base_url="http://aml.example.com"))

    # 2. Localhost PUBLIC_BASE_URL rejected in staging too
    with pytest.raises(ValidationError, match="PUBLIC_BASE_URL"):
        Settings(**_valid_prod_kwargs(environment="staging", public_base_url="https://localhost:8000"))

    # 3. Explicit ENABLE_TLS=false rejected in production
    with pytest.raises(ValidationError, match="ENABLE_TLS"):
        Settings(**_valid_prod_kwargs(enable_tls=False))

    # 4. Omitting enable_tls in production fails secure -> True
    s_default_tls = Settings(**_valid_prod_kwargs(public_base_url="https://aml.example.com"))
    assert s_default_tls.enable_tls is True
    assert s_default_tls.allow_offline_dev is False
    assert s_default_tls.allow_public_signup is False


# ── MED-3: Watchlist Sync Uses request_with_resilience & Shared Pool ─────────
@pytest.mark.asyncio
async def test_med3_watchlist_sync_uses_request_with_resilience_and_shared_pool():
    """Watchlist feed downloads must route through request_with_resilience with zero ad-hoc AsyncClient."""
    import services.watchlist_sync as ws_mod

    src = inspect.getsource(ws_mod.WatchlistSyncEngine._fetch_all_records)
    assert "httpx.AsyncClient(" not in src, "_fetch_all_records must not construct ad-hoc httpx.AsyncClient"

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.content = b"<sdnList></sdnList>"
    fake_resp.headers = {}

    with patch("services.http_client.request_with_resilience", AsyncMock(return_value=fake_resp)) as mock_res, \
         patch("services.http_client.is_outbound_egress_allowed", return_value=True):
        content = await ws_mod._fetch_feed_content("https://www.treasury.gov/ofac/downloads/sdn.xml")
        assert content == b"<sdnList></sdnList>"
        mock_res.assert_awaited_once()
        call_kwargs = mock_res.call_args.kwargs
        assert call_kwargs["target"] == "watchlist_feed"
        assert call_kwargs["retries"] == 2
        assert call_kwargs["follow_redirects"] is False


# ── MED-4: KEDA Prometheus TLS + Docker Compose Healthcheck Hardening ────────
def test_med4_keda_prometheus_tls_and_compose_healthcheck_hardening():
    """KEDA Prometheus trigger must use HTTPS + bearer TriggerAuthentication; compose must not leak ES password in argv."""
    keda_path = ROOT / "deployments" / "kubernetes" / "keda-scaledobjects.yaml"
    docs = [d for d in yaml.safe_load_all(keda_path.read_text(encoding="utf-8")) if d]

    auth_names = [d["metadata"]["name"] for d in docs if d["kind"] == "TriggerAuthentication"]
    assert "aml-kafka-trigger-auth" in auth_names
    assert "aml-prometheus-trigger-auth" in auth_names

    outbox_scaler = next(
        d for d in docs if d["kind"] == "ScaledObject" and d["metadata"]["name"] == "aml-outbox-relay-scaler"
    )
    prom_trigger = outbox_scaler["spec"]["triggers"][0]
    assert prom_trigger["metadata"]["serverAddress"].startswith("https://")
    assert prom_trigger["metadata"]["authModes"] == "bearer"
    assert prom_trigger["authenticationRef"]["name"] == "aml-prometheus-trigger-auth"

    compose_text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "changeme_in_production" not in compose_text
    assert "-u elastic:" not in compose_text
    assert "curl -s -K -" in compose_text


# ── MED-5: Error Shielding + Strict Job & Rule Payload Validation ────────────
@pytest.mark.asyncio
async def test_med5_evidence_presign_shields_internal_runtime_errors():
    """POST /cases/{id}/evidence/presign-upload must never leak raw RuntimeError text on 503."""
    token = _make_auth_token(role="ADMIN")
    case_id = str(uuid.uuid4())
    transport = httpx.ASGITransport(app=app)

    with patch("services.auth._verify_token_version", AsyncMock(return_value=None)), \
         patch("routers.evidence.verify_case_exists_for_evidence_repo", AsyncMock(return_value=uuid.UUID(case_id))), \
         patch(
             "services.evidence_storage.get_evidence_storage_backend",
             side_effect=RuntimeError("S3 bucket credential arn:aws:iam::123456789012:role/secret failed"),
         ):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post(
                f"/api/v1/cases/{case_id}/evidence/presign-upload",
                headers={"Authorization": f"Bearer {token}"},
                json={"filename": "receipt.pdf", "content_type": "application/pdf", "file_size": 1024},
            )
            assert res.status_code == 503
            detail = res.json()["detail"]
            assert "arn:aws" not in detail
            assert "secret" not in detail
            assert "temporarily unavailable" in detail.lower()


def test_med5_strict_job_and_rule_payload_validation():
    """AsyncJobCreateRequest and Rule payload models must reject malformed/unbounded inputs with ValidationError."""
    from routers.jobs import AsyncJobCreateRequest
    from routers.rules import LegacyRulesConfigPayload, RuleBacktestPayload

    # Invalid EMAIL_NOTIFICATION recipient -> 422 ValidationError
    with pytest.raises(ValidationError, match="recipient"):
        AsyncJobCreateRequest(job_type="EMAIL_NOTIFICATION", payload={"recipient": "not-an-email"})

    # Missing/invalid UUID on EXAMINER_PACKET_ZIP -> 422 ValidationError
    with pytest.raises(ValidationError, match="case_id"):
        AsyncJobCreateRequest(job_type="EXAMINER_PACKET_ZIP", payload={"case_id": "invalid-uuid"})

    # Excessive nesting depth on job payload -> 422 ValidationError
    with pytest.raises(ValidationError, match="depth"):
        AsyncJobCreateRequest(
            job_type="ALERT_PDF_EXPORT",
            payload={"a": {"b": {"c": {"d": {"e": 1}}}}},
        )

    # Valid payloads succeed
    valid_email = AsyncJobCreateRequest(
        job_type="EMAIL_NOTIFICATION",
        payload={"recipient": "mlro@bank.example", "subject": "Audit"},
    )
    assert valid_email.job_type == "EMAIL_NOTIFICATION"

    # RuleBacktestPayload rejects overly nested candidate_config
    with pytest.raises(ValidationError, match="depth"):
        RuleBacktestPayload(candidate_config={"l1": {"l2": {"l3": {"l4": {"l5": True}}}}})

    # LegacyRulesConfigPayload rejects overly nested rules dict
    with pytest.raises(ValidationError, match="depth"):
        LegacyRulesConfigPayload(rules={"r1": {"a": {"b": {"c": {"d": 1}}}}})


# ── LOW-1: Canonical Error Envelopes on Early Pure-ASGI Middlewares ──────────
@pytest.mark.asyncio
async def test_low1_early_middleware_errors_include_correlation_and_trace_id():
    """Body-limit 413 and CSRF 403 JSON responses must include canonical correlation_id & trace_id fields."""
    transport = httpx.ASGITransport(app=app)
    token = _make_auth_token(role="ADMIN")

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Body-limit 413 via oversized Content-Length
        res_413 = await ac.post(
            "/api/v1/jobs",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Length": str(10 * 1024 * 1024),
                "Content-Type": "application/json",
            },
            content=b"{}",
        )
        assert res_413.status_code == 413
        body_413 = res_413.json()
        assert "detail" in body_413
        assert "correlation_id" in body_413
        assert "trace_id" in body_413

        # 2. CSRF 403 on cookie-authenticated POST without X-CSRF-Protection: 1
        res_403 = await ac.post(
            "/api/v1/jobs",
            cookies={"access_token": token},
            json={"job_type": "ALERT_PDF_EXPORT", "payload": {}},
        )
        assert res_403.status_code == 403
        body_403 = res_403.json()
        assert "detail" in body_403
        assert "correlation_id" in body_403
        assert "trace_id" in body_403


# ── LOW-2: Unused aiohttp Import Removed from routers/auth.py ────────────────
def test_low2_routers_auth_has_no_unused_aiohttp_import():
    """routers/auth.py must not import unused aiohttp client library."""
    tree = ast.parse((ROOT / "routers" / "auth.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "aiohttp" not in imported


# ── Section 4 Hardening: Health Telemetry, Report ETag/304 & Prometheus SLO ──
@pytest.mark.asyncio
async def test_section4_health_system_reports_load_shedding_and_cell_id():
    """GET /api/v1/health/system must expose deployment_cell_id, deployment_region, and load_shedding telemetry."""
    token = _make_auth_token(role="ADMIN")
    transport = httpx.ASGITransport(app=app)
    with patch("services.auth._verify_token_version", AsyncMock(return_value=None)), \
         patch("routers.health.ping_postgres_pool_repo", AsyncMock(return_value={"latency_ms": 1.2, "pool_size": 15, "free_connections": 14})):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/v1/health/system", headers={"Authorization": f"Bearer {token}"})
            assert res.status_code == 200
            data = res.json()
            assert "deployment_cell_id" in data
            assert "deployment_region" in data
            assert "load_shedding" in data
            assert "in_flight_requests" in data["load_shedding"]
            assert "max_concurrency" in data["load_shedding"]


@pytest.mark.asyncio
async def test_section4_compliance_reports_support_etag_304_with_no_store():
    """GET /api/v1/reports/sar-summary must return strong ETag, honor If-None-Match -> 304, and keep no-store."""
    token = _make_auth_token(role="MLRO")
    transport = httpx.ASGITransport(app=app)
    fake_stats = {"total_drafts": 7, "approved_drafts": 3, "submitted_drafts": 2, "rejected_drafts": 1}

    with patch("services.auth._verify_token_version", AsyncMock(return_value=None)), \
         patch("routers.compliance_reporting.fetch_sar_summary_repo", AsyncMock(return_value=fake_stats)), \
         patch("routers.compliance_reporting._cached_report", AsyncMock(return_value={
             "tenant_id": "00000000-0000-0000-0000-000000000001",
             "total_sar_drafts": 7,
             "approved_sar_drafts": 3,
             "submitted_sar_drafts": 2,
             "rejected_sar_drafts": 1,
         })):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r1 = await ac.get("/api/v1/reports/sar-summary", headers={"Authorization": f"Bearer {token}"})
            assert r1.status_code == 200
            etag = r1.headers.get("ETag")
            assert etag and etag.startswith('"')
            assert "no-store" in r1.headers.get("Cache-Control", "")
            assert r1.headers.get("CDN-Cache-Control") == "no-store"

            r2 = await ac.get(
                "/api/v1/reports/sar-summary",
                headers={"Authorization": f"Bearer {token}", "If-None-Match": etag},
            )
            assert r2.status_code == 304
            assert r2.headers.get("ETag") == etag
            assert "no-store" in r2.headers.get("Cache-Control", "")
            assert r2.headers.get("CDN-Cache-Control") == "no-store"


def test_section4_prometheus_slo_rules_manifest_valid():
    """deployments/monitoring/prometheus-slo-rules.yaml must define burn-rate, latency, circuit-breaker, and lag alerts."""
    rules_path = ROOT / "deployments" / "monitoring" / "prometheus-slo-rules.yaml"
    doc = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    assert doc["kind"] == "PrometheusRule"
    alert_names = {
        rule["alert"]
        for grp in doc["spec"]["groups"]
        for rule in grp["rules"]
    }
    assert {
        "AMLHighErrorBurnRateFast",
        "AMLScoreLatencyP99Breach",
        "AMLCircuitBreakerOpen",
        "AMLAdaptiveLoadSheddingActive",
        "AMLReadReplicaLagHigh",
        "AMLOutboxBacklogGrowing",
    }.issubset(alert_names)
