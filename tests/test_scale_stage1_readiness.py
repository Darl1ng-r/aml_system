"""
Scale Pillar — Stage 1 Readiness Verification Suite (1,000 -> 10,000 Concurrent Users)
====================================================================================
Verifies all 5 Stage 1 Foundations & Statelessness requirements and all closed gaps:
  1. 100% Stateless App Tier:
     - SigV4 pre-signed S3 PUT/GET URLs (bounded TTL 60..900s, SSE-KMS/AES256, tenant isolation)
     - Fail-closed guard forbidding LocalEvidenceBackend in hardened prod/staging
     - Direct pre-sign HTTP endpoints on Case Evidence Locker
     - Fail-closed OIDC PKCE state (503 instead of single-pod memory fallback in hardened mode)
     - Fail-closed RateLimiter + physically isolated Cache Redis (allkeys-lfu) vs State Redis (noeviction)
  2. Connection Pooling:
     - HA PgBouncer (replicas>=2, POOL_MODE=transaction, MAX_PREPARED_STATEMENTS=0, preStop sleep 8, grace 35s)
     - Bounded asyncpg pool min/max + acquire timeout + command_timeout
  3. Bounded Timeouts & Event-Loop Hygiene:
     - RequestTimeoutMiddleware (504), bounded compute executors (ml/crypto/analytics)
  4. Kubernetes ConfigMap & Default-Deny NetworkPolicy Wiring:
     - REDIS_CACHE_HOST / REDIS_CACHE_PORT in aml-config.yaml
     - allow-apps-to-redis-cache ingress + app/worker egress rules in network-policies.yaml
  5. Decoupled Probes, Graceful Shutdown & PDBs:
     - Immediate /health/ready -> 503 {"status": "draining"} while /health/live stays 200 {"status": "alive"}
     - FastAPI preStop sleep 8, terminationGracePeriodSeconds 35, dynamic PDB minAvailable: "50%"
"""

from __future__ import annotations

import ast
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import yaml

from config import settings
from main import app
from routers.health import (
    is_server_draining,
    mark_server_draining,
    reset_server_draining,
)
from services.auth import create_access_token
from services.evidence_storage import (
    PRESIGN_MAX_EXPIRY_SECONDS,
    PRESIGN_MIN_EXPIRY_SECONDS,
    LocalEvidenceBackend,
    S3EvidenceBackend,
    get_evidence_storage_backend,
)
from services.sso import (
    SSOStateStoreUnavailableError,
    _local_sso_states,
    consume_sso_state,
    store_sso_state,
)

TENANT_A = "00000000-0000-0000-0000-000000000001"
TENANT_B = "00000000-0000-0000-0000-000000000002"


def _auth_headers(role: str = "MLRO", tenant_id: str = TENANT_A) -> dict[str, str]:
    token = create_access_token(
        {
            "sub": str(uuid.uuid4()),
            "username": f"stage1_{role.lower()}",
            "role": role,
            "tenant_id": tenant_id,
            "token_version": 1,
        }
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-CSRF-Protection": "1",
    }


def _load_yaml_docs(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        return [doc for doc in yaml.safe_load_all(fh) if doc]


# ── 1A. Pre-Signed S3 URLs & Stateless Evidence Storage Guard ────────────────


def test_stage1_s3_presigned_put_and_get_sigv4_structure_and_clamping():
    """S3EvidenceBackend mints valid SigV4 query-string PUT/GET URLs with clamped TTL, SSE, and tenant boundaries."""
    backend = S3EvidenceBackend(
        bucket="aml-compliance-evidence-prod",
        region="us-east-1",
        endpoint="",
        access_key="AKIAEXAMPLESTAGE1",
        secret_key="SecretKeyExampleForSigV4UnitTestingOnly123456",
        kms_key_id="arn:aws:kms:us-east-1:111122223333:key/abcd-1234",
        worm_enabled=True,
    )

    # Expiry clamping lower bound (10 -> 60)
    put_min = backend.generate_presigned_put_url(
        TENANT_A,
        "ev123_bank_statement.pdf",
        "application/pdf",
        expires_in=10,
    )
    assert put_min["method"] == "PUT"
    assert put_min["expires_in"] == PRESIGN_MIN_EXPIRY_SECONDS
    assert put_min["storage_key"] == f"s3://aml-compliance-evidence-prod/evidence/{TENANT_A}/ev123_bank_statement.pdf"
    assert put_min["required_headers"]["content-type"] == "application/pdf"
    assert put_min["required_headers"]["x-amz-server-side-encryption"] == "aws:kms"
    assert put_min["required_headers"]["x-amz-server-side-encryption-aws-kms-key-id"] == (
        "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
    )

    parsed_put = urlparse(put_min["url"])
    assert parsed_put.scheme == "https"
    assert parsed_put.netloc == "aml-compliance-evidence-prod.s3.us-east-1.amazonaws.com"
    assert parsed_put.path == f"/evidence/{TENANT_A}/ev123_bank_statement.pdf"
    qs = parse_qs(parsed_put.query)
    assert qs["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
    assert qs["X-Amz-Expires"] == [str(PRESIGN_MIN_EXPIRY_SECONDS)]
    assert "content-type" in qs["X-Amz-SignedHeaders"][0]
    assert "x-amz-server-side-encryption" in qs["X-Amz-SignedHeaders"][0]
    assert len(qs["X-Amz-Signature"][0]) == 64

    # Expiry clamping upper bound (9999 -> 900) + custom HTTPS MinIO/GCS endpoint + download disposition
    minio_backend = S3EvidenceBackend(
        bucket="aml-evidence",
        region="eu-west-1",
        endpoint="https://minio.internal.bank.example:9000",
        access_key="MINIOACCESS",
        secret_key="MINIOSECRETKEY0123456789",
        kms_key_id="",
    )
    get_max = minio_backend.generate_presigned_get_url(
        TENANT_A,
        f"s3://aml-evidence/evidence/{TENANT_A}/ev123_wire.pdf",
        expires_in=9999,
        download_filename="wire_receipt.pdf",
    )
    assert get_max["method"] == "GET"
    assert get_max["expires_in"] == PRESIGN_MAX_EXPIRY_SECONDS
    parsed_get = urlparse(get_max["url"])
    assert parsed_get.netloc == "minio.internal.bank.example:9000"
    assert parsed_get.path == f"/aml-evidence/evidence/{TENANT_A}/ev123_wire.pdf"
    get_qs = parse_qs(parsed_get.query)
    assert get_qs["X-Amz-Expires"] == [str(PRESIGN_MAX_EXPIRY_SECONDS)]
    assert get_qs["response-content-disposition"] == ['attachment; filename="wire_receipt.pdf"']
    assert len(get_qs["X-Amz-Signature"][0]) == 64

    # Strict cross-tenant, cross-bucket, and path-traversal rejection
    with pytest.raises(ValueError, match="tenant namespace"):
        minio_backend.generate_presigned_get_url(
            TENANT_A,
            f"s3://aml-evidence/evidence/{TENANT_B}/stolen.pdf",
        )
    with pytest.raises(ValueError, match="different bucket"):
        minio_backend.generate_presigned_get_url(
            TENANT_A,
            f"s3://other-bucket/evidence/{TENANT_A}/file.pdf",
        )
    with pytest.raises(ValueError, match="Invalid object_key"):
        minio_backend.generate_presigned_put_url(TENANT_A, "../escape.pdf", "application/pdf")


def test_stage1_evidence_storage_fails_closed_on_local_disk_in_hardened_prod(monkeypatch):
    """Hardened environments MUST fail closed instead of falling back to pod-local disk storage."""
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "evidence_storage_backend", "local")
    monkeypatch.setattr(settings, "evidence_s3_bucket", "")

    with pytest.raises(RuntimeError, match="Local pod filesystem evidence storage is forbidden"):
        get_evidence_storage_backend()

    # Even if mode is 's3', missing bucket must still fail closed in hardened prod
    monkeypatch.setattr(settings, "evidence_storage_backend", "s3")
    monkeypatch.setattr(settings, "evidence_s3_bucket", "")
    with pytest.raises(RuntimeError, match="Local pod filesystem evidence storage is forbidden"):
        get_evidence_storage_backend()

    # Properly configured S3 returns S3EvidenceBackend
    monkeypatch.setattr(settings, "evidence_s3_bucket", "aml-compliance-evidence-prod")
    monkeypatch.setattr(settings, "evidence_s3_endpoint", "")
    backend = get_evidence_storage_backend()
    assert isinstance(backend, S3EvidenceBackend)


@pytest.mark.asyncio
async def test_stage1_presign_upload_and_download_http_endpoints(monkeypatch):
    """HTTP pre-sign endpoints mint direct-to-S3 URLs, enforce validation, and reject non-S3 cleanly."""
    case_id = str(uuid.uuid4())
    evidence_id = str(uuid.uuid4())
    s3_backend = S3EvidenceBackend(
        bucket="aml-prod-evidence",
        region="us-east-1",
        endpoint="",
        access_key="AKIAUNITTEST",
        secret_key="SecretKeyForUnitTestOnly987654321",
        kms_key_id="",
    )

    transport = httpx.ASGITransport(app=app)
    with patch("routers.evidence.verify_case_exists_for_evidence_repo", AsyncMock(return_value=uuid.UUID(case_id))), \
         patch("services.evidence_storage.get_evidence_storage_backend", return_value=s3_backend), \
         patch("services.evidence_storage.S3EvidenceBackend", return_value=s3_backend), \
         patch(
             "routers.evidence.fetch_case_evidence_for_download_repo",
             AsyncMock(
                 return_value={
                     "storage_key": f"s3://aml-prod-evidence/evidence/{TENANT_A}/{evidence_id}_sar_support.pdf",
                     "filename": "sar_support.pdf",
                     "content_type": "application/pdf",
                     "sha256_digest": "a" * 64,
                     "storage_backend": "s3",
                 }
             ),
         ), \
         patch("services.auth._verify_token_version", AsyncMock(return_value=None)):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            # 1. Valid pre-signed PUT upload URL
            resp_put = await ac.post(
                f"/api/v1/cases/{case_id}/evidence/presign-upload",
                headers=_auth_headers("MLRO"),
                json={
                    "filename": "wire_proof.pdf",
                    "content_type": "application/pdf",
                    "file_size": 1024 * 512,
                    "expires_in": 180,
                },
            )
            assert resp_put.status_code == 200, resp_put.text
            body = resp_put.json()
            assert body["method"] == "PUT"
            assert body["expires_in"] == 180
            assert "X-Amz-Signature=" in body["upload_url"]
            assert body["required_headers"]["content-type"] == "application/pdf"
            assert body["required_headers"]["x-amz-server-side-encryption"] == "AES256"

            # 2. Reject active/forbidden HTML extension
            resp_bad_ext = await ac.post(
                f"/api/v1/cases/{case_id}/evidence/presign-upload",
                headers=_auth_headers("MLRO"),
                json={
                    "filename": "exploit.html",
                    "content_type": "text/plain",
                    "file_size": 512,
                },
            )
            assert resp_bad_ext.status_code == 400

            # 3. Valid pre-signed GET download URL
            resp_get = await ac.get(
                f"/api/v1/cases/{case_id}/evidence/{evidence_id}/presign-download?expires_in=120",
                headers=_auth_headers("AUDITOR"),
            )
            assert resp_get.status_code == 200, resp_get.text
            dl_body = resp_get.json()
            assert dl_body["method"] == "GET"
            assert dl_body["expires_in"] == 120
            assert dl_body["sha256_digest"] == "a" * 64
            assert "X-Amz-Signature=" in dl_body["download_url"]

    # 4. Local backend mode returns explicit 501 Not Implemented on presign-upload
    local_backend = LocalEvidenceBackend("/tmp/aml_stage1_presign_test")
    with patch("routers.evidence.verify_case_exists_for_evidence_repo", AsyncMock(return_value=uuid.UUID(case_id))), \
         patch("services.evidence_storage.get_evidence_storage_backend", return_value=local_backend), \
         patch("services.auth._verify_token_version", AsyncMock(return_value=None)):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            resp_local = await ac.post(
                f"/api/v1/cases/{case_id}/evidence/presign-upload",
                headers=_auth_headers("MLRO"),
                json={
                    "filename": "report.pdf",
                    "content_type": "application/pdf",
                    "file_size": 1024,
                },
            )
            assert resp_local.status_code == 501


# ── 1B. Fail-Closed OIDC PKCE State & Rate Limiter in Hardened Prod ──────────


@pytest.mark.asyncio
async def test_stage1_sso_state_fails_closed_in_hardened_mode_when_redis_down(monkeypatch):
    """Hardened mode NEVER falls back to single-pod _local_sso_states when State Redis is unreachable."""
    monkeypatch.setattr(settings, "environment", "production")
    state_token = f"stage1_state_{uuid.uuid4().hex}"
    _local_sso_states.pop(state_token, None)

    # Write fails closed when Redis returns None or raises ConnectionError
    with patch("services.sso.get_async_redis_client", AsyncMock(side_effect=ConnectionError("redis down"))):
        with pytest.raises(SSOStateStoreUnavailableError):
            await store_sso_state(state_token, {"provider_id": "p1", "tenant_id": TENANT_A})
        assert state_token not in _local_sso_states

    # Even if an entry existed in local memory, hardened consume_sso_state MUST NOT return it
    _local_sso_states[state_token] = (9e18, {"provider_id": "p1", "tenant_id": TENANT_A})
    try:
        with patch("services.sso.get_async_redis_client", AsyncMock(return_value=None)):
            with pytest.raises(SSOStateStoreUnavailableError):
                await consume_sso_state(state_token)
    finally:
        _local_sso_states.pop(state_token, None)

    # HTTP callback maps SSOStateStoreUnavailableError cleanly to 503 Service Unavailable
    provider_id = str(uuid.uuid4())
    transport = httpx.ASGITransport(app=app)
    with patch("services.sso.get_async_redis_client", AsyncMock(side_effect=ConnectionError("redis down"))), \
         patch("services.rate_limiter.get_async_redis_client", AsyncMock(return_value=MagicMock(eval=AsyncMock(return_value=1)))):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get(f"/api/v1/auth/sso/{provider_id}/callback?code=abc&state={state_token}")
            assert resp.status_code == 503


@pytest.mark.asyncio
async def test_stage1_rate_limiter_fails_closed_in_hardened_mode(monkeypatch):
    """RateLimiter fails closed (503) in hardened prod when State Redis is unavailable."""
    from fastapi import HTTPException
    from services.rate_limiter import RateLimiter

    monkeypatch.setattr(settings, "environment", "production")
    limiter = RateLimiter(limit=10, window=60, fail_closed=True, ip_only=True)
    fake_req = MagicMock()
    fake_req.client = MagicMock(host="198.51.100.42")
    fake_req.state = MagicMock(client_ip="198.51.100.42")
    fake_req.headers = {}
    fake_req.url = MagicMock(path="/api/v1/transactions")

    with patch("services.rate_limiter.get_async_redis_client", AsyncMock(side_effect=ConnectionError("redis down"))):
        with pytest.raises(HTTPException) as exc_info:
            await limiter(fake_req)
        assert exc_info.value.status_code == 503


# ── 1C, 2A, 5A. Kubernetes Manifests: Cache Redis, PgBouncer, Probes & PDBs ──


def test_stage1_k8s_configmap_redis_split_and_network_policies():
    """Verifies K8s ConfigMap, Redis physical isolation, and default-deny NetworkPolicies for Cache Redis."""
    cfg = _load_yaml_docs("deployments/kubernetes/aml-config.yaml")[0]
    data = cfg["data"]
    assert data["EVIDENCE_STORAGE_BACKEND"] == "s3"
    assert data["EVIDENCE_S3_BUCKET"]
    assert data["PGBOUNCER_ENABLED"] == "true"
    assert data["POSTGRES_HOST"] == "aml-pgbouncer-service"
    assert data["POSTGRES_PORT"] == "6432"
    assert data["REDIS_HOST"] == "aml-redis-service"
    assert data["REDIS_PORT"] == "6379"
    assert data["REDIS_CACHE_HOST"] == "aml-redis-cache-service"
    assert data["REDIS_CACHE_PORT"] == "6379"

    # Physical State Redis (noeviction) vs Cache Redis (allkeys-lfu)
    redis_docs = _load_yaml_docs("deployments/kubernetes/redis.yaml")
    state_redis = next(d for d in redis_docs if d["kind"] == "StatefulSet" and d["metadata"]["name"] == "aml-redis")
    cache_redis = next(d for d in redis_docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "aml-redis-cache")
    state_cmd = " ".join(state_redis["spec"]["template"]["spec"]["containers"][0]["command"])
    cache_cmd = " ".join(cache_redis["spec"]["template"]["spec"]["containers"][0]["command"])
    assert "--maxmemory-policy noeviction" in state_cmd
    assert "--maxmemory-policy allkeys-lfu" in cache_cmd
    assert "--appendonly no" in cache_cmd

    # NetworkPolicies allow app & workers -> aml-redis-cache:6379
    netpols = {d["metadata"]["name"]: d for d in _load_yaml_docs("deployments/kubernetes/network-policies.yaml")}
    assert "allow-apps-to-redis-cache" in netpols
    cache_in = netpols["allow-apps-to-redis-cache"]["spec"]
    assert cache_in["podSelector"]["matchLabels"]["app"] == "aml-redis-cache"
    allowed_sources = {
        src["podSelector"]["matchLabels"]["app"]
        for src in cache_in["ingress"][0]["from"]
    }
    assert {"aml-fastapi-app", "aml-scoring-worker", "aml-outbox-relay", "aml-sync-worker"} <= allowed_sources
    assert cache_in["ingress"][0]["ports"][0]["port"] == 6379

    for pol_name in (
        "allow-fastapi-egress",
        "allow-scoring-worker-egress",
        "allow-sync-worker-egress",
        "allow-outbox-relay-egress",
    ):
        egress_rules = netpols[pol_name]["spec"]["egress"]
        has_cache_egress = any(
            any(
                t.get("podSelector", {}).get("matchLabels", {}).get("app") == "aml-redis-cache"
                for t in rule.get("to", [])
            )
            and any(p.get("port") == 6379 for p in rule.get("ports", []))
            for rule in egress_rules
        )
        assert has_cache_egress, f"{pol_name} missing TCP 6379 egress rule to aml-redis-cache"


def test_stage1_k8s_pgbouncer_transaction_pooling_and_graceful_drain():
    """HA PgBouncer uses transaction pooling, disables prepared statements, and drains gracefully."""
    docs = _load_yaml_docs("deployments/kubernetes/pgbouncer.yaml")
    dep = next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "aml-pgbouncer")
    assert dep["spec"]["replicas"] >= 2
    pod_spec = dep["spec"]["template"]["spec"]
    assert pod_spec["terminationGracePeriodSeconds"] == 35

    container = pod_spec["containers"][0]
    env_map = {e["name"]: e.get("value") for e in container["env"]}
    assert env_map["POOL_MODE"] == "transaction"
    assert env_map["MAX_PREPARED_STATEMENTS"] == "0"
    prestop_cmd = " ".join(container["lifecycle"]["preStop"]["exec"]["command"])
    assert "sleep 8" in prestop_cmd


def test_stage1_k8s_fastapi_probes_prestop_and_pdbs():
    """FastAPI Deployment decouples /health/live & /health/ready, drains with preStop sleep 8, and enforces PDBs."""
    docs = _load_yaml_docs("deployments/kubernetes/fastapi-app.yaml")
    dep = next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "aml-fastapi-app")
    hpa = next(d for d in docs if d["kind"] == "HorizontalPodAutoscaler")

    assert dep["spec"]["replicas"] >= 2
    assert hpa["spec"]["minReplicas"] >= 2
    pod_spec = dep["spec"]["template"]["spec"]
    assert pod_spec["terminationGracePeriodSeconds"] == 35

    container = pod_spec["containers"][0]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["startupProbe"]["httpGet"]["path"] == "/health/live"
    assert container["livenessProbe"]["httpGet"]["path"] == "/health/live"
    assert container["readinessProbe"]["httpGet"]["path"] == "/health/ready"
    prestop_cmd = " ".join(container["lifecycle"]["preStop"]["exec"]["command"])
    assert "sleep 8" in prestop_cmd

    # Dynamic percentage PDB for FastAPI + minAvailable >= 1 PDBs for PgBouncer & workers
    fastapi_pdb = _load_yaml_docs("deployments/kubernetes/fastapi-pdb.yaml")[0]
    assert fastapi_pdb["spec"]["minAvailable"] == "50%"

    worker_pdbs = {d["metadata"]["name"]: d for d in _load_yaml_docs("deployments/kubernetes/workers-pdb.yaml")}
    for name in ("aml-outbox-relay-pdb", "aml-scoring-worker-pdb", "aml-pgbouncer-pdb", "aml-redpanda-pdb"):
        assert name in worker_pdbs
        assert worker_pdbs[name]["spec"]["minAvailable"] >= 1


# ── 5B. Immediate Graceful-Drain /health/ready Flip ──────────────────────────


@pytest.mark.asyncio
async def test_stage1_graceful_drain_flips_readiness_503_while_liveness_stays_200():
    """During SIGTERM drain, /health/ready returns 503 draining immediately while /health/live stays 200 alive."""
    transport = httpx.ASGITransport(app=app)
    reset_server_draining()
    assert is_server_draining() is False

    try:
        mark_server_draining()
        assert is_server_draining() is True

        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            live_resp = await ac.get("/health/live")
            assert live_resp.status_code == 200
            assert live_resp.json() == {"status": "alive"}

            ready_resp = await ac.get("/health/ready")
            assert ready_resp.status_code == 503
            assert ready_resp.json() == {"status": "draining"}
    finally:
        reset_server_draining()
        assert is_server_draining() is False


def test_stage1_lifespan_wires_reset_and_mark_server_draining():
    """Verifies main.py lifespan resets draining on startup and marks draining immediately on shutdown."""
    with open("main.py", "r", encoding="utf-8") as fh:
        source = fh.read()
    tree = ast.parse(source)
    lifespan_fn = next(
        node for node in ast.walk(tree) if isinstance(node, ast.AsyncFunctionDef) and node.name == "lifespan"
    )
    fn_src = ast.get_source_segment(source, lifespan_fn) or ""
    assert "reset_server_draining()" in fn_src
    assert "mark_server_draining()" in fn_src
    assert fn_src.index("reset_server_draining()") < fn_src.index("yield") < fn_src.index("mark_server_draining()")


# ── 3. Bounded Timeouts & Event-Loop Offload Hygiene ─────────────────────────


def test_stage1_bounded_timeouts_and_compute_executors_configured():
    """Verifies RequestTimeoutMiddleware, bounded DB timeouts, and bounded CPU compute executors are wired."""
    middleware_classes = {m.cls.__name__ for m in app.user_middleware}
    assert "RequestTimeoutMiddleware" in middleware_classes

    from services.compute_executor import get_executor_status

    acq_timeout = float(getattr(settings, "postgres_acquire_timeout_seconds", 5.0))
    assert 1.0 <= acq_timeout <= 10.0
    assert 1 <= int(getattr(settings, "postgres_pool_min_size", 2)) <= int(getattr(settings, "postgres_pool_max_size", 15))

    with open("database/postgres.py", "r", encoding="utf-8") as fh:
        pg_src = fh.read()
    assert "command_timeout=15.0" in pg_src
    assert 'statement_cache_size' in pg_src

    stats = get_executor_status()
    assert set(stats.keys()) >= {"ml", "crypto", "analytics"}
    for pool_name, info in stats.items():
        assert info["max_workers"] >= 1, f"Compute executor {pool_name} has invalid max_workers"
