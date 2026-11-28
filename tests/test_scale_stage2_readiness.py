"""
Scale Pillar — Stage 2 Readiness Verification Suite (10,000 -> 50,000 Concurrent Users)
=====================================================================================
Verifies all 5 Stage 2 Offload, Replicas & Async Buffering capabilities:
  1. Edge / CDN Offload:
     - RFC 9213 CDN-Cache-Control headers across versioned static assets, JWKS, HTML shells, and /api/* PII routes
     - Declarative Cloudflare/CloudFront Edge Policy IaC (cache rules, WAF, Turnstile, edge rate limits) + hardened Ingress
  2. Dedicated Dual-Redis Caching:
     - HA Cache Redis (replicas>=2, allkeys-lfu, zone spread, PDB)
     - Cache-Aside on compliance reporting hot reads (bypassing cleanly under RAW stickiness)
  3. Multi-Replica Streaming Read Replicas + RAW Stickiness:
     - Comma-separated POSTGRES_REPLICA_HOSTS multi-replica DSN parsing, round-robin routing, sibling failover, lag failover
     - K8s Option A topology: Primary + 2+ load-balanced streaming standbys with pg_is_in_recovery() readiness & PDB
  4. Queue-Based Load Leveling:
     - Live PostgreSQL `async_jobs` (Migration 039, FORCE RLS, idempotency dedupe, atomic Transactional Outbox)
     - Idempotent async job worker execution, poison-pill DLQ routing, zero-loss offset commit guard
     - Non-breaking ?async_mode=true (202 Accepted) on heavy PDF & Examiner ZIP endpoints
     - Redpanda 12-partition default + declarative partitioned topics & DLQ bootstrap Job
  5. Horizontal Autoscaling (HPA + KEDA) & >= 3 Availability Zones:
     - FastAPI HPA: CPU 60%, Memory 75%, custom RPS metric, anti-thrashing behavior, minReplicas >= 3
     - KEDA ScaledObjects for scoring-worker, sync-worker, job-worker (Kafka lag) & outbox-relay (Prometheus backlog)
     - Zone topologySpreadConstraints across all workload manifests + prod Kustomization parity
"""

from __future__ import annotations

from collections import namedtuple
import pathlib
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import yaml

from config import settings
from database import postgres as pg_mod
from database.read_after_write import force_primary_read_var
from main import app
from services.async_jobs import (
    JOBS_EXPORTS_DLQ_TOPIC,
    JOBS_EXPORTS_TOPIC,
    JOBS_NOTIFICATIONS_TOPIC,
    execute_async_job,
)
from services.auth import create_access_token
from services.secrets_manager import get_postgres_replica_dsns
from workers.job_worker import process_job_message

ROOT = pathlib.Path(__file__).resolve().parent.parent
TENANT_A = "00000000-0000-0000-0000-000000000001"
TENANT_B = "00000000-0000-0000-0000-000000000002"


def _auth_headers(role: str = "MLRO", tenant_id: str = TENANT_A) -> dict[str, str]:
    token = create_access_token(
        {
            "sub": str(uuid.uuid4()),
            "username": f"stage2_{role.lower()}",
            "role": role,
            "tenant_id": tenant_id,
            "token_version": 1,
        }
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-CSRF-Protection": "1",
    }


def _load_yaml_docs(rel_path: str) -> list[dict]:
    with open(ROOT / rel_path, "r", encoding="utf-8") as fh:
        return [d for d in yaml.safe_load_all(fh) if d]


# ── 1. Edge / CDN Offload ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stage2_cdn_cache_control_headers_across_static_jwks_and_api():
    """Verifies RFC 9213 CDN-Cache-Control offload on static/JWKS and strict no-store on /api/* PII routes."""
    transport = httpx.ASGITransport(app=app)
    with patch("services.auth._verify_token_version", AsyncMock(return_value=None)), \
         patch(
             "routers.compliance_reporting.fetch_sar_summary_repo",
             AsyncMock(
                 return_value={
                     "total_drafts": 4,
                     "approved_drafts": 2,
                     "submitted_drafts": 1,
                     "rejected_drafts": 1,
                 }
             ),
         ):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            # Versioned static asset -> 1-year immutable edge & browser cache
            res_static = await ac.get("/static/style.css?v=stage2cdn")
            assert res_static.status_code == 200
            assert "immutable" in res_static.headers.get("cache-control", "")
            assert res_static.headers.get("cdn-cache-control") == "public, max-age=31536000, immutable"

            # Public JWKS -> 5-minute edge cache with stale-while-revalidate + ETag
            res_jwks = await ac.get("/.well-known/jwks.json")
            assert res_jwks.status_code == 200
            assert res_jwks.headers.get("cache-control") == "public, max-age=300"
            assert "stale-while-revalidate=60" in res_jwks.headers.get("cdn-cache-control", "")
            assert res_jwks.headers.get("etag")

            # Authenticated API endpoint -> strict no-store at BOTH browser and CDN edge
            res_api = await ac.get("/api/v1/reports/sar-summary", headers=_auth_headers("MLRO"))
            assert res_api.status_code == 200
            assert "no-store" in res_api.headers.get("cache-control", "")
            assert res_api.headers.get("cdn-cache-control") == "no-store"
            vary_tokens = {v.strip().lower() for v in res_api.headers.get("vary", "").split(",")}
            assert {"origin", "cookie"} <= vary_tokens


def test_stage2_edge_cdn_waf_policy_and_ingress_manifest():
    """Verifies declarative Cloudflare/CloudFront Edge CDN + WAF + Rate Limit IaC and hardened Ingress."""
    policy = _load_yaml_docs("deployments/edge/cloudflare-edge-policy.yaml")[0]
    assert policy["kind"] == "EdgeCDNPolicy"
    spec = policy["spec"]
    assert spec["transport"]["tls_min_version"] == "1.3"
    assert spec["transport"]["authenticated_origin_pulls_mtls"] is True

    rules = {r["id"]: r for r in spec["cache_rules"]}
    assert rules["immutable-versioned-static-assets"]["action"] == "CACHE"
    assert rules["immutable-versioned-static-assets"]["edge_ttl_seconds"] == 31536000
    assert rules["public-oidc-jwks"]["action"] == "CACHE"
    assert rules["bypass-all-api-pii-endpoints"]["action"] == "BYPASS_CACHE"
    assert rules["bypass-all-api-pii-endpoints"]["enforce_response_headers"]["CDN-Cache-Control"] == "no-store"
    assert rules["bypass-authenticated-sessions-and-rfi"]["action"] == "BYPASS_CACHE"

    waf_names = {r["name"] for r in spec["waf"]["managed_rulesets"] if r["enabled"]}
    assert {"cloudflare-managed-ruleset", "owasp-core-ruleset"} <= waf_names
    rl_ids = {r["id"] for r in spec["edge_rate_limiting"]}
    assert {"auth-bruteforce-edge-shield", "transaction-ingest-burst-shield", "global-ip-ddos-ceiling"} <= rl_ids

    ingress_docs = _load_yaml_docs("deployments/kubernetes/ingress-tls.yaml")
    ing = next(d for d in ingress_docs if d["kind"] == "Ingress")
    ann = ing["metadata"]["annotations"]
    assert "nginx.ingress.kubernetes.io/limit-rps" in ann
    assert "nginx.ingress.kubernetes.io/limit-burst-multiplier" in ann
    assert "nginx.ingress.kubernetes.io/limit-connections" in ann
    assert "nginx.ingress.kubernetes.io/upstream-keepalive-connections" in ann
    assert "nginx.ingress.kubernetes.io/configuration-snippet" not in ann


# ── 2. Dedicated Dual-Redis Caching ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_stage2_ha_cache_redis_and_compliance_reporting_cache_aside():
    """Verifies HA Cache Redis K8s config (replicas>=2, PDB) and Cache-Aside + RAW bypass on reports."""
    redis_docs = _load_yaml_docs("deployments/kubernetes/redis.yaml")
    cache_dep = next(d for d in redis_docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "aml-redis-cache")
    assert cache_dep["spec"]["replicas"] >= 2
    cache_spec = cache_dep["spec"]["template"]["spec"]
    assert any(
        c["topologyKey"] == "topology.kubernetes.io/zone" for c in cache_spec.get("topologySpreadConstraints", [])
    )

    worker_pdbs = {d["metadata"]["name"]: d for d in _load_yaml_docs("deployments/kubernetes/workers-pdb.yaml")}
    assert worker_pdbs["aml-redis-cache-pdb"]["spec"]["minAvailable"] >= 1

    # Verify Cache-Aside deduplicates repeated report queries and bypasses cleanly under RAW stickiness
    mock_fetch = AsyncMock(
        return_value={"total_drafts": 7, "approved_drafts": 3, "submitted_drafts": 2, "rejected_drafts": 2}
    )
    fake_store: dict[str, str] = {}

    class _FakeCacheRedis:
        async def get(self, key):
            return fake_store.get(key)

        async def set(self, key, val, ex=None, nx=False):
            if nx and key in fake_store:
                return False
            fake_store[key] = val
            return True

        async def eval(self, script, numkeys, *args):
            if args:
                fake_store.pop(args[0], None)
            return 1

    fake_redis = _FakeCacheRedis()
    transport = httpx.ASGITransport(app=app)
    with patch("services.auth._verify_token_version", AsyncMock(return_value=None)), \
         patch("routers.compliance_reporting.fetch_sar_summary_repo", mock_fetch), \
         patch("services.cache_aside.get_async_cache_redis_client", AsyncMock(return_value=fake_redis)):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r1 = await ac.get("/api/v1/reports/sar-summary", headers=_auth_headers("MLRO", TENANT_B))
            r2 = await ac.get("/api/v1/reports/sar-summary", headers=_auth_headers("MLRO", TENANT_B))
            assert r1.status_code == 200 and r2.status_code == 200
            assert r1.json()["total_sar_drafts"] == 7
            assert mock_fetch.await_count == 1  # 2nd request served from Cache Redis

            # Strong consistency header triggers RAW stickiness -> bypasses cache directly to Primary
            r3 = await ac.get(
                "/api/v1/reports/sar-summary",
                headers={**_auth_headers("MLRO", TENANT_B), "X-Read-Consistency": "strong"},
            )
            assert r3.status_code == 200
            assert mock_fetch.await_count == 2


# ── 3. Multi-Replica Streaming Read Replicas + RAW Stickiness ────────────────


def _make_fake_pool(label: str, *, fail_acquire: bool = False):
    pool = MagicMock()
    pool._loop = SimpleNamespace(is_closed=lambda: False)
    pool.label = label
    pool.acquire_count = 0

    class _Tx:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    conn = MagicMock()
    conn.pool_label = label
    conn.execute = AsyncMock()
    conn.transaction = MagicMock(return_value=_Tx())

    async def _acquire(timeout=5.0):
        pool.acquire_count += 1
        if fail_acquire:
            raise ConnectionError(f"{label} down")
        return conn

    pool.acquire = AsyncMock(side_effect=_acquire)
    pool.release = AsyncMock()
    pool.get_size = MagicMock(return_value=2)
    pool.get_idle_size = MagicMock(return_value=1)
    pool.get_max_size = MagicMock(return_value=4)
    return pool


@pytest.mark.asyncio
async def test_stage2_multi_replica_dsn_parsing_round_robin_and_failover(monkeypatch):
    """Verifies comma-separated multi-replica DSNs, round-robin reads, sibling failover, and lag failover."""
    monkeypatch.setattr(settings, "postgres_replica_hosts", "pg-rep-1.internal:5432, pg-rep-2.internal:5433")
    dsns = get_postgres_replica_dsns()
    assert len(dsns) == 2
    assert "pg-rep-1.internal:5432" in dsns[0]
    assert "pg-rep-2.internal:5433" in dsns[1]

    primary = _make_fake_pool("primary")
    rep1 = _make_fake_pool("rep1")
    rep2 = _make_fake_pool("rep2")

    orig_pool = pg_mod.db_pool
    orig_rep = pg_mod.db_replica_pool
    orig_reps = list(pg_mod.db_replica_pools)
    orig_rr = pg_mod._replica_rr_index

    try:
        pg_mod.db_pool = primary
        pg_mod.db_replica_pools = [rep1, rep2]
        pg_mod.db_replica_pool = rep1
        pg_mod._replica_rr_index = 0

        with patch("observability.storage_monitor.get_observed_replica_lag_seconds", return_value=0.1):
            seen = []
            for _ in range(4):
                async with pg_mod.get_async_db_read_conn(tenant_id=TENANT_A) as conn:
                    seen.append(conn.pool_label)
            assert seen == ["rep1", "rep2", "rep1", "rep2"]
            assert primary.acquire_count == 0

            # Sibling failover: rep1 fails -> transparently routes to rep2 without touching Primary
            rep1_bad = _make_fake_pool("rep1", fail_acquire=True)
            pg_mod.db_replica_pools = [rep1_bad, rep2]
            pg_mod.db_replica_pool = rep1_bad
            pg_mod._replica_rr_index = 0
            async with pg_mod.get_async_db_read_conn(tenant_id=TENANT_A) as conn:
                assert conn.pool_label == "rep2"
            assert primary.acquire_count == 0

            # Both replicas fail -> falls back to Primary
            rep2_bad = _make_fake_pool("rep2", fail_acquire=True)
            pg_mod.db_replica_pools = [rep1_bad, rep2_bad]
            pg_mod.db_replica_pool = rep1_bad
            async with pg_mod.get_async_db_read_conn(tenant_id=TENANT_A) as conn:
                assert conn.pool_label == "primary"
            assert primary.acquire_count == 1

        # Replication lag > 2.0s -> automatic Primary failover
        pg_mod.db_replica_pools = [rep1, rep2]
        pg_mod.db_replica_pool = rep1
        with patch("observability.storage_monitor.get_observed_replica_lag_seconds", return_value=3.2):
            async with pg_mod.get_async_db_read_conn(tenant_id=TENANT_A) as conn:
                assert conn.pool_label == "primary"
        assert primary.acquire_count == 2
    finally:
        pg_mod.db_pool = orig_pool
        pg_mod.db_replica_pool = orig_rep
        pg_mod.db_replica_pools = orig_reps
        pg_mod._replica_rr_index = orig_rr


def test_stage2_k8s_postgres_multi_replica_option_a_topology():
    """Verifies K8s Option A: Primary + dedicated 2+ streaming Read Replica StatefulSet load-balanced across AZs."""
    docs = _load_yaml_docs("deployments/kubernetes/postgres.yaml")
    cm = next(d for d in docs if d["kind"] == "ConfigMap")
    assert "max_wal_senders = 10" in cm["data"]["postgresql.conf"]

    sts_by_name = {d["metadata"]["name"]: d for d in docs if d["kind"] == "StatefulSet"}
    assert sts_by_name["aml-postgres"]["spec"]["replicas"] == 1
    rep_sts = sts_by_name["aml-postgres-replica"]
    assert rep_sts["spec"]["replicas"] >= 2
    rep_pod_spec = rep_sts["spec"]["template"]["spec"]
    assert any(
        c["topologyKey"] == "topology.kubernetes.io/zone" for c in rep_pod_spec.get("topologySpreadConstraints", [])
    )
    rep_container = rep_pod_spec["containers"][0]
    readiness_cmd = " ".join(rep_container["readinessProbe"]["exec"]["command"])
    assert "pg_is_in_recovery()" in readiness_cmd
    prestop_cmd = " ".join(rep_container["lifecycle"]["preStop"]["exec"]["command"])
    assert "sleep 8" in prestop_cmd

    svc_by_name = {d["metadata"]["name"]: d for d in docs if d["kind"] == "Service"}
    assert svc_by_name["aml-postgres-replica"]["spec"]["selector"] == {"app": "aml-postgres-replica"}

    worker_pdbs = {d["metadata"]["name"]: d for d in _load_yaml_docs("deployments/kubernetes/workers-pdb.yaml")}
    assert worker_pdbs["aml-postgres-replica-pdb"]["spec"]["minAvailable"] >= 1

    netpols = {d["metadata"]["name"]: d for d in _load_yaml_docs("deployments/kubernetes/network-policies.yaml")}
    assert "allow-apps-to-postgres-replica" in netpols


# ── 4. Queue-Based Load Leveling (Live PG + Outbox + Worker + DLQ + Topics) ──


@pytest.mark.asyncio
async def test_stage2_async_jobs_live_pg_outbox_idempotency_rls_and_worker_execution():
    """End-to-end live PostgreSQL test for async_jobs FORCE RLS, atomic Outbox, idempotency, worker & DLQ."""
    await pg_mod.init_db_pool()
    created_job_id = None
    idem_key = f"stage2-idem-{uuid.uuid4().hex}"

    try:
        # 1. Verify Migration 039 enforced FORCE ROW LEVEL SECURITY on async_jobs
        pool = await pg_mod.get_db_pool()
        async with pool.acquire(timeout=5.0) as conn:
            rls_row = await conn.fetchrow(
                """
                SELECT relrowsecurity, relforcerowsecurity
                FROM pg_class
                WHERE relname = 'async_jobs';
                """
            )
            assert rls_row is not None
            assert rls_row["relrowsecurity"] is True
            assert rls_row["relforcerowsecurity"] is True

        transport = httpx.ASGITransport(app=app)
        with patch("services.auth._verify_token_version", AsyncMock(return_value=None)):
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                # 2. Enqueue async EMAIL_NOTIFICATION job via HTTP POST /api/v1/jobs (202 Accepted)
                resp1 = await ac.post(
                    "/api/v1/jobs",
                    headers={**_auth_headers("MLRO", TENANT_A), "Idempotency-Key": idem_key},
                    json={
                        "job_type": "EMAIL_NOTIFICATION",
                        "payload": {
                            "recipient": "mlro@bank.example",
                            "subject": "Stage 2 Queue Load Leveling Verification",
                        },
                    },
                )
                assert resp1.status_code == 202, resp1.text
                b1 = resp1.json()
                created_job_id = b1["job_id"]
                assert b1["status"] == "QUEUED"
                assert b1["topic"] == JOBS_NOTIFICATIONS_TOPIC
                assert b1["deduplicated"] is False

                # 3. Replay identical Idempotency-Key -> deduplicated cleanly with same job_id
                resp2 = await ac.post(
                    "/api/v1/jobs",
                    headers={**_auth_headers("MLRO", TENANT_A), "Idempotency-Key": idem_key},
                    json={
                        "job_type": "EMAIL_NOTIFICATION",
                        "payload": {
                            "recipient": "mlro@bank.example",
                            "subject": "Stage 2 Queue Load Leveling Verification",
                        },
                    },
                )
                assert resp2.status_code == 202
                b2 = resp2.json()
                assert b2["job_id"] == created_job_id
                assert b2["deduplicated"] is True

                # 4. Cross-tenant isolation check (TENANT_B cannot view TENANT_A job)
                resp_cross = await ac.get(
                    f"/api/v1/jobs/{created_job_id}",
                    headers=_auth_headers("MLRO", TENANT_B),
                )
                assert resp_cross.status_code == 404

                # 5. Verify atomic transactional_outbox row was written for the job
                async with pg_mod.get_async_db_conn(tenant_id=TENANT_A) as conn:
                    outbox_rows = await conn.fetch(
                        """
                        SELECT aggregate_type, aggregate_id, headers
                        FROM transactional_outbox
                        WHERE aggregate_type = 'ASYNC_JOB_DISPATCH' AND aggregate_id = $1;
                        """,
                        created_job_id,
                    )
                    assert len(outbox_rows) == 1

                # 6. Execute async job via worker service -> transitions QUEUED -> COMPLETED
                exec1 = await execute_async_job(
                    {"job_id": created_job_id, "tenant_id": TENANT_A, "job_type": "EMAIL_NOTIFICATION"}
                )
                assert exec1["status"] == "COMPLETED"

                # 7. Replay execute_async_job (Kafka at-least-once redelivery) -> SKIPPED_IDEMPOTENT
                exec2 = await execute_async_job(
                    {"job_id": created_job_id, "tenant_id": TENANT_A, "job_type": "EMAIL_NOTIFICATION"}
                )
                assert exec2["status"] == "SKIPPED_IDEMPOTENT"

                # 8. Status API reflects COMPLETED
                resp_done = await ac.get(
                    f"/api/v1/jobs/{created_job_id}",
                    headers={**_auth_headers("MLRO", TENANT_A), "X-Read-Consistency": "strong"},
                )
                assert resp_done.status_code == 200
                assert resp_done.json()["status"] == "COMPLETED"

        # 9. Poison message DLQ + Zero-Loss Guard verification
        _TP = namedtuple("TopicPartition", ["topic", "partition"])
        tp = _TP(topic=JOBS_EXPORTS_TOPIC, partition=0)
        bad_msg = SimpleNamespace(
            offset=41,
            value={"job_id": str(uuid.uuid4()), "tenant_id": TENANT_A, "job_type": "ALERT_PDF_EXPORT"},
        )
        dlq_producer_ok = MagicMock(send_and_wait=AsyncMock())
        consumer_ok = MagicMock(commit=AsyncMock())

        with patch("workers.job_worker.execute_async_job", AsyncMock(side_effect=RuntimeError("boom"))), \
             patch("workers.job_worker.fail_async_job_repo", AsyncMock()), \
             patch("asyncio.sleep", AsyncMock()):
            ok = await process_job_message(bad_msg, tp, dlq_producer_ok, consumer_ok)
            assert ok is False
            assert dlq_producer_ok.send_and_wait.await_count == 1
            assert dlq_producer_ok.send_and_wait.call_args.kwargs["topic"] == JOBS_EXPORTS_DLQ_TOPIC
            consumer_ok.commit.assert_awaited_once_with({tp: 42})

            # Zero-loss guard: if BOTH execution AND DLQ publish fail, NEVER commit offset
            dlq_producer_fail = MagicMock(send_and_wait=AsyncMock(side_effect=ConnectionError("broker down")))
            consumer_guard = MagicMock(commit=AsyncMock())
            ok2 = await process_job_message(bad_msg, tp, dlq_producer_fail, consumer_guard)
            assert ok2 is False
            consumer_guard.commit.assert_not_awaited()
    finally:
        if created_job_id:
            async with pg_mod.get_async_db_conn(tenant_id=TENANT_A) as conn:
                await conn.execute(
                    "DELETE FROM transactional_outbox WHERE aggregate_type = 'ASYNC_JOB_DISPATCH' AND aggregate_id = $1;",
                    created_job_id,
                )
                await conn.execute("DELETE FROM async_jobs WHERE id = $1::uuid;", created_job_id)


@pytest.mark.asyncio
async def test_stage2_alerts_pdf_and_examiner_packet_async_mode_offload():
    """Verifies ?async_mode=true offloads heavy PDF & Examiner Packet exports to 202 Accepted async jobs."""
    fake_job = {"job_id": str(uuid.uuid4()), "job_type": "ALERT_PDF_EXPORT", "status": "QUEUED"}
    case_id = str(uuid.uuid4())
    transport = httpx.ASGITransport(app=app)

    with patch("services.auth._verify_token_version", AsyncMock(return_value=None)), \
         patch("repositories.jobs_repo.enqueue_async_job_atomic", AsyncMock(return_value=(fake_job, False))) as mock_enq:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r_pdf = await ac.get(
                "/api/v1/alerts/export/pdf?async_mode=true",
                headers=_auth_headers("ANALYST"),
            )
            assert r_pdf.status_code == 202
            assert r_pdf.json()["job_id"] == fake_job["job_id"]
            assert r_pdf.json()["status_url"] == f"/api/v1/jobs/{fake_job['job_id']}"

            r_zip = await ac.post(
                f"/api/v1/audit/examiner-packet/{case_id}?async_mode=true",
                headers=_auth_headers("MLRO"),
            )
            assert r_zip.status_code == 202
            assert mock_enq.await_count == 2


def test_stage2_redpanda_12_partitions_and_topic_dlq_bootstrap_job():
    """Verifies Redpanda 3-node cluster defaults to 12 partitions and provisions all partitioned topics & DLQs."""
    rp_docs = _load_yaml_docs("deployments/kubernetes/redpanda.yaml")
    rp_sts = next(d for d in rp_docs if d["kind"] == "StatefulSet")
    assert rp_sts["spec"]["replicas"] == 3
    cmd = " ".join(rp_sts["spec"]["template"]["spec"]["containers"][0]["command"])
    assert "redpanda.default_topic_partitions=12" in cmd
    assert "redpanda.default_topic_replications=3" in cmd

    job_doc = _load_yaml_docs("deployments/kubernetes/redpanda-topics-job.yaml")[0]
    assert job_doc["kind"] == "Job"
    script = " ".join(job_doc["spec"]["template"]["spec"]["containers"][0]["command"])
    for topic in (
        "aml.transactions.raw",
        "aml.transactions.raw.dlq",
        "aml.transactions.scored",
        "aml.transactions.dlq",
        "aml.jobs.exports",
        "aml.jobs.exports.dlq",
        "aml.jobs.notifications",
        "aml.jobs.notifications.dlq",
    ):
        assert topic in script, f"Topic '{topic}' missing from redpanda-topics-job.yaml"


# ── 5. Horizontal Autoscaling (HPA + KEDA) & >= 3 Availability Zones ─────────


def test_stage2_hpa_60pct_cpu_rps_and_keda_lag_autoscaling():
    """Verifies FastAPI HPA (CPU 60%, Memory 75%, RPS metric, behavior) and KEDA ScaledObjects."""
    fastapi_docs = _load_yaml_docs("deployments/kubernetes/fastapi-app.yaml")
    dep = next(d for d in fastapi_docs if d["kind"] == "Deployment")
    hpa = next(d for d in fastapi_docs if d["kind"] == "HorizontalPodAutoscaler")

    assert dep["spec"]["replicas"] >= 3
    assert hpa["spec"]["minReplicas"] >= 3
    assert hpa["spec"]["maxReplicas"] >= 30
    assert hpa["spec"]["behavior"]["scaleDown"]["stabilizationWindowSeconds"] >= 300

    metrics = hpa["spec"]["metrics"]
    cpu_metric = next(m for m in metrics if m["type"] == "Resource" and m["resource"]["name"] == "cpu")
    mem_metric = next(m for m in metrics if m["type"] == "Resource" and m["resource"]["name"] == "memory")
    rps_metric = next(m for m in metrics if m["type"] == "Pods" and m["pods"]["metric"]["name"] == "http_requests_per_second")
    assert cpu_metric["resource"]["target"]["averageUtilization"] == 60
    assert mem_metric["resource"]["target"]["averageUtilization"] == 75
    assert rps_metric["pods"]["target"]["averageValue"] == "150"

    keda_docs = _load_yaml_docs("deployments/kubernetes/keda-scaledobjects.yaml")
    auth_doc = next(d for d in keda_docs if d["kind"] == "TriggerAuthentication")
    assert auth_doc["metadata"]["name"] == "aml-kafka-trigger-auth"

    scalers = {d["metadata"]["name"]: d for d in keda_docs if d["kind"] == "ScaledObject"}
    assert set(scalers.keys()) == {
        "aml-scoring-worker-scaler",
        "aml-sync-worker-scaler",
        "aml-job-worker-scaler",
        "aml-outbox-relay-scaler",
    }
    assert scalers["aml-scoring-worker-scaler"]["spec"]["maxReplicaCount"] == 12
    assert scalers["aml-sync-worker-scaler"]["spec"]["maxReplicaCount"] == 12
    assert scalers["aml-job-worker-scaler"]["spec"]["maxReplicaCount"] == 6
    assert scalers["aml-outbox-relay-scaler"]["spec"]["maxReplicaCount"] == 8
    assert scalers["aml-scoring-worker-scaler"]["spec"]["triggers"][0]["type"] == "kafka"
    assert scalers["aml-outbox-relay-scaler"]["spec"]["triggers"][0]["type"] == "prometheus"


def test_stage2_multi_az_topology_spread_and_prod_kustomization():
    """Verifies >=3 AZ topologySpreadConstraints across workloads and prod Kustomization completeness."""
    manifests_requiring_zone_spread = [
        ("deployments/kubernetes/fastapi-app.yaml", "Deployment", "aml-fastapi-app"),
        ("deployments/kubernetes/pgbouncer.yaml", "Deployment", "aml-pgbouncer"),
        ("deployments/kubernetes/postgres.yaml", "StatefulSet", "aml-postgres-replica"),
        ("deployments/kubernetes/redis.yaml", "Deployment", "aml-redis-cache"),
        ("deployments/kubernetes/redpanda.yaml", "StatefulSet", "aml-redpanda"),
        ("deployments/kubernetes/outbox-relay.yaml", "Deployment", "aml-outbox-relay"),
        ("deployments/kubernetes/scoring-worker.yaml", "Deployment", "aml-scoring-worker"),
        ("deployments/kubernetes/sync-worker.yaml", "Deployment", "aml-sync-worker"),
        ("deployments/kubernetes/job-worker.yaml", "Deployment", "aml-job-worker"),
    ]
    for path, kind, name in manifests_requiring_zone_spread:
        docs = _load_yaml_docs(path)
        workload = next(d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name)
        pod_spec = workload["spec"]["template"]["spec"]
        spreads = pod_spec.get("topologySpreadConstraints", [])
        assert any(
            s.get("topologyKey") == "topology.kubernetes.io/zone" and s.get("maxSkew") == 1
            for s in spreads
        ), f"{path} ({name}) missing topology.kubernetes.io/zone maxSkew=1 spread constraint"

    # Verify prod Kustomization includes all Stage 2 resources and every path exists on disk
    kust = _load_yaml_docs("deployments/kubernetes/overlays/prod/kustomization.yaml")[0]
    resources = kust["resources"]
    for expected in ("../../job-worker.yaml", "../../redpanda-topics-job.yaml", "../../keda-scaledobjects.yaml"):
        assert expected in resources
    prod_dir = ROOT / "deployments/kubernetes/overlays/prod"
    for res in resources:
        assert (prod_dir / res).resolve().exists(), f"Missing Kustomization resource: {res}"
