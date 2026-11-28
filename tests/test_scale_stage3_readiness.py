"""
Scale Pillar — Stage 3 Readiness & Chaos Verification Suite (50,000 -> 100,000+ Users)
======================================================================================
Executes deterministic chaos drills, live PostgreSQL time-range partitioning checks,
adaptive load-shedding proofs, outbound retry budget throttling, DR/PITR drills,
and load-testing / CI manifest validations (Stage 3 Option A):

  1. Adaptive Load Shedding & Circuit Breakers:
     - Priority classification (P0_CRITICAL vs P1_HIGH vs P2_NORMAL vs P3_SHEDDABLE)
     - Overload spike sheds P3/P2 with 503 + Retry-After + X-Load-Shed-Tier while P0 stays 200
     - Fleet-wide RetryBudget caps retry storms (<= 20%) + CircuitBreaker trips OPEN on 3s stalls
  2. Time-Range Table Partitioning (Live PostgreSQL Migration 040):
     - `transactional_outbox` (weekly) & `audit_log` (monthly) have relkind='p', child partitions,
       FORCE ROW LEVEL SECURITY on parent AND every child partition, and WORM immutability rules
     - EXPLAIN proves partition pruning on bounded timestamp queries
     - `maintain_partitions.py` & `drop_expired_outbox_partitions()` work idempotently
  3. Multi-Region Cell Seam & Automated DR / PITR Drills:
     - `resolve_tenant_cell()` default & JSON override
     - Live `run_dr_failover_drill()` returns PASS
     - Validates `partition-maintenance-cronjob.yaml`, `pitr-backup-cronjob.yaml`, blueprint & runbook
  4. Chaos Drills & Load Proof:
     - Chaos Drill 1: Kill Cache Redis -> <= 200ms fail-open, zero 5xx
     - Chaos Drill 2: Kill Read Replica #1 -> failover to Replica #2 -> Primary, zero errors
     - Chaos Drill 3: Inject 3s downstream latency -> fast split timeout, CB opens, event loop healthy
     - Chaos Drill 4: Overload spike -> P3 shed cleanly, P0 unaffected
     - Validates k6 (`3x_spike`/`soak`/p95/p99), Locust mixed users + spike shape, and scheduled CI workflow
"""

from __future__ import annotations

import asyncio
import pathlib
import time
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import asyncpg
import httpx
import pytest
import yaml

from config import settings
from database import postgres as pg_mod
from main import app
from observability.event_loop_monitor import probe_event_loop_lag_seconds
from observability.load_shedding import (
    P0_CRITICAL,
    P1_HIGH,
    P2_NORMAL,
    P3_SHEDDABLE,
    classify_request_priority,
    evaluate_shed_decision,
    resolve_tenant_cell,
)
from scripts.dr_failover_drill import run_dr_failover_drill
from scripts.maintain_partitions import run_partition_maintenance
from services.auth import create_access_token
from services.http_client import (
    CircuitOpenError,
    RetryBudget,
    get_circuit_breaker,
    request_with_resilience,
    reset_all_circuit_breakers,
)
from services.secrets_manager import get_postgres_dsn

ROOT = pathlib.Path(__file__).resolve().parent.parent
TENANT_A = "00000000-0000-0000-0000-000000000001"
TENANT_B = "00000000-0000-0000-0000-000000000002"


def _auth_headers(role: str = "MLRO", tenant_id: str = TENANT_A) -> dict[str, str]:
    token = create_access_token(
        {
            "sub": str(uuid.uuid4()),
            "username": f"stage3_{role.lower()}",
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


# ── 1. Adaptive Load Shedding & Outbound Retry Budget ────────────────────────


def test_stage3_priority_classification_and_shed_thresholds():
    """Verifies P0 critical traffic is never shed while P3 and P2 shed progressively under saturation."""
    assert classify_request_priority("/health/ready") == P0_CRITICAL
    assert classify_request_priority("/api/v1/auth/login", "POST") == P0_CRITICAL
    assert classify_request_priority("/api/v1/transactions/ingest", "POST") == P0_CRITICAL
    assert classify_request_priority("/api/v1/ctr/filings", "POST") == P0_CRITICAL

    assert classify_request_priority("/api/v1/alerts") == P1_HIGH
    assert classify_request_priority("/api/v1/cases") == P1_HIGH

    assert classify_request_priority("/api/v1/customers") == P2_NORMAL
    assert classify_request_priority("/api/v1/search") == P2_NORMAL

    assert classify_request_priority("/api/v1/reports/sar-summary") == P3_SHEDDABLE
    assert classify_request_priority("/api/v1/alerts/export/pdf") == P3_SHEDDABLE
    assert classify_request_priority("/api/v1/audit/examiner-packet/123") == P3_SHEDDABLE
    assert classify_request_priority("/api/v1/jobs") == P3_SHEDDABLE

    # Under 75% concurrency (150/200) -> P3 sheds, P2 & P0 admitted
    shed_p3, _, reason_p3 = evaluate_shed_decision("/api/v1/reports/sar-summary", in_flight=150, event_loop_lag_seconds=0.0, db_pool_utilization=0.0)
    shed_p2, _, _ = evaluate_shed_decision("/api/v1/customers", in_flight=150, event_loop_lag_seconds=0.0, db_pool_utilization=0.0)
    shed_p0, _, _ = evaluate_shed_decision("/api/v1/transactions/ingest", "POST", in_flight=199, event_loop_lag_seconds=0.9, db_pool_utilization=1.0)
    assert shed_p3 is True and reason_p3 == "concurrency_high"
    assert shed_p2 is False
    assert shed_p0 is False

    # Under 95% DB pool saturation -> both P3 and P2 shed, P0 & P1 still protected
    shed_p2_pool, _, reason_p2 = evaluate_shed_decision("/api/v1/customers", in_flight=10, event_loop_lag_seconds=0.0, db_pool_utilization=0.95)
    shed_p1_pool, _, _ = evaluate_shed_decision("/api/v1/alerts", in_flight=10, event_loop_lag_seconds=0.0, db_pool_utilization=0.95)
    assert shed_p2_pool is True and reason_p2 == "db_pool_critical"
    assert shed_p1_pool is False


@pytest.mark.asyncio
async def test_stage3_chaos_drill_4_overload_spike_sheds_p3_protects_p0():
    """Chaos Drill 4: Simulated event-loop lag spike sheds P3 reports (503 + Retry-After) while P0 stays 200."""
    transport = httpx.ASGITransport(app=app)
    with patch("observability.load_shedding._current_event_loop_lag_seconds", return_value=0.18), \
         patch("services.auth._verify_token_version", AsyncMock(return_value=None)):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            # P3 analytics report gracefully shed with 503 + Retry-After + tier headers
            r_p3 = await ac.get("/api/v1/reports/sar-summary", headers=_auth_headers("MLRO"))
            assert r_p3.status_code == 503
            assert int(r_p3.headers["retry-after"]) in range(2, 6)
            assert r_p3.headers["x-load-shed-tier"] == P3_SHEDDABLE
            assert r_p3.headers["x-load-shed-reason"] == "event_loop_lag"
            assert r_p3.json()["priority_tier"] == P3_SHEDDABLE

            # P0 health & JWKS continue succeeding cleanly (0% shedding on P0)
            r_p0_live = await ac.get("/health/live")
            r_p0_jwks = await ac.get("/.well-known/jwks.json")
            assert r_p0_live.status_code == 200
            assert r_p0_jwks.status_code == 200


def test_stage3_outbound_retry_budget_caps_retry_storm():
    """Verifies fleet RetryBudget caps retries to <= 20% of traffic window after minimum grace floor."""
    rb = RetryBudget(target="test_storm", window_seconds=10.0, max_retry_ratio=0.20, min_retries_per_window=3)
    for _ in range(20):
        rb.record_request()
    # 20% of 20 = 4 allowed retries; 5th retry MUST be rejected to prevent retry storm
    assert [rb.allow_retry() for _ in range(4)] == [True, True, True, True]
    assert rb.allow_retry() is False
    snap = rb.snapshot()
    assert snap["requests_in_window"] == 20
    assert snap["retries_in_window"] == 4
    assert snap["budget_limit"] == 4


# ── 2. Chaos Drills 1, 2 & 3 (Kill Cache Redis, Kill Replica, 3s Latency) ────


@pytest.mark.asyncio
async def test_stage3_chaos_drill_1_kill_cache_redis_fails_open_fast():
    """Chaos Drill 1: Dead/stalled Cache Redis fails open to PostgreSQL in < 200ms with zero 5xx."""
    mock_fetch = AsyncMock(
        return_value={"total_drafts": 11, "approved_drafts": 5, "submitted_drafts": 4, "rejected_drafts": 2}
    )

    class _DeadCacheRedis:
        async def get(self, key):
            raise TimeoutError("Cache Redis socket dead")

        async def set(self, *args, **kwargs):
            raise TimeoutError("Cache Redis socket dead")

    transport = httpx.ASGITransport(app=app)
    with patch("services.auth._verify_token_version", AsyncMock(return_value=None)), \
         patch("routers.compliance_reporting.fetch_sar_summary_repo", mock_fetch), \
         patch("services.cache_aside.get_async_cache_redis_client", AsyncMock(return_value=_DeadCacheRedis())):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            t0 = time.monotonic()
            resp = await ac.get("/api/v1/reports/sar-summary", headers=_auth_headers("MLRO"))
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            assert resp.status_code == 200
            assert resp.json()["total_sar_drafts"] == 11
            assert elapsed_ms < 200.0, f"Cache Redis fail-open took {elapsed_ms:.1f}ms (>= 200ms)"


@pytest.mark.asyncio
async def test_stage3_chaos_drill_2_kill_read_replica_seamless_failover():
    """Chaos Drill 2: Killing Read Replica #1 fails over seamlessly to Replica #2, then Primary on double-fault."""

    def _pool(label: str, *, dead: bool = False):
        p = MagicMock()
        p._loop = SimpleNamespace(is_closed=lambda: False)
        conn = MagicMock(pool_label=label, execute=AsyncMock())

        class _Tx:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        conn.transaction = MagicMock(return_value=_Tx())
        if dead:
            p.acquire = AsyncMock(side_effect=ConnectionError(f"{label} killed"))
        else:
            p.acquire = AsyncMock(return_value=conn)
        p.release = AsyncMock()
        p.get_size = MagicMock(return_value=2)
        p.get_idle_size = MagicMock(return_value=1)
        p.get_max_size = MagicMock(return_value=4)
        return p

    primary = _pool("primary")
    rep1_dead = _pool("rep1", dead=True)
    rep2_alive = _pool("rep2", dead=False)
    rep2_dead = _pool("rep2", dead=True)

    orig = (pg_mod.db_pool, pg_mod.db_replica_pool, list(pg_mod.db_replica_pools), pg_mod._replica_rr_index)
    try:
        pg_mod.db_pool = primary
        pg_mod.db_replica_pools = [rep1_dead, rep2_alive]
        pg_mod.db_replica_pool = rep1_dead
        pg_mod._replica_rr_index = 0

        with patch("observability.storage_monitor.get_observed_replica_lag_seconds", return_value=0.05):
            async with pg_mod.get_async_db_read_conn(tenant_id=TENANT_A) as c1:
                assert c1.pool_label == "rep2"

            # Kill second replica too -> falls back to primary with zero error
            pg_mod.db_replica_pools = [rep1_dead, rep2_dead]
            pg_mod.db_replica_pool = rep1_dead
            async with pg_mod.get_async_db_read_conn(tenant_id=TENANT_A) as c2:
                assert c2.pool_label == "primary"
    finally:
        pg_mod.db_pool, pg_mod.db_replica_pool, pg_mod.db_replica_pools, pg_mod._replica_rr_index = orig


@pytest.mark.asyncio
async def test_stage3_chaos_drill_3_inject_3s_downstream_latency_trips_breaker_and_preserves_loop():
    """Chaos Drill 3: 3s downstream stall hits bounded timeout fast, trips CircuitBreaker OPEN, keeps loop healthy."""
    reset_all_circuit_breakers()
    target = "chaos_slow_downstream"
    cb = get_circuit_breaker(target, failure_threshold=3, recovery_timeout=30.0)

    async def _stalled_send(*args, **kwargs):
        # Emulate a 3-second downstream stall interrupted cleanly by httpx split timeout
        req_timeout = args[4] if len(args) > 4 else kwargs.get("req_timeout")
        read_limit = getattr(req_timeout, "read", 0.1) or 0.1
        try:
            await asyncio.wait_for(asyncio.sleep(3.0), timeout=min(0.08, float(read_limit)))
        except asyncio.TimeoutError:
            raise httpx.ReadTimeout("Injected 3s downstream latency timeout")

    t0 = time.monotonic()
    with patch("services.http_client._send_http_attempt", side_effect=_stalled_send):
        for _ in range(3):
            with pytest.raises(httpx.ReadTimeout):
                await request_with_resilience(
                    "GET",
                    "https://slow.downstream.example/api",
                    target=target,
                    timeout=0.08,
                    retries=0,
                )
        # 4th call fails IMMEDIATELY with CircuitOpenError (0ms network wait!)
        t_open = time.monotonic()
        with pytest.raises(CircuitOpenError):
            await request_with_resilience(
                "GET",
                "https://slow.downstream.example/api",
                target=target,
                timeout=0.08,
                retries=0,
            )
        open_ms = (time.monotonic() - t_open) * 1000.0

    total_elapsed = time.monotonic() - t0
    loop_lag_ms = (await probe_event_loop_lag_seconds()) * 1000.0
    assert cb.state == "open"
    assert total_elapsed < 1.0, f"Expected fast timeout containment (<1s), got {total_elapsed:.2f}s"
    assert open_ms < 10.0, f"Open circuit breaker should fail fast (<10ms), got {open_ms:.2f}ms"
    assert loop_lag_ms < 50.0, f"Event loop saturated during downstream latency drill ({loop_lag_ms:.1f}ms)"


# ── 3. Live PostgreSQL Time-Range Partitioning Proof (Migration 040) ─────────


@pytest.mark.asyncio
async def test_stage3_live_pg_time_partitioning_pruning_worm_and_maintenance():
    """Proves live PG Migration 040 partitioning, child FORCE RLS, partition pruning, WORM rules, and maintenance."""
    conn = await asyncpg.connect(get_postgres_dsn())
    probe_outbox_id = uuid.uuid4()
    try:
        # 1. Both tables are declarative range-partitioned parents (relkind='p')
        for tbl in ("transactional_outbox", "audit_log"):
            row = await conn.fetchrow(
                """
                SELECT c.relkind, pg_get_partkeydef(c.oid) AS partkey,
                       c.relrowsecurity, c.relforcerowsecurity,
                       (SELECT COUNT(*) FROM pg_inherits ih WHERE ih.inhparent = c.oid) AS children
                FROM pg_class c
                WHERE c.relname = $1 AND c.relnamespace = 'public'::regnamespace;
                """,
                tbl,
            )
            assert row["relkind"] in ("p", b"p"), f"{tbl} is not partitioned!"
            assert row["partkey"].startswith("RANGE (")
            assert row["relrowsecurity"] is True and row["relforcerowsecurity"] is True
            assert row["children"] >= 10, f"{tbl} missing pre-created partitions ({row['children']})"

            # Every child partition ALSO enforces FORCE ROW LEVEL SECURITY
            unforced_children = await conn.fetch(
                """
                SELECT c.relname
                FROM pg_inherits ih
                JOIN pg_class c ON c.oid = ih.inhrelid
                WHERE ih.inhparent = $1::regclass
                  AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);
                """,
                tbl,
            )
            assert unforced_children == [], f"{tbl} has child partitions missing FORCE RLS: {unforced_children}"

        # 2. Verify PostgreSQL partition pruning on a bounded time window
        now_utc = datetime.now(timezone.utc)
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", TENANT_A)
            plan_rows = await conn.fetch(
                """
                EXPLAIN (COSTS OFF)
                SELECT id FROM audit_log
                WHERE tenant_id = $1::uuid
                  AND occurred_at >= $2::timestamptz
                  AND occurred_at < $2::timestamptz + INTERVAL '1 hour';
                """,
                TENANT_A,
                now_utc,
            )
            plan_text = "\n".join(r[0] for r in plan_rows)
            # Only ONE monthly partition is scanned (not all 15+ child partitions)
            scanned_monthly = [line for line in plan_rows if "audit_log_p" in line[0]]
            assert len(scanned_monthly) <= 2, f"Expected partition pruning on audit_log:\n{plan_text}"

        # 3. Verify transactional_outbox insert routes into weekly partition & cleanup works
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", TENANT_A)
            await conn.execute(
                """
                INSERT INTO transactional_outbox (
                    id, tenant_id, aggregate_type, aggregate_id, event_type, payload, status, created_at
                ) VALUES ($1::uuid, $2::uuid, 'STAGE3_TEST', $3, 'stage3.partition.probe', '{}'::jsonb, 'PUBLISHED', NOW());
                """,
                probe_outbox_id,
                TENANT_A,
                str(probe_outbox_id),
            )
            found = await conn.fetchval(
                "SELECT tableoid::regclass::text FROM transactional_outbox WHERE id = $1;",
                probe_outbox_id,
            )
            assert found.startswith("transactional_outbox_p"), f"Unexpected outbox partition: {found}"
            await conn.execute("DELETE FROM transactional_outbox WHERE id = $1;", probe_outbox_id)

        # 4. Verify WORM rules (`audit_log_no_update` / `audit_log_no_delete`) still exist on partitioned audit_log
        rules = {
            r["rulename"]
            for r in await conn.fetch("SELECT rulename FROM pg_rules WHERE tablename = 'audit_log';")
        }
        assert {"audit_log_no_update", "audit_log_no_delete"} <= rules
    finally:
        await conn.close()

    # 5. Execute automated maintenance & DR failover readiness drill live
    maint = await run_partition_maintenance(outbox_weeks_ahead=8, audit_months_ahead=12, outbox_retention_weeks=2)
    assert set(maint.keys()) == {
        "outbox_partitions_created",
        "audit_partitions_created",
        "outbox_partitions_dropped",
    }

    dr_report = await run_dr_failover_drill()
    assert dr_report["drill_status"] == "PASS", dr_report
    assert dr_report["checks"]["time_partitioning_active"] is True
    assert dr_report["checks"]["force_rls_enforced"] is True
    assert dr_report["checks"]["wal_pitr_capable"] is True


# ── 4. Multi-Region Cell Seam, CronJobs, Runbook, Load & CI Verification ─────


def test_stage3_cell_routing_cronjobs_blueprint_and_load_chaos_pipeline(monkeypatch):
    """Verifies cell routing seam, DR/Partition CronJobs, k6/Locust Stage 3 suites, and CI workflow."""
    assert resolve_tenant_cell(TENANT_A) == "cell-us-east-1"
    monkeypatch.setattr(
        settings,
        "tenant_cell_routing_json",
        f'{{"{TENANT_B}": "cell-eu-central-1"}}',
    )
    assert resolve_tenant_cell(TENANT_B) == "cell-eu-central-1"
    assert resolve_tenant_cell(TENANT_A) == "cell-us-east-1"

    # CronJobs & Prod Kustomization
    part_cron = _load_yaml_docs("deployments/kubernetes/partition-maintenance-cronjob.yaml")[0]
    assert part_cron["kind"] == "CronJob"
    assert part_cron["spec"]["concurrencyPolicy"] == "Forbid"

    pitr_docs = _load_yaml_docs("deployments/kubernetes/pitr-backup-cronjob.yaml")
    pitr_names = {d["metadata"]["name"] for d in pitr_docs if d["kind"] == "CronJob"}
    assert pitr_names == {"aml-pitr-backup", "aml-pitr-restore-drill"}

    kust = _load_yaml_docs("deployments/kubernetes/overlays/prod/kustomization.yaml")[0]
    assert "../../partition-maintenance-cronjob.yaml" in kust["resources"]
    assert "../../pitr-backup-cronjob.yaml" in kust["resources"]

    # Blueprint & updated runbook
    blueprint = (ROOT / "docs/architecture/multi_region_cell_sharding_blueprint.md").read_text(encoding="utf-8")
    assert "60%" in blueprint and "RPO <= 5 minutes" in blueprint and "transactions_partitioned" in blueprint
    runbook = (ROOT / "docs/runbooks/SRE-RB-042-outbox-partition-recovery.md").read_text(encoding="utf-8")
    assert "aml-postgres-replica-0" in runbook and "scripts/dr_failover_drill.py" in runbook

    # Upgraded k6, Locust, and scheduled CI workflow
    k6_src = (ROOT / "load_test_k6.js").read_text(encoding="utf-8")
    for token in ("3x_spike", "soak", "p(95)<300", "p(99)<750", "p0_unexpected_5xx", "Idempotency-Key"):
        assert token in k6_src

    locust_src = (ROOT / "locustfile.py").read_text(encoding="utf-8")
    for token in ("AMLIngestionUser", "AMLComplianceAnalystUser", "ThreeXSpikeLoadShape", "Idempotency-Key"):
        assert token in locust_src

    wf = yaml.safe_load((ROOT / ".github/workflows/load-and-chaos.yml").read_text(encoding="utf-8"))
    assert "schedule" in wf[True] or "schedule" in wf.get("on", {})
    assert "chaos-and-resilience-drills" in wf["jobs"]
    assert "k6-spike-verification" in wf["jobs"]
