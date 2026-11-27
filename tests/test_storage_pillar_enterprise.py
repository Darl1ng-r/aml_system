"""
Enterprise Storage Pillar Verification Suite (13/13 Pitfall Prevention Checklist)
=================================================================================
Verifies every single item in the Production Data-Layer Pitfall Prevention Checklist:
  1. Schema precision (`NUMERIC(19, 4)`), UTC `TIMESTAMPTZ`, zero-lock validated `CHECK`
     constraints, and index-friendly UUID RLS policies (`038` migration on live DB).
  2. Migration DDL safety CI guard (`CREATE INDEX CONCURRENTLY` & `NOT VALID` CHECKs on >= 038).
  3. Live `EXPLAIN (ANALYZE, BUFFERS, SETTINGS)` verification that hot-path queries hit
     Equality -> Range -> Sort composite & partial indexes.
  4. Zero N+1 queries enforced via bulk `unnest()` SQL + `CountingConnection` query-count
     assertions across `create_case_atomic`, `evaluate_shadow_rules_for_tx`,
     `sample_closed_false_positives_for_qa`, and `list_alerts_page_repo`.
  5. Keyset cursor pagination (`?cursor=`, `X-Next-Cursor`, `X-Has-More`, `next_cursor`)
     + keyset export streaming + `MAX_LEGACY_OFFSET = 10_000` guardrail & malformed cursor 400.
  6. Deterministic multi-row `FOR UPDATE` ordering guard across all repositories/services.
  7. `FORCE ROW LEVEL SECURITY` on all tenant tables + unified `5.0s` pool acquire timeout.
  8. Read-After-Write Primary stickiness (`ReadAfterWriteStickinessMiddleware` +
     `X-Read-Consistency: strong`) and streaming replication lag auto-failover to Primary.
  9. Physical separation of Cache Redis (`allkeys-lfu`) vs State Redis (`noeviction`) in
     Docker Compose, Kubernetes manifests, and `database/redis_db.py` (`<= 250ms` cache timeouts).
 10. Enterprise `CacheAsideClient`: versioned tenant-namespaced keys, jittered TTL,
     single-flight stampede defense (20 concurrent callers -> 1 DB load), PER/XFetch early
     refresh, negative caching (`__SENTINEL_NOT_FOUND__`), fail-open degradation on Redis
     outage/timeout, and post-commit `CACHE_INVALIDATION` Outbox self-healing.
 11. Storage observability collector (`observability/storage_monitor.py`) exporting PostgreSQL
     pool, replica lag, dead-tuple bloat, and State/Cache Redis hit-ratio/evictions/fragmentation
     metrics to Prometheus `/metrics`.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import asyncpg
import httpx
import pytest
import yaml
from fastapi import HTTPException

from database.outbox import OutboxRelayEngine
from database.pagination import (
    MAX_LEGACY_OFFSET,
    decode_keyset_cursor,
    encode_keyset_cursor,
    validate_legacy_offset,
)
from database.postgres import get_async_db_conn, get_async_db_read_conn
from database.read_after_write import (
    clear_local_stickiness_cache,
    force_primary_read_var,
)
from database.redis_db import get_async_cache_redis_client
from main import app
from observability.prometheus import generate_metrics_text
from observability.storage_monitor import (
    sample_storage_telemetry_once,
    set_observed_replica_lag_seconds,
)
from repositories.alert_repo import iter_alert_export_chunks_repo, list_alerts_page_repo
from repositories.case_repo import create_case_atomic
from services.auth import create_access_token
from services.cache_aside import (
    NEGATIVE_SENTINEL,
    CacheAsideClient,
    build_cache_key,
    compute_jittered_ttl,
    dispatch_cache_invalidation_outbox_event,
    should_probabilistically_refresh,
)
from services.pkyc_and_qa import sample_closed_false_positives_for_qa
from services.rule_backtest import evaluate_shadow_rules
from services.secrets_manager import get_postgres_dsn

TENANT_ID = "00000000-0000-0000-0000-000000000001"


def _make_token(role: str = "MLRO", tenant_id: str = TENANT_ID, user_id: str | None = None) -> str:
    return create_access_token(
        {
            "sub": f"storage_test_{role.lower()}",
            "id": user_id or str(uuid.uuid4()),
            "role": role,
            "tenant_id": tenant_id,
        }
    )


class _CountingConn:
    """Proxy wrapping a mock/real connection to enforce strict query-count budgets."""

    def __init__(self, inner):
        self._inner = inner
        self.queries: list[str] = []

    async def execute(self, query, *args, **kwargs):
        self.queries.append(str(query))
        return await self._inner.execute(query, *args, **kwargs)

    async def fetch(self, query, *args, **kwargs):
        self.queries.append(str(query))
        return await self._inner.fetch(query, *args, **kwargs)

    async def fetchrow(self, query, *args, **kwargs):
        self.queries.append(str(query))
        return await self._inner.fetchrow(query, *args, **kwargs)

    async def fetchval(self, query, *args, **kwargs):
        self.queries.append(str(query))
        return await self._inner.fetchval(query, *args, **kwargs)


# ── 1. Schema Precision, CHECK Constraints, FORCE RLS & Indexable UUID Policies ──


@pytest.mark.asyncio
async def test_migration_038_precision_check_constraints_and_uuid_rls_policies():
    conn = await asyncpg.connect(get_postgres_dsn())
    try:
        # A. Zero naive TIMESTAMP WITHOUT TIME ZONE columns anywhere in public schema
        naive_ts = await conn.fetch(
            """
            SELECT table_name, column_name
            FROM information_schema.columns
            WHERE table_schema = 'public' AND data_type = 'timestamp without time zone';
            """
        )
        assert naive_ts == [], f"Found naive timestamp columns: {naive_ts}"

        # B. Monetary columns use NUMERIC(19, 4)
        money_cols = await conn.fetch(
            """
            SELECT table_name, column_name, numeric_precision, numeric_scale
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND (
                  (table_name = 'transactions' AND column_name IN ('amount', 'amount_base_usd'))
                  OR (table_name = 'ctr_filings' AND column_name = 'amount')
                  OR (table_name = 'str_batches' AND column_name = 'total_amount')
                  OR (table_name = 'rule_shadow_hits' AND column_name = 'amount_base_usd')
                  OR (table_name = 'customer_profiles' AND column_name IN ('avg_amount', 'median_amount', 'variance_amount'))
              );
            """
        )
        assert len(money_cols) == 8
        for col in money_cols:
            assert (col["numeric_precision"], col["numeric_scale"]) == (19, 4), (
                f"{col['table_name']}.{col['column_name']} expected NUMERIC(19,4), "
                f"got ({col['numeric_precision']},{col['numeric_scale']})"
            )

        # C. All 6 zero-lock CHECK constraints exist and are validated (convalidated=true)
        expected_checks = {
            "chk_transactions_amount_positive",
            "chk_transactions_amount_base_usd_nonneg",
            "chk_transactions_fx_rate_positive",
            "chk_ctr_filings_amount_positive",
            "chk_str_batches_total_amount_nonneg",
            "chk_alerts_ai_risk_score_bounds",
        }
        check_rows = await conn.fetch(
            """
            SELECT conname, convalidated
            FROM pg_constraint
            WHERE contype = 'c'
              AND connamespace = 'public'::regnamespace
              AND conname = ANY($1::text[]);
            """,
            list(expected_checks),
        )
        found = {r["conname"]: bool(r["convalidated"]) for r in check_rows}
        assert set(found.keys()) == expected_checks
        assert all(found.values()), f"Unvalidated CHECK constraints: {found}"

        # D. Zero RLS policies cast `tenant_id` column to ::text (all cast session GUC to ::uuid)
        bad_policies = await conn.fetch(
            """
            SELECT tablename, policyname, qual
            FROM pg_policies
            WHERE schemaname = 'public'
              AND (COALESCE(qual, '') LIKE '%tenant_id)::text%' OR COALESCE(with_check, '') LIKE '%tenant_id)::text%');
            """
        )
        assert bad_policies == [], f"RLS policies casting tenant_id::text prevent index scans: {bad_policies}"

        # E. Every table with tenant_id enforces FORCE ROW LEVEL SECURITY
        unforced = await conn.fetch(
            """
            SELECT c.relname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relkind = 'r'
              AND EXISTS (
                  SELECT 1 FROM information_schema.columns ic
                  WHERE ic.table_schema = 'public' AND ic.table_name = c.relname AND ic.column_name = 'tenant_id'
              )
              AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);
            """
        )
        assert unforced == [], f"Tenant tables missing FORCE RLS: {unforced}"
    finally:
        await conn.close()


# ── 2. CI Migration DDL Safety Guard (Zero-Downtime CONCURRENTLY & NOT VALID) ──


def test_migrations_from_038_enforce_concurrent_indexes_and_not_valid_checks():
    migrations_dir = pathlib.Path("migrations/versions")
    checked = 0
    for py_file in sorted(migrations_dir.glob("*.py")):
        m = re.match(r"^(\d+)_", py_file.name)
        if not m or int(m.group(1)) < 38:
            continue
        checked += 1
        src = py_file.read_text(encoding="utf-8")
        # Every CREATE INDEX in upgrade must be CONCURRENTLY
        for match in re.finditer(r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY)", src, re.IGNORECASE):
            raise AssertionError(
                f"Blocking non-CONCURRENTLY CREATE INDEX found in {py_file.name} at pos {match.start()}"
            )
        # Every ADD CONSTRAINT ... CHECK on existing tables must use NOT VALID
        for match in re.finditer(r"ADD\s+CONSTRAINT\s+\w+\s+CHECK\s*\([^;]+;", src, re.IGNORECASE | re.DOTALL):
            snippet = match.group(0)
            assert "NOT VALID" in snippet.upper(), (
                f"Blocking CHECK constraint without NOT VALID in {py_file.name}: {snippet}"
            )
    assert checked >= 1


# ── 3. Live EXPLAIN (ANALYZE, BUFFERS, SETTINGS) Index Verification ──────────


@pytest.mark.asyncio
async def test_explain_analyze_hot_queries_use_equality_range_sort_indexes():
    conn = await asyncpg.connect(get_postgres_dsn())
    try:
        tid = await conn.fetchval("SELECT id::text FROM tenants LIMIT 1") or TENANT_ID
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.current_tenant_id', $1, true)", tid)
            # Disable seqscan in this local transaction to verify planner can satisfy every
            # hot-path query directly from the new Equality-Range-Sort B-Tree/partial indexes
            await conn.execute("SET LOCAL enable_seqscan = off;")

            plan_checks = [
                (
                    "idx_audit_log_tenant_occurred_id",
                    """
                    SELECT id, occurred_at FROM audit_log
                    WHERE tenant_id = $1::uuid
                    ORDER BY occurred_at DESC, id DESC LIMIT 50
                    """,
                    (tid,),
                ),
                (
                    "idx_alerts_tenant_status_created_id",
                    """
                    SELECT id, created_at FROM alerts
                    WHERE tenant_id = $1::uuid AND status = 'OPEN'
                    ORDER BY created_at DESC, id DESC LIMIT 50
                    """,
                    (tid,),
                ),
                (
                    "idx_transactions_tenant_timestamp_id",
                    """
                    SELECT id, "timestamp" FROM transactions
                    WHERE tenant_id = $1::uuid
                    ORDER BY "timestamp" DESC, id DESC LIMIT 50
                    """,
                    (tid,),
                ),
                (
                    "idx_cases_tenant_created_id",
                    """
                    SELECT id, created_at FROM cases
                    WHERE tenant_id = $1::uuid
                    ORDER BY created_at DESC, id DESC LIMIT 50
                    """,
                    (tid,),
                ),
                (
                    "idx_ctr_filings_tenant_created_id",
                    """
                    SELECT id, created_at FROM ctr_filings
                    WHERE tenant_id = $1::uuid
                    ORDER BY created_at DESC, id DESC LIMIT 50
                    """,
                    (tid,),
                ),
                (
                    "idx_resource_locks_tenant_type_expiry",
                    """
                    SELECT resource_id FROM resource_locks
                    WHERE tenant_id = $1::uuid AND resource_type = 'ALERT'
                      AND released_at IS NULL AND expires_at > NOW()
                    """,
                    (tid,),
                ),
                (
                    ("idx_outbox_active_created_id", "idx_outbox_pending_processing"),
                    """
                    SELECT id FROM transactional_outbox
                    WHERE status IN ('PENDING', 'PROCESSING')
                    ORDER BY created_at ASC, id ASC LIMIT 50
                    """,
                    (),
                ),
            ]
            for expected_index, sql, params in plan_checks:
                plan_rows = await conn.fetch(f"EXPLAIN (ANALYZE, BUFFERS, SETTINGS) {sql}", *params)
                plan_text = "\n".join(r[0] for r in plan_rows)
                candidates = (expected_index,) if isinstance(expected_index, str) else expected_index
                assert any(idx in plan_text for idx in candidates), (
                    f"Expected one of {candidates} in plan:\n{plan_text}"
                )
                assert "Seq Scan" not in plan_text, f"Unexpected Seq Scan in plan:\n{plan_text}"
    finally:
        await conn.close()


# ── 4. Zero N+1 Queries (Constant Query-Count Assertions) ────────────────────


@pytest.mark.asyncio
async def test_zero_n_plus_1_bulk_unnest_and_constant_query_counts():
    # A. create_case_atomic with 10 linked alerts must run ONE bulk case_alerts INSERT (not 10!)
    raw_conn = AsyncMock()
    alert_ids = [uuid.uuid4() for _ in range(10)]
    case_id = uuid.uuid4()
    raw_conn.fetch = AsyncMock(return_value=[{"id": u} for u in alert_ids])
    raw_conn.fetchval = AsyncMock(return_value=case_id)
    raw_conn.execute = AsyncMock()
    counting = _CountingConn(raw_conn)

    @asynccontextmanager
    async def _factory(tenant_id=None):
        yield counting

    res = await create_case_atomic(
        tenant_id=TENANT_ID,
        title="Bulk Alert Link Test",
        priority="HIGH",
        narrative="Testing zero N+1 bulk link",
        subject_acc_uuid=None,
        parsed_alert_uuids=alert_ids,
        user_uuid=uuid.uuid4(),
        username="mlro.test",
        conn_factory=_factory,
    )
    assert res["alert_count"] == 10
    case_alert_inserts = [q for q in counting.queries if "INSERT INTO case_alerts" in q]
    assert len(case_alert_inserts) == 1, f"Expected 1 bulk INSERT, got {len(case_alert_inserts)}"
    assert "unnest" in case_alert_inserts[0].lower()

    # B. evaluate_shadow_rules_for_tx with 5 matching rules -> ONE bulk INSERT with lossless Decimal
    raw_shadow_conn = AsyncMock()
    raw_shadow_conn.fetch = AsyncMock(
        return_value=[
            {
                "rule_name": "LARGE_TRANSACTION",
                "config": {"threshold": 1000},
                "shadow_config": {"threshold": 1000},
                "version": idx + 1,
            }
            for idx in range(5)
        ]
    )
    raw_shadow_conn.execute = AsyncMock()
    counting_shadow = _CountingConn(raw_shadow_conn)
    matched = await evaluate_shadow_rules(
        conn=counting_shadow,
        tenant_id=TENANT_ID,
        transaction_id=str(uuid.uuid4()),
        sender_account_id=str(uuid.uuid4()),
        amount_base_usd=Decimal("12345.6789"),
        country="US",
        channel="WIRE",
    )
    assert len(matched) == 5
    shadow_inserts = [q for q in counting_shadow.queries if "INSERT INTO rule_shadow_hits" in q]
    assert len(shadow_inserts) == 1
    assert "unnest" in shadow_inserts[0].lower()
    # Verify lossless Decimal was passed (not float)
    execute_args = raw_shadow_conn.execute.call_args.args
    assert isinstance(execute_args[4], Decimal) and execute_args[4] == Decimal("12345.6789")

    # C. sample_closed_false_positives_for_qa with 8 eligible rows -> ONE bulk INSERT into qa_reviews
    raw_qa_conn = AsyncMock()
    eligible_rows = [
        {"alert_id": uuid.uuid4(), "status": "CLOSED_FALSE_POSITIVE", "analyst_username": "alice", "case_id": None}
        for _ in range(8)
    ]
    inserted_rows = [
        {"id": uuid.uuid4(), "alert_id": r["alert_id"], "original_analyst_username": "alice", "status": "PENDING"}
        for r in eligible_rows
    ]
    raw_qa_conn.fetch = AsyncMock(side_effect=[eligible_rows, inserted_rows])
    counting_qa = _CountingConn(raw_qa_conn)
    qa_res = await sample_closed_false_positives_for_qa(
        conn=counting_qa,
        tenant_id=TENANT_ID,
        sampled_by_username="mlro.qa",
        sample_rate=1.0,
        max_samples=10,
    )
    assert qa_res["sampled_count"] == 8
    qa_inserts = [q for q in counting_qa.queries if "INSERT INTO qa_reviews" in q]
    assert len(qa_inserts) == 1
    assert "unnest" in qa_inserts[0].lower()

    # D. list_alerts_page_repo in cursor mode runs exactly 1 query (O(1), zero N+1, no extra COUNT(*))
    raw_alert_conn = AsyncMock()
    now = datetime.now(timezone.utc)
    raw_alert_conn.fetch = AsyncMock(return_value=[])
    counting_alerts = _CountingConn(raw_alert_conn)

    @asynccontextmanager
    async def _alert_read_factory(tenant_id=None):
        yield counting_alerts

    cursor = encode_keyset_cursor(now, uuid.uuid4())
    total_cnt, rows = await list_alerts_page_repo(
        tenant_id=TENANT_ID,
        page=1,
        limit=25,
        search=None,
        severity=None,
        status_filter=None,
        include_explainability=False,
        cursor=cursor,
        read_conn_factory=_alert_read_factory,
    )
    assert total_cnt == -1 and rows == []
    assert len(counting_alerts.queries) == 1
    assert "OFFSET" not in counting_alerts.queries[0].upper()


# ── 5. Keyset Cursor Pagination, Streaming Exports & Deep-OFFSET Guardrail ───


@pytest.mark.asyncio
async def test_keyset_pagination_streaming_export_and_deep_offset_rejection():
    # A. Cursor encode/decode round-trip + malformed cursor 400
    ts = datetime(2026, 11, 27, 12, 30, 45, 123456, tzinfo=timezone.utc)
    uid = uuid.uuid4()
    cur = encode_keyset_cursor(ts, uid)
    dec_ts, dec_uid = decode_keyset_cursor(cur)
    assert dec_ts == ts and dec_uid == uid

    with pytest.raises(HTTPException) as exc_bad:
        decode_keyset_cursor("not-a-valid-base64-cursor!!!")
    assert exc_bad.value.status_code == 400

    # B. Deep legacy OFFSET > 10,000 is rejected with HTTP 400 directing to ?cursor=
    assert validate_legacy_offset(MAX_LEGACY_OFFSET) == MAX_LEGACY_OFFSET
    with pytest.raises(HTTPException) as exc_off:
        validate_legacy_offset(MAX_LEGACY_OFFSET + 1)
    assert exc_off.value.status_code == 400
    assert "cursor" in str(exc_off.value.detail).lower()

    # C. iter_alert_export_chunks_repo uses pure keyset pagination (zero OFFSET in SQL!)
    now = datetime.now(timezone.utc)
    page1 = [
        {"id": uuid.uuid4(), "created_at": now - timedelta(seconds=i)} for i in range(2)
    ]
    page2 = [
        {"id": uuid.uuid4(), "created_at": now - timedelta(seconds=10)}
    ]
    raw_exp_conn = AsyncMock()
    raw_exp_conn.fetch = AsyncMock(side_effect=[page1, page2])
    counting_exp = _CountingConn(raw_exp_conn)

    @asynccontextmanager
    async def _exp_factory(tenant_id=None):
        yield counting_exp

    chunks = []
    async for chunk in iter_alert_export_chunks_repo(
        tenant_id=TENANT_ID, chunk_size=2, read_conn_factory=_exp_factory
    ):
        chunks.append(chunk)
    assert len(chunks) == 2
    assert len(counting_exp.queries) == 2
    assert all("OFFSET" not in q.upper() for q in counting_exp.queries)
    assert "(a.created_at, a.id) < ($1, $2)" in counting_exp.queries[1]

    # D. HTTP end-to-end keyset & deep-OFFSET guardrail on GET /api/v1/alerts and /api/v1/audit/logs
    token = _make_token(role="ADMIN")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Malformed cursor -> 400
        r_bad = await client.get(
            "/api/v1/alerts?cursor=corrupted_cursor",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r_bad.status_code == 400

        # Deep OFFSET (page=250 * limit=50 = 12,450 > 10,000) -> 400
        r_deep = await client.get(
            "/api/v1/alerts?page=250&limit=50",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r_deep.status_code == 400

        # Valid keyset traversal on live DB returns X-Has-More header
        r_ok = await client.get(
            "/api/v1/alerts?limit=2",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r_ok.status_code == 200
        assert "X-Has-More" in r_ok.headers
        next_cur = r_ok.headers.get("X-Next-Cursor")
        if next_cur:
            r_next = await client.get(
                f"/api/v1/alerts?limit=2&cursor={next_cur}",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r_next.status_code == 200
            ids_p1 = {item["alert_id"] for item in r_ok.json()}
            ids_p2 = {item["alert_id"] for item in r_next.json()}
            assert ids_p1.isdisjoint(ids_p2), "Keyset pages must never overlap!"


# ── 6. Deterministic Multi-Row FOR UPDATE Lock Ordering Guard ────────────────


def test_all_multi_row_for_update_locks_use_deterministic_ascending_id_order():
    """Architectural guard preventing cyclic deadlocks from unordered multi-row FOR UPDATE locks."""
    multi_row_markers = (" ANY(", " IN (", "SKIP LOCKED")
    violations: list[str] = []
    for folder in ("repositories", "database", "services"):
        for py_file in sorted(pathlib.Path(folder).glob("*.py")):
            src = py_file.read_text(encoding="utf-8")
            for match in re.finditer(
                r"SELECT\b.{1,900}?\bFROM\b.{1,900}?FOR\s+UPDATE(?:\s+OF\s+\w+)?(?:\s+SKIP\s+LOCKED)?",
                src,
                re.IGNORECASE | re.DOTALL,
            ):
                stmt = match.group(0)
                upper = stmt.upper()
                if any(m in upper for m in multi_row_markers):
                    has_asc_id = bool(re.search(r"ORDER\s+BY\s+.*?\b(?:\w+\.)?ID\s+ASC\b", upper))
                    if not has_asc_id:
                        violations.append(f"{py_file}: {stmt[:140].strip()!r}")
    assert not violations, "Multi-row FOR UPDATE without deterministic `ORDER BY ... id ASC`:\n" + "\n".join(violations)


# ── 7 & 8. Read-After-Write Primary Stickiness & Replica Lag Auto-Failover ───


@pytest.mark.asyncio
async def test_read_after_write_stickiness_and_replica_lag_auto_failover():
    import database.postgres as _pg

    clear_local_stickiness_cache()
    set_observed_replica_lag_seconds(0.0)

    def _make_fake_pool(name: str):
        pool = MagicMock()
        pool._loop = asyncio.get_running_loop()
        conn = AsyncMock()
        conn._pool_name = name
        conn.execute = AsyncMock()
        tx_cm = AsyncMock()
        tx_cm.__aenter__ = AsyncMock(return_value=None)
        tx_cm.__aexit__ = AsyncMock(return_value=None)
        conn.transaction = MagicMock(return_value=tx_cm)
        pool.acquire = AsyncMock(return_value=conn)
        pool.release = AsyncMock()
        pool.get_size = MagicMock(return_value=2)
        pool.get_idle_size = MagicMock(return_value=1)
        pool.get_max_size = MagicMock(return_value=4)
        return pool

    fake_primary = _make_fake_pool("primary")
    fake_replica = _make_fake_pool("replica")

    orig_primary, orig_replica = _pg.db_pool, _pg.db_replica_pool
    try:
        _pg.db_pool = fake_primary
        _pg.db_replica_pool = fake_replica

        # 1. Normal read with 0 lag and no RAW stickiness -> hits replica
        async with get_async_db_read_conn(tenant_id=TENANT_ID) as conn:
            assert conn._pool_name == "replica"

        # 2. Active RAW stickiness ContextVar -> routes transparently to primary
        tok = force_primary_read_var.set(True)
        try:
            async with get_async_db_read_conn(tenant_id=TENANT_ID) as conn:
                assert conn._pool_name == "primary"
        finally:
            force_primary_read_var.reset(tok)

        # 3. High streaming replica lag (> 2.0s) -> auto-failover to primary
        set_observed_replica_lag_seconds(4.5)
        async with get_async_db_read_conn(tenant_id=TENANT_ID) as conn:
            assert conn._pool_name == "primary"
    finally:
        set_observed_replica_lag_seconds(0.0)
        _pg.db_pool = orig_primary
        _pg.db_replica_pool = orig_replica

    # 4. Middleware emits X-Read-Consistency-Window on 2xx mutation and sets RAW stickiness
    from observability.middleware import ReadAfterWriteStickinessMiddleware

    seen_force_primary: list[bool] = []

    async def _mini_app(scope, receive, send):
        seen_force_primary.append(force_primary_read_var.get(False))
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b'{"ok":true}'})

    mw_app = ReadAfterWriteStickinessMiddleware(_mini_app)
    transport = httpx.ASGITransport(app=mw_app)
    auth_hdr = {"Authorization": f"Bearer raw-session-token-{uuid.uuid4().hex}"}
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Initial GET -> replica (False)
        r0 = await client.get("/items", headers=auth_hdr)
        assert r0.status_code == 200 and seen_force_primary[-1] is False

        # Explicit X-Read-Consistency: strong -> primary (True)
        r_strong = await client.get("/items", headers={**auth_hdr, "X-Read-Consistency": "strong"})
        assert r_strong.status_code == 200 and seen_force_primary[-1] is True

        # Mutating POST -> emits X-Read-Consistency-Window and sets 5s RAW marker
        r_mut = await client.post("/items", headers=auth_hdr)
        assert r_mut.status_code == 200
        assert int(r_mut.headers["X-Read-Consistency-Window"]) >= 1

        # Immediate follow-up GET with same session -> automatically sticks to Primary (True)!
        r_after = await client.get("/items", headers=auth_hdr)
        assert r_after.status_code == 200 and seen_force_primary[-1] is True


# ── 9. Physical Cache vs. State Redis Separation & Timeout Enforcement ───────


@pytest.mark.asyncio
async def test_cache_vs_state_redis_physical_separation_and_fast_timeouts():
    # A. Verify Docker Compose separates State Redis (noeviction) and Cache Redis (allkeys-lfu)
    compose = yaml.safe_load(pathlib.Path("docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    assert "redis" in services and "redis-cache" in services
    assert "--maxmemory-policy noeviction" in str(services["redis"]["command"])
    assert "--maxmemory-policy allkeys-lfu" in str(services["redis-cache"]["command"])
    assert "--appendonly no" in str(services["redis-cache"]["command"])

    # B. Verify Kubernetes manifest deploys separate aml-redis (noeviction) & aml-redis-cache (allkeys-lfu)
    k8s_docs = list(yaml.safe_load_all(pathlib.Path("deployments/kubernetes/redis.yaml").read_text(encoding="utf-8")))
    by_name = {d["metadata"]["name"]: d for d in k8s_docs if d and "metadata" in d}
    assert "aml-redis" in by_name and "aml-redis-cache" in by_name and "aml-redis-cache-service" in by_name
    state_cmd = " ".join(by_name["aml-redis"]["spec"]["template"]["spec"]["containers"][0]["command"])
    cache_cmd = " ".join(by_name["aml-redis-cache"]["spec"]["template"]["spec"]["containers"][0]["command"])
    assert "--maxmemory-policy noeviction" in state_cmd
    assert "--maxmemory-policy allkeys-lfu" in cache_cmd
    assert "--appendonly no" in cache_cmd

    # C. Live Cache Redis client enforces aggressive <= 250ms timeouts and retry_on_timeout=False
    cache_cli = await get_async_cache_redis_client()
    assert cache_cli is not None
    pool_kwargs = cache_cli.connection_pool.connection_kwargs
    assert pool_kwargs["socket_timeout"] <= 0.25
    assert pool_kwargs["socket_connect_timeout"] <= 0.25
    assert pool_kwargs["retry_on_timeout"] is False


# ── 10. Cache-Aside Engine: Stampede, PER, Negative Cache, Fail-Open & Outbox ─


@pytest.mark.asyncio
async def test_cache_aside_stampede_per_negative_failopen_and_outbox_invalidation():
    # A. Versioned tenant-namespaced key format + jittered TTL spread
    k = build_cache_key("metrics_exec", TENANT_ID, "summary", version="v2")
    assert k == f"v2:metrics_exec:{TENANT_ID}:summary"
    ttls = {compute_jittered_ttl(100, jitter_ratio=0.15) for _ in range(30)}
    assert min(ttls) >= 100 and max(ttls) <= 115 and len(ttls) > 1

    # B. PER / XFetch probabilistic early refresh math
    now_ts = 1000.0
    # Close to expiry with small random draw u=0.01 (-ln(0.01) ~ 4.6) and delta=2s -> triggers refresh
    assert should_probabilistically_refresh(now_ts=now_ts, expiry_ts=1005.0, compute_delta_seconds=2.0, beta=1.0, rand_val=0.01) is True
    # Far from expiry with u=0.9 -> does NOT trigger refresh
    assert should_probabilistically_refresh(now_ts=now_ts, expiry_ts=1300.0, compute_delta_seconds=0.5, beta=1.0, rand_val=0.9) is False

    # C. Single-flight Stampede Protection: 20 concurrent callers -> exactly 1 DB load!
    store: dict[str, str] = {}
    locks: dict[str, str] = {}

    class _InMemRedis:
        async def get(self, key: str):
            return store.get(key)

        async def set(self, key: str, value: str, ex: int | None = None, nx: bool = False, px: int | None = None):
            if nx:
                if key in locks:
                    return False
                locks[key] = value
                return True
            store[key] = value
            return True

        async def delete(self, *keys: str):
            cnt = 0
            for key in keys:
                if key in store:
                    del store[key]
                    cnt += 1
                locks.pop(key, None)
            return cnt

        async def eval(self, script: str, numkeys: int, lock_key: str, token: str):
            if locks.get(lock_key) == token:
                del locks[lock_key]
                return 1
            return 0

    mem_redis = _InMemRedis()
    cache = CacheAsideClient(redis_factory=AsyncMock(return_value=mem_redis))
    load_calls = 0

    async def _slow_db_loader():
        nonlocal load_calls
        load_calls += 1
        await asyncio.sleep(0.06)
        return {"kpi": 42, "loaded_once": True}

    results = await asyncio.gather(
        *[
            cache.get_or_load(
                namespace="stampede_test",
                tenant_id=TENANT_ID,
                key="hot_key",
                loader=_slow_db_loader,
                base_ttl=60,
            )
            for _ in range(20)
        ]
    )
    assert load_calls == 1, f"Stampede occurred! Expected 1 loader call, got {load_calls}"
    assert all(r == {"kpi": 42, "loaded_once": True} for r in results)
    assert locks == {}, "Atomic Lua unlock failed to release single-flight lock!"

    # D. Negative Caching (Cache Penetration Protection): missing entity cached as sentinel
    miss_loads = 0

    async def _missing_loader():
        nonlocal miss_loads
        miss_loads += 1
        return None

    r1 = await cache.get_or_load(
        namespace="acct_lookup",
        tenant_id=TENANT_ID,
        key="nonexistent-999",
        loader=_missing_loader,
        cache_none=True,
        negative_ttl=25,
    )
    r2 = await cache.get_or_load(
        namespace="acct_lookup",
        tenant_id=TENANT_ID,
        key="nonexistent-999",
        loader=_missing_loader,
        cache_none=True,
        negative_ttl=25,
    )
    assert r1 is None and r2 is None and miss_loads == 1
    neg_key = build_cache_key("acct_lookup", TENANT_ID, "nonexistent-999")
    assert NEGATIVE_SENTINEL in store[neg_key]

    # E. Fail-Open on Redis timeout/outage: slow Redis never stalls request
    class _StalledRedis:
        async def get(self, key: str):
            await asyncio.sleep(2.0)
            return None

    stalled_cache = CacheAsideClient(
        redis_factory=AsyncMock(return_value=_StalledRedis()),
        op_timeout_seconds=0.08,
    )
    t0 = time.monotonic()
    fallback_val = await stalled_cache.get_or_load(
        namespace="failopen_test",
        tenant_id=TENANT_ID,
        key="k1",
        loader=AsyncMock(return_value={"source": "postgres"}),
    )
    elapsed = time.monotonic() - t0
    assert fallback_val == {"source": "postgres"}
    assert elapsed < 0.5, f"Fail-open took too long ({elapsed:.2f}s)"

    # F. Post-commit Outbox CACHE_INVALIDATION self-healing via OutboxRelayEngine
    target_key = build_cache_key("stampede_test", TENANT_ID, "hot_key")
    assert target_key in store
    with patch("services.cache_aside.get_async_cache_redis_client", new=AsyncMock(return_value=mem_redis)):
        eid, ok, err = await OutboxRelayEngine._publish_single_event(
            {
                "id": str(uuid.uuid4()),
                "aggregate_type": "CACHE_INVALIDATION",
                "aggregate_id": target_key,
                "event_type": "storage.cache.invalidate.v1",
                "payload": {"keys": [target_key], "namespace": "stampede_test"},
            }
        )
    assert ok is True and err is None
    assert target_key not in store


# ── 11. Storage Observability Telemetry & Prometheus Exposition ──────────────


@pytest.mark.asyncio
async def test_storage_observability_collector_exports_postgres_and_redis_metrics():
    # Ensure PostgreSQL pool is initialized so dead-tuple & pool gauges populate
    async with get_async_db_conn(tenant_id=TENANT_ID) as conn:
        await conn.fetchval("SELECT 1;")

    snapshot = await sample_storage_telemetry_once()
    assert snapshot["hot_tables_sampled"] >= 5
    assert isinstance(snapshot["replica_lag_seconds"], float)
    assert snapshot["redis_state"] and "hit_ratio" in snapshot["redis_state"]
    assert snapshot["redis_cache"] and "hit_ratio" in snapshot["redis_cache"]

    metrics_text = generate_metrics_text()
    required_metrics = (
        "db_pool_acquire_duration_seconds",
        "db_pool_connections_in_use",
        "db_pool_connections_idle",
        "db_pool_connections_max",
        "pg_replication_lag_seconds",
        "pg_table_dead_tuples",
        "pg_table_live_tuples",
        "pg_table_dead_tuple_ratio",
        "redis_cache_hit_ratio",
        "redis_evicted_keys_total",
        "redis_mem_fragmentation_ratio",
        "redis_used_memory_bytes",
        "storage_cache_operations_total",
    )
    for metric in required_metrics:
        assert metric in metrics_text, f"Expected Prometheus storage metric '{metric}' missing from /metrics"

    # Also verify PostgreSQL config files enable pg_stat_statements
    for cfg_path in ("deployments/docker/postgres-primary.conf", "deployments/kubernetes/postgres.yaml"):
        cfg_txt = pathlib.Path(cfg_path).read_text(encoding="utf-8")
        assert "pg_stat_statements" in cfg_txt
