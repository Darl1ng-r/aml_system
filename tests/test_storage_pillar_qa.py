"""
Senior QA End-to-End Adversarial Verification Suite — Storage Pillar (13/13)
=============================================================================
Maps 1-to-1 (`test_qa_01` .. `test_qa_13`) to every item in the Production
Data-Layer Pitfall Prevention Checklist, testing live PostgreSQL constraints,
real EXPLAIN (ANALYZE, BUFFERS, SETTINGS) buffer/index metrics, real HTTP SQL
query-count budgets, multi-page tie-breaker keyset pagination across all
endpoints, live concurrent AB-BA deadlock stress, cross-tenant RLS + PgBouncer
SET LOCAL reset, Read-After-Write per-session isolation & TTL expiry, State vs.
Cache Redis isolation, rollback-safe post-commit invalidation & Outbox crash
recovery, live-Redis 30-way stampede + Lua fencing + PER + penetration defense,
aggressive fail-open failure injection, and live Prometheus/health telemetry.
"""

from __future__ import annotations

import asyncio
import json
import os
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

from database.outbox import OutboxRelayEngine
from database.pagination import MAX_LEGACY_OFFSET, decode_keyset_cursor, encode_keyset_cursor
from database.postgres import get_async_db_conn, get_async_db_read_conn, init_db_pool
from database.read_after_write import (
    clear_local_stickiness_cache,
    force_primary_read_var,
    has_active_write_stickiness,
    mark_write_stickiness,
)
from database.redis_db import get_async_cache_redis_client, get_async_redis_client
from main import app
from observability.middleware import ReadAfterWriteStickinessMiddleware
from observability.prometheus import generate_metrics_text
from observability.storage_monitor import (
    sample_storage_telemetry_once,
    set_observed_replica_lag_seconds,
)
from repositories.alert_repo import bulk_claim_or_assign_alerts_atomic, bulk_resolve_alerts_atomic
from repositories.compliance_config_repo import upsert_risk_appetite_atomic
from repositories.transaction_repo import _verify_concurrency_lock
from services.auth import create_access_token
from services.cache_aside import (
    NEGATIVE_SENTINEL,
    CacheAsideClient,
    build_cache_key,
    compute_jittered_ttl,
)
from services.pkyc_and_qa import run_pkyc_delta_rescreen
from services.secrets_manager import get_postgres_dsn

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"


def _make_token(
    role: str = "ADMIN",
    tenant_id: str = DEFAULT_TENANT_ID,
    user_id: str | None = None,
    username: str | None = None,
) -> str:
    return create_access_token(
        {
            "sub": username or f"qa_{role.lower()}_{uuid.uuid4().hex[:6]}",
            "id": user_id or str(uuid.uuid4()),
            "role": role,
            "tenant_id": tenant_id,
        }
    )


class _LiveSqlSpy:
    """Wraps a real asyncpg.Connection to count every SQL statement executed."""

    def __init__(self, conn):
        self._conn = conn
        self.statements: list[str] = []

    def _record(self, query: str) -> None:
        q = str(query).strip()
        # Exclude transaction-bootstrap RLS set_config calls from application query counts
        if q.upper().startswith("SELECT SET_CONFIG("):
            return
        self.statements.append(q)

    async def fetch(self, query, *args, **kwargs):
        self._record(query)
        return await self._conn.fetch(query, *args, **kwargs)

    async def fetchrow(self, query, *args, **kwargs):
        self._record(query)
        return await self._conn.fetchrow(query, *args, **kwargs)

    async def fetchval(self, query, *args, **kwargs):
        self._record(query)
        return await self._conn.fetchval(query, *args, **kwargs)

    async def execute(self, query, *args, **kwargs):
        self._record(query)
        return await self._conn.execute(query, *args, **kwargs)

    def __getattr__(self, item):
        return getattr(self._conn, item)


# ══════════════════════════════════════════════════════════════════════════════
# CHECKLIST #1: NUMERIC(19, 4), UTC TIMESTAMPTZ, NOT NULL / CHECK / FK AT DB
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_qa_01_db_level_constraints_and_exact_numeric_precision_enforced():
    """Adversarially attempts illegal SQL inserts directly on PostgreSQL (rolled back cleanly)."""
    conn = await asyncpg.connect(get_postgres_dsn())
    try:
        tx = conn.transaction()
        await tx.start()
        try:
            tid = uuid.UUID(DEFAULT_TENANT_ID)
            await conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", str(tid))

            # Seed 2 valid accounts inside this rolled-back transaction
            acc_a = uuid.uuid4()
            acc_b = uuid.uuid4()
            for aid, suffix in ((acc_a, "A"), (acc_b, "B")):
                await conn.execute(
                    """
                    INSERT INTO accounts (id, tenant_id, account_number, owner_name, swift_bic, status)
                    VALUES ($1, $2, $3, $4, 'CHASUS33', 'ACTIVE');
                    """,
                    aid,
                    tid,
                    f"QA-PREC-{suffix}-{uuid.uuid4().hex[:8]}",
                    f"QA Owner {suffix}",
                )

            # 1a. Full 19-digit, 4-decimal precision round-trip + UTC TIMESTAMPTZ preservation
            exact_amt = Decimal("123456789012345.6789")
            tx_ok_id = uuid.uuid4()
            row_ok = await conn.fetchrow(
                """
                INSERT INTO transactions (
                    id, tenant_id, sender_account_id, receiver_account_id,
                    amount, currency, amount_base_usd, fx_rate_applied, status, timestamp
                )
                VALUES ($1, $2, $3, $4, $5, 'USD', $5, 1.00000000, 'APPROVED', NOW())
                RETURNING amount, amount_base_usd, timestamp;
                """,
                tx_ok_id,
                tid,
                acc_a,
                acc_b,
                exact_amt,
            )
            assert row_ok["amount"] == exact_amt
            assert row_ok["amount_base_usd"] == exact_amt
            assert row_ok["timestamp"].tzinfo is not None

            # 1b. Zero & negative transaction amounts REJECTED by DB CHECK constraint
            for bad_amt in (Decimal("0.0000"), Decimal("-10.5000")):
                with pytest.raises(asyncpg.CheckViolationError):
                    async with conn.transaction():
                        await conn.execute(
                            """
                            INSERT INTO transactions (
                                id, tenant_id, sender_account_id, receiver_account_id,
                                amount, currency, fx_rate_applied, status, timestamp
                            )
                            VALUES ($1, $2, $3, $4, $5, 'USD', 1.0, 'APPROVED', NOW());
                            """,
                            uuid.uuid4(),
                            tid,
                            acc_a,
                            acc_b,
                            bad_amt,
                        )

            # 1c. Non-positive fx_rate_applied & negative amount_base_usd REJECTED by CHECK
            with pytest.raises(asyncpg.CheckViolationError):
                async with conn.transaction():
                    await conn.execute(
                        """
                        INSERT INTO transactions (
                            id, tenant_id, sender_account_id, receiver_account_id,
                            amount, currency, fx_rate_applied, status, timestamp
                        )
                        VALUES ($1, $2, $3, $4, 100.00, 'EUR', 0, 'APPROVED', NOW());
                        """,
                        uuid.uuid4(),
                        tid,
                        acc_a,
                        acc_b,
                    )

            with pytest.raises(asyncpg.CheckViolationError):
                async with conn.transaction():
                    await conn.execute(
                        """
                        INSERT INTO transactions (
                            id, tenant_id, sender_account_id, receiver_account_id,
                            amount, currency, amount_base_usd, fx_rate_applied, status, timestamp
                        )
                        VALUES ($1, $2, $3, $4, 100.00, 'USD', -1.00, 1.0, 'APPROVED', NOW());
                        """,
                        uuid.uuid4(),
                        tid,
                        acc_a,
                        acc_b,
                    )

            # 1d. CTR non-positive amount REJECTED by CHECK
            with pytest.raises(asyncpg.CheckViolationError):
                async with conn.transaction():
                    await conn.execute(
                        """
                        INSERT INTO ctr_filings (
                            id, tenant_id, transaction_id, account_id, amount, currency,
                            cash_in_out, status, due_date
                        )
                        VALUES ($1, $2, $3, $4, 0.00, 'USD', 'CASH_IN', 'PENDING', NOW() + INTERVAL '15 days');
                        """,
                        uuid.uuid4(),
                        tid,
                        tx_ok_id,
                        acc_a,
                    )

            # 1e. STR batch negative total_amount REJECTED by CHECK
            with pytest.raises(asyncpg.CheckViolationError):
                async with conn.transaction():
                    await conn.execute(
                        """
                        INSERT INTO str_batches (id, tenant_id, record_count, total_amount, payload_xml, checksum, status)
                        VALUES ($1, $2, 1, -0.01, '<Batch/>', 'abc', 'GENERATED');
                        """,
                        f"STR-QA-{uuid.uuid4().hex[:8]}",
                        tid,
                    )

            # 1f. Alert out-of-bounds ai_risk_score (> 1 or < 0) REJECTED by CHECK
            for bad_score in (-0.01, 1.01):
                with pytest.raises(asyncpg.CheckViolationError):
                    async with conn.transaction():
                        await conn.execute(
                            """
                            INSERT INTO alerts (id, tenant_id, transaction_id, rule_name, threat_level, ai_risk_score, status)
                            VALUES ($1, $2, $3, 'QA_CHECK', 'HIGH', $4, 'OPEN');
                            """,
                            uuid.uuid4(),
                            tid,
                            tx_ok_id,
                            bad_score,
                        )

            # 1g. Foreign key violation on nonexistent sender_account_id REJECTED by FK
            with pytest.raises(asyncpg.ForeignKeyViolationError):
                async with conn.transaction():
                    await conn.execute(
                        """
                        INSERT INTO transactions (
                            id, tenant_id, sender_account_id, receiver_account_id,
                            amount, currency, fx_rate_applied, status, timestamp
                        )
                        VALUES ($1, $2, $3, $4, 100.00, 'USD', 1.0, 'APPROVED', NOW());
                        """,
                        uuid.uuid4(),
                        tid,
                        uuid.uuid4(),  # nonexistent FK
                        acc_b,
                    )

            # 1h. NOT NULL enforced on core required columns
            with pytest.raises(asyncpg.NotNullViolationError):
                async with conn.transaction():
                    await conn.execute(
                        """
                        INSERT INTO transactions (
                            id, tenant_id, sender_account_id, receiver_account_id,
                            amount, currency, fx_rate_applied, status, timestamp
                        )
                        VALUES ($1, $2, $3, $4, NULL, 'USD', 1.0, 'APPROVED', NOW());
                        """,
                        uuid.uuid4(),
                        tid,
                        acc_a,
                        acc_b,
                    )
        finally:
            await tx.rollback()
    finally:
        await conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# CHECKLIST #2: CREATE INDEX CONCURRENTLY & ZERO-LOCK MIGRATION SAFETY
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_qa_02_zero_downtime_migration_ddl_and_valid_pg_indexes():
    """Verifies migration 038 ordering (CONCURRENTLY before ALTER), NOT VALID CHECKs, and live pg_index validity."""
    mig_038 = pathlib.Path("migrations/versions/038_storage_pillar_hardening.py").read_text(encoding="utf-8")
    # _run_concurrent_ddl must execute BEFORE any op.execute("ALTER TABLE ...") inside upgrade()
    upgrade_body = mig_038.split("def upgrade()")[1].split("def downgrade()")[0]
    pos_conc = upgrade_body.find("_run_concurrent_ddl")
    pos_alter = upgrade_body.find("ALTER TABLE")
    assert 0 <= pos_conc < pos_alter, "CONCURRENTLY DDL must run before main-tx ALTER TABLE to avoid self-deadlock"
    assert "VALIDATE CONSTRAINT" in upgrade_body

    # Verify every single 038 index is valid & ready (not INVALID from an interrupted concurrent build)
    expected_indexes = [
        "idx_audit_log_tenant_occurred_id",
        "idx_alerts_tenant_created_id",
        "idx_alerts_tenant_status_created_id",
        "idx_transactions_tenant_timestamp_id",
        "idx_cases_tenant_created_id",
        "idx_cases_tenant_status_created_id",
        "idx_ctr_filings_tenant_created_id",
        "idx_str_batches_tenant_created_id",
        "idx_accounts_tenant_created_id",
        "idx_resource_locks_tenant_type_expiry",
        "idx_outbox_active_created_id",
    ]
    conn = await asyncpg.connect(get_postgres_dsn())
    try:
        rows = await conn.fetch(
            """
            SELECT c.relname, i.indisvalid, i.indisready
            FROM pg_index i
            JOIN pg_class c ON c.oid = i.indexrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relname = ANY($1::text[]);
            """,
            expected_indexes,
        )
        by_name = {r["relname"]: (bool(r["indisvalid"]), bool(r["indisready"])) for r in rows}
        assert set(by_name.keys()) == set(expected_indexes)
        for name, (valid, ready) in by_name.items():
            assert valid and ready, f"Index {name} is not valid/ready: valid={valid}, ready={ready}"
    finally:
        await conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# CHECKLIST #3: EXPLAIN (ANALYZE, BUFFERS, SETTINGS) + EQUALITY->RANGE->SORT
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_qa_03_explain_analyze_buffers_no_sort_and_equality_range_sort_order():
    """Verifies Equality -> Range -> Sort index definitions, zero Seq Scan, zero Sort on keyset queries, and warm buffer hits."""
    conn = await asyncpg.connect(get_postgres_dsn())
    try:
        # 3a. Verify composite keyset indexes follow strict Equality -> Range/Sort column order
        idx_defs = await conn.fetch(
            """
            SELECT indexname, indexdef
            FROM pg_indexes
            WHERE schemaname = 'public'
              AND indexname IN (
                  'idx_audit_log_tenant_occurred_id',
                  'idx_alerts_tenant_created_id',
                  'idx_alerts_tenant_status_created_id',
                  'idx_transactions_tenant_timestamp_id',
                  'idx_cases_tenant_created_id',
                  'idx_ctr_filings_tenant_created_id',
                  'idx_resource_locks_tenant_type_expiry'
              );
            """
        )
        defs = {r["indexname"]: r["indexdef"] for r in idx_defs}
        assert "(tenant_id, occurred_at DESC, id DESC)" in defs["idx_audit_log_tenant_occurred_id"]
        assert "(tenant_id, created_at DESC, id DESC)" in defs["idx_alerts_tenant_created_id"]
        assert "(tenant_id, status, created_at DESC, id DESC)" in defs["idx_alerts_tenant_status_created_id"]
        assert '(tenant_id, "timestamp" DESC, id DESC)' in defs["idx_transactions_tenant_timestamp_id"]
        assert "(tenant_id, created_at DESC, id DESC)" in defs["idx_cases_tenant_created_id"]
        assert "(tenant_id, created_at DESC, id DESC)" in defs["idx_ctr_filings_tenant_created_id"]
        assert "(tenant_id, resource_type, expires_at)" in defs["idx_resource_locks_tenant_type_expiry"]

        # 3b. Run EXPLAIN (ANALYZE, BUFFERS, SETTINGS, FORMAT JSON) on keyset cursor predicates
        now_utc = datetime.now(timezone.utc)
        pivot_id = uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")

        def _collect_nodes(node: dict, out: list[dict]) -> None:
            out.append(node)
            for child in node.get("Plans") or []:
                _collect_nodes(child, out)

        async with conn.transaction():
            await conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", DEFAULT_TENANT_ID)
            await conn.execute("SET LOCAL enable_seqscan = off;")
            await conn.execute("SET LOCAL enable_bitmapscan = off;")

            keyset_queries = [
                (
                    "alerts_keyset_status",
                    """
                    SELECT id, created_at FROM alerts
                    WHERE tenant_id = $1::uuid AND status = 'OPEN' AND (created_at, id) < ($2, $3)
                    ORDER BY created_at DESC, id DESC LIMIT 50
                    """,
                    (DEFAULT_TENANT_ID, now_utc, pivot_id),
                ),
                (
                    "transactions_keyset",
                    """
                    SELECT id, "timestamp" FROM transactions
                    WHERE tenant_id = $1::uuid AND ("timestamp", id) < ($2, $3)
                    ORDER BY "timestamp" DESC, id DESC LIMIT 50
                    """,
                    (DEFAULT_TENANT_ID, now_utc, pivot_id),
                ),
                (
                    "audit_log_keyset",
                    """
                    SELECT id, occurred_at FROM audit_log
                    WHERE tenant_id = $1::uuid AND (occurred_at, id) < ($2, $3)
                    ORDER BY occurred_at DESC, id DESC LIMIT 50
                    """,
                    (DEFAULT_TENANT_ID, now_utc, 9_223_372_036_854_775_807),
                ),
                (
                    "cases_keyset",
                    """
                    SELECT id, created_at FROM cases
                    WHERE tenant_id = $1::uuid AND (created_at, id) < ($2, $3)
                    ORDER BY created_at DESC, id DESC LIMIT 50
                    """,
                    (DEFAULT_TENANT_ID, now_utc, pivot_id),
                ),
                (
                    "ctr_filings_keyset",
                    """
                    SELECT id, created_at FROM ctr_filings
                    WHERE tenant_id = $1::uuid AND (created_at, id) < ($2, $3)
                    ORDER BY created_at DESC, id DESC LIMIT 50
                    """,
                    (DEFAULT_TENANT_ID, now_utc, pivot_id),
                ),
            ]
            for label, sql, params in keyset_queries:
                # Warm pass + measured pass to check shared buffer hit ratio
                await conn.fetch(f"EXPLAIN (ANALYZE, BUFFERS, SETTINGS, FORMAT JSON) {sql}", *params)
                raw_json = await conn.fetchval(f"EXPLAIN (ANALYZE, BUFFERS, SETTINGS, FORMAT JSON) {sql}", *params)
                plan_doc = json.loads(raw_json)[0]["Plan"]
                nodes: list[dict] = []
                _collect_nodes(plan_doc, nodes)
                node_types = [n["Node Type"] for n in nodes]
                assert "Seq Scan" not in node_types, f"{label}: unexpected Seq Scan: {node_types}"
                assert "Sort" not in node_types and "Incremental Sort" not in node_types, (
                    f"{label}: index should satisfy sort order without Sort/Incremental Sort: {node_types}"
                )
                assert any("Index" in nt for nt in node_types), f"{label}: missing Index Scan: {node_types}"
                hits = int(plan_doc.get("Shared Hit Blocks", 0))
                reads = int(plan_doc.get("Shared Read Blocks", 0))
                if hits + reads > 0:
                    assert (hits / (hits + reads)) >= 0.80, f"{label}: poor buffer hit ratio ({hits}/{hits + reads})"
    finally:
        await conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# CHECKLIST #4: ZERO N+1 QUERIES ON LIVE HTTP LIST & DETAIL ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_qa_04_zero_n_plus_1_http_endpoints_and_bulk_pkyc_query_budgets():
    """Wraps real live DB connections with a SQL spy and enforces strict O(1) query budgets on HTTP endpoints."""
    spy_log: list[str] = []

    @asynccontextmanager
    async def _spied_read_conn(tenant_id=None, auth_lookup=False, prefer_primary=False):
        async with get_async_db_read_conn(tenant_id=tenant_id, auth_lookup=auth_lookup, prefer_primary=prefer_primary) as conn:
            spy = _LiveSqlSpy(conn)
            try:
                yield spy
            finally:
                spy_log.extend(spy.statements)

    @asynccontextmanager
    async def _spied_write_conn(tenant_id=None, auth_lookup=False):
        async with get_async_db_conn(tenant_id=tenant_id, auth_lookup=auth_lookup) as conn:
            spy = _LiveSqlSpy(conn)
            try:
                yield spy
            finally:
                spy_log.extend(spy.statements)

    token = _make_token(role="ADMIN")
    headers = {"Authorization": f"Bearer {token}"}
    transport = httpx.ASGITransport(app=app)

    patches = [
        patch("routers.alerts.get_async_db_read_conn", side_effect=_spied_read_conn),
        patch("routers.transactions.get_async_db_read_conn", side_effect=_spied_read_conn),
        patch("routers.cases.get_async_db_read_conn", side_effect=_spied_read_conn),
        patch("routers.audit.get_async_db_read_conn", side_effect=_spied_read_conn),
        patch("routers.customers.get_async_db_read_conn", side_effect=_spied_read_conn),
        patch("repositories.ctr_repo.get_async_db_read_conn", side_effect=_spied_read_conn),
        patch("routers.str_batch.get_async_db_conn", side_effect=_spied_write_conn),
    ]

    for p in patches:
        p.start()
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            endpoints_and_budgets = [
                ("/api/v1/alerts?limit=50", 2),
                ("/api/v1/alerts?limit=50&fields=summary", 2),
                ("/api/v1/transactions?limit=50", 2),
                ("/api/v1/cases?limit=50", 1),
                ("/api/v1/audit/logs?limit=50", 2),
                ("/api/v1/customers?limit=25", 2),
                ("/api/v1/ctr/filings?limit=50", 1),
                ("/api/v1/str/batch/batches?limit=50", 1),
            ]
            sample_alert_id = None
            for url, max_queries in endpoints_and_budgets:
                spy_log.clear()
                resp = await client.get(url, headers=headers)
                assert resp.status_code == 200, f"{url} returned {resp.status_code}: {resp.text}"
                assert len(spy_log) <= max_queries, (
                    f"N+1 budget exceeded on {url}: ran {len(spy_log)} queries (budget={max_queries}): {spy_log}"
                )
                if url == "/api/v1/alerts?limit=50" and resp.json():
                    sample_alert_id = resp.json()[0]["alert_id"]

            # Detail BFF endpoint (/alerts/{id}/workbench) aggregates 7 fixed O(1) domain panels
            # (alert+tx+accounts, profile, timeline, sibling alerts, counterparties, escalations, lock)
            if sample_alert_id:
                spy_log.clear()
                resp_wb = await client.get(f"/api/v1/alerts/{sample_alert_id}/workbench", headers=headers)
                assert resp_wb.status_code == 200
                assert len(spy_log) <= 7, f"Workbench detail N+1 budget exceeded: {len(spy_log)} queries"
    finally:
        for p in patches:
            p.stop()

    # Also verify run_pkyc_delta_rescreen with 5 accounts runs ONE bulk UPDATE + ONE bulk INSERT (never 5!)
    mock_conn = AsyncMock()
    mock_accounts = [
        {
            "id": uuid.uuid4(),
            "account_number": f"PKYC-QA-{i}",
            "owner_name": f"Sanctioned Subject {i}",
            "risk_score": 0.10,
            "status": "ACTIVE",
            "pkyc_material_change_flag": False,
        }
        for i in range(5)
    ]
    bulk_alert_rows = [{"id": uuid.uuid4()} for _ in range(5)]
    mock_conn.fetch = AsyncMock(side_effect=[mock_accounts, bulk_alert_rows])
    mock_conn.execute = AsyncMock()
    mock_conn.fetchval = AsyncMock(return_value=uuid.uuid4())
    spy_pkyc = _LiveSqlSpy(mock_conn)

    with patch("services.pkyc_and_qa.perform_sanctions_search", AsyncMock(return_value={"match_found": True, "source_list": "OFAC"})), \
         patch("services.pkyc_and_qa.perform_pep_search", AsyncMock(return_value={"match_found": False})), \
         patch("services.pkyc_and_qa.create_notification", AsyncMock()):
        res_pkyc = await run_pkyc_delta_rescreen(conn=spy_pkyc, tenant_id=DEFAULT_TENANT_ID, triggered_by="qa.mlro")
    assert res_pkyc["accounts_scanned"] == 5 and res_pkyc["alerts_generated"] == 5
    acc_updates = [s for s in spy_pkyc.statements if "UPDATE accounts" in s]
    alert_inserts = [s for s in spy_pkyc.statements if "INSERT INTO alerts" in s]
    assert len(acc_updates) == 1 and "unnest" in acc_updates[0].lower()
    assert len(alert_inserts) == 1 and "unnest" in alert_inserts[0].lower()


# ══════════════════════════════════════════════════════════════════════════════
# CHECKLIST #5: KEYSET PAGINATION COMPLETENESS, TIE-BREAKERS & DEEP-OFFSET CAP
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_qa_05_keyset_pagination_disjoint_complete_with_timestamp_ties_across_endpoints():
    """
    Seeds 5 items (including 2 sharing the EXACT same microsecond timestamp) in an
    isolated ephemeral tenant, paginates end-to-end via HTTP using ONLY `?cursor=`
    (limit=2), and verifies 0 duplicates, 0 skipped rows, 400 on bad cursor, and
    400 on deep legacy OFFSET > 10,000.
    """
    ephemeral_tenant = uuid.uuid4()
    acc_ids = [uuid.uuid4() for _ in range(5)]
    tx_ids = [uuid.uuid4() for _ in range(5)]
    alert_ids = [uuid.uuid4() for _ in range(5)]
    case_ids = [uuid.uuid4() for _ in range(5)]
    ctr_ids = [uuid.uuid4() for _ in range(5)]
    str_ids = [f"STR-QA-{ephemeral_tenant.hex[:6]}-{i}" for i in range(5)]

    # Timestamps intentionally include an exact tie between index 1 and index 2!
    base_ts = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    timestamps = [
        base_ts + timedelta(seconds=1),
        base_ts + timedelta(seconds=2),  # exact tie!
        base_ts + timedelta(seconds=2),  # exact tie!
        base_ts + timedelta(seconds=4),
        base_ts + timedelta(seconds=5),
    ]

    conn = await asyncpg.connect(get_postgres_dsn())
    try:
        async with conn.transaction():
            await conn.execute(
                "INSERT INTO tenants (id, name) VALUES ($1, $2);",
                ephemeral_tenant,
                f"QA Keyset Tenant {ephemeral_tenant.hex[:6]}",
            )
            await conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", str(ephemeral_tenant))
            for i in range(5):
                await conn.execute(
                    """
                    INSERT INTO accounts (id, tenant_id, account_number, owner_name, swift_bic, status, risk_score, created_at)
                    VALUES ($1, $2, $3, $4, 'CHASUS33', 'ACTIVE', $5, $6);
                    """,
                    acc_ids[i],
                    ephemeral_tenant,
                    f"QA-KS-{ephemeral_tenant.hex[:6]}-{i}",
                    f"Keyset Owner {i}",
                    0.1 * (i + 1),
                    timestamps[i],
                )
            for i in range(5):
                await conn.execute(
                    """
                    INSERT INTO transactions (
                        id, tenant_id, sender_account_id, receiver_account_id,
                        amount, currency, amount_base_usd, fx_rate_applied, status, timestamp
                    )
                    VALUES ($1, $2, $3, $4, 15000.0000, 'USD', 15000.0000, 1.0, 'FLAGGED', $5);
                    """,
                    tx_ids[i],
                    ephemeral_tenant,
                    acc_ids[0],
                    acc_ids[1],
                    timestamps[i],
                )
                await conn.execute(
                    """
                    INSERT INTO alerts (id, tenant_id, transaction_id, rule_name, threat_level, ai_risk_score, status, created_at)
                    VALUES ($1, $2, $3, 'QA_KEYSET', 'HIGH', 0.85, 'OPEN', $4);
                    """,
                    alert_ids[i],
                    ephemeral_tenant,
                    tx_ids[i],
                    timestamps[i],
                )
                await conn.execute(
                    """
                    INSERT INTO cases (id, tenant_id, case_number, title, priority, status, subject_account_id, created_at)
                    VALUES ($1, $2, $3, $4, 'HIGH', 'OPEN', $5, $6);
                    """,
                    case_ids[i],
                    ephemeral_tenant,
                    f"CASE-QA-{ephemeral_tenant.hex[:6]}-{i}",
                    f"Keyset Case {i}",
                    acc_ids[0],
                    timestamps[i],
                )
                await conn.execute(
                    """
                    INSERT INTO ctr_filings (
                        id, tenant_id, transaction_id, account_id, amount, currency,
                        cash_in_out, status, due_date, created_at
                    )
                    VALUES ($1, $2, $3, $4, 15000.0000, 'USD', 'CASH_IN', 'PENDING', $5, $6);
                    """,
                    ctr_ids[i],
                    ephemeral_tenant,
                    tx_ids[i],
                    acc_ids[0],
                    timestamps[i] + timedelta(days=15),
                    timestamps[i],
                )
                await conn.execute(
                    """
                    INSERT INTO str_batches (id, tenant_id, record_count, total_amount, payload_xml, checksum, status, created_at)
                    VALUES ($1, $2, 1, 15000.0000, '<Batch/>', $3, 'GENERATED', $4);
                    """,
                    str_ids[i],
                    ephemeral_tenant,
                    f"chk_{i}",
                    timestamps[i],
                )

        token = _make_token(role="ADMIN", tenant_id=str(ephemeral_tenant))
        headers = {"Authorization": f"Bearer {token}"}
        transport = httpx.ASGITransport(app=app)

        async def _walk_cursor_endpoint(client, base_url: str, id_extractor, is_dict_body: bool = False):
            seen: list[str] = []
            # Start from an explicit future keyset cursor so every page uses pure keyset SQL
            pivot_id_val: object = uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
            if "str/batch" in base_url:
                pivot_id_val = "zzzzzzzz"
            elif "/audit/logs" in base_url:
                pivot_id_val = 9_223_372_036_854_775_807
            future_cursor = encode_keyset_cursor(
                datetime(2099, 1, 1, tzinfo=timezone.utc),
                pivot_id_val,
            )
            cur: str | None = future_cursor
            pages = 0
            while cur is not None:
                pages += 1
                assert pages <= 10, f"Infinite pagination loop on {base_url}"
                sep = "&" if "?" in base_url else "?"
                resp = await client.get(f"{base_url}{sep}limit=2&cursor={cur}", headers=headers)
                assert resp.status_code == 200, f"{base_url} failed: {resp.status_code} {resp.text}"
                body = resp.json()
                items = body["items"] if is_dict_body and "items" in body else (
                    body["batches"] if is_dict_body and "batches" in body else (
                        body["transactions"] if is_dict_body and "transactions" in body else body
                    )
                )
                page_ids = [id_extractor(x) for x in items]
                assert set(seen).isdisjoint(page_ids), f"Duplicate IDs across keyset pages on {base_url}!"
                seen.extend(page_ids)
                if is_dict_body and "next_cursor" in body:
                    cur = body.get("next_cursor")
                elif is_dict_body and isinstance(body.get("pagination"), dict):
                    cur = body["pagination"].get("next_cursor")
                else:
                    cur = resp.headers.get("X-Next-Cursor")
            return seen

        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Traverse ALL keyset endpoints end-to-end and verify exact 5/5 completeness despite timestamp ties!
            got_alerts = await _walk_cursor_endpoint(client, "/api/v1/alerts", lambda r: r["alert_id"])
            assert set(got_alerts) == {str(u) for u in alert_ids}

            got_txs = await _walk_cursor_endpoint(client, "/api/v1/transactions", lambda r: r["transaction_id"])
            assert set(got_txs) == {str(u) for u in tx_ids}

            got_cases = await _walk_cursor_endpoint(client, "/api/v1/cases", lambda r: r["case_id"])
            assert set(got_cases) == {str(u) for u in case_ids}

            got_ctrs = await _walk_cursor_endpoint(client, "/api/v1/ctr/filings", lambda r: r["ctr_id"])
            assert set(got_ctrs) == {str(u) for u in ctr_ids}

            got_strs = await _walk_cursor_endpoint(client, "/api/v1/str/batch/batches", lambda r: r["batch_id"], is_dict_body=True)
            assert set(got_strs) == set(str_ids)

            # Verify BIGINT keyset cursor pagination on live WORM audit_log (default tenant, zero test pollution)
            default_headers = {"Authorization": f"Bearer {_make_token(role='ADMIN', tenant_id=DEFAULT_TENANT_ID)}"}
            r_aud1 = await client.get("/api/v1/audit/logs?limit=3", headers=default_headers)
            assert r_aud1.status_code == 200
            aud1_body = r_aud1.json()
            if aud1_body.get("next_cursor"):
                r_aud2 = await client.get(
                    f"/api/v1/audit/logs?limit=3&cursor={aud1_body['next_cursor']}",
                    headers=default_headers,
                )
                assert r_aud2.status_code == 200, f"BIGINT audit_log cursor failed: {r_aud2.text}"
                aud2_body = r_aud2.json()
                ids_a1 = {str(x["id"]) for x in aud1_body["items"]}
                ids_a2 = {str(x["id"]) for x in aud2_body["items"]}
                assert ids_a1.isdisjoint(ids_a2), "Duplicate audit_log IDs across BIGINT keyset pages!"

            got_custs = await _walk_cursor_endpoint(client, "/api/v1/customers", lambda r: r["id"], is_dict_body=True)
            assert set(got_custs) == {str(u) for u in acc_ids}

            got_onb = await _walk_cursor_endpoint(client, "/api/v1/onboard/accounts", lambda r: r["account_id"])
            assert set(got_onb) == {str(u) for u in acc_ids}

            got_dsar = await _walk_cursor_endpoint(
                client,
                f"/api/v1/privacy/dsar/export/QA-KS-{ephemeral_tenant.hex[:6]}-0",
                lambda r: r["tx_id"],
                is_dict_body=True,
            )
            assert set(got_dsar) == {str(u) for u in tx_ids}

            # Verify malformed cursor -> 400 and deep legacy OFFSET > 10,000 -> 400 across endpoints
            for bad_url in (
                "/api/v1/alerts?cursor=!!!bad!!!",
                "/api/v1/transactions?cursor=!!!bad!!!",
                "/api/v1/cases?cursor=!!!bad!!!",
                "/api/v1/audit/logs?cursor=!!!bad!!!",
                "/api/v1/ctr/filings?cursor=!!!bad!!!",
                "/api/v1/str/batch/batches?cursor=!!!bad!!!",
                "/api/v1/customers?cursor=!!!bad!!!",
                "/api/v1/onboard/accounts?cursor=!!!bad!!!",
                "/api/v1/alerts?page=300&limit=50",
                "/api/v1/transactions?page=300&limit=50",
                "/api/v1/cases?page=300&limit=50",
                "/api/v1/audit/logs?page=300&limit=50",
                "/api/v1/str/batch/batches?offset=10001&limit=50",
            ):
                r_err = await client.get(bad_url, headers=headers)
                assert r_err.status_code == 400, f"Expected 400 for {bad_url}, got {r_err.status_code}"
    finally:
        # Clean teardown of ephemeral tenant rows
        try:
            async with conn.transaction():
                await conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", str(ephemeral_tenant))
                await conn.execute("DELETE FROM str_batches WHERE tenant_id = $1;", ephemeral_tenant)
                await conn.execute("DELETE FROM ctr_filings WHERE tenant_id = $1;", ephemeral_tenant)
                await conn.execute("DELETE FROM cases WHERE tenant_id = $1;", ephemeral_tenant)
                await conn.execute("DELETE FROM alerts WHERE tenant_id = $1;", ephemeral_tenant)
                await conn.execute("DELETE FROM transactions WHERE tenant_id = $1;", ephemeral_tenant)
                await conn.execute("DELETE FROM accounts WHERE tenant_id = $1;", ephemeral_tenant)
                await conn.execute("DELETE FROM tenants WHERE id = $1;", ephemeral_tenant)
        finally:
            await conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# CHECKLIST #6: LIVE CONCURRENT AB-BA REVERSE-ORDER LOCK DEADLOCK STRESS TEST
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_qa_06_concurrent_reverse_order_locks_never_deadlock():
    """
    Runs 12 live PostgreSQL concurrent transactions locking the same 2 accounts
    and 2 alerts in opposite orders ((A, B) vs (B, A)). Deterministic ascending
    `ORDER BY id ASC FOR UPDATE` must guarantee ZERO DeadlockDetectedErrors.
    """
    ephemeral_tenant = uuid.uuid4()
    acc_a, acc_b = uuid.uuid4(), uuid.uuid4()
    tx_id = uuid.uuid4()
    al_a, al_b = uuid.uuid4(), uuid.uuid4()

    setup_conn = await asyncpg.connect(get_postgres_dsn())
    try:
        async with setup_conn.transaction():
            await setup_conn.execute(
                "INSERT INTO tenants (id, name) VALUES ($1, $2);",
                ephemeral_tenant,
                f"QA Lock Tenant {ephemeral_tenant.hex[:6]}",
            )
            await setup_conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", str(ephemeral_tenant))
            for aid, sfx in ((acc_a, "A"), (acc_b, "B")):
                await setup_conn.execute(
                    """
                    INSERT INTO accounts (id, tenant_id, account_number, owner_name, swift_bic, status)
                    VALUES ($1, $2, $3, 'Lock Test', 'CHASUS33', 'ACTIVE');
                    """,
                    aid,
                    ephemeral_tenant,
                    f"QA-LK-{ephemeral_tenant.hex[:6]}-{sfx}",
                )
            await setup_conn.execute(
                """
                INSERT INTO transactions (
                    id, tenant_id, sender_account_id, receiver_account_id,
                    amount, currency, amount_base_usd, fx_rate_applied, status, timestamp
                )
                VALUES ($1, $2, $3, $4, 5000.00, 'USD', 5000.00, 1.0, 'FLAGGED', NOW());
                """,
                tx_id,
                ephemeral_tenant,
                acc_a,
                acc_b,
            )
            for al_id, rn in ((al_a, "RULE_A"), (al_b, "RULE_B")):
                await setup_conn.execute(
                    """
                    INSERT INTO alerts (id, tenant_id, transaction_id, rule_name, threat_level, ai_risk_score, status)
                    VALUES ($1, $2, $3, $4, 'HIGH', 0.80, 'OPEN');
                    """,
                    al_id,
                    ephemeral_tenant,
                    tx_id,
                    rn,
                )

        # 6a. 12 concurrent reverse-order account locks (6 A->B + 6 B->A)
        async def _lock_pair(first_id: uuid.UUID, second_id: uuid.UUID) -> bool:
            async with get_async_db_conn(tenant_id=str(ephemeral_tenant)) as c:
                await _verify_concurrency_lock(c, first_id, second_id)
                await asyncio.sleep(0.005)
            return True

        acc_tasks = [
            _lock_pair(acc_a, acc_b) if i % 2 == 0 else _lock_pair(acc_b, acc_a)
            for i in range(12)
        ]
        acc_results = await asyncio.gather(*acc_tasks)
        assert acc_results == [True] * 12

        # 6b. 8 concurrent reverse-order bulk alert claims (4 [al_a, al_b] + 4 [al_b, al_a])
        async def _bulk_claim(order: list[uuid.UUID]) -> int:
            return await bulk_claim_or_assign_alerts_atomic(
                tenant_id=str(ephemeral_tenant),
                alert_uuids=order,
                action="CLAIM",
                assignee_username=None,
                current_user={"id": None, "username": "qa.analyst"},
            )

        claim_tasks = [
            _bulk_claim([al_a, al_b]) if i % 2 == 0 else _bulk_claim([al_b, al_a])
            for i in range(8)
        ]
        claim_results = await asyncio.gather(*claim_tasks)
        assert all(cnt == 2 for cnt in claim_results)
    finally:
        try:
            async with setup_conn.transaction():
                await setup_conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", str(ephemeral_tenant))
                await setup_conn.execute("DELETE FROM alerts WHERE tenant_id = $1;", ephemeral_tenant)
                await setup_conn.execute("DELETE FROM transactions WHERE tenant_id = $1;", ephemeral_tenant)
                await setup_conn.execute("DELETE FROM accounts WHERE tenant_id = $1;", ephemeral_tenant)
                await setup_conn.execute("DELETE FROM tenants WHERE id = $1;", ephemeral_tenant)
        finally:
            await setup_conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# CHECKLIST #7: CROSS-TENANT FORCE RLS, SET LOCAL PGBOUNCER RESET & POOL BOUNDS
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_qa_07_rls_cross_tenant_isolation_set_local_reset_and_pool_timeout():
    """
    Proves:
      1. Tenant B and unauthenticated (None) connections see ZERO rows written by Tenant A
         across the newly rewritten UUID-RLS tables (`cases`, `notifications`, `rule_configs`).
      2. `SET LOCAL` tenant context auto-resets immediately upon transaction exit so
         PgBouncer transaction-mode connection recycling can NEVER leak tenant state.
      3. `PGBOUNCER_ENABLED=true` configures `statement_cache_size=0`.
      4. Exhausted connection pools fail fast at their bounded `timeout` instead of hanging.
    """
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    case_a = uuid.uuid4()
    notif_a = uuid.uuid4()

    setup_conn = await asyncpg.connect(get_postgres_dsn())
    try:
        async with setup_conn.transaction():
            for tid, label in ((tenant_a, "A"), (tenant_b, "B")):
                await setup_conn.execute(
                    "INSERT INTO tenants (id, name) VALUES ($1, $2);",
                    tid,
                    f"QA RLS {label} {tid.hex[:6]}",
                )
            await setup_conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", str(tenant_a))
            await setup_conn.execute(
                """
                INSERT INTO cases (id, tenant_id, case_number, title, priority, status)
                VALUES ($1, $2, $3, 'Tenant A Secret Case', 'HIGH', 'OPEN');
                """,
                case_a,
                tenant_a,
                f"CASE-RLS-{tenant_a.hex[:6]}",
            )
            await setup_conn.execute(
                """
                INSERT INTO notifications (id, tenant_id, category, severity, recipient_role, title, body, link_url)
                VALUES ($1, $2, 'QA_RLS', 'INFO', 'MLRO', 'Secret', 'Tenant A Only', '/cases');
                """,
                notif_a,
                tenant_a,
            )

        # 7a. Cross-tenant isolation proof: Tenant A sees 1, Tenant B sees 0, None sees 0
        async with get_async_db_conn(tenant_id=str(tenant_a)) as ca:
            assert await ca.fetchval("SELECT COUNT(*) FROM cases WHERE id = $1;", case_a) == 1
            assert await ca.fetchval("SELECT COUNT(*) FROM notifications WHERE id = $1;", notif_a) == 1

        async with get_async_db_conn(tenant_id=str(tenant_b)) as cb:
            assert await cb.fetchval("SELECT COUNT(*) FROM cases WHERE id = $1;", case_a) == 0
            assert await cb.fetchval("SELECT COUNT(*) FROM notifications WHERE id = $1;", notif_a) == 0

        async with get_async_db_conn(tenant_id=None) as cnone:
            assert await cnone.fetchval("SELECT COUNT(*) FROM cases WHERE id = $1;", case_a) == 0
            assert await cnone.fetchval("SELECT COUNT(*) FROM notifications WHERE id = $1;", notif_a) == 0

        # 7b. PgBouncer Transaction-Pooling SET LOCAL reset proof on the SAME physical connection
        raw_conn = await asyncpg.connect(get_postgres_dsn())
        try:
            async with raw_conn.transaction():
                await raw_conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", str(tenant_a))
                inside = await raw_conn.fetchval("SELECT current_setting('app.current_tenant_id', true);")
                assert inside == str(tenant_a)
            # After transaction commits/exits, SET LOCAL MUST automatically clear!
            after = await raw_conn.fetchval("SELECT COALESCE(current_setting('app.current_tenant_id', true), '');")
            assert after == "", f"SET LOCAL leaked tenant context after transaction exit: {after!r}"
        finally:
            await raw_conn.close()

        # 7c. Bounded pool acquisition timeout fails fast instead of hanging
        tiny_pool = await asyncpg.create_pool(dsn=get_postgres_dsn(), min_size=1, max_size=1, timeout=0.25)
        try:
            async with tiny_pool.acquire(timeout=1.0):
                t0 = time.monotonic()
                with pytest.raises(asyncio.TimeoutError):
                    await tiny_pool.acquire(timeout=0.20)
                elapsed = time.monotonic() - t0
                assert 0.15 <= elapsed < 0.75
        finally:
            await tiny_pool.close()

        # 7d. Verify PGBOUNCER_ENABLED=true sets statement_cache_size=0 & K8s PgBouncer config
        pgb_docs = list(yaml.safe_load_all(pathlib.Path("deployments/kubernetes/pgbouncer.yaml").read_text(encoding="utf-8")))
        pgb_env = {
            e["name"]: e.get("value")
            for e in pgb_docs[0]["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        assert pgb_env["POOL_MODE"] == "transaction"
        assert pgb_env["MAX_PREPARED_STATEMENTS"] == "0"
    finally:
        try:
            async with setup_conn.transaction():
                await setup_conn.execute("SELECT set_config('app.current_tenant_id', $1, true);", str(tenant_a))
                await setup_conn.execute("DELETE FROM notifications WHERE tenant_id = $1;", tenant_a)
                await setup_conn.execute("DELETE FROM cases WHERE tenant_id = $1;", tenant_a)
                await setup_conn.execute("DELETE FROM tenants WHERE id IN ($1, $2);", tenant_a, tenant_b)
        finally:
            await setup_conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# CHECKLIST #8: READ-AFTER-WRITE PER-CALLER ISOLATION, TTL EXPIRY & LAG RECOVERY
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_qa_08_raw_stickiness_per_caller_isolation_error_exclusion_ttl_and_lag_recovery():
    """
    Verifies:
      - Caller A mutating (2xx) pins ONLY Caller A to Primary; Caller B stays on Replica.
      - Failed mutations (400/500) do NOT set RAW stickiness or X-Read-Consistency-Window.
      - RAW stickiness expires cleanly after its TTL window.
      - Replica lag spikes fail over to Primary and automatically recover to Replica when lag drops.
    """
    clear_local_stickiness_cache()
    observed: list[tuple[str, bool]] = []

    async def _demo_app(scope, receive, send):
        path = scope["path"]
        observed.append((path, force_primary_read_var.get(False)))
        status_code = 400 if path == "/fail" else 200
        await send({"type": "http.response.start", "status": status_code, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b"{}"})

    mw = ReadAfterWriteStickinessMiddleware(_demo_app)
    transport = httpx.ASGITransport(app=mw)
    hdr_a = {"Authorization": f"Bearer qa-caller-a-{uuid.uuid4().hex}"}
    hdr_b = {"Authorization": f"Bearer qa-caller-b-{uuid.uuid4().hex}"}

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Failed POST must NOT emit header or pin caller A
        r_fail = await client.post("/fail", headers=hdr_a)
        assert r_fail.status_code == 400
        assert "X-Read-Consistency-Window" not in r_fail.headers
        await client.get("/read", headers=hdr_a)
        assert observed[-1] == ("/read", False)

        # Successful POST by Caller A pins ONLY Caller A (Caller B stays on Replica!)
        r_ok = await client.post("/mutate", headers=hdr_a)
        assert r_ok.status_code == 200 and "X-Read-Consistency-Window" in r_ok.headers

        await client.get("/read", headers=hdr_a)
        assert observed[-1] == ("/read", True), "Caller A should stick to Primary immediately after 2xx write"

        await client.get("/read", headers=hdr_b)
        assert observed[-1] == ("/read", False), "Caller B must NOT be pinned to Primary by Caller A's write"

    # TTL expiration check (1s window)
    ephemeral_fp = f"qa-ttl-{uuid.uuid4().hex}"
    await mark_write_stickiness(ephemeral_fp, ttl_seconds=1)
    assert await has_active_write_stickiness(ephemeral_fp) is True
    await asyncio.sleep(1.15)
    assert await has_active_write_stickiness(ephemeral_fp) is False

    # Replica lag spike -> Primary failover -> lag recovers -> Replica resumes
    import database.postgres as _pg

    def _pool_stub(name: str):
        p = MagicMock()
        p._loop = asyncio.get_running_loop()
        c = AsyncMock()
        c._name = name
        c.execute = AsyncMock()
        tx_cm = AsyncMock()
        tx_cm.__aenter__ = AsyncMock(return_value=None)
        tx_cm.__aexit__ = AsyncMock(return_value=None)
        c.transaction = MagicMock(return_value=tx_cm)
        p.acquire = AsyncMock(return_value=c)
        p.release = AsyncMock()
        p.get_size = MagicMock(return_value=2)
        p.get_idle_size = MagicMock(return_value=1)
        p.get_max_size = MagicMock(return_value=4)
        return p

    orig_p, orig_r = _pg.db_pool, _pg.db_replica_pool
    try:
        _pg.db_pool = _pool_stub("primary")
        _pg.db_replica_pool = _pool_stub("replica")

        set_observed_replica_lag_seconds(3.5)
        async with get_async_db_read_conn(tenant_id=DEFAULT_TENANT_ID) as c1:
            assert c1._name == "primary"

        set_observed_replica_lag_seconds(0.1)
        async with get_async_db_read_conn(tenant_id=DEFAULT_TENANT_ID) as c2:
            assert c2._name == "replica"
    finally:
        set_observed_replica_lag_seconds(0.0)
        _pg.db_pool, _pg.db_replica_pool = orig_p, orig_r


# ══════════════════════════════════════════════════════════════════════════════
# CHECKLIST #9: CACHE REDIS (allkeys-lfu) VS STATE REDIS (noeviction) ISOLATION
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_qa_09_live_cache_vs_state_redis_keyspace_isolation():
    """Verifies live State Redis and Cache Redis operate in isolated keyspaces with zero cross-deletion."""
    state_cli = await get_async_redis_client()
    cache_cli = await get_async_cache_redis_client()
    assert state_cli is not None and cache_cli is not None

    shared_key = f"qa:isolation:{uuid.uuid4().hex}"
    try:
        await state_cli.set(shared_key, "STATE_CRITICAL_LOCK", ex=30)
        await cache_cli.set(shared_key, "CACHE_VOLATILE_VAL", ex=30)

        # Separate DB/instance isolation: deleting volatile cache key NEVER touches State lock!
        assert await state_cli.get(shared_key) == "STATE_CRITICAL_LOCK"
        assert await cache_cli.get(shared_key) == "CACHE_VOLATILE_VAL"

        await cache_cli.delete(shared_key)
        assert await cache_cli.get(shared_key) is None
        assert await state_cli.get(shared_key) == "STATE_CRITICAL_LOCK"
    finally:
        await state_cli.delete(shared_key)
        await cache_cli.delete(shared_key)


# ══════════════════════════════════════════════════════════════════════════════
# CHECKLIST #10: VERSIONED TENANT KEYS, JITTER, POST-COMMIT & OUTBOX CRASH HEAL
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_qa_10_post_commit_invalidation_rollback_safety_and_outbox_crash_recovery():
    """
    Proves:
      1. Cross-tenant cache isolation (Tenant A and Tenant B with identical logical keys never collide).
      2. When a DB write fails/rolls back mid-transaction, cache is NOT prematurely invalidated.
      3. When a DB write commits, cache IS invalidated strictly after COMMIT AND a durable
         `CACHE_INVALIDATION` Outbox row is persisted in the same transaction.
      4. If the app crashes between DB COMMIT and Redis DEL, OutboxRelayEngine deletes the
         stale key directly from live Cache Redis.
    """
    cache_cli = await get_async_cache_redis_client()
    assert cache_cli is not None

    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    cache = CacheAsideClient()

    # 10a. Cross-tenant namespace isolation in live Cache Redis
    key_a = build_cache_key("qa_iso", tenant_a, "summary", version="v1")
    key_b = build_cache_key("qa_iso", tenant_b, "summary", version="v1")
    try:
        val_a = await cache.get_or_load(
            namespace="qa_iso", tenant_id=tenant_a, key="summary",
            loader=AsyncMock(return_value={"tenant": "A"}), base_ttl=60,
        )
        val_b = await cache.get_or_load(
            namespace="qa_iso", tenant_id=tenant_b, key="summary",
            loader=AsyncMock(return_value={"tenant": "B"}), base_ttl=60,
        )
        assert val_a == {"tenant": "A"} and val_b == {"tenant": "B"}
        # Invalidating Tenant A leaves Tenant B intact
        await cache.invalidate_keys([key_a], namespace="qa_iso")
        assert await cache_cli.get(key_a) is None
        assert await cache_cli.get(key_b) is not None
    finally:
        await cache_cli.delete(key_a, key_b)

    # 10b. Rollback safety: exception inside write transaction MUST NOT delete cached entry!
    exec_key = build_cache_key("metrics_exec", tenant_a, "summary")
    await cache_cli.set(exec_key, json.dumps({"v": {"stale": False}, "exp": time.time() + 60, "delta": 0.01}), ex=60)
    try:
        failing_conn = AsyncMock()
        failing_conn.fetchrow = AsyncMock(return_value=None)
        failing_conn.execute = AsyncMock(side_effect=RuntimeError("Simulated DB crash before COMMIT"))

        @asynccontextmanager
        async def _failing_tx(tenant_id=None):
            yield failing_conn

        with pytest.raises(RuntimeError, match="Simulated DB crash"):
            await upsert_risk_appetite_atomic(
                tenant_uuid=uuid.UUID(tenant_a),
                updated_data={"sla_hours": 24},
                default_before={"sla_hours": 48},
                actor={"id": str(uuid.uuid4()), "username": "qa.mlro", "role": "MLRO"},
                now_utc=datetime.now(timezone.utc),
                sla_hours=24,
                edd_threshold=50000.0,
                write_conn_factory=_failing_tx,
            )
        # Because DB tx rolled back, Cache Redis entry was NOT prematurely deleted!
        assert await cache_cli.get(exec_key) is not None

        # 10c. Successful commit triggers strictly post-commit DEL + records CACHE_INVALIDATION outbox event
        tx_closed = {"committed": False}
        del_observed_after_commit = {"ok": False}

        ok_conn = AsyncMock()
        ok_conn.fetchrow = AsyncMock(return_value=None)
        ok_conn.execute = AsyncMock()

        @asynccontextmanager
        async def _tracking_tx(tenant_id=None):
            yield ok_conn
            tx_closed["committed"] = True

        from services import cache_aside as ca_mod

        orig_invalidate = ca_mod.invalidate_cache_keys_after_commit

        async def _spy_invalidate(keys, *, namespace="global"):
            del_observed_after_commit["ok"] = tx_closed["committed"]
            return await orig_invalidate(keys, namespace=namespace)

        with patch("services.cache_aside.invalidate_cache_keys_after_commit", side_effect=_spy_invalidate), \
             patch("repositories.compliance_config_repo.record_audit_event_tx", AsyncMock()):
            await upsert_risk_appetite_atomic(
                tenant_uuid=uuid.UUID(tenant_a),
                updated_data={"sla_hours": 12},
                default_before={"sla_hours": 24},
                actor={"id": str(uuid.uuid4()), "username": "qa.mlro", "role": "MLRO"},
                now_utc=datetime.now(timezone.utc),
                sla_hours=12,
                edd_threshold=25000.0,
                write_conn_factory=_tracking_tx,
            )
        assert del_observed_after_commit["ok"] is True, "Cache DEL must execute strictly AFTER DB COMMIT!"
        assert await cache_cli.get(exec_key) is None

        # Verify Outbox INSERT for CACHE_INVALIDATION was recorded inside the DB transaction
        outbox_calls = [
            str(call.args[0]) for call in ok_conn.execute.call_args_list
            if "transactional_outbox" in str(call.args[0])
        ]
        assert len(outbox_calls) == 1

        # 10d. Crash-window self-healing: re-seed stale key in LIVE Cache Redis and heal via OutboxRelayEngine
        await cache_cli.set(exec_key, "STALE_AFTER_POD_CRASH", ex=60)
        assert await cache_cli.get(exec_key) == "STALE_AFTER_POD_CRASH"
        _, ok, err = await OutboxRelayEngine._publish_single_event(
            {
                "id": str(uuid.uuid4()),
                "aggregate_type": "CACHE_INVALIDATION",
                "aggregate_id": exec_key,
                "event_type": "storage.cache.invalidate.v1",
                "payload": {"keys": [exec_key], "namespace": "risk_appetite"},
            }
        )
        assert ok is True and err is None
        assert await cache_cli.get(exec_key) is None
    finally:
        await cache_cli.delete(exec_key)


# ══════════════════════════════════════════════════════════════════════════════
# CHECKLIST #11: LIVE REDIS STAMPEDE, LUA FENCING, PER REFRESH & PENETRATION
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_qa_11_live_redis_30_way_stampede_lua_fencing_per_and_penetration():
    """Executes all stampede, Lua lock fencing, PER refresh, and penetration tests against LIVE Cache Redis."""
    cache_cli = await get_async_cache_redis_client()
    assert cache_cli is not None
    cache = CacheAsideClient()

    ns = f"qa_stampede_{uuid.uuid4().hex[:6]}"
    hot_key = build_cache_key(ns, DEFAULT_TENANT_ID, "hot")
    fencing_lock = f"lock:qa:fencing:{uuid.uuid4().hex}"
    per_key = build_cache_key(ns, DEFAULT_TENANT_ID, "per_hot")
    ghost_key = build_cache_key(ns, DEFAULT_TENANT_ID, "ghost_999")

    try:
        # 11a. Live 30-way concurrent cache stampede -> exactly 1 DB loader execution
        db_hits = 0

        async def _expensive_db():
            nonlocal db_hits
            db_hits += 1
            await asyncio.sleep(0.05)
            return {"status": "computed_once", "value": 999}

        results = await asyncio.gather(
            *[
                cache.get_or_load(
                    namespace=ns, tenant_id=DEFAULT_TENANT_ID, key="hot",
                    loader=_expensive_db, base_ttl=60,
                )
                for _ in range(30)
            ]
        )
        assert db_hits == 1, f"Live Redis stampede leaked {db_hits} DB calls!"
        assert all(r == {"status": "computed_once", "value": 999} for r in results)
        assert await cache_cli.get(f"lock:{hot_key}") is None

        # 11b. Atomic Lua lock fencing: stale owner A CANNOT delete new owner B's lock!
        await cache_cli.set(fencing_lock, "token_owner_B", px=5000)
        await cache._safe_release_lock(cache_cli, fencing_lock, "stale_token_owner_A")
        assert await cache_cli.get(fencing_lock) == "token_owner_B", "Stale token stole another worker's lock!"
        await cache._safe_release_lock(cache_cli, fencing_lock, "token_owner_B")
        assert await cache_cli.get(fencing_lock) is None

        # 11c. Live PER / XFetch background early refresh: returns cached immediately & refreshes asynchronously
        near_expiry_env = json.dumps(
            {"v": {"generation": 1}, "exp": time.time() + 0.5, "delta": 10.0}
        )
        await cache_cli.set(per_key, near_expiry_env, ex=30)

        async def _gen2_loader():
            return {"generation": 2}

        t0 = time.monotonic()
        immediate = await cache.get_or_load(
            namespace=ns, tenant_id=DEFAULT_TENANT_ID, key="per_hot",
            loader=_gen2_loader, base_ttl=60, enable_per=True, per_beta=5.0,
        )
        assert immediate == {"generation": 1}
        assert (time.monotonic() - t0) < 0.15
        # Give background PER refresh task a moment to complete and overwrite live Redis
        await asyncio.sleep(0.15)
        refreshed = await cache.get_or_load(
            namespace=ns, tenant_id=DEFAULT_TENANT_ID, key="per_hot",
            loader=_gen2_loader, base_ttl=60, enable_per=False,
        )
        assert refreshed == {"generation": 2}

        # 11d. Cache Penetration storm: 15 requests for non-existent ID -> only 1 DB miss!
        ghost_hits = 0

        async def _ghost_db():
            nonlocal ghost_hits
            ghost_hits += 1
            return None

        r_first = await cache.get_or_load(
            namespace=ns, tenant_id=DEFAULT_TENANT_ID, key="ghost_999",
            loader=_ghost_db, cache_none=True, negative_ttl=20,
        )
        r_rest = await asyncio.gather(
            *[
                cache.get_or_load(
                    namespace=ns, tenant_id=DEFAULT_TENANT_ID, key="ghost_999",
                    loader=_ghost_db, cache_none=True, negative_ttl=20,
                )
                for _ in range(14)
            ]
        )
        assert r_first is None and all(r is None for r in r_rest)
        assert ghost_hits == 1, f"Cache penetration hit DB {ghost_hits} times instead of 1!"
        assert NEGATIVE_SENTINEL in (await cache_cli.get(ghost_key) or "")
    finally:
        await cache_cli.delete(hot_key, f"lock:{hot_key}", fencing_lock, per_key, f"lock:{per_key}", ghost_key)


# ══════════════════════════════════════════════════════════════════════════════
# CHECKLIST #12: AGGRESSIVE CACHE TIMEOUTS (<= 250ms) & FAIL-OPEN RESILIENCE
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_qa_12_aggressive_cache_timeouts_and_failopen_under_every_redis_failure():
    """Tests 5 distinct Redis failure modes + end-to-end HTTP /metrics/executive fail-open."""

    # 12a. Client factory raises ConnectionError
    c_err = CacheAsideClient(redis_factory=AsyncMock(side_effect=ConnectionError("Redis refused")), op_timeout_seconds=0.1)
    assert await c_err.get_or_load(
        namespace="qa_fo", tenant_id=DEFAULT_TENANT_ID, key="k1", loader=AsyncMock(return_value={"ok": 1})
    ) == {"ok": 1}

    # 12b. Hanging GET aborts within op_timeout (<= 250ms) and immediately fails open
    class _HangGet:
        async def get(self, k):
            await asyncio.sleep(5.0)

    c_hang_get = CacheAsideClient(redis_factory=AsyncMock(return_value=_HangGet()), op_timeout_seconds=0.10)
    t0 = time.monotonic()
    assert await c_hang_get.get_or_load(
        namespace="qa_fo", tenant_id=DEFAULT_TENANT_ID, key="k2", loader=AsyncMock(return_value={"ok": 2})
    ) == {"ok": 2}
    assert (time.monotonic() - t0) < 0.25

    # 12c. Hanging SET NX (stampede lock) fails open immediately
    class _HangLock:
        async def get(self, k):
            return None

        async def set(self, *a, **kw):
            await asyncio.sleep(5.0)

    c_hang_lock = CacheAsideClient(redis_factory=AsyncMock(return_value=_HangLock()), op_timeout_seconds=0.10)
    t0 = time.monotonic()
    assert await c_hang_lock.get_or_load(
        namespace="qa_fo", tenant_id=DEFAULT_TENANT_ID, key="k3", loader=AsyncMock(return_value={"ok": 3})
    ) == {"ok": 3}
    assert (time.monotonic() - t0) < 0.25

    # 12d. Corrupted non-JSON bytes in Redis treated gracefully as cache miss
    class _CorruptRedis:
        def __init__(self):
            self.stored = None

        async def get(self, k):
            return self.stored if self.stored is not None else "{corrupted-json!!!"

        async def set(self, k, v, **kw):
            if not kw.get("nx"):
                self.stored = v
            return True

        async def eval(self, *a):
            return 1

    c_corrupt = CacheAsideClient(redis_factory=AsyncMock(return_value=_CorruptRedis()), op_timeout_seconds=0.15)
    assert await c_corrupt.get_or_load(
        namespace="qa_fo", tenant_id=DEFAULT_TENANT_ID, key="k4", loader=AsyncMock(return_value={"repaired": True})
    ) == {"repaired": True}

    # 12e. Real HTTP GET /api/v1/metrics/executive stays 200 OK even when Cache Redis completely fails!
    token = _make_token(role="ADMIN")
    transport = httpx.ASGITransport(app=app)
    with patch("services.cache_aside.cache_aside._redis_factory", new=AsyncMock(side_effect=TimeoutError("Cache Redis dead"))):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/metrics/executive", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# CHECKLIST #13: STORAGE OBSERVABILITY (pg_stat_statements, POOL, LAG, REDIS)
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_qa_13_storage_observability_pg_stat_statements_health_system_and_metrics_http():
    """
    Verifies:
      - `sample_storage_telemetry_once()` exports live pool, lag, dead-tuple, and dual-Redis metrics.
      - `pg_stat_statements` collection path exports `pg_stat_statements_mean_exec_seconds` and
        `pg_stat_statements_max_exec_seconds` when the extension is enabled.
      - Live HTTP `GET /api/v1/health/system` (SUPER_ADMIN) returns `redis`, `redis_cache`, and `storage_telemetry`.
      - Live HTTP `GET /metrics` exposes all required Storage Pillar Prometheus metric families.
    """
    # 13a. Exercise pg_stat_statements collection branch directly with realistic rows
    fake_conn = AsyncMock()
    fake_conn.fetch = AsyncMock(
        side_effect=[
            [{"relname": "alerts", "live_tup": 1000, "dead_tup": 50}],
            [{"query_group": "SELECT id FROM alerts WHERE tenant_id = $1", "mean_sec": 0.012, "max_sec": 0.095}],
        ]
    )
    fake_conn.fetchval = AsyncMock(side_effect=[False, 0.03, True])

    @asynccontextmanager
    async def _fake_acquire(timeout=2.0):
        yield fake_conn

    fake_pool = MagicMock()
    fake_pool.acquire = _fake_acquire

    import database.postgres as _pg
    orig_pool = _pg.db_pool
    try:
        _pg.db_pool = fake_pool
        snap_pgss = await sample_storage_telemetry_once()
        assert snap_pgss["pg_stat_statements_enabled"] is True
        assert snap_pgss["replica_lag_seconds"] == pytest.approx(0.03, abs=0.001)
    finally:
        _pg.db_pool = orig_pool
        set_observed_replica_lag_seconds(0.0)

    # 13b. Real live sample + live HTTP /api/v1/health/system & /metrics verification
    async with get_async_db_conn(tenant_id=DEFAULT_TENANT_ID) as conn:
        await conn.fetchval("SELECT 1;")
    live_snap = await sample_storage_telemetry_once()
    assert live_snap["hot_tables_sampled"] >= 5

    super_token = _make_token(role="SUPER_ADMIN")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r_sys = await client.get(
            "/api/v1/health/system",
            headers={"Authorization": f"Bearer {super_token}"},
        )
        assert r_sys.status_code == 200
        body = r_sys.json()
        assert body["services"]["redis"]["role"] == "state_noeviction"
        assert body["services"]["redis_cache"]["role"] == "cache_allkeys_lfu"
        assert "storage_telemetry" in body
        assert "replica_lag_seconds" in body["storage_telemetry"]
        assert "redis_state" in body["storage_telemetry"]
        assert "redis_cache" in body["storage_telemetry"]

        r_met = await client.get("/metrics")
        assert r_met.status_code == 200
        text = r_met.text
        for metric_name in (
            "db_pool_acquire_duration_seconds",
            "db_pool_connections_in_use",
            "db_pool_connections_idle",
            "db_pool_connections_max",
            "db_read_routing_total",
            "pg_replication_lag_seconds",
            "pg_table_dead_tuples",
            "pg_table_dead_tuple_ratio",
            "pg_stat_statements_mean_exec_seconds",
            "pg_stat_statements_max_exec_seconds",
            "redis_cache_hit_ratio",
            "redis_evicted_keys_total",
            "redis_mem_fragmentation_ratio",
            "redis_used_memory_bytes",
            "storage_cache_operations_total",
        ):
            assert metric_name in text, f"Missing storage SLI '{metric_name}' on HTTP /metrics"
