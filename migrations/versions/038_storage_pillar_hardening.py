"""Storage Pillar Hardening: NUMERIC(19,4) Precision, Zero-Lock CHECK Constraints,
Index-Friendly UUID RLS Policies, and CONCURRENTLY Equality-Range-Sort Indexes.

Revision ID: 038
Revises: 037
Create Date: 2026-11-27 20:50:00.000000
"""

from typing import Sequence, Union
from alembic import op
from sqlalchemy import text

revision: str = "038"
down_revision: Union[str, None] = "037"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# 17 standard tenant-scoped tables whose legacy RLS policies cast `tenant_id::text`
# (which blocks index-only tenant filtering) instead of casting the session GUC to `::uuid`.
_STANDARD_UUID_RLS_POLICIES: list[tuple[str, str]] = [
    ("auditor_rooms", "auditor_rooms_isolation"),
    ("case_evidence", "case_evidence_tenant_isolation"),
    ("cases", "cases_tenant_isolation"),
    ("corporate_ownership_edges", "corporate_ownership_edges_isolation"),
    ("ctr_filings", "ctr_filings_tenant_isolation"),
    ("notifications", "notifications_isolation"),
    ("pkyc_rescreen_runs", "pkyc_rescreen_runs_isolation"),
    ("qa_reviews", "qa_reviews_isolation"),
    ("rfi_requests", "rfi_requests_isolation"),
    ("risk_appetite_settings", "risk_appetite_tenant_isolation"),
    ("rule_configs", "rule_configs_tenant_isolation"),
    ("rule_shadow_hits", "rule_shadow_hits_isolation"),
    ("sar_drafts", "sar_drafts_tenant_isolation"),
    ("siem_configs", "siem_configs_isolation"),
    ("sso_providers", "sso_providers_isolation"),
    ("tenant_webhooks", "tenant_webhooks_isolation"),
    ("webhook_deliveries", "webhook_deliveries_isolation"),
]

_CONCURRENT_INDEX_CREATE_SQL: list[str] = [
    # Audit log: matches ORDER BY occurred_at DESC, id DESC within tenant (eliminates global index scan + Incremental Sort)
    """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_log_tenant_occurred_id
    ON audit_log (tenant_id, occurred_at DESC, id DESC);
    """,
    # Alerts: deterministic keyset pagination (all + status-filtered)
    """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_tenant_created_id
    ON alerts (tenant_id, created_at DESC, id DESC);
    """,
    """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_tenant_status_created_id
    ON alerts (tenant_id, status, created_at DESC, id DESC);
    """,
    # Transactions: deterministic keyset pagination
    """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_transactions_tenant_timestamp_id
    ON transactions (tenant_id, "timestamp" DESC, id DESC);
    """,
    # Cases: deterministic keyset pagination (all + status-filtered)
    """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cases_tenant_created_id
    ON cases (tenant_id, created_at DESC, id DESC);
    """,
    """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cases_tenant_status_created_id
    ON cases (tenant_id, status, created_at DESC, id DESC);
    """,
    # CTR filings: deterministic keyset pagination
    """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ctr_filings_tenant_created_id
    ON ctr_filings (tenant_id, created_at DESC, id DESC);
    """,
    # STR batches: previously had zero secondary indexes
    """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_str_batches_tenant_created_id
    ON str_batches (tenant_id, created_at DESC, id DESC);
    """,
    # Accounts / Customers: deterministic keyset pagination
    """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_accounts_tenant_created_id
    ON accounts (tenant_id, created_at DESC, id DESC);
    """,
    # Resource locks: eliminates Seq Scan on active lock probes
    """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_resource_locks_tenant_type_expiry
    ON resource_locks (tenant_id, resource_type, expires_at)
    WHERE released_at IS NULL;
    """,
    # Transactional outbox: deterministic SKIP LOCKED polling order (created_at ASC, id ASC)
    """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_outbox_active_created_id
    ON transactional_outbox (created_at ASC, id ASC)
    WHERE status IN ('PENDING', 'PROCESSING');
    """,
]

_CONCURRENT_INDEX_DROP_SQL: list[str] = [
    "DROP INDEX CONCURRENTLY IF EXISTS idx_outbox_active_created_id;",
    "DROP INDEX CONCURRENTLY IF EXISTS idx_resource_locks_tenant_type_expiry;",
    "DROP INDEX CONCURRENTLY IF EXISTS idx_accounts_tenant_created_id;",
    "DROP INDEX CONCURRENTLY IF EXISTS idx_str_batches_tenant_created_id;",
    "DROP INDEX CONCURRENTLY IF EXISTS idx_ctr_filings_tenant_created_id;",
    "DROP INDEX CONCURRENTLY IF EXISTS idx_cases_tenant_status_created_id;",
    "DROP INDEX CONCURRENTLY IF EXISTS idx_cases_tenant_created_id;",
    "DROP INDEX CONCURRENTLY IF EXISTS idx_transactions_tenant_timestamp_id;",
    "DROP INDEX CONCURRENTLY IF EXISTS idx_alerts_tenant_status_created_id;",
    "DROP INDEX CONCURRENTLY IF EXISTS idx_alerts_tenant_created_id;",
    "DROP INDEX CONCURRENTLY IF EXISTS idx_audit_log_tenant_occurred_id;",
]

_CHECK_CONSTRAINTS: list[tuple[str, str, str]] = [
    ("transactions", "chk_transactions_amount_positive", "amount > 0"),
    (
        "transactions",
        "chk_transactions_amount_base_usd_nonneg",
        "amount_base_usd IS NULL OR amount_base_usd >= 0",
    ),
    ("transactions", "chk_transactions_fx_rate_positive", "fx_rate_applied > 0"),
    ("ctr_filings", "chk_ctr_filings_amount_positive", "amount > 0"),
    ("str_batches", "chk_str_batches_total_amount_nonneg", "total_amount >= 0"),
    (
        "alerts",
        "chk_alerts_ai_risk_score_bounds",
        "ai_risk_score IS NULL OR (ai_risk_score >= 0 AND ai_risk_score <= 1)",
    ),
]


def _run_concurrent_ddl(statements: list[str]) -> None:
    """Executes CONCURRENTLY DDL on a dedicated AUTOCOMMIT connection before main-tx locks."""
    engine = op.get_bind().engine
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for stmt in statements:
            conn.execute(text(stmt))


def upgrade() -> None:
    # 1. Run all CREATE INDEX CONCURRENTLY statements first (zero locks held on main tx -> no deadlock)
    _run_concurrent_ddl(_CONCURRENT_INDEX_CREATE_SQL)

    # 2. Widen remaining sub-precision monetary columns to NUMERIC(19, 4)
    op.execute(
        """
        ALTER TABLE rule_shadow_hits
            ALTER COLUMN amount_base_usd TYPE NUMERIC(19, 4);
        """
    )
    op.execute(
        """
        ALTER TABLE customer_profiles
            ALTER COLUMN avg_amount TYPE NUMERIC(19, 4),
            ALTER COLUMN median_amount TYPE NUMERIC(19, 4),
            ALTER COLUMN variance_amount TYPE NUMERIC(19, 4);
        """
    )

    # 3. Rewrite all 18 RLS policies from `tenant_id::text = ...` to index-friendly `tenant_id = ...::uuid`
    for table_name, policy_name in _STANDARD_UUID_RLS_POLICIES:
        op.execute(f"DROP POLICY IF EXISTS {policy_name} ON {table_name};")
        op.execute(
            f"""
            CREATE POLICY {policy_name} ON {table_name}
                FOR ALL
                USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
            """
        )

    op.execute("DROP POLICY IF EXISTS transactional_outbox_tenant_isolation ON transactional_outbox;")
    op.execute(
        """
        CREATE POLICY transactional_outbox_tenant_isolation ON transactional_outbox
            FOR ALL
            USING (
                tenant_id IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                tenant_id IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
        """
    )

    # 4. Add zero-lock CHECK constraints using NOT VALID followed by VALIDATE CONSTRAINT
    for table_name, constraint_name, check_expr in _CHECK_CONSTRAINTS:
        op.execute(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conname = '{constraint_name}'
                      AND conrelid = '{table_name}'::regclass
                ) THEN
                    ALTER TABLE {table_name}
                        ADD CONSTRAINT {constraint_name}
                        CHECK ({check_expr}) NOT VALID;
                END IF;
            END $$;
            """
        )
        op.execute(f"ALTER TABLE {table_name} VALIDATE CONSTRAINT {constraint_name};")


def downgrade() -> None:
    # 1. Drop CHECK constraints
    for table_name, constraint_name, _ in reversed(_CHECK_CONSTRAINTS):
        op.execute(f"ALTER TABLE {table_name} DROP CONSTRAINT IF EXISTS {constraint_name};")

    # 2. Restore legacy RLS policies
    for table_name, policy_name in _STANDARD_UUID_RLS_POLICIES:
        op.execute(f"DROP POLICY IF EXISTS {policy_name} ON {table_name};")
        op.execute(
            f"""
            CREATE POLICY {policy_name} ON {table_name}
                FOR ALL
                USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''))
                WITH CHECK (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''));
            """
        )

    op.execute("DROP POLICY IF EXISTS transactional_outbox_tenant_isolation ON transactional_outbox;")
    op.execute(
        """
        CREATE POLICY transactional_outbox_tenant_isolation ON transactional_outbox
            FOR ALL
            USING (
                tenant_id IS NULL
                OR tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            )
            WITH CHECK (
                tenant_id IS NULL
                OR tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );
        """
    )

    # 3. Restore previous column precisions
    op.execute(
        """
        ALTER TABLE rule_shadow_hits
            ALTER COLUMN amount_base_usd TYPE NUMERIC(18, 2);
        """
    )
    op.execute(
        """
        ALTER TABLE customer_profiles
            ALTER COLUMN avg_amount TYPE NUMERIC(15, 2),
            ALTER COLUMN median_amount TYPE NUMERIC(15, 2),
            ALTER COLUMN variance_amount TYPE NUMERIC(15, 2);
        """
    )

    # Note: Dropping CONCURRENTLY indexes runs safely on separate autocommit connection after tx
    # only if no locks are held; during downgrade we drop indexes cleanly.
    for stmt in _CONCURRENT_INDEX_DROP_SQL:
        op.execute(stmt.replace(" CONCURRENTLY", ""))
