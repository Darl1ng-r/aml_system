"""Scale Pillar Stage 2: Async Export, Analytics & Notification Jobs Table with FORCE RLS
and CONCURRENTLY Deduplication + Keyset Indexes.

Revision ID: 039
Revises: 038
Create Date: 2026-11-27 23:05:00.000000
"""

from typing import Sequence, Union
from alembic import op
from sqlalchemy import text

revision: str = "039"
down_revision: Union[str, None] = "038"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_CONCURRENT_INDEX_CREATE_SQL: list[str] = [
    """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_async_jobs_tenant_created_id
    ON async_jobs (tenant_id, created_at DESC, id DESC);
    """,
    """
    CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_async_jobs_tenant_status_created
    ON async_jobs (tenant_id, status, created_at DESC);
    """,
    """
    CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_async_jobs_tenant_idempotency
    ON async_jobs (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
    """,
]


def upgrade() -> None:
    engine = op.get_bind().engine
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS async_jobs (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
                    job_type VARCHAR(64) NOT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'QUEUED',
                    idempotency_key VARCHAR(255),
                    requested_by VARCHAR(128) NOT NULL,
                    requested_role VARCHAR(64) NOT NULL DEFAULT 'ANALYST',
                    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                    result_meta JSONB NOT NULL DEFAULT '{}'::jsonb,
                    artifact_storage_key TEXT,
                    artifact_sha256 VARCHAR(64),
                    artifact_content_type VARCHAR(128),
                    artifact_filename VARCHAR(255),
                    error_message TEXT,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    started_at TIMESTAMPTZ,
                    completed_at TIMESTAMPTZ,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT chk_async_jobs_type CHECK (
                        job_type IN (
                            'ALERT_PDF_EXPORT',
                            'ALERT_CSV_EXPORT',
                            'EXAMINER_PACKET_ZIP',
                            'EMAIL_NOTIFICATION',
                            'RULE_BACKTEST_ANALYTICS'
                        )
                    ),
                    CONSTRAINT chk_async_jobs_status CHECK (
                        status IN ('QUEUED', 'PROCESSING', 'COMPLETED', 'FAILED', 'DEAD_LETTERED')
                    ),
                    CONSTRAINT chk_async_jobs_retry_nonneg CHECK (retry_count >= 0)
                );
                """
            )
        )
        conn.execute(text("ALTER TABLE async_jobs ENABLE ROW LEVEL SECURITY;"))
        conn.execute(text("ALTER TABLE async_jobs FORCE ROW LEVEL SECURITY;"))
        conn.execute(text("DROP POLICY IF EXISTS async_jobs_tenant_isolation ON async_jobs;"))
        conn.execute(
            text(
                """
                CREATE POLICY async_jobs_tenant_isolation ON async_jobs
                FOR ALL
                USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
                """
            )
        )
        conn.execute(
            text(
                """
                DO $$
                BEGIN
                    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aml_app') THEN
                        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE async_jobs TO aml_app;
                    END IF;
                END $$;
                """
            )
        )
        for ddl in _CONCURRENT_INDEX_CREATE_SQL:
            conn.execute(text(ddl))


def downgrade() -> None:
    op.execute(text("DROP TABLE IF EXISTS async_jobs CASCADE;"))
