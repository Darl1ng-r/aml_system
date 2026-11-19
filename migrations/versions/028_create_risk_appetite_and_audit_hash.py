"""create_risk_appetite_and_audit_hash

Revision ID: 028
Revises: 027
Create Date: 2026-11-19 12:10:00.000000

Changes:
  1. Creates tenant-isolated `risk_appetite_settings` table with Row-Level Security
     so institutional risk appetite thresholds persist across restarts and pods.
  2. Adds `prev_hash` and `record_hash` columns to `audit_log` to support verifiable
     cryptographic hash-chain tamper detection in /api/v1/audit/verify-chain.
"""
from typing import Sequence
from alembic import op

revision: str = '028'
down_revision: str | None = '027'
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS risk_appetite_settings (
            tenant_id UUID PRIMARY KEY,
            config JSONB NOT NULL,
            updated_by VARCHAR(100) NOT NULL DEFAULT 'SYSTEM',
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        ALTER TABLE risk_appetite_settings ENABLE ROW LEVEL SECURITY;
        ALTER TABLE risk_appetite_settings FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS risk_appetite_tenant_isolation ON risk_appetite_settings;
        CREATE POLICY risk_appetite_tenant_isolation ON risk_appetite_settings
            USING (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            )
            WITH CHECK (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );

        ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash VARCHAR(64);
        ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS record_hash VARCHAR(64);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE audit_log DROP COLUMN IF EXISTS record_hash;
        ALTER TABLE audit_log DROP COLUMN IF EXISTS prev_hash;
        DROP TABLE IF EXISTS risk_appetite_settings CASCADE;
        """
    )
