"""Create case_evidence table and RLS policies

Revision ID: 023
Revises: 022
Create Date: 2026-09-25 17:45:00.000000

Changes:
  1. case_evidence table for document and file attachment management per case.
  2. Row Level Security policy for multi-tenant isolation.
  3. Indexes for fast lookup by case_id and tenant_id.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '023'
down_revision: Union[str, None] = '022'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS case_evidence (
            id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            case_id       UUID         NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            tenant_id     UUID         NOT NULL,
            filename      VARCHAR(500) NOT NULL,
            content_type  VARCHAR(100) DEFAULT 'application/octet-stream',
            file_size     INTEGER      DEFAULT 0,
            storage_key   TEXT         NOT NULL,
            uploaded_by   UUID         REFERENCES users(id),
            uploaded_by_name VARCHAR(100) NOT NULL DEFAULT '',
            uploaded_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            description   TEXT,
            tags          VARCHAR(100)[] DEFAULT ARRAY[]::VARCHAR(100)[]
        );

        CREATE INDEX IF NOT EXISTS idx_case_evidence_case
            ON case_evidence(case_id);
        CREATE INDEX IF NOT EXISTS idx_case_evidence_tenant
            ON case_evidence(tenant_id, uploaded_at DESC);

        ALTER TABLE case_evidence ENABLE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS case_evidence_tenant_isolation ON case_evidence;
        CREATE POLICY case_evidence_tenant_isolation ON case_evidence
            FOR ALL
            USING (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS case_evidence CASCADE;
        """
    )
