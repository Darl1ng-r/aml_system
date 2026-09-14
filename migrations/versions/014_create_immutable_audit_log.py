"""create_immutable_audit_log

Revision ID: 014
Revises: 013
Create Date: 2026-09-14 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '014'
down_revision: Union[str, None] = '013'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- Create tamper-evident append-only audit log table
        CREATE TABLE IF NOT EXISTS audit_log (
            id BIGSERIAL PRIMARY KEY,
            tenant_id UUID,
            occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            actor_id VARCHAR(100),
            actor_username VARCHAR(100),
            actor_role VARCHAR(50),
            actor_ip VARCHAR(50),
            actor_user_agent TEXT,
            session_id VARCHAR(200),
            action VARCHAR(100) NOT NULL,
            resource_type VARCHAR(50),
            resource_id VARCHAR(100),
            before_state JSONB,
            after_state JSONB,
            details JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_audit_log_tenant ON audit_log(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_id);
        CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
        CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource_type, resource_id);
        CREATE INDEX IF NOT EXISTS idx_audit_log_occurred_at ON audit_log(occurred_at DESC);

        -- Non-bypassable immutability rules: block UPDATE and DELETE
        CREATE OR REPLACE RULE audit_log_no_update AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
        CREATE OR REPLACE RULE audit_log_no_delete AS ON DELETE TO audit_log DO INSTEAD NOTHING;

        -- Row-Level Security for multi-tenant isolation
        ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS audit_log_tenant_isolation ON audit_log;
        CREATE POLICY audit_log_tenant_isolation ON audit_log
            FOR SELECT
            USING (
                tenant_id IS NULL OR
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );

        DROP POLICY IF EXISTS audit_log_insert_policy ON audit_log;
        CREATE POLICY audit_log_insert_policy ON audit_log
            FOR INSERT
            WITH CHECK (true);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP RULE IF EXISTS audit_log_no_update ON audit_log;
        DROP RULE IF EXISTS audit_log_no_delete ON audit_log;
        DROP TABLE IF EXISTS audit_log CASCADE;
        """
    )
