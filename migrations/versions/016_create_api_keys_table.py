"""create_api_keys_table

Revision ID: 016
Revises: 015
Create Date: 2026-09-14 13:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '016'
down_revision: Union[str, None] = '015'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            name VARCHAR(100) NOT NULL,
            key_prefix VARCHAR(16) NOT NULL,
            hashed_secret VARCHAR(128) NOT NULL,
            scopes JSONB NOT NULL DEFAULT '["transactions:ingest"]'::jsonb,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_by UUID,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at TIMESTAMPTZ,
            last_used_at TIMESTAMPTZ
        );

        CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
        CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);

        ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS api_keys_tenant_isolation ON api_keys;
        CREATE POLICY api_keys_tenant_isolation ON api_keys
            FOR ALL
            USING (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS api_keys CASCADE;
        """
    )
