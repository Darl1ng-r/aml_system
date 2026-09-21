"""create_transactional_outbox

Revision ID: 021
Revises: 020
Create Date: 2026-09-21 16:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '021'
down_revision: Union[str, None] = '020'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- Transactional Outbox for Zero-Loss Dual Write to Kafka/Redpanda
        CREATE TABLE IF NOT EXISTS transactional_outbox (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID,
            aggregate_type VARCHAR(50) NOT NULL,
            aggregate_id VARCHAR(100) NOT NULL,
            event_type VARCHAR(100) NOT NULL,
            payload JSONB NOT NULL,
            headers JSONB DEFAULT '{}'::jsonb,
            status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
            retry_count INT NOT NULL DEFAULT 0,
            last_error TEXT,
            published_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_outbox_status_created ON transactional_outbox (created_at) WHERE status = 'PENDING';
        CREATE INDEX IF NOT EXISTS idx_outbox_aggregate ON transactional_outbox (aggregate_type, aggregate_id);
        CREATE INDEX IF NOT EXISTS idx_outbox_tenant ON transactional_outbox (tenant_id);

        -- Enable RLS
        ALTER TABLE transactional_outbox ENABLE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS transactional_outbox_tenant_isolation ON transactional_outbox;
        CREATE POLICY transactional_outbox_tenant_isolation ON transactional_outbox
            FOR ALL
            USING (
                tenant_id IS NULL OR
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            )
            WITH CHECK (
                tenant_id IS NULL OR
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS transactional_outbox CASCADE;
        """
    )
