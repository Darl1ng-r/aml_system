"""create_sar_drafts_table

Revision ID: 015
Revises: 014
Create Date: 2026-09-14 13:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '015'
down_revision: Union[str, None] = '014'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS sar_drafts (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            alert_id UUID REFERENCES alerts(id),
            case_id UUID,
            drafted_by UUID,
            drafted_by_username VARCHAR(100) NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'PENDING_MLRO_REVIEW',
            narrative TEXT NOT NULL,
            xml_payload TEXT,
            rejection_reason TEXT,
            reviewed_by UUID,
            reviewed_by_username VARCHAR(100),
            reviewed_at TIMESTAMPTZ,
            fincen_tracking_id VARCHAR(100),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_sar_drafts_tenant ON sar_drafts(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_sar_drafts_status ON sar_drafts(status);
        CREATE INDEX IF NOT EXISTS idx_sar_drafts_alert ON sar_drafts(alert_id);

        ALTER TABLE sar_drafts ENABLE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS sar_drafts_tenant_isolation ON sar_drafts;
        CREATE POLICY sar_drafts_tenant_isolation ON sar_drafts
            FOR ALL
            USING (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS sar_drafts CASCADE;
        """
    )
