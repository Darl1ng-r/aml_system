"""create_ctr_filings_table

Revision ID: 019
Revises: 018
Create Date: 2026-09-14 15:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '019'
down_revision: Union[str, None] = '018'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS ctr_filings (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            transaction_id UUID REFERENCES transactions(id) ON DELETE SET NULL,
            account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
            amount NUMERIC(15, 2) NOT NULL,
            currency VARCHAR(3) DEFAULT 'USD',
            cash_in_out VARCHAR(15) NOT NULL DEFAULT 'DEPOSIT', -- DEPOSIT, WITHDRAWAL, EXCHANGE
            status VARCHAR(30) NOT NULL DEFAULT 'PENDING', -- PENDING, FILED, EXEMPT, REJECTED
            due_date TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '15 days'),
            fincen_tracking_id VARCHAR(100),
            filed_at TIMESTAMPTZ,
            filed_by UUID,
            filed_by_username VARCHAR(100),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_ctr_filings_tenant ON ctr_filings(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_ctr_filings_status ON ctr_filings(status);
        CREATE INDEX IF NOT EXISTS idx_ctr_filings_due_date ON ctr_filings(due_date);

        ALTER TABLE ctr_filings ENABLE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS ctr_filings_tenant_isolation ON ctr_filings;
        CREATE POLICY ctr_filings_tenant_isolation ON ctr_filings
            FOR ALL
            USING (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS ctr_filings CASCADE;
        """
    )
