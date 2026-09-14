"""create_edd_and_account_lifecycle

Revision ID: 018
Revises: 017
Create Date: 2026-09-14 14:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '018'
down_revision: Union[str, None] = '017'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- Add account lifecycle & freeze columns to accounts table
        ALTER TABLE accounts ADD COLUMN IF NOT EXISTS status VARCHAR(30) DEFAULT 'ACTIVE';
        ALTER TABLE accounts ADD COLUMN IF NOT EXISTS frozen_reason VARCHAR(255);
        ALTER TABLE accounts ADD COLUMN IF NOT EXISTS frozen_at TIMESTAMPTZ;
        ALTER TABLE accounts ADD COLUMN IF NOT EXISTS freezing_order_ref VARCHAR(100);

        -- Ensure existing accounts are marked ACTIVE
        UPDATE accounts SET status = 'ACTIVE' WHERE status IS NULL;

        CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);

        -- Create Enhanced Due Diligence (EDD) requests table
        CREATE TABLE IF NOT EXISTS edd_requests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            case_id UUID REFERENCES cases(id) ON DELETE SET NULL,
            account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
            trigger_reason VARCHAR(100) NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'PENDING', -- PENDING, DOCUMENTS_RECEIVED, APPROVED, REJECTED
            source_of_wealth TEXT,
            source_of_funds TEXT,
            mlro_decision VARCHAR(30), -- APPROVED, RESTRICTED, EXIT_RELATIONSHIP
            mlro_notes TEXT,
            requested_by UUID,
            requested_by_username VARCHAR(100),
            reviewed_by UUID,
            reviewed_by_username VARCHAR(100),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            resolved_at TIMESTAMPTZ
        );

        CREATE INDEX IF NOT EXISTS idx_edd_requests_tenant ON edd_requests(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_edd_requests_status ON edd_requests(status);
        CREATE INDEX IF NOT EXISTS idx_edd_requests_account ON edd_requests(account_id);

        ALTER TABLE edd_requests ENABLE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS edd_requests_tenant_isolation ON edd_requests;
        CREATE POLICY edd_requests_tenant_isolation ON edd_requests
            FOR ALL
            USING (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS edd_requests CASCADE;
        ALTER TABLE accounts DROP COLUMN IF EXISTS freezing_order_ref;
        ALTER TABLE accounts DROP COLUMN IF EXISTS frozen_at;
        ALTER TABLE accounts DROP COLUMN IF EXISTS frozen_reason;
        ALTER TABLE accounts DROP COLUMN IF EXISTS status;
        """
    )
