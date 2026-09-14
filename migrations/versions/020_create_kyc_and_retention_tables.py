"""create_kyc_and_retention_tables

Revision ID: 020
Revises: 019
Create Date: 2026-09-14 16:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '020'
down_revision: Union[str, None] = '019'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- Periodic KYC Review & CDD Refresh (GAP-6)
        CREATE TABLE IF NOT EXISTS kyc_reviews (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
            review_type VARCHAR(30) NOT NULL DEFAULT 'PERIODIC', -- PERIODIC, TRIGGERED, EDD_REFRESH
            due_date TIMESTAMPTZ NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'SCHEDULED', -- SCHEDULED, IN_PROGRESS, COMPLETED, OVERDUE
            outcome VARCHAR(30), -- RISK_UNCHANGED, RISK_UPGRADED, RISK_DOWNGRADED
            notes TEXT,
            reviewer_username VARCHAR(100),
            completed_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_kyc_reviews_tenant ON kyc_reviews(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_kyc_reviews_due ON kyc_reviews(due_date);
        CREATE INDEX IF NOT EXISTS idx_kyc_reviews_status ON kyc_reviews(status);

        -- Data Retention Policies (GAP-11)
        CREATE TABLE IF NOT EXISTS data_retention_policies (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            entity_type VARCHAR(50) NOT NULL, -- transactions, alerts, cases, sar_drafts, ctr_filings
            retention_days INT NOT NULL DEFAULT 1825, -- 5 years standard BSA requirement
            legal_basis VARCHAR(100) NOT NULL DEFAULT 'BSA 31 CFR 1010.430',
            action_type VARCHAR(30) NOT NULL DEFAULT 'ARCHIVE_COLD_STORAGE', -- ARCHIVE_COLD_STORAGE, PURGE
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        -- Legal Holds preventing automated deletion / DSAR erasure (GAP-13)
        CREATE TABLE IF NOT EXISTS legal_holds (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
            case_id UUID REFERENCES cases(id) ON DELETE SET NULL,
            reference_number VARCHAR(100) NOT NULL,
            reason TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_by_username VARCHAR(100),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            released_at TIMESTAMPTZ
        );

        CREATE INDEX IF NOT EXISTS idx_legal_holds_account ON legal_holds(account_id);

        -- ML Model Registry & Champion/Challenger (GAP-15)
        CREATE TABLE IF NOT EXISTS ml_model_registry (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            version VARCHAR(30) UNIQUE NOT NULL,
            model_type VARCHAR(50) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'SHADOW', -- CHAMPION, SHADOW, RETIRED
            accuracy NUMERIC(5, 4),
            precision_val NUMERIC(5, 4),
            recall_val NUMERIC(5, 4),
            auc_pr NUMERIC(5, 4),
            description TEXT,
            registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        -- RLS Policies
        ALTER TABLE kyc_reviews ENABLE ROW LEVEL SECURITY;
        ALTER TABLE data_retention_policies ENABLE ROW LEVEL SECURITY;
        ALTER TABLE legal_holds ENABLE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS kyc_reviews_tenant_isolation ON kyc_reviews;
        CREATE POLICY kyc_reviews_tenant_isolation ON kyc_reviews
            FOR ALL
            USING (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );

        DROP POLICY IF EXISTS data_retention_policies_tenant_isolation ON data_retention_policies;
        CREATE POLICY data_retention_policies_tenant_isolation ON data_retention_policies
            FOR ALL
            USING (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );

        DROP POLICY IF EXISTS legal_holds_tenant_isolation ON legal_holds;
        CREATE POLICY legal_holds_tenant_isolation ON legal_holds
            FOR ALL
            USING (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS ml_model_registry CASCADE;
        DROP TABLE IF EXISTS legal_holds CASCADE;
        DROP TABLE IF EXISTS data_retention_policies CASCADE;
        DROP TABLE IF EXISTS kyc_reviews CASCADE;
        """
    )
