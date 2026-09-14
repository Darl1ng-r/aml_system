"""create_case_management_tables

Revision ID: 017
Revises: 016
Create Date: 2026-09-14 14:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '017'
down_revision: Union[str, None] = '016'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- Cases table
        CREATE TABLE IF NOT EXISTS cases (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL,
            case_number VARCHAR(30) UNIQUE NOT NULL,
            title VARCHAR(255) NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'OPEN', -- OPEN, INVESTIGATING, PENDING_EDD, PENDING_SAR, CLOSED
            priority VARCHAR(10) NOT NULL DEFAULT 'MEDIUM', -- LOW, MEDIUM, HIGH, CRITICAL
            assigned_to UUID,
            assigned_username VARCHAR(100),
            subject_account_id UUID REFERENCES accounts(id),
            narrative TEXT,
            closure_reason VARCHAR(50), -- FALSE_POSITIVE, SAR_FILED, LAW_ENFORCEMENT_REFERRAL, CLOSED_CLEARED
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            closed_at TIMESTAMPTZ
        );

        CREATE INDEX IF NOT EXISTS idx_cases_tenant ON cases(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
        CREATE INDEX IF NOT EXISTS idx_cases_assignee ON cases(assigned_to);
        CREATE INDEX IF NOT EXISTS idx_cases_account ON cases(subject_account_id);

        -- Case to Alerts association
        CREATE TABLE IF NOT EXISTS case_alerts (
            case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
            alert_id UUID REFERENCES alerts(id) ON DELETE CASCADE,
            added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (case_id, alert_id)
        );

        -- Case investigation notes / timeline
        CREATE TABLE IF NOT EXISTS case_notes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
            author_id UUID,
            author_username VARCHAR(100) NOT NULL,
            note TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_case_notes_case ON case_notes(case_id);

        -- RLS Policies
        ALTER TABLE cases ENABLE ROW LEVEL SECURITY;
        ALTER TABLE case_notes ENABLE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS cases_tenant_isolation ON cases;
        CREATE POLICY cases_tenant_isolation ON cases
            FOR ALL
            USING (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS case_notes CASCADE;
        DROP TABLE IF EXISTS case_alerts CASCADE;
        DROP TABLE IF EXISTS cases CASCADE;
        """
    )
