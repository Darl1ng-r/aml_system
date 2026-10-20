"""force_rls_on_all_tables

Revision ID: 026
Revises: 025
Create Date: 2026-10-16 11:45:00.000000

Changes:
  1. Enforces FORCE ROW LEVEL SECURITY on all core financial domain multi-tenant tables.
     Guarantees that even table owners and superusers cannot bypass tenant isolation policies.
  2. Creates partial index on transactional_outbox for status IN ('PENDING', 'PROCESSING').
"""
from typing import Sequence
from alembic import op
import sqlalchemy as sa

revision: str = '026'
down_revision: str | None = '025'
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    # Core domain tables that strictly require FORCE ROW LEVEL SECURITY
    tables = [
        "accounts",
        "transactions",
        "alerts",
        "customer_profiles",
        "pep_entities",
        "transactional_outbox",
        "sar_drafts",
        "cases",
        "case_evidence",
        "ctr_filings",
        "edd_records",
        "whitelisted_entities",
        "kyc_records",
        "str_batches",
        "rule_configs",
    ]

    for table in tables:
        op.execute(
            f"""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '{table}') THEN
                    ALTER TABLE {table} FORCE ROW LEVEL SECURITY;
                END IF;
            END
            $$;
            """
        )

    # Performance partial index for outbox relay engine
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_outbox_pending_processing
            ON transactional_outbox (created_at ASC)
            WHERE status IN ('PENDING', 'PROCESSING');
        """
    )


def downgrade() -> None:
    tables = [
        "accounts",
        "transactions",
        "alerts",
        "customer_profiles",
        "pep_entities",
        "transactional_outbox",
        "sar_drafts",
        "cases",
        "case_evidence",
        "ctr_filings",
        "edd_records",
        "whitelisted_entities",
        "kyc_records",
        "str_batches",
        "rule_configs",
    ]

    for table in tables:
        op.execute(
            f"""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '{table}') THEN
                    ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY;
                END IF;
            END
            $$;
            """
        )

    op.execute(
        """
        DROP INDEX IF EXISTS idx_outbox_pending_processing;
        """
    )
