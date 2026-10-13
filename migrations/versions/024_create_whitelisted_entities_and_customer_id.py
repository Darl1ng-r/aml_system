"""create_whitelisted_entities_and_customer_id

Revision ID: 024
Revises: 023
Create Date: 2026-10-13 18:00:00.000000

Changes:
  1. whitelisted_entities table for persistent false positive screening resolution (Four-Eyes principle).
  2. customer_id and tax_id columns on accounts table for entity-level aggregation (TIN / Beneficial Ownership scoping).
  3. Row Level Security policy for multi-tenant isolation on whitelisted_entities.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '024'
down_revision: Union[str, None] = '023'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- 1. Whitelisted entities table for false-positive suppression
        CREATE TABLE IF NOT EXISTS whitelisted_entities (
            id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id           UUID         NOT NULL,
            customer_id         VARCHAR(100),
            matched_entity_name VARCHAR(255) NOT NULL,
            matched_rule        VARCHAR(100) NOT NULL,
            disposition         VARCHAR(50)  NOT NULL DEFAULT 'FALSE_POSITIVE',
            cleared_by          VARCHAR(100) NOT NULL,
            cleared_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            expires_at          TIMESTAMPTZ,
            notes               TEXT,
            created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_whitelisted_entities_tenant_rule 
            ON whitelisted_entities(tenant_id, matched_rule);
        CREATE INDEX IF NOT EXISTS idx_whitelisted_entities_name 
            ON whitelisted_entities(tenant_id, matched_entity_name);
        CREATE INDEX IF NOT EXISTS idx_whitelisted_entities_cust
            ON whitelisted_entities(tenant_id, customer_id);

        -- Row Level Security
        ALTER TABLE whitelisted_entities ENABLE ROW LEVEL SECURITY;
        ALTER TABLE whitelisted_entities FORCE ROW LEVEL SECURITY;

        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies WHERE policyname = 'rls_whitelisted_entities_isolation'
            ) THEN
                CREATE POLICY rls_whitelisted_entities_isolation ON whitelisted_entities
                    FOR ALL
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
            END IF;
        END $$;

        -- 2. Add customer_id and tax_id to accounts table for entity scoping
        ALTER TABLE accounts ADD COLUMN IF NOT EXISTS customer_id VARCHAR(100);
        ALTER TABLE accounts ADD COLUMN IF NOT EXISTS tax_id VARCHAR(50);

        CREATE INDEX IF NOT EXISTS idx_accounts_customer_id ON accounts(customer_id);
        CREATE INDEX IF NOT EXISTS idx_accounts_tax_id ON accounts(tax_id);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS whitelisted_entities CASCADE;
        ALTER TABLE accounts DROP COLUMN IF EXISTS customer_id;
        ALTER TABLE accounts DROP COLUMN IF EXISTS tax_id;
        """
    )
