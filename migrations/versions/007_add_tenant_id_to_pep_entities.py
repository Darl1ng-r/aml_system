"""add_tenant_id_to_pep_entities

Revision ID: 007
Revises: 006
Create Date: 2026-07-17 03:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '007'
down_revision: Union[str, None] = '006'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    # Add tenant_id column if not present (safeguarded for existing databases)
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name='pep_entities' AND column_name='tenant_id'
            ) THEN
                ALTER TABLE pep_entities ADD COLUMN tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;
                CREATE INDEX idx_pep_entities_tenant ON pep_entities(tenant_id);
            END IF;
        END $$;

        -- Enable & Force Row-Level Security (RLS) on pep_entities table
        ALTER TABLE pep_entities ENABLE ROW LEVEL SECURITY;
        ALTER TABLE pep_entities FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS rls_tenant_isolation ON pep_entities;

        CREATE POLICY rls_tenant_isolation ON pep_entities
            FOR ALL
            USING (
                NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
                OR tenant_id IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
                OR tenant_id IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
    """)


def downgrade() -> None:
    op.execute("""
        DROP POLICY IF EXISTS rls_tenant_isolation ON pep_entities;
        ALTER TABLE pep_entities DISABLE ROW LEVEL SECURITY;
        DROP INDEX IF EXISTS idx_pep_entities_tenant;
        ALTER TABLE pep_entities DROP COLUMN IF EXISTS tenant_id;
    """)
