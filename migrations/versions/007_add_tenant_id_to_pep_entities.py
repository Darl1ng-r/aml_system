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
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table('pep_entities'):
        columns = [c['name'] for c in inspector.get_columns('pep_entities')]
        if 'tenant_id' not in columns:
            op.add_column(
                'pep_entities',
                sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True)
            )
            op.create_index('idx_pep_entities_tenant', 'pep_entities', ['tenant_id'])

    # Enable & Force Row-Level Security (RLS) on pep_entities table
    op.execute("""
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
    """)

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table('pep_entities'):
        columns = [c['name'] for c in inspector.get_columns('pep_entities')]
        if 'tenant_id' in columns:
            op.drop_index('idx_pep_entities_tenant', table_name='pep_entities')
            op.drop_column('pep_entities', 'tenant_id')
