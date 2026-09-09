"""add_password_hash_and_fail_closed_rls

Revision ID: 009
Revises: 008
Create Date: 2026-09-09 17:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '009'
down_revision: Union[str, None] = '008'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # 1. Add password_hash and is_active to users table
    if inspector.has_table('users'):
        columns = [c['name'] for c in inspector.get_columns('users')]
        if 'password_hash' not in columns:
            op.add_column('users', sa.Column('password_hash', sa.String(length=255), nullable=True))
        if 'is_active' not in columns:
            op.add_column('users', sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'))

    # 2. Enforce fail-closed Row Level Security (RLS) policies
    # If app.current_tenant_id is not set, access is denied (fails closed).
    op.execute("""
        -- Accounts
        DROP POLICY IF EXISTS rls_tenant_isolation ON accounts;
        CREATE POLICY rls_tenant_isolation ON accounts
            FOR ALL
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        -- Transactions
        DROP POLICY IF EXISTS rls_tenant_isolation ON transactions;
        CREATE POLICY rls_tenant_isolation ON transactions
            FOR ALL
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        -- Alerts
        DROP POLICY IF EXISTS rls_tenant_isolation ON alerts;
        CREATE POLICY rls_tenant_isolation ON alerts
            FOR ALL
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        -- Customer Profiles
        DROP POLICY IF EXISTS rls_tenant_isolation ON customer_profiles;
        CREATE POLICY rls_tenant_isolation ON customer_profiles
            FOR ALL
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        -- PEP Entities (global PEP records have tenant_id IS NULL; tenant-scoped records require tenant match)
        DROP POLICY IF EXISTS rls_tenant_isolation ON pep_entities;
        CREATE POLICY rls_tenant_isolation ON pep_entities
            FOR ALL
            USING (
                tenant_id IS NULL 
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                tenant_id IS NOT NULL 
                AND tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
    """)


def downgrade() -> None:
    # Revert to migration 002 & 007 legacy policies
    op.execute("""
        DROP POLICY IF EXISTS rls_tenant_isolation ON accounts;
        CREATE POLICY rls_tenant_isolation ON accounts
            FOR ALL
            USING (
                NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );

        DROP POLICY IF EXISTS rls_tenant_isolation ON transactions;
        CREATE POLICY rls_tenant_isolation ON transactions
            FOR ALL
            USING (
                NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );

        DROP POLICY IF EXISTS rls_tenant_isolation ON alerts;
        CREATE POLICY rls_tenant_isolation ON alerts
            FOR ALL
            USING (
                NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );

        DROP POLICY IF EXISTS rls_tenant_isolation ON customer_profiles;
        CREATE POLICY rls_tenant_isolation ON customer_profiles
            FOR ALL
            USING (
                NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
    """)

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table('users'):
        columns = [c['name'] for c in inspector.get_columns('users')]
        if 'is_active' in columns:
            op.drop_column('users', 'is_active')
        if 'password_hash' in columns:
            op.drop_column('users', 'password_hash')
