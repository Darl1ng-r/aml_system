"""Enable Row-Level Security (RLS) per tenant for multi-tenancy database isolation

Revision ID: 002
Revises: 001
Create Date: 2026-07-16
"""
from typing import Sequence, Union
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        -- ================================================================
        -- 1. Create tenants table & seed default tenant
        -- ================================================================
        CREATE TABLE IF NOT EXISTS tenants (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            name VARCHAR(100) NOT NULL UNIQUE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        INSERT INTO tenants (id, name)
        VALUES ('00000000-0000-0000-0000-000000000001', 'Default Financial Institution')
        ON CONFLICT (id) DO NOTHING;

        -- ================================================================
        -- 2. Create users table with tenant association
        -- ================================================================
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            username VARCHAR(100) UNIQUE NOT NULL,
            role VARCHAR(50) DEFAULT 'ANALYST',
            tenant_id UUID REFERENCES tenants(id) DEFAULT '00000000-0000-0000-0000-000000000001',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        -- ================================================================
        -- 3. Add tenant_id to customer_profiles & populate existing rows
        -- ================================================================
        ALTER TABLE customer_profiles
        ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);

        UPDATE customer_profiles cp
        SET tenant_id = a.tenant_id
        FROM accounts a
        WHERE cp.account_id = a.id AND cp.tenant_id IS NULL;

        -- Assign default tenant_id to any orphaned NULL records
        UPDATE accounts SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
        UPDATE transactions SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
        UPDATE alerts SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
        UPDATE customer_profiles SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;

        -- Create indexes on tenant_id for RLS evaluation performance
        CREATE INDEX IF NOT EXISTS idx_accounts_tenant ON accounts(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_transactions_tenant ON transactions(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_customer_profiles_tenant ON customer_profiles(tenant_id);

        -- ================================================================
        -- 4. Enable & Force Row-Level Security (RLS) on all tenant tables
        -- ================================================================
        ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
        ALTER TABLE accounts FORCE ROW LEVEL SECURITY;

        ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
        ALTER TABLE transactions FORCE ROW LEVEL SECURITY;

        ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
        ALTER TABLE alerts FORCE ROW LEVEL SECURITY;

        ALTER TABLE customer_profiles ENABLE ROW LEVEL SECURITY;
        ALTER TABLE customer_profiles FORCE ROW LEVEL SECURITY;

        -- ================================================================
        -- 5. Drop old policies if any
        -- ================================================================
        DROP POLICY IF EXISTS rls_tenant_isolation ON accounts;
        DROP POLICY IF EXISTS rls_tenant_isolation ON transactions;
        DROP POLICY IF EXISTS rls_tenant_isolation ON alerts;
        DROP POLICY IF EXISTS rls_tenant_isolation ON customer_profiles;

        -- ================================================================
        -- 6. Define Strict Tenant Isolation RLS Policies
        -- ================================================================
        -- If app.current_tenant_id is NOT set (system context), full access.
        -- If app.current_tenant_id IS set, restricts strictly to rows matching tenant_id.

        CREATE POLICY rls_tenant_isolation ON accounts
            FOR ALL
            USING (
                NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );

        CREATE POLICY rls_tenant_isolation ON transactions
            FOR ALL
            USING (
                NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );

        CREATE POLICY rls_tenant_isolation ON alerts
            FOR ALL
            USING (
                NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );

        CREATE POLICY rls_tenant_isolation ON customer_profiles
            FOR ALL
            USING (
                NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
                OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
    """)


def downgrade() -> None:
    op.execute("""
        DROP POLICY IF EXISTS rls_tenant_isolation ON customer_profiles;
        DROP POLICY IF EXISTS rls_tenant_isolation ON alerts;
        DROP POLICY IF EXISTS rls_tenant_isolation ON transactions;
        DROP POLICY IF EXISTS rls_tenant_isolation ON accounts;

        ALTER TABLE customer_profiles DISABLE ROW LEVEL SECURITY;
        ALTER TABLE alerts DISABLE ROW LEVEL SECURITY;
        ALTER TABLE transactions DISABLE ROW LEVEL SECURITY;
        ALTER TABLE accounts DISABLE ROW LEVEL SECURITY;

        ALTER TABLE customer_profiles DROP COLUMN IF EXISTS tenant_id;
    """)
