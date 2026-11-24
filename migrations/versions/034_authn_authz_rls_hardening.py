"""AuthN/AuthZ Security Hardening: Enforce FORCE ROW LEVEL SECURITY across all multi-tenant tables (AUTHZ-01)

Revision ID: 034
Revises: 033
Create Date: 2026-11-24 17:02:00.000000

Remediates PostgreSQL table-owner RLS bypass (owner=aml_app) across all 15 previously
unforced or unprotected tables:
  - str_batches: ENABLE + FORCE RLS + USING/WITH CHECK tenant_id policy
  - users: ENABLE + FORCE RLS + tenant_id OR transaction-local app.auth_lookup='true'
  - case_notes & case_alerts: ENABLE + FORCE RLS + parent cases tenant policy
  - ml_feedback_samples: add tenant_id column (backfilled from alerts) + ENABLE + FORCE RLS
  - rule_config_history: upgrade SELECT-only policy to ALL (USING + WITH CHECK) + FORCE RLS
  - audit_log: tighten tenant SELECT/INSERT policies (remove tenant_id IS NULL leak) + FORCE RLS
  - alert_escalations, api_keys, data_retention_policies, edd_requests, kyc_reviews,
    legal_holds, resource_locks: ENABLE + FORCE RLS + WITH CHECK enforcement
"""

from typing import Sequence, Union
from alembic import op

revision: str = "034"
down_revision: Union[str, None] = "033"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Direct tenant_id tables that lacked FORCE RLS or ENABLE RLS + policy
    direct_tenant_tables = [
        "str_batches",
        "alert_escalations",
        "data_retention_policies",
        "edd_requests",
        "kyc_reviews",
        "legal_holds",
        "resource_locks",
        "rule_config_history",
    ]
    for tbl in direct_tenant_tables:
        op.execute(
            f"""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '{tbl}') THEN
                    ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;
                    ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY;
                    DROP POLICY IF EXISTS {tbl}_tenant_isolation ON {tbl};
                    CREATE POLICY {tbl}_tenant_isolation ON {tbl}
                        FOR ALL
                        USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                        WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
                END IF;
            END
            $$;
            """
        )

    # 1b. api_keys: forced tenant isolation with transaction-local auth_lookup SELECT for M2M verify_api_key
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'api_keys') THEN
                ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
                ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
                DROP POLICY IF EXISTS api_keys_tenant_isolation ON api_keys;
                DROP POLICY IF EXISTS api_keys_tenant_select ON api_keys;
                DROP POLICY IF EXISTS api_keys_tenant_write ON api_keys;
                CREATE POLICY api_keys_tenant_select ON api_keys
                    FOR SELECT
                    USING (
                        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                        OR current_setting('app.auth_lookup', true) = 'true'
                    );
                CREATE POLICY api_keys_tenant_write ON api_keys
                    FOR ALL
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
            END IF;
        END
        $$;
        """
    )

    # 2. users: forced tenant isolation with transaction-local auth_lookup allowance for login/refresh/MFA
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users') THEN
                ALTER TABLE users ENABLE ROW LEVEL SECURITY;
                ALTER TABLE users FORCE ROW LEVEL SECURITY;
                DROP POLICY IF EXISTS users_tenant_isolation ON users;
                CREATE POLICY users_tenant_isolation ON users
                    FOR ALL
                    USING (
                        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                        OR current_setting('app.auth_lookup', true) = 'true'
                    )
                    WITH CHECK (
                        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                        OR current_setting('app.auth_lookup', true) = 'true'
                    );
            END IF;
        END
        $$;
        """
    )

    # 3. case_notes & case_alerts: inherit tenant isolation via parent cases table
    for tbl in ("case_notes", "case_alerts"):
        op.execute(
            f"""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '{tbl}') THEN
                    ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;
                    ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY;
                    DROP POLICY IF EXISTS {tbl}_tenant_isolation ON {tbl};
                    CREATE POLICY {tbl}_tenant_isolation ON {tbl}
                        FOR ALL
                        USING (
                            EXISTS (
                                SELECT 1 FROM cases c
                                WHERE c.id = {tbl}.case_id
                                  AND c.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                            )
                        )
                        WITH CHECK (
                            EXISTS (
                                SELECT 1 FROM cases c
                                WHERE c.id = {tbl}.case_id
                                  AND c.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                            )
                        );
                END IF;
            END
            $$;
            """
        )

    # 4. ml_feedback_samples: add tenant_id column, backfill from alerts, enforce forced RLS
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'ml_feedback_samples') THEN
                ALTER TABLE ml_feedback_samples ADD COLUMN IF NOT EXISTS tenant_id UUID;
                UPDATE ml_feedback_samples m
                SET tenant_id = a.tenant_id
                FROM alerts a
                WHERE m.alert_id = a.id AND m.tenant_id IS NULL;

                CREATE INDEX IF NOT EXISTS idx_ml_feedback_samples_tenant_id ON ml_feedback_samples (tenant_id);

                ALTER TABLE ml_feedback_samples ENABLE ROW LEVEL SECURITY;
                ALTER TABLE ml_feedback_samples FORCE ROW LEVEL SECURITY;
                DROP POLICY IF EXISTS ml_feedback_samples_tenant_isolation ON ml_feedback_samples;
                CREATE POLICY ml_feedback_samples_tenant_isolation ON ml_feedback_samples
                    FOR ALL
                    USING (
                        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                        OR (
                            tenant_id IS NULL AND EXISTS (
                                SELECT 1 FROM alerts a
                                WHERE a.id = ml_feedback_samples.alert_id
                                  AND a.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                            )
                        )
                    )
                    WITH CHECK (
                        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                        OR (
                            tenant_id IS NULL AND EXISTS (
                                SELECT 1 FROM alerts a
                                WHERE a.id = ml_feedback_samples.alert_id
                                  AND a.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                            )
                        )
                    );
            END IF;
        END
        $$;
        """
    )

    # 5. audit_log: tighten SELECT policy (remove tenant_id IS NULL cross-tenant leak) + FORCE RLS
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'audit_log') THEN
                ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
                ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
                DROP POLICY IF EXISTS audit_log_tenant_isolation ON audit_log;
                DROP POLICY IF EXISTS audit_log_insert_policy ON audit_log;
                CREATE POLICY audit_log_tenant_isolation ON audit_log
                    FOR SELECT
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
                CREATE POLICY audit_log_insert_policy ON audit_log
                    FOR INSERT
                    WITH CHECK (
                        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                        OR tenant_id IS NULL
                    );
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    for tbl in (
        "str_batches",
        "alert_escalations",
        "api_keys",
        "data_retention_policies",
        "edd_requests",
        "kyc_reviews",
        "legal_holds",
        "resource_locks",
        "rule_config_history",
        "users",
        "case_notes",
        "case_alerts",
        "ml_feedback_samples",
        "audit_log",
    ):
        op.execute(
            f"""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '{tbl}') THEN
                    ALTER TABLE {tbl} NO FORCE ROW LEVEL SECURITY;
                END IF;
            END
            $$;
            """
        )
