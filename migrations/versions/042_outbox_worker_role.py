"""Provision least-privilege `aml_outbox_worker` PostgreSQL role with scoped BYPASSRLS
strictly for `transactional_outbox` relay and partition lifecycle maintenance.

Fixes RLS blindness under `aml_app` (`NOBYPASSRLS`) where `OutboxRelayEngine` could not
see tenant-scoped rows and `drop_expired_outbox_partitions()` could falsely see 0 pending
rows and drop unpublished tenant events.

Revision ID: 042
Revises: 041
Create Date: 2026-11-28 16:50:00.000000
"""

from __future__ import annotations

import os
import secrets
from typing import Sequence, Union

from alembic import op

revision: str = "042"
down_revision: Union[str, None] = "041"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _resolve_outbox_worker_password() -> str:
    pw = os.getenv("AML_OUTBOX_WORKER_PASSWORD", "").strip()
    if pw:
        return pw
    env = os.getenv("ENVIRONMENT", "development").strip().lower()
    if env in {"production", "prod", "staging"}:
        raise RuntimeError(
            "CRITICAL: AML_OUTBOX_WORKER_PASSWORD environment variable must be set "
            "when running migration 042 in hardened environments."
        )
    return secrets.token_urlsafe(24)


def upgrade() -> None:
    role_pw = _resolve_outbox_worker_password().replace("'", "''")
    op.execute(
        f"""
        DO $$
        DECLARE
            can_manage_roles BOOLEAN;
        BEGIN
            SELECT COALESCE(rolsuper OR rolcreaterole, FALSE)
            INTO can_manage_roles
            FROM pg_catalog.pg_roles
            WHERE rolname = current_user;

            IF can_manage_roles THEN
                IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'aml_outbox_worker') THEN
                    CREATE ROLE aml_outbox_worker
                        WITH LOGIN PASSWORD '{role_pw}'
                        NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;
                ELSIF current_user != 'aml_outbox_worker' THEN
                    ALTER ROLE aml_outbox_worker WITH NOSUPERUSER BYPASSRLS;
                END IF;
            ELSE
                RAISE NOTICE 'Skipping CREATE/ALTER ROLE aml_outbox_worker because current_user (%) lacks CREATEROLE; provision role via DBA/superuser.', current_user;
            END IF;
        END
        $$;

        DO $$
        DECLARE
            part_rec RECORD;
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'aml_outbox_worker') THEN
                REVOKE ALL ON SCHEMA public FROM aml_outbox_worker;
                GRANT USAGE ON SCHEMA public TO aml_outbox_worker;
                -- Strictly scoped privileges: ONLY transactional_outbox (no access to PII/accounts/users/SARs)
                GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE transactional_outbox TO aml_outbox_worker;
                GRANT EXECUTE ON FUNCTION ensure_outbox_weekly_partitions(INT, INT) TO aml_outbox_worker;
                GRANT EXECUTE ON FUNCTION ensure_audit_monthly_partitions(INT, INT) TO aml_outbox_worker;
                GRANT EXECUTE ON FUNCTION drop_expired_outbox_partitions(INT) TO aml_outbox_worker;

                FOR part_rec IN
                    SELECT child.relname
                    FROM pg_inherits inh
                    JOIN pg_class parent ON inh.inhparent = parent.oid
                    JOIN pg_class child ON inh.inhrelid = child.oid
                    WHERE parent.relname = 'transactional_outbox'
                LOOP
                    EXECUTE format(
                        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I TO aml_outbox_worker;',
                        part_rec.relname
                    );
                END LOOP;
            END IF;
        END
        $$;

        -- Defense-in-depth PostgreSQL-level fail-closed guard on drop_expired_outbox_partitions():
        -- Refuses to run under any NOBYPASSRLS non-superuser role (e.g. aml_app) so RLS can NEVER
        -- hide unpublished PENDING/PROCESSING tenant rows and trigger silent partition drops.
        CREATE OR REPLACE FUNCTION drop_expired_outbox_partitions(
            retention_weeks INT DEFAULT 2
        ) RETURNS INT
        LANGUAGE plpgsql
        AS $$
        DECLARE
            can_bypass_rls BOOLEAN;
            cutoff TIMESTAMPTZ := (date_trunc('week', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
                                  - make_interval(weeks => GREATEST(1, retention_weeks));
            rec RECORD;
            bound_expr TEXT;
            upper_str TEXT;
            upper_ts TIMESTAMPTZ;
            has_active BOOLEAN;
            dropped_count INT := 0;
        BEGIN
            SELECT COALESCE(rolbypassrls OR rolsuper, FALSE)
            INTO can_bypass_rls
            FROM pg_catalog.pg_roles
            WHERE rolname = current_user;

            IF NOT COALESCE(can_bypass_rls, FALSE) THEN
                RAISE EXCEPTION
                    'Refusing to run drop_expired_outbox_partitions() under NOBYPASSRLS role %: RLS would hide unpublished tenant outbox events.',
                    current_user
                    USING ERRCODE = '42501';
            END IF;

            FOR rec IN
                SELECT c.oid, c.relname
                FROM pg_inherits ih
                JOIN pg_class c ON c.oid = ih.inhrelid
                WHERE ih.inhparent = 'transactional_outbox'::regclass
                  AND c.relname <> 'transactional_outbox_default'
            LOOP
                SELECT pg_get_expr(c.relpartbound, c.oid) INTO bound_expr
                FROM pg_class c WHERE c.oid = rec.oid;

                upper_str := substring(bound_expr FROM 'TO \(''([^'']+)''\)');
                IF upper_str IS NULL THEN
                    CONTINUE;
                END IF;

                upper_ts := upper_str::timestamptz;
                IF upper_ts <= cutoff THEN
                    EXECUTE format(
                        'SELECT EXISTS (SELECT 1 FROM %I WHERE status IN (''PENDING'', ''PROCESSING'') LIMIT 1);',
                        rec.relname
                    ) INTO has_active;

                    IF NOT has_active THEN
                        EXECUTE format('DROP TABLE IF EXISTS %I;', rec.relname);
                        dropped_count := dropped_count + 1;
                    END IF;
                END IF;
            END LOOP;
            RETURN dropped_count;
        END;
        $$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'aml_outbox_worker') THEN
                REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM aml_outbox_worker;
                REVOKE USAGE ON SCHEMA public FROM aml_outbox_worker;
            END IF;
        END
        $$;
        """
    )
