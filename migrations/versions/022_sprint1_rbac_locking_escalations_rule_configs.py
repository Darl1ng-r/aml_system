"""Sprint 1: audit_log REVOKE, resource locks, alert escalations, per-tenant rule_configs

Revision ID: 022
Revises: 021
Create Date: 2026-09-25 17:00:00.000000

Changes:
  1. REVOKE UPDATE/DELETE/TRUNCATE on audit_log from aml_app_user (DB-level immutability).
  2. resource_locks — pessimistic lease registry for alert/case collision prevention.
  3. alert_escalations — Tier 1 -> Tier 2 handoff audit chain.
  4. rule_configs — per-tenant, per-rule versioned rule configuration table with
     full audit trail, replacing the flat rules_configuration and JSON-file approach.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '022'
down_revision: Union[str, None] = '021'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. Harden audit_log: revoke mutation privileges from app role ──────────
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aml_app_user') THEN
                REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_log FROM aml_app_user;
                RAISE NOTICE 'Revoked UPDATE/DELETE/TRUNCATE on audit_log from aml_app_user.';
            ELSE
                RAISE NOTICE 'Role aml_app_user not found — skipping audit_log revoke (non-fatal).';
            END IF;
        END
        $$;
        """
    )

    # ── 2. resource_locks — pessimistic lease registry ────────────────────────
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS resource_locks (
            resource_type   VARCHAR(20)  NOT NULL CHECK (resource_type IN ('ALERT', 'CASE')),
            resource_id     UUID         NOT NULL,
            locked_by       UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            locked_by_name  VARCHAR(100) NOT NULL DEFAULT '',
            tenant_id       UUID         NOT NULL,
            locked_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            expires_at      TIMESTAMPTZ  NOT NULL,
            lock_token      UUID         NOT NULL DEFAULT gen_random_uuid(),
            released_at     TIMESTAMPTZ,
            force_broken_by UUID         REFERENCES users(id),
            PRIMARY KEY (resource_type, resource_id)
        );

        CREATE INDEX IF NOT EXISTS idx_resource_locks_tenant
            ON resource_locks(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_resource_locks_expiry
            ON resource_locks(expires_at) WHERE released_at IS NULL;
        CREATE INDEX IF NOT EXISTS idx_resource_locks_holder
            ON resource_locks(locked_by) WHERE released_at IS NULL;

        ALTER TABLE resource_locks ENABLE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS resource_locks_tenant_isolation ON resource_locks;
        CREATE POLICY resource_locks_tenant_isolation ON resource_locks
            FOR ALL
            USING (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );
        """
    )

    # ── 3. alert_escalations — Tier 1 -> Tier 2 handoff chain ─────────────────
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_escalations (
            id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id         UUID         NOT NULL,
            alert_id          UUID         NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
            case_id           UUID         REFERENCES cases(id) ON DELETE SET NULL,
            escalated_by      UUID         NOT NULL REFERENCES users(id),
            escalated_by_name VARCHAR(100) NOT NULL DEFAULT '',
            escalated_to      UUID         REFERENCES users(id),
            escalated_to_name VARCHAR(100),
            escalated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            from_tier         SMALLINT     NOT NULL CHECK (from_tier IN (1, 2)),
            to_tier           SMALLINT     NOT NULL CHECK (to_tier   IN (2, 3)),
            escalation_reason TEXT         NOT NULL DEFAULT '',
            resolved_at       TIMESTAMPTZ,
            resolution_action VARCHAR(50)
        );

        CREATE INDEX IF NOT EXISTS idx_alert_escalations_alert
            ON alert_escalations(alert_id);
        CREATE INDEX IF NOT EXISTS idx_alert_escalations_tenant_time
            ON alert_escalations(tenant_id, escalated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_alert_escalations_assignee
            ON alert_escalations(escalated_to) WHERE resolved_at IS NULL;

        ALTER TABLE alert_escalations ENABLE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS alert_escalations_tenant_isolation ON alert_escalations;
        CREATE POLICY alert_escalations_tenant_isolation ON alert_escalations
            FOR ALL
            USING (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );
        """
    )

    # ── 4. rule_configs — per-tenant, per-rule versioned config ───────────────
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS rule_configs (
            id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id       UUID         NOT NULL,
            rule_name       VARCHAR(100) NOT NULL,
            enabled         BOOLEAN      NOT NULL DEFAULT true,
            config          JSONB        NOT NULL DEFAULT '{}'::jsonb,
            version         INTEGER      NOT NULL DEFAULT 1,
            updated_by      UUID         REFERENCES users(id),
            updated_by_name VARCHAR(100),
            updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            description     TEXT,
            CONSTRAINT uq_rule_configs_tenant_rule UNIQUE (tenant_id, rule_name)
        );

        CREATE TABLE IF NOT EXISTS rule_config_history (
            id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            rule_config_id  UUID         NOT NULL REFERENCES rule_configs(id) ON DELETE CASCADE,
            tenant_id       UUID         NOT NULL,
            rule_name       VARCHAR(100) NOT NULL,
            enabled         BOOLEAN      NOT NULL,
            config          JSONB        NOT NULL,
            version         INTEGER      NOT NULL,
            changed_by      UUID         REFERENCES users(id),
            changed_by_name VARCHAR(100),
            changed_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            change_reason   TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_rule_configs_tenant_name
            ON rule_configs(tenant_id, rule_name);
        CREATE INDEX IF NOT EXISTS idx_rule_config_history_rule
            ON rule_config_history(rule_config_id, changed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_rule_config_history_tenant
            ON rule_config_history(tenant_id, changed_at DESC);

        ALTER TABLE rule_configs ENABLE ROW LEVEL SECURITY;
        ALTER TABLE rule_config_history ENABLE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS rule_configs_tenant_isolation ON rule_configs;
        CREATE POLICY rule_configs_tenant_isolation ON rule_configs
            FOR ALL
            USING (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );

        DROP POLICY IF EXISTS rule_config_history_tenant_isolation ON rule_config_history;
        CREATE POLICY rule_config_history_tenant_isolation ON rule_config_history
            FOR SELECT
            USING (
                tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), '')
            );

        -- Seed defaults for the bootstrap tenant
        INSERT INTO rule_configs (tenant_id, rule_name, enabled, config, version, updated_by_name, description)
        SELECT
            '00000000-0000-0000-0000-000000000001'::uuid,
            rule_name, enabled, config::jsonb, 1, 'SYSTEM', description
        FROM (VALUES
            ('LARGE_TRANSACTION', true,
             '{"threshold": 10000.0, "currency": "USD"}',
             'Flag single transactions exceeding the reporting threshold (BSA s5313)'),
            ('STRUCTURING_SMURFING', true,
             '{"threshold": 10000.0, "window_hours": 24, "min_tx_count": 2}',
             'Detect structuring below BSA threshold across 24h sliding window (31 CFR 1010.314)'),
            ('VELOCITY_MONITORING', true,
             '{"history_days": 30, "deviation_threshold": 3.0}',
             'Z-score spike detection against 30-day baseline'),
            ('RAPID_MOVEMENT_FUNDS', true,
             '{"window_minutes": 10, "amount_ratio_threshold": 0.90}',
             'Rapid layering: outgoing >=90%% of inbound within 10 minutes'),
            ('DORMANT_ACCOUNT', true,
             '{"dormant_period_days": 90, "activation_threshold": 50000.0}',
             'Dormant account reactivated with high-value transaction'),
            ('GEOGRAPHIC_SANCTIONS', true,
             '{"high_risk_countries": ["RU", "IR", "KP", "SY", "BY", "CU", "VE"], "sanctions_similarity_threshold": 0.80}',
             'BIC country-code and fuzzy Elasticsearch sanctions/PEP screening'),
            ('ROUND_TRIP_DETECTION', false,
             '{"window_hours": 72, "return_ratio_threshold": 0.85, "min_hop_count": 2}',
             'PLACEHOLDER: detect funds returning to sender via intermediaries (FATF R.15)'),
            ('SHELL_COMPANY_PATTERN', false,
             '{"newly_incorporated_days": 180, "high_value_threshold": 100000.0}',
             'PLACEHOLDER: newly incorporated entity transacting high values (FinCEN CDD Rule)')
        ) AS defaults(rule_name, enabled, config, description)
        ON CONFLICT (tenant_id, rule_name) DO NOTHING;
        """
    )

    # ── 5. Performance indexes for alert triage inbox ─────────────────────────
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status_severity
            ON alerts(tenant_id, status, threat_level, created_at DESC);

        CREATE INDEX IF NOT EXISTS idx_alerts_assignee_status
            ON alerts(assigned_officer_id, status)
            WHERE status NOT IN ('CLOSED_SAR', 'CLOSED_FALSE_POSITIVE', 'CLOSED');
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX IF EXISTS idx_alerts_assignee_status;
        DROP INDEX IF EXISTS idx_alerts_tenant_status_severity;
        DROP TABLE IF EXISTS rule_config_history CASCADE;
        DROP TABLE IF EXISTS rule_configs CASCADE;
        DROP TABLE IF EXISTS alert_escalations CASCADE;
        DROP TABLE IF EXISTS resource_locks CASCADE;
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aml_app_user') THEN
                GRANT UPDATE, DELETE ON TABLE audit_log TO aml_app_user;
            END IF;
        END
        $$;
        """
    )
