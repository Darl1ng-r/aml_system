"""P0 Enterprise Launch Readiness: Webhooks, SIEM persistence, FX columns, Evidence SHA256/WORM, SAR 30/90d clocks, GDPR erasure & OIDC SSO

Revision ID: 030
Revises: 029
Create Date: 2026-11-21 01:35:00.000000
"""

from typing import Sequence, Union
from alembic import op

revision: str = '030'
down_revision: Union[str, None] = '029'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- 1. Outbound Core-Banking Webhooks (P0-2)
        CREATE TABLE IF NOT EXISTS tenant_webhooks (
            id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id           UUID         NOT NULL,
            name                VARCHAR(150) NOT NULL,
            url                 TEXT         NOT NULL,
            signing_secret_enc  TEXT         NOT NULL,
            subscribed_events   TEXT[]       NOT NULL DEFAULT ARRAY['ACCOUNT_FROZEN', 'ACCOUNT_UNFROZEN', 'TRANSACTION_HELD', 'SAR_FILED']::TEXT[],
            enabled             BOOLEAN      NOT NULL DEFAULT TRUE,
            created_by          VARCHAR(100) NOT NULL DEFAULT '',
            created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_tenant_webhooks_tenant
            ON tenant_webhooks (tenant_id, enabled);

        ALTER TABLE tenant_webhooks ENABLE ROW LEVEL SECURITY;
        ALTER TABLE tenant_webhooks FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS tenant_webhooks_isolation ON tenant_webhooks;
        CREATE POLICY tenant_webhooks_isolation ON tenant_webhooks
            FOR ALL
            USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''));

        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id     UUID        NOT NULL,
            webhook_id    UUID        NOT NULL REFERENCES tenant_webhooks(id) ON DELETE CASCADE,
            event_type    VARCHAR(80) NOT NULL,
            payload       JSONB       NOT NULL DEFAULT '{}'::jsonb,
            status        VARCHAR(32) NOT NULL DEFAULT 'PENDING',
            http_status   INTEGER,
            attempts      INTEGER     NOT NULL DEFAULT 1,
            last_error    TEXT,
            delivered_at  TIMESTAMPTZ,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_created
            ON webhook_deliveries (webhook_id, created_at DESC);

        ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
        ALTER TABLE webhook_deliveries FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS webhook_deliveries_isolation ON webhook_deliveries;
        CREATE POLICY webhook_deliveries_isolation ON webhook_deliveries
            FOR ALL
            USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''));

        -- 2. Persisted SIEM Configurations (P0-2)
        CREATE TABLE IF NOT EXISTS siem_configs (
            tenant_id           UUID         PRIMARY KEY,
            enabled             BOOLEAN      NOT NULL DEFAULT FALSE,
            destination_url     TEXT         NOT NULL DEFAULT '',
            auth_token_enc      TEXT         NOT NULL DEFAULT '',
            format              VARCHAR(40)  NOT NULL DEFAULT 'SPLUNK_HEC',
            total_forwarded     BIGINT       NOT NULL DEFAULT 0,
            last_dispatched_at  TIMESTAMPTZ,
            updated_by          VARCHAR(100) NOT NULL DEFAULT '',
            updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        );

        ALTER TABLE siem_configs ENABLE ROW LEVEL SECURITY;
        ALTER TABLE siem_configs FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS siem_configs_isolation ON siem_configs;
        CREATE POLICY siem_configs_isolation ON siem_configs
            FOR ALL
            USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''));

        -- 3. Enterprise OIDC SSO Providers (P0-6)
        CREATE TABLE IF NOT EXISTS sso_providers (
            id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id           UUID         NOT NULL,
            provider_name       VARCHAR(120) NOT NULL,
            issuer_url          TEXT         NOT NULL,
            client_id           VARCHAR(255) NOT NULL,
            client_secret_enc   TEXT         NOT NULL DEFAULT '',
            scopes              VARCHAR(255) NOT NULL DEFAULT 'openid profile email groups',
            group_role_mapping  JSONB        NOT NULL DEFAULT '{}'::jsonb,
            default_role        VARCHAR(40)  NOT NULL DEFAULT 'L1_ANALYST',
            enabled             BOOLEAN      NOT NULL DEFAULT TRUE,
            created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_sso_providers_tenant
            ON sso_providers (tenant_id, enabled);

        ALTER TABLE sso_providers ENABLE ROW LEVEL SECURITY;
        ALTER TABLE sso_providers FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS sso_providers_isolation ON sso_providers;
        CREATE POLICY sso_providers_isolation ON sso_providers
            FOR ALL
            USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''));

        -- 4. Evidence Locker Chain-of-Custody & WORM Metadata (P0-3)
        ALTER TABLE case_evidence
            ADD COLUMN IF NOT EXISTS sha256_digest    VARCHAR(64),
            ADD COLUMN IF NOT EXISTS storage_backend  VARCHAR(32) NOT NULL DEFAULT 'local',
            ADD COLUMN IF NOT EXISTS scan_status      VARCHAR(32) NOT NULL DEFAULT 'CLEAN';

        -- 5. SAR Statutory 30-Day / 90-Day Clocks & XSD Metadata (P0-4)
        ALTER TABLE sar_drafts
            ADD COLUMN IF NOT EXISTS detection_date             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            ADD COLUMN IF NOT EXISTS statutory_deadline_at      TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS continuing_activity_due_at TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS fiu_format                 VARCHAR(32) NOT NULL DEFAULT 'FINCEN_BSABATCH',
            ADD COLUMN IF NOT EXISTS xsd_validated              BOOLEAN     NOT NULL DEFAULT FALSE;

        UPDATE sar_drafts
        SET statutory_deadline_at = COALESCE(detection_date, created_at, NOW()) + INTERVAL '30 days'
        WHERE statutory_deadline_at IS NULL;

        -- 6. FX Normalized Base Amount on Transactions (P0-1)
        ALTER TABLE transactions
            ADD COLUMN IF NOT EXISTS amount_base_usd NUMERIC(18, 2),
            ADD COLUMN IF NOT EXISTS fx_rate_applied NUMERIC(18, 8) NOT NULL DEFAULT 1.0;

        -- 7. GDPR Erasure Tracking on Accounts (P0-5)
        ALTER TABLE accounts
            ADD COLUMN IF NOT EXISTS erased_at      TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS erasure_reason TEXT;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE accounts
            DROP COLUMN IF EXISTS erasure_reason,
            DROP COLUMN IF EXISTS erased_at;
        ALTER TABLE transactions
            DROP COLUMN IF EXISTS fx_rate_applied,
            DROP COLUMN IF EXISTS amount_base_usd;
        ALTER TABLE sar_drafts
            DROP COLUMN IF EXISTS xsd_validated,
            DROP COLUMN IF EXISTS fiu_format,
            DROP COLUMN IF EXISTS continuing_activity_due_at,
            DROP COLUMN IF EXISTS statutory_deadline_at,
            DROP COLUMN IF EXISTS detection_date;
        ALTER TABLE case_evidence
            DROP COLUMN IF EXISTS scan_status,
            DROP COLUMN IF EXISTS storage_backend,
            DROP COLUMN IF EXISTS sha256_digest;
        DROP TABLE IF EXISTS sso_providers CASCADE;
        DROP TABLE IF EXISTS siem_configs CASCADE;
        DROP TABLE IF EXISTS webhook_deliveries CASCADE;
        DROP TABLE IF EXISTS tenant_webhooks CASCADE;
        """
    )
