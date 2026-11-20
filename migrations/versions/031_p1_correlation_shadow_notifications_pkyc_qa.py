"""P1 High-Impact UX & Intelligence Multipliers: Case Auto-Correlation, Rule Shadow Mode, Notifications/SLA, pKYC Rescreening & QA Four-Eyes Sampling

Revision ID: 031
Revises: 030
Create Date: 2026-11-21 02:12:00.000000
"""

from typing import Sequence, Union
from alembic import op

revision: str = '031'
down_revision: Union[str, None] = '030'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- 1. Champion-Challenger Rule Shadow Hits (P1-2)
        CREATE TABLE IF NOT EXISTS rule_shadow_hits (
            id                 UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id          UUID          NOT NULL,
            rule_name          VARCHAR(120)  NOT NULL,
            transaction_id     UUID,
            sender_account_id  UUID,
            amount_base_usd    NUMERIC(18,2),
            rule_version       INTEGER       NOT NULL DEFAULT 1,
            matched_reason     TEXT          NOT NULL DEFAULT '',
            created_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_rule_shadow_hits_tenant_rule_created
            ON rule_shadow_hits (tenant_id, rule_name, created_at DESC);

        ALTER TABLE rule_shadow_hits ENABLE ROW LEVEL SECURITY;
        ALTER TABLE rule_shadow_hits FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS rule_shadow_hits_isolation ON rule_shadow_hits;
        CREATE POLICY rule_shadow_hits_isolation ON rule_shadow_hits
            FOR ALL
            USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''));

        -- 2. Persistent In-App Notifications & SLA Escalations (P1-4)
        CREATE TABLE IF NOT EXISTS notifications (
            id                 UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id          UUID          NOT NULL,
            recipient_user_id  UUID,
            recipient_role     VARCHAR(40),
            category           VARCHAR(60)   NOT NULL,
            severity           VARCHAR(20)   NOT NULL DEFAULT 'INFO',
            title              VARCHAR(240)  NOT NULL,
            body               TEXT          NOT NULL DEFAULT '',
            link_url           VARCHAR(300)  NOT NULL DEFAULT '',
            resource_type      VARCHAR(40),
            resource_id        VARCHAR(120),
            is_read            BOOLEAN       NOT NULL DEFAULT FALSE,
            created_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_notifications_tenant_unread_created
            ON notifications (tenant_id, is_read, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_notifications_dedup
            ON notifications (tenant_id, category, resource_id, created_at DESC);

        ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
        ALTER TABLE notifications FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS notifications_isolation ON notifications;
        CREATE POLICY notifications_isolation ON notifications
            FOR ALL
            USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''));

        -- 3. Independent QA Four-Eyes Sampling Reviews (P1-5)
        CREATE TABLE IF NOT EXISTS qa_reviews (
            id                        UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id                 UUID          NOT NULL,
            alert_id                  UUID          NOT NULL,
            case_id                   UUID,
            original_disposition      VARCHAR(60)   NOT NULL DEFAULT 'CLOSED_FALSE_POSITIVE',
            original_analyst_username VARCHAR(120)  NOT NULL DEFAULT '',
            sampled_by_username       VARCHAR(120)  NOT NULL DEFAULT '',
            qa_reviewer_username      VARCHAR(120),
            status                    VARCHAR(32)   NOT NULL DEFAULT 'PENDING',
            qa_notes                  TEXT,
            sampled_at                TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
            reviewed_at               TIMESTAMPTZ
        );
        CREATE UNIQUE INDEX IF NOT EXISTS uq_qa_reviews_tenant_alert
            ON qa_reviews (tenant_id, alert_id);
        CREATE INDEX IF NOT EXISTS idx_qa_reviews_tenant_status
            ON qa_reviews (tenant_id, status, sampled_at DESC);

        ALTER TABLE qa_reviews ENABLE ROW LEVEL SECURITY;
        ALTER TABLE qa_reviews FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS qa_reviews_isolation ON qa_reviews;
        CREATE POLICY qa_reviews_isolation ON qa_reviews
            FOR ALL
            USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''));

        -- 4. Perpetual KYC (pKYC) Delta Rescreening Audit Runs (P1-5)
        CREATE TABLE IF NOT EXISTS pkyc_rescreen_runs (
            id                      UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id               UUID          NOT NULL,
            triggered_by            VARCHAR(120)  NOT NULL DEFAULT 'SYSTEM',
            accounts_scanned        INTEGER       NOT NULL DEFAULT 0,
            material_changes_found  INTEGER       NOT NULL DEFAULT 0,
            alerts_generated        INTEGER       NOT NULL DEFAULT 0,
            started_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
            completed_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_pkyc_runs_tenant_started
            ON pkyc_rescreen_runs (tenant_id, started_at DESC);

        ALTER TABLE pkyc_rescreen_runs ENABLE ROW LEVEL SECURITY;
        ALTER TABLE pkyc_rescreen_runs FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS pkyc_rescreen_runs_isolation ON pkyc_rescreen_runs;
        CREATE POLICY pkyc_rescreen_runs_isolation ON pkyc_rescreen_runs
            FOR ALL
            USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''));

        -- 5. Column Additions on Existing Tables (Idempotent)
        ALTER TABLE rule_configs
            ADD COLUMN IF NOT EXISTS mode          VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
            ADD COLUMN IF NOT EXISTS shadow_config JSONB;

        ALTER TABLE cases
            ADD COLUMN IF NOT EXISTS correlation_key VARCHAR(128);
        CREATE INDEX IF NOT EXISTS idx_cases_tenant_correlation_status
            ON cases (tenant_id, correlation_key, status);

        ALTER TABLE accounts
            ADD COLUMN IF NOT EXISTS last_rescreened_at         TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS pkyc_material_change_flag  BOOLEAN NOT NULL DEFAULT FALSE;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE accounts
            DROP COLUMN IF EXISTS pkyc_material_change_flag,
            DROP COLUMN IF EXISTS last_rescreened_at;

        DROP INDEX IF EXISTS idx_cases_tenant_correlation_status;
        ALTER TABLE cases
            DROP COLUMN IF EXISTS correlation_key;

        ALTER TABLE rule_configs
            DROP COLUMN IF EXISTS shadow_config,
            DROP COLUMN IF EXISTS mode;

        DROP TABLE IF EXISTS pkyc_rescreen_runs;
        DROP TABLE IF EXISTS qa_reviews;
        DROP TABLE IF EXISTS notifications;
        DROP TABLE IF EXISTS rule_shadow_hits;
        """
    )
