"""Logic Pillar Enterprise Hardening: NUMERIC(19, 4) Precision, Durable Idempotency Store,
Unique Deduplication Constraints & Immutable SR 11-7 Provenance

Revision ID: 036
Revises: 035
Create Date: 2026-11-26 03:36:00.000000
"""

from typing import Sequence, Union
from alembic import op

revision: str = "036"
down_revision: Union[str, None] = "035"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- 1. Financial Precision Upgrade: NUMERIC(19, 4) supports 3-decimal ISO-4217
        --    currencies (KWD/BHD/OMR/JOD) and 4-decimal settlement precision.
        ALTER TABLE transactions
            ALTER COLUMN amount TYPE NUMERIC(19, 4),
            ALTER COLUMN amount_base_usd TYPE NUMERIC(19, 4);

        ALTER TABLE ctr_filings
            ALTER COLUMN amount TYPE NUMERIC(19, 4);

        -- 2. Durable PostgreSQL L2 Idempotency Store with FORCE ROW LEVEL SECURITY
        CREATE TABLE IF NOT EXISTS idempotency_records (
            tenant_id        UUID         NOT NULL,
            scope            VARCHAR(64)  NOT NULL,
            idempotency_key  VARCHAR(128) NOT NULL,
            request_hash     VARCHAR(64)  NOT NULL,
            status           VARCHAR(16)  NOT NULL DEFAULT 'IN_FLIGHT',
            response_status  INTEGER,
            response_body    JSONB,
            created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            expires_at       TIMESTAMPTZ  NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
            PRIMARY KEY (tenant_id, scope, idempotency_key)
        );

        CREATE INDEX IF NOT EXISTS idx_idempotency_records_expires
            ON idempotency_records (expires_at);

        ALTER TABLE idempotency_records ENABLE ROW LEVEL SECURITY;
        ALTER TABLE idempotency_records FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS idempotency_records_tenant_isolation ON idempotency_records;
        CREATE POLICY idempotency_records_tenant_isolation ON idempotency_records
            FOR ALL
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'aml_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON idempotency_records TO aml_app;
            END IF;
        END
        $$;

        -- 3. Immutable SR 11-7 / FinCEN Regulatory Provenance & Ledger Idempotency Columns
        ALTER TABLE transactions
            ADD COLUMN IF NOT EXISTS idempotency_key       VARCHAR(128),
            ADD COLUMN IF NOT EXISTS fx_rate_source        VARCHAR(32),
            ADD COLUMN IF NOT EXISTS fx_rate_quoted_at     TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS evaluated_at          TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS ruleset_hash          VARCHAR(64),
            ADD COLUMN IF NOT EXISTS model_version         VARCHAR(64),
            ADD COLUMN IF NOT EXISTS evaluation_provenance JSONB;

        ALTER TABLE alerts
            ADD COLUMN IF NOT EXISTS ruleset_hash          VARCHAR(64),
            ADD COLUMN IF NOT EXISTS model_version         VARCHAR(64),
            ADD COLUMN IF NOT EXISTS evaluated_at          TIMESTAMPTZ;

        -- 4. Safe Legacy Duplicate Retention (preserve earliest row per unique key before indexing)
        WITH ranked_alerts AS (
            SELECT id,
                   FIRST_VALUE(id) OVER (
                       PARTITION BY tenant_id, transaction_id, rule_name
                       ORDER BY created_at ASC, id ASC
                   ) AS keep_id,
                   ROW_NUMBER() OVER (
                       PARTITION BY tenant_id, transaction_id, rule_name
                       ORDER BY created_at ASC, id ASC
                   ) AS rn
            FROM alerts
            WHERE tenant_id IS NOT NULL
              AND transaction_id IS NOT NULL
              AND rule_name IS NOT NULL
        ),
        dup_alerts AS (
            SELECT id, keep_id FROM ranked_alerts WHERE rn > 1
        )
        UPDATE sar_drafts s
        SET alert_id = d.keep_id
        FROM dup_alerts d
        WHERE s.alert_id = d.id;

        WITH ranked_alerts AS (
            SELECT id,
                   ROW_NUMBER() OVER (
                       PARTITION BY tenant_id, transaction_id, rule_name
                       ORDER BY created_at ASC, id ASC
                   ) AS rn
            FROM alerts
            WHERE tenant_id IS NOT NULL
              AND transaction_id IS NOT NULL
              AND rule_name IS NOT NULL
        )
        DELETE FROM alerts a
        USING ranked_alerts r
        WHERE a.id = r.id
          AND r.rn > 1;

        WITH ranked_ctrs AS (
            SELECT id,
                   ROW_NUMBER() OVER (
                       PARTITION BY tenant_id, transaction_id
                       ORDER BY created_at ASC, id ASC
                   ) AS rn
            FROM ctr_filings
            WHERE tenant_id IS NOT NULL
              AND transaction_id IS NOT NULL
        )
        DELETE FROM ctr_filings c
        USING ranked_ctrs r
        WHERE c.id = r.id
          AND r.rn > 1;

        -- 5. Unique Deduplication Indexes (backing ON CONFLICT DO NOTHING & Redis-failover safety)
        CREATE UNIQUE INDEX IF NOT EXISTS uq_transactions_tenant_idempotency_key
            ON transactions (tenant_id, idempotency_key)
            WHERE idempotency_key IS NOT NULL;

        CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_tenant_tx_rule
            ON alerts (tenant_id, transaction_id, rule_name)
            WHERE transaction_id IS NOT NULL AND rule_name IS NOT NULL;

        CREATE UNIQUE INDEX IF NOT EXISTS uq_ctr_filings_tenant_tx
            ON ctr_filings (tenant_id, transaction_id)
            WHERE transaction_id IS NOT NULL;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX IF EXISTS uq_ctr_filings_tenant_tx;
        DROP INDEX IF EXISTS uq_alerts_tenant_tx_rule;
        DROP INDEX IF EXISTS uq_transactions_tenant_idempotency_key;

        ALTER TABLE alerts
            DROP COLUMN IF EXISTS evaluated_at,
            DROP COLUMN IF EXISTS model_version,
            DROP COLUMN IF EXISTS ruleset_hash;

        ALTER TABLE transactions
            DROP COLUMN IF EXISTS evaluation_provenance,
            DROP COLUMN IF EXISTS model_version,
            DROP COLUMN IF EXISTS ruleset_hash,
            DROP COLUMN IF EXISTS evaluated_at,
            DROP COLUMN IF EXISTS fx_rate_quoted_at,
            DROP COLUMN IF EXISTS fx_rate_source,
            DROP COLUMN IF EXISTS idempotency_key;

        DROP TABLE IF EXISTS idempotency_records CASCADE;

        ALTER TABLE ctr_filings
            ALTER COLUMN amount TYPE NUMERIC(15, 2);

        ALTER TABLE transactions
            ALTER COLUMN amount_base_usd TYPE NUMERIC(18, 2),
            ALTER COLUMN amount TYPE NUMERIC(15, 2);
        """
    )
