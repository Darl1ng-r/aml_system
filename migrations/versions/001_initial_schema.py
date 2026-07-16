"""Initial schema baseline — accounts, transactions, alerts, customer_profiles

Revision ID: 001
Revises: None
Create Date: 2026-07-16

This migration captures the complete current schema so that Alembic has a
baseline.  Existing databases should run ``alembic stamp 001`` to mark this
revision as already applied.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        -- ================================================================
        -- Extension for UUID generation
        -- ================================================================
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

        -- ================================================================
        -- Accounts
        -- ================================================================
        CREATE TABLE IF NOT EXISTS accounts (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            tenant_id UUID NOT NULL,
            account_number VARCHAR(50) UNIQUE NOT NULL,
            owner_name VARCHAR(200) NOT NULL,
            swift_bic VARCHAR(20),
            risk_score NUMERIC(5, 4) DEFAULT 0.0,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        -- ================================================================
        -- Transactions
        -- ================================================================
        CREATE TABLE IF NOT EXISTS transactions (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            tenant_id UUID,
            sender_account_id UUID REFERENCES accounts(id),
            receiver_account_id UUID REFERENCES accounts(id),
            amount NUMERIC(15, 2) NOT NULL,
            currency VARCHAR(3) DEFAULT 'USD',
            status VARCHAR(20) DEFAULT 'PENDING',
            timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            country VARCHAR(3),
            merchant VARCHAR(100),
            device VARCHAR(100),
            channel VARCHAR(50),
            neo4j_synced BOOLEAN DEFAULT FALSE
        );

        CREATE INDEX IF NOT EXISTS idx_transactions_sender
            ON transactions(sender_account_id);
        CREATE INDEX IF NOT EXISTS idx_transactions_receiver
            ON transactions(receiver_account_id);
        CREATE INDEX IF NOT EXISTS idx_transactions_timestamp
            ON transactions(timestamp);
        CREATE INDEX IF NOT EXISTS idx_transactions_neo4j_synced
            ON transactions(neo4j_synced) WHERE neo4j_synced = FALSE;

        -- ================================================================
        -- Alerts
        -- ================================================================
        CREATE TABLE IF NOT EXISTS alerts (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            tenant_id UUID,
            transaction_id UUID REFERENCES transactions(id),
            rule_name VARCHAR(100),
            threat_level VARCHAR(20),
            ai_risk_score NUMERIC(5, 4),
            explainability_payload TEXT,
            status VARCHAR(20) DEFAULT 'OPEN',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_transaction
            ON alerts(transaction_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_status
            ON alerts(status);

        -- ================================================================
        -- Customer Profiles (behavioural baselines)
        -- ================================================================
        CREATE TABLE IF NOT EXISTS customer_profiles (
            account_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
            avg_amount NUMERIC(15, 2) DEFAULT 0.00,
            median_amount NUMERIC(15, 2) DEFAULT 0.00,
            variance_amount NUMERIC(15, 2) DEFAULT 0.00,
            daily_frequency NUMERIC(10, 4) DEFAULT 0.00,
            weekly_frequency NUMERIC(10, 4) DEFAULT 0.00,
            monthly_frequency INT DEFAULT 0,
            unique_receivers_count INT DEFAULT 0,
            unique_receiver_countries_count INT DEFAULT 0,
            avg_hour NUMERIC(4, 2) DEFAULT 0.00,
            variance_hour NUMERIC(6, 2) DEFAULT 0.00,
            top_countries TEXT[],
            top_merchants TEXT[],
            top_devices TEXT[],
            top_channels TEXT[],
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
    """)


def downgrade() -> None:
    op.execute("""
        DROP TABLE IF EXISTS customer_profiles CASCADE;
        DROP TABLE IF EXISTS alerts CASCADE;
        DROP TABLE IF EXISTS transactions CASCADE;
        DROP TABLE IF EXISTS accounts CASCADE;
    """)
