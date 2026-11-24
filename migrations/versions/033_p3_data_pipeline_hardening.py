"""P3 Data Pipeline Reliability Hardening: Account Date of Birth & Crash-Safe Webhook Delivery Deduplication Index

Revision ID: 033
Revises: 032
Create Date: 2026-11-24 05:37:00.000000
"""

from typing import Sequence, Union
from alembic import op

revision: str = '033'
down_revision: Union[str, None] = '032'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- 1. Preserve IndividualOnboard.date_of_birth without silent field drop (V-08)
        ALTER TABLE accounts
            ADD COLUMN IF NOT EXISTS date_of_birth DATE;

        -- 2. Partial index for O(1) crash-safe per-subscriber webhook deduplication on retry (T-04)
        CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_delivered_event
            ON webhook_deliveries (tenant_id, webhook_id, (payload->>'event_id'))
            WHERE status = 'DELIVERED';
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX IF EXISTS idx_webhook_deliveries_delivered_event;
        ALTER TABLE accounts
            DROP COLUMN IF EXISTS date_of_birth;
        """
    )
