"""add_performance_indexes

Revision ID: 012
Revises: 011
Create Date: 2026-09-11 16:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '012'
down_revision: Union[str, None] = '011'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    # 1. Composite index for 24h velocity and customer baseline queries
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_transactions_sender_timestamp
            ON transactions (sender_account_id, timestamp DESC);

        CREATE INDEX IF NOT EXISTS idx_transactions_tenant_timestamp
            ON transactions (tenant_id, timestamp DESC);

        CREATE INDEX IF NOT EXISTS idx_alerts_tenant_created
            ON alerts (tenant_id, created_at DESC);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX IF EXISTS idx_transactions_sender_timestamp;
        DROP INDEX IF EXISTS idx_transactions_tenant_timestamp;
        DROP INDEX IF EXISTS idx_alerts_tenant_created;
        """
    )
