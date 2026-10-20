"""add_outbox_retention_indexes

Revision ID: 025
Revises: 024
Create Date: 2026-10-16 10:40:00.000000

Changes:
  1. Creates idx_outbox_published_prune partial index on transactional_outbox(published_at)
     WHERE status = 'PUBLISHED' for high-throughput retention pruning without table lock contention.
"""
from typing import Sequence
from alembic import op
import sqlalchemy as sa

revision: str = '025'
down_revision: str | None = '024'
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        -- Partial index to optimize chunked pruning of historical published outbox records
        CREATE INDEX IF NOT EXISTS idx_outbox_published_prune 
            ON transactional_outbox (published_at) 
            WHERE status = 'PUBLISHED';
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP INDEX IF EXISTS idx_outbox_published_prune;
        """
    )
