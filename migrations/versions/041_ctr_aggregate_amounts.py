"""Add 31 CFR 1010.313 aggregated CTR reporting columns to `ctr_filings`.

Revision ID: 041
Revises: 040
Create Date: 2026-11-28 16:35:00.000000
"""

from typing import Sequence, Union
from alembic import op
from sqlalchemy import text

revision: str = "041"
down_revision: Union[str, None] = "040"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        text(
            """
            ALTER TABLE ctr_filings
                ADD COLUMN IF NOT EXISTS aggregate_amount_usd NUMERIC(18, 2),
                ADD COLUMN IF NOT EXISTS aggregated_tx_count INT NOT NULL DEFAULT 1;
            """
        )
    )


def downgrade() -> None:
    op.execute(
        text(
            """
            ALTER TABLE ctr_filings
                DROP COLUMN IF EXISTS aggregated_tx_count,
                DROP COLUMN IF EXISTS aggregate_amount_usd;
            """
        )
    )
