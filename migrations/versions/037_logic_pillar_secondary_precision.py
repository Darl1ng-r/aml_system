"""Logic Pillar Secondary Financial Precision: Widen str_batches.total_amount to NUMERIC(19, 4)

Revision ID: 037
Revises: 036
Create Date: 2026-11-26 04:00:00.000000
"""

from typing import Sequence, Union
from alembic import op

revision: str = "037"
down_revision: Union[str, None] = "036"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE str_batches
            ALTER COLUMN total_amount TYPE NUMERIC(19, 4);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE str_batches
            ALTER COLUMN total_amount TYPE NUMERIC(18, 2);
        """
    )
