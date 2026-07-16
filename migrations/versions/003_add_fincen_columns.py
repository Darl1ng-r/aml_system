"""add_fincen_columns

Revision ID: 003
Revises: 002
Create Date: 2026-07-16 13:55:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '003'
down_revision: Union[str, None] = '002'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('alerts', sa.Column('fincen_tracking_id', sa.String(length=100), nullable=True))
    op.add_column('alerts', sa.Column('fincen_filing_status', sa.String(length=50), nullable=True))
    op.add_column('alerts', sa.Column('fincen_submitted_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('alerts', 'fincen_submitted_at')
    op.drop_column('alerts', 'fincen_filing_status')
    op.drop_column('alerts', 'fincen_tracking_id')
