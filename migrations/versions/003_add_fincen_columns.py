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
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table('alerts'):
        columns = [c['name'] for c in inspector.get_columns('alerts')]
        if 'fincen_tracking_id' not in columns:
            op.add_column('alerts', sa.Column('fincen_tracking_id', sa.String(length=100), nullable=True))
        if 'fincen_filing_status' not in columns:
            op.add_column('alerts', sa.Column('fincen_filing_status', sa.String(length=50), nullable=True))
        if 'fincen_submitted_at' not in columns:
            op.add_column('alerts', sa.Column('fincen_submitted_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table('alerts'):
        columns = [c['name'] for c in inspector.get_columns('alerts')]
        if 'fincen_submitted_at' in columns:
            op.drop_column('alerts', 'fincen_submitted_at')
        if 'fincen_filing_status' in columns:
            op.drop_column('alerts', 'fincen_filing_status')
        if 'fincen_tracking_id' in columns:
            op.drop_column('alerts', 'fincen_tracking_id')
