"""add_rba_enhancements

Revision ID: 008
Revises: 007
Create Date: 2026-07-17 19:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '008'
down_revision: Union[str, None] = '007'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table('accounts'):
        columns = [c['name'] for c in inspector.get_columns('accounts')]
        if 'risk_category' not in columns:
            op.add_column('accounts', sa.Column('risk_category', sa.String(length=20), nullable=True, server_default='LOW'))

    if inspector.has_table('customer_profiles'):
        columns = [c['name'] for c in inspector.get_columns('customer_profiles')]
        if 'kyc_risk_tier' not in columns:
            op.add_column('customer_profiles', sa.Column('kyc_risk_tier', sa.String(length=20), nullable=True, server_default='STANDARD'))
        if 'jurisdiction_risk_score' not in columns:
            op.add_column('customer_profiles', sa.Column('jurisdiction_risk_score', sa.Float(), nullable=True, server_default='0.1'))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table('customer_profiles'):
        columns = [c['name'] for c in inspector.get_columns('customer_profiles')]
        if 'jurisdiction_risk_score' in columns:
            op.drop_column('customer_profiles', 'jurisdiction_risk_score')
        if 'kyc_risk_tier' in columns:
            op.drop_column('customer_profiles', 'kyc_risk_tier')

    if inspector.has_table('accounts'):
        columns = [c['name'] for c in inspector.get_columns('accounts')]
        if 'risk_category' in columns:
            op.drop_column('accounts', 'risk_category')
