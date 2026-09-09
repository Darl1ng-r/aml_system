"""add_mfa_support

Revision ID: 010
Revises: 009
Create Date: 2026-09-09 17:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '010'
down_revision: Union[str, None] = '009'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table('users'):
        columns = [c['name'] for c in inspector.get_columns('users')]
        if 'mfa_enabled' not in columns:
            op.add_column('users', sa.Column('mfa_enabled', sa.Boolean(), nullable=False, server_default='false'))
        if 'mfa_secret' not in columns:
            op.add_column('users', sa.Column('mfa_secret', sa.String(length=64), nullable=True))
        if 'recovery_codes' not in columns:
            op.add_column('users', sa.Column('recovery_codes', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table('users'):
        columns = [c['name'] for c in inspector.get_columns('users')]
        if 'recovery_codes' in columns:
            op.drop_column('users', 'recovery_codes')
        if 'mfa_secret' in columns:
            op.drop_column('users', 'mfa_secret')
        if 'mfa_enabled' in columns:
            op.drop_column('users', 'mfa_enabled')
