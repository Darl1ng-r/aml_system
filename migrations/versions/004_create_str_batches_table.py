"""create_str_batches_table

Revision ID: 004
Revises: 003
Create Date: 2026-07-16 13:56:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '004'
down_revision: Union[str, None] = '003'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create str_batches table
    op.create_table(
        'str_batches',
        sa.Column('id', sa.String(length=100), primary_key=True),
        sa.Column('tenant_id', sa.UUID(), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True),
        sa.Column('record_count', sa.Integer(), nullable=False),
        sa.Column('total_amount', sa.Numeric(precision=18, scale=2), nullable=False),
        sa.Column('payload_xml', sa.Text(), nullable=False),
        sa.Column('checksum', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=50), server_default='GENERATED', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False)
    )

    # 2. Add str_batch_id foreign key column to alerts table
    op.add_column('alerts', sa.Column('str_batch_id', sa.String(length=100), sa.ForeignKey('str_batches.id', ondelete='SET NULL'), nullable=True))


def downgrade() -> None:
    op.drop_column('alerts', 'str_batch_id')
    op.drop_table('str_batches')
