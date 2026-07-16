"""create_ml_feedback_samples_table

Revision ID: 006
Revises: 005
Create Date: 2026-07-16 14:41:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '006'
down_revision: Union[str, None] = '005'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'ml_feedback_samples',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('alert_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('alerts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('transaction_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('transactions.id', ondelete='CASCADE'), nullable=True),
        sa.Column('label', sa.Integer(), nullable=False), # 0 = False Positive, 1 = True Positive / SAR
        sa.Column('features_json', sa.Text(), nullable=False),
        sa.Column('analyst_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('justification', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False)
    )


def downgrade() -> None:
    op.drop_table('ml_feedback_samples')
