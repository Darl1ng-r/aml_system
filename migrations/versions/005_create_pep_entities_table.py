"""create_pep_entities_table

Revision ID: 005
Revises: 004
Create Date: 2026-07-16 13:58:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '005'
down_revision: Union[str, None] = '004'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'pep_entities',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('name', sa.String(length=255), nullable=False, index=True),
        sa.Column('pep_tier', sa.String(length=50), nullable=False), # TIER_1, TIER_2, TIER_3, TIER_4
        sa.Column('position', sa.String(length=255), nullable=False),
        sa.Column('country', sa.String(length=3), nullable=False),
        sa.Column('rca_flag', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('source_database', sa.String(length=100), server_default='FATF_PEP_REGISTER', nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True, index=True),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False)
    )


def downgrade() -> None:
    op.drop_table('pep_entities')
