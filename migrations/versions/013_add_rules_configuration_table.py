"""add_rules_configuration_table

Revision ID: 013
Revises: 012
Create Date: 2026-09-12 04:35:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '013'
down_revision: Union[str, None] = '012'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS rules_configuration (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            rules_json JSONB NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_by VARCHAR(100) NOT NULL DEFAULT 'SYSTEM'
        );

        CREATE INDEX IF NOT EXISTS idx_rules_config_updated_at
            ON rules_configuration (updated_at DESC);
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DROP TABLE IF EXISTS rules_configuration CASCADE;
        """
    )
