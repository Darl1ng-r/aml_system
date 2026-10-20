"""enable_pg_trgm_and_sanctions_indexes

Revision ID: 027
Revises: 026
Create Date: 2026-10-16 22:00:00.000000

Changes:
  1. Enables pg_trgm extension on PostgreSQL 16 for sub-millisecond fuzzy sanctions matching.
  2. Creates GIN trigram index on pep_entities (name gin_trgm_ops) to prune datastore sprawl
     and enable in-engine fuzzy identity matching without Elasticsearch dependencies.
"""
from typing import Sequence
from alembic import op
import sqlalchemy as sa

revision: str = '027'
down_revision: str | None = '026'
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    # 1. Enable pg_trgm extension for trigram fuzzy matching
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")

    # 2. GIN Trigram index for fast fuzzy matching on sanctions / PEP names
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'pep_entities') THEN
                CREATE INDEX IF NOT EXISTS idx_pep_entities_name_trgm
                    ON pep_entities USING gin (name gin_trgm_ops);
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_pep_entities_name_trgm;")
