"""rotate_aml_app_password_from_env

Revision ID: 035
Revises: 034
Create Date: 2026-11-25 07:20:00.000000

Idempotently aligns the PostgreSQL `aml_app` role password with the
AML_APP_PASSWORD environment variable (remediating P0-06 where migration 011
previously seeded a hardcoded literal password).
"""
from typing import Sequence
import os
from alembic import op

revision: str = '035'
down_revision: str | None = '034'
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    env_pw = os.getenv("AML_APP_PASSWORD", "").strip()
    if not env_pw:
        return
    escaped_pw = env_pw.replace("'", "''")
    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'aml_app')
               AND current_user != 'aml_app' THEN
                ALTER ROLE aml_app WITH LOGIN PASSWORD '{escaped_pw}' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    # Password rotation is intentionally non-reversible
    pass
