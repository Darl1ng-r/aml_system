"""create_aml_app_role_and_token_version

Revision ID: 011
Revises: 010
Create Date: 2026-09-09 20:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '011'
down_revision: Union[str, None] = '010'
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # 1. Add token_version to users table
    if inspector.has_table('users'):
        columns = [c['name'] for c in inspector.get_columns('users')]
        if 'token_version' not in columns:
            op.add_column('users', sa.Column('token_version', sa.Integer(), nullable=False, server_default='1'))

    # 2. Provision unprivileged aml_app role with NOSUPERUSER NOBYPASSRLS
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'aml_app') THEN
                CREATE ROLE aml_app WITH LOGIN PASSWORD 'aml_app_secure_pass_2026' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
            ELSE
                ALTER ROLE aml_app WITH NOSUPERUSER NOBYPASSRLS;
            END IF;
        END
        $$;
        GRANT USAGE ON SCHEMA public TO aml_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aml_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aml_app;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aml_app;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO aml_app;
        """
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table('users'):
        columns = [c['name'] for c in inspector.get_columns('users')]
        if 'token_version' in columns:
            op.drop_column('users', 'token_version')
