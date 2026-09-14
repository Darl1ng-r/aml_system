"""
Alembic Environment Configuration
===================================
Reads the PostgreSQL connection string from our existing ``config.py``
and runs migrations using pg8000 (synchronous, multi-statement compatible).
"""

import sys
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

# Read the Alembic .ini for logging config
config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ── Build the database DSN from our project config ──────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD

SYNC_DATABASE_URL = (
    f"postgresql+pg8000://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
    f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
)

# No SQLAlchemy MetaData — we use raw SQL migrations
target_metadata = None


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — emits SQL to stdout."""
    context.configure(
        url=SYNC_DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode using pg8000 engine."""
    connectable = create_engine(
        SYNC_DATABASE_URL,
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

