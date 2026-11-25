"""
Alembic Environment Configuration
===================================
Reads the PostgreSQL connection string dynamically (Vault -> env -> settings),
URL-encodes credentials safely, enforces TLS SSLContext when ENABLE_TLS=true,
and sets an explicit connection timeout on pg8000.
"""

import asyncio
import os
import sys
from logging.config import fileConfig
from urllib.parse import quote_plus

from alembic import context
from sqlalchemy import create_engine, pool

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings
from services.secrets_manager import get_postgres_password

# Bootstrap Vault secrets synchronously when VAULT_ADDR is configured (P1-10)
if os.getenv("VAULT_ADDR", "").strip():
    from services.vault_loader import VaultSecretsLoader

    async def _bootstrap_and_close() -> None:
        await VaultSecretsLoader.bootstrap()
        await VaultSecretsLoader.shutdown()

    asyncio.run(_bootstrap_and_close())

_user = quote_plus(settings.postgres_user)
_password = quote_plus(get_postgres_password())
SYNC_DATABASE_URL = (
    f"postgresql+pg8000://{_user}:{_password}"
    f"@{settings.postgres_host}:{settings.postgres_port}/{settings.postgres_db}"
)

target_metadata = None


def _build_connect_args() -> dict:
    connect_args: dict = {"timeout": 15}
    from services.tls_manager import get_ssl_context
    ssl_ctx = get_ssl_context()
    if ssl_ctx is not None:
        connect_args["ssl_context"] = ssl_ctx
    return connect_args


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
        connect_args=_build_connect_args(),
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
