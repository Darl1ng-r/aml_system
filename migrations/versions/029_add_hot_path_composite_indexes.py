"""Add hot-path composite indexes for transactions, audit_log, and accounts

Revision ID: 029
Revises: 028
Create Date: 2026-11-21 00:45:00.000000
"""

from typing import Sequence, Union
from alembic import op
from sqlalchemy import text

revision: str = '029'
down_revision: Union[str, None] = '028'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _run_concurrent_ddl(statements: list[str]) -> None:
    """Executes CONCURRENTLY DDL statements on a dedicated AUTOCOMMIT connection (pg8000 & psycopg safe)."""
    engine = op.get_bind().engine
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for stmt in statements:
            conn.execute(text(stmt))


def upgrade() -> None:
    """Create missing hot-path composite indexes concurrently without blocking production writes."""
    _run_concurrent_ddl([
        """
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tx_receiver_timestamp
        ON transactions (receiver_account_id, timestamp DESC);
        """,
        """
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tx_sender_receiver_timestamp
        ON transactions (sender_account_id, receiver_account_id, timestamp DESC);
        """,
        """
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_log_tenant_created_id
        ON audit_log (tenant_id, created_at DESC, id DESC);
        """,
        """
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_accounts_tenant_risk_score
        ON accounts (tenant_id, risk_score DESC);
        """,
    ])


def downgrade() -> None:
    _run_concurrent_ddl([
        "DROP INDEX CONCURRENTLY IF EXISTS idx_accounts_tenant_risk_score;",
        "DROP INDEX CONCURRENTLY IF EXISTS idx_audit_log_tenant_created_id;",
        "DROP INDEX CONCURRENTLY IF EXISTS idx_tx_sender_receiver_timestamp;",
        "DROP INDEX CONCURRENTLY IF EXISTS idx_tx_receiver_timestamp;",
    ])
