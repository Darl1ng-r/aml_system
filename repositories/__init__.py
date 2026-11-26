"""
AML Sentinel Data Access Layer (Repositories)
=============================================
Isolates all PostgreSQL SQL queries, RLS context handling, deterministic row locking,
and ACID multi-table writes away from HTTP controllers and pure domain math.
"""

from repositories.ctr_repo import list_ctr_filings_repo, submit_ctr_filing_atomic
from repositories.idempotency_repo import (
    complete_db_idempotency,
    release_in_flight_db_idempotency,
    try_reserve_db_idempotency,
)
from repositories.transaction_repo import (
    DuplicateTransactionIdempotencyError,
    fetch_account_context,
    fetch_rule_evaluation_snapshot,
    get_transaction_by_id_repo,
    list_transactions_page_repo,
    persist_scored_transaction_atomic,
)

__all__ = [
    "DuplicateTransactionIdempotencyError",
    "complete_db_idempotency",
    "fetch_account_context",
    "fetch_rule_evaluation_snapshot",
    "get_transaction_by_id_repo",
    "list_ctr_filings_repo",
    "list_transactions_page_repo",
    "persist_scored_transaction_atomic",
    "release_in_flight_db_idempotency",
    "submit_ctr_filing_atomic",
    "try_reserve_db_idempotency",
]
