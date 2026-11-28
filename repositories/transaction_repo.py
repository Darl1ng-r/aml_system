"""
Transaction, Account & Rule-Snapshot Repository
===============================================
Centralizes all PostgreSQL persistence for AML transaction ingestion and scoring:
  1. Single-query account resolution & 24h velocity fetch on read replica.
  2. Single-query consolidated rule-snapshot CTE on read replica (collapses 7
     concurrent write-pool checkouts into 1 read-only query, fixes 5 mixed-currency
     SQL bugs via `COALESCE(amount_base_usd, amount)`, and replaces non-deterministic
     `NOW()` with injected `$tx_time`).
  3. Single ACID transaction persisting row-locked account state checks, transaction
     ledger record with provenance & idempotency key, deduplicated alerts, BSA CTR
     & structuring detection, shadow rule hits, HELD webhooks, WORM audit log, and
     canonical transactional outbox event.
"""

from __future__ import annotations

import inspect
import json
import logging
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Mapping, Optional

from database.postgres import get_async_db_conn, get_async_db_read_conn
from domain.money import to_decimal
from domain.rules_core import (
    AccountRuleSnapshot,
    CTRDecision,
    evaluate_ctr_and_structuring_pure,
)

logger = logging.getLogger(__name__)


class DuplicateTransactionIdempotencyError(Exception):
    """Raised when PostgreSQL unique constraint blocks a duplicate `(tenant_id, idempotency_key)`."""

    def __init__(self, idempotency_key: str, existing_transaction_id: Optional[str] = None) -> None:
        self.idempotency_key = idempotency_key
        self.existing_transaction_id = existing_transaction_id
        super().__init__(f"Duplicate transaction idempotency key: {idempotency_key}")


class ConcurrentAccountBlockError(Exception):
    """Raised when an account transitions to FROZEN or CIP_PENDING concurrently under FOR UPDATE."""

    def __init__(self, account_id: str, account_status: str) -> None:
        self.account_id = account_id
        self.account_status = account_status
        super().__init__(f"Transaction aborted: Account {account_id} is {account_status}.")


def _row_val(row: Any, key: str, default: Any = None) -> Any:
    if row is None:
        return default
    if hasattr(row, "get"):
        val = row.get(key)
        return val if val is not None else default
    if isinstance(row, dict) and key in row:
        val = row[key]
        return val if val is not None else default
    try:
        val = row[key]
        return val if val is not None else default
    except Exception:
        return default


def _is_valid_uuid(val: Any) -> bool:
    if not val:
        return False
    try:
        uuid.UUID(str(val))
        return True
    except (ValueError, TypeError):
        return False


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _dec(val: Any, default: str = "0") -> Decimal:
    if val is None:
        return Decimal(default)
    try:
        return to_decimal(val)
    except Exception:
        return Decimal(default)


async def _run_in_savepoint(conn: Any, fn):
    """Runs a best-effort query inside a PostgreSQL SAVEPOINT when supported so caught errors never abort the outer tx."""
    tx_factory = getattr(conn, "transaction", None)
    if callable(tx_factory) and not inspect.iscoroutinefunction(tx_factory):
        sp = tx_factory()
        if hasattr(sp, "__aenter__"):
            async with sp:
                return await fn()
    return await fn()


async def fetch_account_context(
    sender_ref: str,
    receiver_ref: str,
    *,
    tenant_id: Any = None,
    evaluated_at: datetime | None = None,
    conn: Any = None,
) -> Any:
    """
    Resolves sender & receiver accounts (by UUID or account_number) and 24h velocity
    using one consolidated read-only CTE query.
    """
    sender_is_uuid = _is_valid_uuid(sender_ref)
    receiver_is_uuid = _is_valid_uuid(receiver_ref)
    sender_clause = "id = $1::uuid" if sender_is_uuid else "account_number = $1"
    receiver_clause = "id = $2::uuid" if receiver_is_uuid else "account_number = $2"
    ref_time = _ensure_utc(evaluated_at or datetime.now(timezone.utc))

    sql = f"""
        WITH sender_info AS (
            SELECT id, tenant_id, account_number, risk_score, owner_name, swift_bic, status, customer_id, tax_id
            FROM accounts
            WHERE {sender_clause}
        ),
        receiver_info AS (
            SELECT id, account_number, risk_score, owner_name, swift_bic, status
            FROM accounts
            WHERE {receiver_clause}
        ),
        velocity_info AS (
            SELECT COUNT(*) AS velocity_count
            FROM transactions
            WHERE sender_account_id = (SELECT id FROM sender_info)
              AND timestamp >= ($3::timestamptz - INTERVAL '24 hours')
              AND timestamp <= $3::timestamptz
        )
        SELECT
            s.id AS sender_id,
            s.tenant_id AS sender_tenant,
            s.account_number AS sender_account_number,
            s.risk_score AS sender_risk,
            s.owner_name AS sender_name,
            s.swift_bic AS sender_bic,
            s.status AS sender_status,
            s.customer_id AS sender_customer_id,
            s.tax_id AS sender_tax_id,
            r.id AS receiver_id,
            r.account_number AS receiver_account_number,
            r.risk_score AS receiver_risk,
            r.owner_name AS receiver_name,
            r.swift_bic AS receiver_bic,
            r.status AS receiver_status,
            COALESCE(v.velocity_count, 0) AS velocity_count
        FROM (SELECT 1) dummy
        LEFT JOIN sender_info s ON TRUE
        LEFT JOIN receiver_info r ON TRUE
        LEFT JOIN velocity_info v ON TRUE;
    """

    if conn is not None:
        return await conn.fetchrow(sql, str(sender_ref), str(receiver_ref), ref_time)

    async with get_async_db_read_conn(tenant_id=tenant_id) as read_conn:
        return await read_conn.fetchrow(sql, str(sender_ref), str(receiver_ref), ref_time)


async def fetch_rule_evaluation_snapshot(
    *,
    tenant_id: str | None,
    sender_id: str | None,
    receiver_id: str | None,
    amount_base_usd: Decimal,
    tx_time: datetime,
    config: Mapping[str, Any],
    tier_discount: Decimal,
    entity_id: str,
    tax_id: str = "",
    sender_name: str = "",
) -> tuple[AccountRuleSnapshot, list[str]]:
    """
    Loads ALL PostgreSQL-backed AML rule facts in ONE single read-replica connection
    using USD-normalized `COALESCE(amount_base_usd, amount)` and deterministic `$tx_time`.
    Eliminates the 7-concurrent-write-pool-connection fan-out per transaction.
    """
    rules_cfg = config.get("rules", {})
    vel_days = int(rules_cfg.get("VELOCITY_MONITORING", {}).get("history_days", 30))
    rapid_mins = int(rules_cfg.get("RAPID_MOVEMENT_FUNDS", {}).get("window_minutes", 10))
    rt_hours = int(rules_cfg.get("ROUND_TRIP_DETECTION", {}).get("window_hours", 72))
    rt_tol = _dec(rules_cfg.get("ROUND_TRIP_DETECTION", {}).get("amount_tolerance", "0.10"), "0.10")
    rt_min = amount_base_usd * (Decimal("1") - rt_tol)
    rt_max = amount_base_usd * (Decimal("1") + rt_tol)

    ext_cfg = rules_cfg.get("STRUCTURING_EXTENDED_7D", {})
    ext_days = int(ext_cfg.get("window_days", 7))
    ext_min_sub = _dec(ext_cfg.get("min_sub_amount", "2500.00"), "2500.00") * tier_discount
    ext_thresh = _dec(ext_cfg.get("threshold", "10000.00"), "10000.00") * tier_discount

    conduit_hours = int(rules_cfg.get("CONDUIT_RAPID_PASSTHROUGH", {}).get("window_hours", 24))
    tx_utc = _ensure_utc(tx_time)

    if not sender_id:
        return AccountRuleSnapshot(), []

    degraded: list[str] = []
    try:
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
            sender_uuid: Optional[uuid.UUID] = None
            receiver_uuid: Optional[uuid.UUID] = None

            if _is_valid_uuid(sender_id):
                sender_uuid = uuid.UUID(str(sender_id))
            else:
                resolved = await conn.fetchval(
                    "SELECT id FROM accounts WHERE account_number = $1 LIMIT 1;",
                    str(sender_id),
                )
                if resolved and _is_valid_uuid(resolved):
                    sender_uuid = uuid.UUID(str(resolved))

            if sender_uuid is None:
                return AccountRuleSnapshot(), []

            if receiver_id:
                if _is_valid_uuid(receiver_id):
                    receiver_uuid = uuid.UUID(str(receiver_id))
                else:
                    resolved_r = await conn.fetchval(
                        "SELECT id FROM accounts WHERE account_number = $1 LIMIT 1;",
                        str(receiver_id),
                    )
                    if resolved_r and _is_valid_uuid(resolved_r):
                        receiver_uuid = uuid.UUID(str(resolved_r))

            row = await conn.fetchrow(
                """
                WITH sender_meta AS (
                    SELECT id, created_at
                    FROM accounts
                    WHERE id = $1::uuid
                ),
                daily_stats AS (
                    SELECT
                        DATE_TRUNC('day', timestamp) AS tx_day,
                        COUNT(*) AS daily_count,
                        SUM(COALESCE(amount_base_usd, amount)) AS daily_amount
                    FROM transactions
                    WHERE sender_account_id = $1::uuid
                      AND timestamp >= ($3::timestamptz - ($4 * INTERVAL '1 day'))
                      AND timestamp < DATE_TRUNC('day', $3::timestamptz)
                    GROUP BY DATE_TRUNC('day', timestamp)
                ),
                vel_hist AS (
                    SELECT
                        COALESCE(AVG(daily_count), 0) AS avg_daily_count,
                        COALESCE(STDDEV(daily_count), 0) AS stddev_daily_count,
                        COALESCE(AVG(daily_amount), 0) AS avg_daily_amount,
                        COALESCE(STDDEV(daily_amount), 0) AS stddev_daily_amount
                    FROM daily_stats
                ),
                vel_today AS (
                    SELECT
                        COUNT(*) AS today_count,
                        COALESCE(SUM(COALESCE(amount_base_usd, amount)), 0) AS today_amount
                    FROM transactions
                    WHERE sender_account_id = $1::uuid
                      AND timestamp >= DATE_TRUNC('day', $3::timestamptz)
                      AND timestamp <= $3::timestamptz
                ),
                last_incoming AS (
                    SELECT COALESCE(amount_base_usd, amount) AS amount_usd, timestamp
                    FROM transactions
                    WHERE receiver_account_id = $1::uuid
                      AND status = 'COMPLETED'
                      AND timestamp >= ($3::timestamptz - ($5 * INTERVAL '1 minute'))
                      AND timestamp <= $3::timestamptz
                    ORDER BY timestamp DESC
                    LIMIT 1
                ),
                last_outgoing AS (
                    SELECT timestamp
                    FROM transactions
                    WHERE sender_account_id = $1::uuid
                      AND timestamp < $3::timestamptz
                    ORDER BY timestamp DESC
                    LIMIT 1
                ),
                reverse_tx AS (
                    SELECT EXISTS(
                        SELECT 1
                        FROM transactions
                        WHERE $2::uuid IS NOT NULL
                          AND sender_account_id = $2::uuid
                          AND receiver_account_id = $1::uuid
                          AND COALESCE(amount_base_usd, amount) BETWEEN $6 AND $7
                          AND timestamp >= ($3::timestamptz - ($8 * INTERVAL '1 hour'))
                          AND timestamp <= $3::timestamptz
                    ) AS has_reverse
                ),
                sub_7d AS (
                    SELECT
                        COALESCE(SUM(COALESCE(t.amount_base_usd, t.amount)), 0) AS total_sub_amount,
                        COUNT(*) AS sub_count
                    FROM transactions t
                    WHERE (
                        t.sender_account_id = $1::uuid
                        OR t.sender_account_id IN (
                            SELECT a.id FROM accounts a
                            WHERE (a.customer_id IS NOT NULL AND a.customer_id = $12::text)
                               OR (a.tax_id IS NOT NULL AND $13::text != '' AND a.tax_id = $13::text)
                               OR ($14::text != '' AND a.owner_name = $14::text)
                        )
                    )
                      AND t.status IN ('COMPLETED', 'PENDING', 'HELD')
                      AND COALESCE(t.amount_base_usd, t.amount) >= $9
                      AND COALESCE(t.amount_base_usd, t.amount) < $10
                      AND t.timestamp >= ($3::timestamptz - ($11 * INTERVAL '1 day'))
                      AND t.timestamp < $3::timestamptz
                ),
                conduit_flow AS (
                    SELECT
                        COALESCE(SUM(CASE WHEN receiver_account_id = $1::uuid THEN COALESCE(amount_base_usd, amount) ELSE 0 END), 0) AS total_inflow,
                        COALESCE(SUM(CASE WHEN sender_account_id = $1::uuid THEN COALESCE(amount_base_usd, amount) ELSE 0 END), 0) AS total_outflow
                    FROM transactions
                    WHERE (receiver_account_id = $1::uuid OR sender_account_id = $1::uuid)
                      AND status IN ('COMPLETED', 'PENDING', 'HELD')
                      AND timestamp >= ($3::timestamptz - ($15 * INTERVAL '1 hour'))
                      AND timestamp < $3::timestamptz
                )
                SELECT
                    sm.created_at AS account_created_at,
                    vh.avg_daily_count,
                    vh.stddev_daily_count,
                    vh.avg_daily_amount,
                    vh.stddev_daily_amount,
                    vt.today_count,
                    vt.today_amount,
                    li.amount_usd AS last_incoming_amount_usd,
                    li.timestamp AS last_incoming_at,
                    lo.timestamp AS last_outgoing_at,
                    rt.has_reverse AS has_reverse_tx,
                    s7.sub_count AS sub_7d_count,
                    s7.total_sub_amount AS sub_7d_amount_usd,
                    cf.total_inflow AS conduit_inflow_24h_usd,
                    cf.total_outflow AS conduit_outflow_24h_usd
                FROM (SELECT 1) dummy
                LEFT JOIN sender_meta sm ON TRUE
                LEFT JOIN vel_hist vh ON TRUE
                LEFT JOIN vel_today vt ON TRUE
                LEFT JOIN last_incoming li ON TRUE
                LEFT JOIN last_outgoing lo ON TRUE
                LEFT JOIN reverse_tx rt ON TRUE
                LEFT JOIN sub_7d s7 ON TRUE
                LEFT JOIN conduit_flow cf ON TRUE;
                """,
                sender_uuid,
                receiver_uuid,
                tx_utc,
                vel_days,
                rapid_mins,
                rt_min,
                rt_max,
                rt_hours,
                ext_min_sub,
                ext_thresh,
                ext_days,
                str(entity_id),
                str(tax_id or ""),
                str(sender_name or ""),
                conduit_hours,
            )

            if not row:
                return AccountRuleSnapshot(), degraded

            return AccountRuleSnapshot(
                velocity_avg_count=_dec(_row_val(row, "avg_daily_count", 0)),
                velocity_std_count=_dec(_row_val(row, "stddev_daily_count", 0)),
                velocity_avg_amount_usd=_dec(_row_val(row, "avg_daily_amount", 0)),
                velocity_std_amount_usd=_dec(_row_val(row, "stddev_daily_amount", 0)),
                today_count=int(_row_val(row, "today_count", 0)),
                today_amount_usd=_dec(_row_val(row, "today_amount", 0)),
                last_incoming_amount_usd=(
                    _dec(_row_val(row, "last_incoming_amount_usd"))
                    if _row_val(row, "last_incoming_amount_usd") is not None
                    else None
                ),
                last_incoming_at=_row_val(row, "last_incoming_at"),
                last_outgoing_at=_row_val(row, "last_outgoing_at"),
                has_reverse_tx=bool(_row_val(row, "has_reverse_tx", False)),
                account_created_at=_row_val(row, "account_created_at"),
                sub_7d_count=int(_row_val(row, "sub_7d_count", 0)),
                sub_7d_amount_usd=_dec(_row_val(row, "sub_7d_amount_usd", 0)),
                conduit_inflow_24h_usd=_dec(_row_val(row, "conduit_inflow_24h_usd", 0)),
                conduit_outflow_24h_usd=_dec(_row_val(row, "conduit_outflow_24h_usd", 0)),
            ), degraded
    except Exception as exc:
        logger.warning("Consolidated rule snapshot query degraded: %s", exc)
        degraded.append("DB_RULE_SNAPSHOT")
        return AccountRuleSnapshot(degraded_rules=tuple(degraded)), degraded


async def _verify_concurrency_lock(conn: Any, sender_id: Any, receiver_id: Any) -> None:
    """
    Acquires deterministic ascending `FOR UPDATE` locks on sender & receiver accounts
    to prevent AB-BA deadlocks and abort if either account transitioned to FROZEN
    or CIP_PENDING concurrently. Fails closed on real database errors.
    """
    if not hasattr(conn, "fetch"):
        return

    locked_accounts = await conn.fetch(
        "SELECT id, status FROM accounts WHERE id IN ($1, $2) ORDER BY id ASC FOR UPDATE;",
        sender_id,
        receiver_id,
    )
    for acc in (locked_accounts or []):
        st = str(_row_val(acc, "status", "ACTIVE")).upper()
        if st in ("FROZEN", "CIP_PENDING"):
            raise ConcurrentAccountBlockError(str(_row_val(acc, "id", "")), st)


async def _evaluate_and_persist_ctr_tx(
    conn: Any,
    *,
    tenant_id: Any,
    tx_id: str,
    sender_id: Any,
    amount_original: Decimal,
    currency: str,
    amount_base_usd: Decimal,
    channel: Optional[str],
    merchant: Optional[str],
    tx_dt: datetime,
    ruleset_hash: Optional[str],
    model_version: Optional[str],
    evaluated_at: datetime,
) -> CTRDecision:
    is_cash_channel = bool(
        (channel and channel.strip().upper() == "CASH")
        or (merchant and merchant.strip().upper() == "CASH")
    )
    if not is_cash_channel:
        return evaluate_ctr_and_structuring_pure(amount_base_usd, channel, merchant)

    prior_24h_cash = Decimal("0")
    cash_count_24h = 0
    prior_24h_sub_cash: Optional[Decimal] = None
    prior_24h_sub_count: Optional[int] = None
    try:
        rolling_cash_row = await _run_in_savepoint(
            conn,
            lambda: conn.fetchrow(
                """
                WITH customer_scope AS (
                    SELECT customer_id FROM accounts WHERE id = $1
                )
                SELECT COALESCE(SUM(COALESCE(t.amount_base_usd, t.amount)), 0) AS total_cash_24h,
                       COUNT(t.id) AS cash_count_24h,
                       COALESCE(
                           SUM(COALESCE(t.amount_base_usd, t.amount))
                           FILTER (WHERE COALESCE(t.amount_base_usd, t.amount) < 10000),
                           0
                       ) AS sub_threshold_cash_24h,
                       COUNT(t.id)
                       FILTER (WHERE COALESCE(t.amount_base_usd, t.amount) < 10000) AS sub_threshold_cash_count_24h
                FROM transactions t
                JOIN accounts a ON t.sender_account_id = a.id
                WHERE (
                    ((SELECT customer_id FROM customer_scope) IS NOT NULL AND a.customer_id = (SELECT customer_id FROM customer_scope))
                    OR ((SELECT customer_id FROM customer_scope) IS NULL AND t.sender_account_id = $1)
                )
                  AND t.id != $2::uuid
                  AND COALESCE(UPPER(t.status), 'COMPLETED') NOT IN ('FAILED', 'CANCELLED', 'REJECTED', 'REVERSED')
                  AND (UPPER(COALESCE(t.channel, '')) = 'CASH' OR UPPER(COALESCE(t.merchant, '')) = 'CASH')
                  AND t.timestamp >= ($3::timestamptz - INTERVAL '24 hours')
                  AND t.timestamp <= $3::timestamptz;
                """,
                sender_id,
                uuid.UUID(tx_id),
                tx_dt,
            ),
        )
        if rolling_cash_row:
            prior_24h_cash = _dec(_row_val(rolling_cash_row, "total_cash_24h", 0))
            cash_count_24h = int(_row_val(rolling_cash_row, "cash_count_24h", 0))
            if "sub_threshold_cash_24h" in rolling_cash_row:
                prior_24h_sub_cash = _dec(_row_val(rolling_cash_row, "sub_threshold_cash_24h", 0))
                prior_24h_sub_count = int(_row_val(rolling_cash_row, "sub_threshold_cash_count_24h", 0))
    except Exception as ex_ctr:
        logger.warning("Failed to query 24h rolling cash aggregation: %s", ex_ctr)

    ctr_decision = evaluate_ctr_and_structuring_pure(
        amount_base_usd=amount_base_usd,
        channel=channel,
        merchant=merchant,
        prior_24h_cash_usd=prior_24h_cash,
        prior_24h_cash_count=cash_count_24h,
        prior_24h_sub_threshold_cash_usd=prior_24h_sub_cash,
        prior_24h_sub_threshold_cash_count=prior_24h_sub_count,
    )

    if ctr_decision.requires_ctr_filing:
        # Derive cash direction safely from channel/merchant hints (default DEPOSIT)
        hint = f"{channel or ''} {merchant or ''}".upper()
        if "WITHDRAW" in hint or "ATM" in hint:
            cash_direction = "WITHDRAWAL"
        elif "EXCHANGE" in hint or "FX" in hint:
            cash_direction = "EXCHANGE"
        else:
            cash_direction = "DEPOSIT"

        # 31 CFR 1010.313 requires filing the aggregated 24h reportable cash total
        aggregated_usd = ctr_decision.total_aggregate_cash_usd
        aggregated_tx_count = ctr_decision.prior_24h_cash_count + 1
        ctr_amount = aggregated_usd if (currency or "USD").upper() == "USD" else amount_original

        try:
            await _run_in_savepoint(
                conn,
                lambda: conn.execute(
                    """
                    INSERT INTO ctr_filings (
                        tenant_id, transaction_id, account_id, amount, currency,
                        cash_in_out, status, aggregate_amount_usd, aggregated_tx_count
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, 'PENDING', $7, $8)
                    ON CONFLICT (tenant_id, transaction_id) WHERE transaction_id IS NOT NULL DO NOTHING;
                    """,
                    tenant_id,
                    uuid.UUID(tx_id),
                    sender_id,
                    ctr_amount,
                    currency,
                    cash_direction,
                    aggregated_usd,
                    aggregated_tx_count,
                ),
            )
        except Exception:
            await _run_in_savepoint(
                conn,
                lambda: conn.execute(
                    """
                    INSERT INTO ctr_filings (tenant_id, transaction_id, account_id, amount, currency, cash_in_out, status)
                    VALUES ($1, $2, $3, $4, $5, $6, 'PENDING')
                    ON CONFLICT (tenant_id, transaction_id) WHERE transaction_id IS NOT NULL DO NOTHING;
                    """,
                    tenant_id,
                    uuid.UUID(tx_id),
                    sender_id,
                    ctr_amount,
                    currency,
                    cash_direction,
                ),
            )

    if ctr_decision.structuring_detected:
        structuring_payload = {
            "rule": "CTR_STRUCTURING_DETECTION",
            "current_amount": str(amount_original),
            "current_currency": currency,
            "current_amount_usd": float(ctr_decision.tx_amount_usd),
            "prior_24h_cash_usd": float(ctr_decision.prior_24h_cash_usd),
            "total_aggregate_cash_usd": float(ctr_decision.total_aggregate_cash_usd),
            "message": "Potential structuring/smurfing detected under FinCEN 31 CFR 1010.313.",
        }
        await conn.execute(
            """
            INSERT INTO alerts (
                tenant_id, transaction_id, rule_name, threat_level, ai_risk_score,
                explainability_payload, ruleset_hash, model_version, evaluated_at
            )
            VALUES ($1, $2, 'CTR_STRUCTURING_DETECTION', 'HIGH', 0.85, $3, $4, $5, $6)
            ON CONFLICT (tenant_id, transaction_id, rule_name)
            WHERE transaction_id IS NOT NULL AND rule_name IS NOT NULL DO NOTHING;
            """,
            tenant_id,
            tx_id,
            json.dumps(structuring_payload),
            ruleset_hash,
            model_version,
            evaluated_at,
        )

    return ctr_decision


async def persist_scored_transaction_atomic(
    *,
    tenant_id: Any,
    tx_id: str,
    sender_id: Any,
    receiver_id: Any,
    sender_account: str,
    receiver_account: str,
    amount_original: Decimal,
    currency: str,
    amount_base_usd: Decimal,
    fx_rate_applied: Decimal,
    fx_rate_source: str,
    fx_rate_quoted_at: datetime,
    tx_timestamp: datetime,
    evaluated_at: datetime,
    country: Optional[str],
    merchant: Optional[str],
    device: Optional[str],
    channel: Optional[str],
    scoring: dict[str, Any],
    acct_meta: Mapping[str, Any],
    actor: Mapping[str, Any],
    idempotency_key: Optional[str] = None,
    upsert_on_id: bool = False,
    outbox_headers: Optional[dict[str, str]] = None,
    ingestion_mode: str = "SYNC",
    write_conn_factory: Any = None,
) -> tuple[datetime, CTRDecision]:
    """
    Commits the entire compliance outcome inside ONE PostgreSQL ACID transaction:
      1. Deterministic `ORDER BY id ASC FOR UPDATE` account status lock.
      2. Transaction insert/upsert with exact Decimal amounts, idempotency_key, and provenance.
      3. `TRANSACTION_HELD` signed interdiction webhook (when HELD).
      4. `SHADOW` challenger rule evaluation into `rule_shadow_hits`.
      5. Deduplicated primary `alerts` insert with provenance.
      6. BSA 31 CFR 1010.311/1010.313 CTR filing + cash structuring alert (deduplicated).
      7. Cryptographic WORM `audit_log` entry for alerted/held transactions.
      8. Canonical `transactional_outbox` event (`aml.core.transaction.ingested.v1`).
    """
    from database.outbox import record_outbox_event

    dt = _ensure_utc(tx_timestamp)
    eval_utc = _ensure_utc(evaluated_at)
    fx_quoted_utc = _ensure_utc(fx_rate_quoted_at)

    ruleset_hash = scoring.get("ruleset_hash")
    model_version = scoring.get("model_version")
    provenance_doc = {
        "ruleset_hash": ruleset_hash,
        "model_version": model_version,
        "iforest_version": scoring.get("iforest_version"),
        "fx_rate_source": fx_rate_source,
        "fx_rate_quoted_at": fx_quoted_utc.isoformat(),
        "evaluated_at": eval_utc.isoformat(),
        "degraded_rules": list(scoring.get("degraded_rules") or []),
        "ingestion_mode": ingestion_mode,
    }

    conn_factory = write_conn_factory or get_async_db_conn
    async with conn_factory(tenant_id=tenant_id) as conn:
        await _verify_concurrency_lock(conn, sender_id, receiver_id)

        try:
            if upsert_on_id:
                await conn.execute(
                    """
                    INSERT INTO transactions (
                        id, tenant_id, sender_account_id, receiver_account_id, amount, currency,
                        amount_base_usd, fx_rate_applied, status, timestamp, country, merchant, device, channel,
                        idempotency_key, fx_rate_source, fx_rate_quoted_at, evaluated_at,
                        ruleset_hash, model_version, evaluation_provenance
                    )
                    VALUES (
                        $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6,
                        $7, $8, $9, $10, $11, $12, $13, $14,
                        $15, $16, $17, $18,
                        $19, $20, $21::jsonb
                    )
                    ON CONFLICT (id) DO UPDATE SET
                        status = EXCLUDED.status,
                        amount_base_usd = EXCLUDED.amount_base_usd,
                        fx_rate_applied = EXCLUDED.fx_rate_applied,
                        fx_rate_source = EXCLUDED.fx_rate_source,
                        fx_rate_quoted_at = EXCLUDED.fx_rate_quoted_at,
                        evaluated_at = EXCLUDED.evaluated_at,
                        ruleset_hash = EXCLUDED.ruleset_hash,
                        model_version = EXCLUDED.model_version,
                        evaluation_provenance = EXCLUDED.evaluation_provenance;
                    """,
                    tx_id,
                    tenant_id,
                    sender_id,
                    receiver_id,
                    amount_original,
                    currency,
                    amount_base_usd,
                    fx_rate_applied,
                    scoring["tx_status"],
                    dt,
                    country,
                    merchant,
                    device,
                    channel,
                    idempotency_key,
                    fx_rate_source,
                    fx_quoted_utc,
                    eval_utc,
                    ruleset_hash,
                    model_version,
                    json.dumps(provenance_doc),
                )
            else:
                await conn.execute(
                    """
                    INSERT INTO transactions (
                        id, tenant_id, sender_account_id, receiver_account_id, amount, currency,
                        amount_base_usd, fx_rate_applied, status, timestamp, country, merchant, device, channel,
                        idempotency_key, fx_rate_source, fx_rate_quoted_at, evaluated_at,
                        ruleset_hash, model_version, evaluation_provenance
                    )
                    VALUES (
                        $1, $2, $3, $4, $5, $6,
                        $7, $8, $9, $10, $11, $12, $13, $14,
                        $15, $16, $17, $18,
                        $19, $20, $21::jsonb
                    );
                    """,
                    tx_id,
                    tenant_id,
                    sender_id,
                    receiver_id,
                    amount_original,
                    currency,
                    amount_base_usd,
                    fx_rate_applied,
                    scoring["tx_status"],
                    dt,
                    country,
                    merchant,
                    device,
                    channel,
                    idempotency_key,
                    fx_rate_source,
                    fx_quoted_utc,
                    eval_utc,
                    ruleset_hash,
                    model_version,
                    json.dumps(provenance_doc),
                )
        except Exception as exc:
            if type(exc).__name__ == "UniqueViolationError" and idempotency_key:
                raise DuplicateTransactionIdempotencyError(idempotency_key) from exc
            raise

        # Enqueue signed core-banking interdiction webhook on HELD transactions
        if scoring.get("decision") == "HELD" and tenant_id:
            from services.webhooks import enqueue_webhook_event_tx

            await enqueue_webhook_event_tx(
                conn=conn,
                tenant_id=str(tenant_id),
                event_type="TRANSACTION_HELD",
                aggregate_id=tx_id,
                payload={
                    "transaction_id": tx_id,
                    "sender_account": sender_account,
                    "receiver_account": receiver_account,
                    "amount": float(amount_original),
                    "currency": currency,
                    "amount_base_usd": float(amount_base_usd),
                    "fx_rate_applied": float(fx_rate_applied),
                    "triggered_rules": scoring.get("triggered_rules", []),
                    "threat_level": scoring.get("threat_level", "HIGH"),
                },
            )

        # Evaluate SHADOW challenger rules silently into rule_shadow_hits
        if tenant_id:
            from services.rule_backtest import evaluate_shadow_rules

            await evaluate_shadow_rules(
                conn=conn,
                tenant_id=tenant_id,
                transaction_id=tx_id,
                sender_account_id=sender_id,
                amount_base_usd=amount_base_usd,
                country=country,
                channel=channel,
            )

        # Persist deduplicated primary alert with provenance
        if scoring["alert_triggered"]:
            threat_level = scoring["threat_level"]
            if threat_level == "NONE":
                threat_level = "CRITICAL" if scoring["dynamic_score"] >= 0.90 else "HIGH"
            rule_name = scoring["triggered_rules"][0] if scoring["triggered_rules"] else "BEHAVIORAL_ANOMALY"

            explainability_payload = {
                "ml_attributions": scoring["attributions"],
                "dynamic_risk": scoring["explainability"],
                "top_drivers": scoring.get("top_drivers", []),
                "provenance": provenance_doc,
            }

            await conn.execute(
                """
                INSERT INTO alerts (
                    tenant_id, transaction_id, rule_name, threat_level, ai_risk_score,
                    explainability_payload, ruleset_hash, model_version, evaluated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (tenant_id, transaction_id, rule_name)
                WHERE transaction_id IS NOT NULL AND rule_name IS NOT NULL DO NOTHING;
                """,
                tenant_id,
                tx_id,
                rule_name,
                threat_level,
                scoring["dynamic_score"],
                json.dumps(explainability_payload),
                ruleset_hash,
                model_version,
                eval_utc,
            )

        # BSA 31 CFR 1010.311 CTR & 31 CFR 1010.313 Structuring — enforced on BOTH sync and async!
        ctr_decision = await _evaluate_and_persist_ctr_tx(
            conn,
            tenant_id=tenant_id,
            tx_id=tx_id,
            sender_id=sender_id,
            amount_original=amount_original,
            currency=currency,
            amount_base_usd=amount_base_usd,
            channel=channel,
            merchant=merchant,
            tx_dt=dt,
            ruleset_hash=ruleset_hash,
            model_version=model_version,
            evaluated_at=eval_utc,
        )

        # Atomically persist cryptographic WORM audit_log for alerted / held transactions
        if (scoring["alert_triggered"] or scoring.get("decision") == "HELD") and tenant_id:
            from services.audit import record_audit_event_tx

            await record_audit_event_tx(
                conn=conn,
                action="TRANSACTION_HELD" if scoring.get("decision") == "HELD" else "TRANSACTION_ALERTED",
                actor_id=str(actor.get("id") or actor.get("username") or "api_ingest"),
                actor_username=str(actor.get("username") or "api_ingest"),
                actor_role=str(actor.get("role") or "ANALYST"),
                resource_type="TRANSACTION",
                resource_id=tx_id,
                tenant_id=str(tenant_id),
                details={
                    "ingestion_mode": ingestion_mode,
                    "decision": scoring.get("decision"),
                    "threat_level": scoring.get("threat_level"),
                    "risk_score": scoring.get("dynamic_score"),
                    "amount": float(amount_original),
                    "currency": currency,
                    "amount_base_usd": float(amount_base_usd),
                    "fx_rate_applied": float(fx_rate_applied),
                    "triggered_rules": scoring.get("triggered_rules", []),
                    "provenance": provenance_doc,
                },
            )

        # Canonical single-publisher transactional outbox event (fail-closed inside ACID tx)
        outbox_payload = {
            "transaction_id": tx_id,
            "tenant_id": str(tenant_id),
            "sender_id": str(sender_id),
            "sender_account": sender_account,
            "receiver_id": str(receiver_id),
            "receiver_account": receiver_account,
            "amount": float(amount_original),
            "currency": currency,
            "amount_base_usd": float(amount_base_usd),
            "fx_rate_applied": float(fx_rate_applied),
            "status": scoring["tx_status"],
            "timestamp": dt.isoformat(),
            "country": country,
            "merchant": merchant,
            "device": device,
            "channel": channel,
            "sender_risk": acct_meta.get("sender_risk"),
            "receiver_risk": acct_meta.get("receiver_risk"),
            "velocity_count": acct_meta.get("velocity_count", acct_meta.get("velocity_24h")),
            "is_geo_risk": scoring.get("is_geo", 0),
            "dynamic_score": scoring["dynamic_score"],
            "alert_triggered": scoring["alert_triggered"],
            "triggered_rules": scoring.get("triggered_rules", []),
            "ruleset_hash": ruleset_hash,
            "model_version": model_version,
            "evaluated_at": eval_utc.isoformat(),
            "ingested_by": str(actor.get("username") or "api_ingest"),
        }
        await record_outbox_event(
            conn=conn,
            aggregate_type="TRANSACTION",
            aggregate_id=tx_id,
            event_type="aml.core.transaction.ingested.v1",
            payload=outbox_payload,
            tenant_id=str(tenant_id) if tenant_id else None,
            headers=outbox_headers,
        )

    return dt, ctr_decision


async def get_transaction_by_id_repo(
    tx_uuid: uuid.UUID,
    tenant_id: Any,
    *,
    read_conn_factory: Any = None,
) -> Any:
    conn_factory = read_conn_factory or get_async_db_read_conn
    async with conn_factory(tenant_id=tenant_id) as conn:
        return await conn.fetchrow(
            """
            SELECT t.id, t.amount, t.currency, t.amount_base_usd, t.fx_rate_applied,
                   t.fx_rate_source, t.fx_rate_quoted_at, t.evaluated_at,
                   t.ruleset_hash, t.model_version,
                   t.status, t.timestamp,
                   t.country, t.merchant, t.device, t.channel,
                   s.account_number as sender_account, s.owner_name as sender_name,
                   r.account_number as receiver_account, r.owner_name as receiver_name
            FROM transactions t
            JOIN accounts s ON t.sender_account_id = s.id
            JOIN accounts r ON t.receiver_account_id = r.id
            WHERE t.id = $1;
            """,
            tx_uuid,
        )


async def list_transactions_page_repo(
    tenant_id: Any,
    cursor_timestamp: datetime | None,
    cursor_id: uuid.UUID | None,
    limit: int,
    offset: int,
    *,
    cursor: str | None = None,
    read_conn_factory: Any = None,
) -> tuple[list, int | None]:
    from database.pagination import decode_keyset_cursor, validate_legacy_offset

    if cursor:
        cursor_timestamp, cursor_id = decode_keyset_cursor(cursor)

    conn_factory = read_conn_factory or get_async_db_read_conn
    async with conn_factory(tenant_id=tenant_id) as conn:
        if cursor_timestamp:
            cid = cursor_id or uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
            rows = await conn.fetch(
                """
                SELECT t.id, t.amount, t.currency, t.amount_base_usd, t.fx_rate_applied,
                       t.status, t.timestamp,
                       t.country, t.channel,
                       s.account_number as sender_account, s.owner_name as sender_name,
                       r.account_number as receiver_account, r.owner_name as receiver_name
                FROM transactions t
                JOIN accounts s ON t.sender_account_id = s.id
                JOIN accounts r ON t.receiver_account_id = r.id
                WHERE t.tenant_id = $1 AND (t.timestamp, t.id) < ($2, $3)
                ORDER BY t.timestamp DESC, t.id DESC
                LIMIT $4;
                """,
                tenant_id,
                cursor_timestamp,
                cid,
                limit + 1 if cursor else limit,
            )
            return rows, None

        safe_offset = validate_legacy_offset(offset)
        total_count = await conn.fetchval(
            "SELECT COUNT(*) FROM transactions WHERE tenant_id = $1;",
            tenant_id,
        )
        rows = await conn.fetch(
            """
            SELECT t.id, t.amount, t.currency, t.amount_base_usd, t.fx_rate_applied,
                   t.status, t.timestamp,
                   t.country, t.channel,
                   s.account_number as sender_account, s.owner_name as sender_name,
                   r.account_number as receiver_account, r.owner_name as receiver_name
            FROM transactions t
            JOIN accounts s ON t.sender_account_id = s.id
            JOIN accounts r ON t.receiver_account_id = r.id
            WHERE t.tenant_id = $1
            ORDER BY t.timestamp DESC, t.id DESC
            LIMIT $2 OFFSET $3;
            """,
            tenant_id,
            limit,
            safe_offset,
        )
        return rows, total_count


async def buffer_async_transaction_outbox_repo(
    *,
    tenant_id: Any,
    tx_id: str,
    buffer_payload: dict[str, Any],
    record_outbox_fn: Any = None,
    write_conn_factory: Any = None,
) -> None:
    """Persists an async-ingested transaction into PostgreSQL transactional_outbox."""
    from database.outbox import record_outbox_event

    writer = record_outbox_fn or record_outbox_event
    conn_factory = write_conn_factory or get_async_db_conn
    async with conn_factory(tenant_id=tenant_id) as conn:
        await writer(
            conn=conn,
            aggregate_type="TRANSACTION_BUFFER",
            aggregate_id=tx_id,
            event_type="aml.core.transaction.buffered.v1",
            payload=buffer_payload,
            tenant_id=str(tenant_id),
            headers={"topic": "aml.transactions.raw"},
        )
