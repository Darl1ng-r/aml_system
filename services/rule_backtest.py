"""
Historical Rule Backtesting & Champion-Challenger Shadow Mode Service (P1-2)
=============================================================================
1. Read-Only Backtesting: Replays proposed rule thresholds against historical
   transactions on the read replica using exact Decimal arithmetic and O(N)
   sliding-deque windows offloaded onto the bounded analytics compute bulkhead.
2. Shadow Challenger Evaluation: Silently evaluates rules configured in `SHADOW`
   mode (or with `shadow_config`) on live transactions and persists hits to
   `rule_shadow_hits` without alerting analysts.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Deque, Dict, List, Optional, Tuple

from database.postgres import get_async_db_read_conn
from domain.money import to_decimal
from services.compute_executor import run_analytics_compute
from services.rules import get_rules_config

logger = logging.getLogger("aml.rule_backtest")


def _dec(val: Any, default: str = "0") -> Decimal:
    if val is None:
        return Decimal(default)
    try:
        return to_decimal(val)
    except Exception:
        return Decimal(default)


def evaluate_rule_on_tx_row(
    rule_name: str,
    cfg: Dict[str, Any],
    tx: Dict[str, Any],
    sender_24h_sum: float | Decimal = Decimal("0"),
    sender_7d_sub_count: int = 0,
    sender_7d_sub_sum: float | Decimal = Decimal("0"),
) -> Tuple[bool, str]:
    """
    Pure, deterministic rule evaluator over a historical/live transaction row
    using exact fixed-point Decimal arithmetic on FX-normalized `amount_base_usd`.
    """
    if cfg.get("enabled") is False:
        return False, ""

    raw_base = tx.get("amount_base_usd")
    amount = _dec(raw_base if raw_base is not None else tx.get("amount"), "0")
    sum_24h = _dec(sender_24h_sum, "0")
    sum_7d = _dec(sender_7d_sub_sum, "0")
    country = str(tx.get("country") or "").upper().strip()
    channel = str(tx.get("channel") or "").upper().strip()
    rname = rule_name.upper().strip()

    if rname == "LARGE_TRANSACTION":
        threshold = _dec(cfg.get("threshold", "10000.00"), "10000.00")
        if amount >= threshold:
            return True, f"amount_usd={amount:.2f} >= threshold={threshold:.2f}"
        return False, ""

    if rname == "STRUCTURING_SMURFING":
        threshold = _dec(cfg.get("threshold", "10000.00"), "10000.00")
        if amount < threshold and (sum_24h >= threshold):
            return True, f"24h_sum={sum_24h:.2f} >= threshold={threshold:.2f} with sub-threshold tx={amount:.2f}"
        return False, ""

    if rname == "STRUCTURING_EXTENDED_7D":
        threshold = _dec(cfg.get("threshold", "10000.00"), "10000.00")
        min_sub = _dec(cfg.get("min_sub_amount", "2500.00"), "2500.00")
        min_count = int(cfg.get("min_count", 3))
        if min_sub <= amount < threshold and sender_7d_sub_count >= min_count and sum_7d >= threshold:
            return True, f"7d_sub_count={sender_7d_sub_count} sum={sum_7d:.2f}"
        return False, ""

    if rname == "AMOUNT_ANOMALY_HEURISTICS":
        jb_min = _dec(cfg.get("just_below_min", "9000.00"), "9000.00")
        jb_max = _dec(cfg.get("just_below_max", "10000.00"), "10000.00")
        rnd_min = _dec(cfg.get("round_number_min", "3000.00"), "3000.00")
        divisor = max(Decimal("1"), _dec(cfg.get("round_divisor", "1000.00"), "1000.00"))
        if jb_min <= amount < jb_max:
            return True, f"just_below_threshold amount={amount:.2f} in [{jb_min:.0f}, {jb_max:.0f})"
        if amount >= rnd_min and (amount % divisor == Decimal("0")):
            return True, f"round_number amount={amount:.2f} divisible by {divisor:.0f}"
        return False, ""

    if rname == "GEOGRAPHIC_SANCTIONS":
        high_risk = {str(c).upper() for c in cfg.get("high_risk_countries", ["RU", "IR", "KP", "SY"])}
        if country and country in high_risk:
            return True, f"high_risk_country={country}"
        return False, ""

    if rname == "CRYPTO_FIAT_VASP_STRUCTURING":
        threshold = _dec(cfg.get("travel_rule_threshold", "1000.00"), "1000.00")
        if channel in ("CRYPTO", "VASP", "DIGITAL_ASSET") and amount >= threshold:
            return True, f"vasp_channel={channel} amount={amount:.2f} >= {threshold:.2f}"
        return False, ""

    if rname == "NEWLY_INCORPORATED_HIGH_VALUE":
        threshold = _dec(cfg.get("high_value_threshold", "50000.00"), "50000.00")
        if amount >= threshold:
            return True, f"high_value={amount:.2f} >= {threshold:.2f}"
        return False, ""

    if rname == "DORMANT_ACCOUNT":
        threshold = _dec(cfg.get("activation_threshold", "50000.00"), "50000.00")
        if amount >= threshold:
            return True, f"activation_amount={amount:.2f} >= {threshold:.2f}"
        return False, ""

    if rname == "TRADE_BASED_ML_OVER_UNDER_INVOICING":
        threshold = _dec(cfg.get("invoice_amount_threshold", "100000.00"), "100000.00")
        if amount >= threshold:
            return True, f"invoice_amount={amount:.2f} >= {threshold:.2f}"
        return False, ""

    if "threshold" in cfg:
        threshold = _dec(cfg["threshold"], "0")
        if amount >= threshold:
            return True, f"amount={amount:.2f} >= threshold={threshold:.2f}"
    return False, ""


class _SlidingDecimalWindow:
    """O(1)-amortized sliding time window maintaining exact Decimal running sum & count."""

    __slots__ = ("_entries", "_sum", "_delta")

    def __init__(self, delta: timedelta) -> None:
        self._entries: Deque[Tuple[datetime, Decimal]] = deque()
        self._sum: Decimal = Decimal("0")
        self._delta = delta

    def evict_before(self, now: datetime) -> None:
        cutoff = now - self._delta
        while self._entries and self._entries[0][0] < cutoff:
            _, old_amt = self._entries.popleft()
            self._sum -= old_amt

    def add(self, ts: datetime, amount: Decimal) -> None:
        self._entries.append((ts, amount))
        self._sum += amount

    @property
    def total(self) -> Decimal:
        return self._sum

    @property
    def count(self) -> int:
        return len(self._entries)


def _run_backtest_replay_sync(
    norm_rule: str,
    lookback_days: int,
    champion_cfg: Dict[str, Any],
    challenger_cfg: Dict[str, Any],
    tx_list: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """O(N) pure-CPU Champion vs Challenger replay executed inside the analytics bulkhead."""
    champ_thresh = _dec(champion_cfg.get("threshold", "10000.00"), "10000.00")
    chall_thresh = _dec(challenger_cfg.get("threshold", "10000.00"), "10000.00")
    champ_min_sub = _dec(champion_cfg.get("min_sub_amount", "2500.00"), "2500.00")
    chall_min_sub = _dec(challenger_cfg.get("min_sub_amount", "2500.00"), "2500.00")

    champ_24h_windows: Dict[str, _SlidingDecimalWindow] = defaultdict(lambda: _SlidingDecimalWindow(timedelta(hours=24)))
    chall_24h_windows: Dict[str, _SlidingDecimalWindow] = defaultdict(lambda: _SlidingDecimalWindow(timedelta(hours=24)))
    champ_7d_windows: Dict[str, _SlidingDecimalWindow] = defaultdict(lambda: _SlidingDecimalWindow(timedelta(days=7)))
    chall_7d_windows: Dict[str, _SlidingDecimalWindow] = defaultdict(lambda: _SlidingDecimalWindow(timedelta(days=7)))

    champion_hits = 0
    challenger_hits = 0
    newly_triggered: List[Dict[str, Any]] = []
    suppressed: List[Dict[str, Any]] = []
    captured_historical_sars = 0
    missed_historical_sars = 0
    avoided_false_positives = 0

    for tx in tx_list:
        sender_key = str(tx.get("sender_account_id") or "")
        ts = tx.get("timestamp") or datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        raw_base = tx.get("amount_base_usd")
        amt = _dec(raw_base if raw_base is not None else tx.get("amount"), "0")

        c24 = champ_24h_windows[sender_key]
        x24 = chall_24h_windows[sender_key]
        c7 = champ_7d_windows[sender_key]
        x7 = chall_7d_windows[sender_key]

        c24.evict_before(ts)
        x24.evict_before(ts)
        c7.evict_before(ts)
        x7.evict_before(ts)

        if amt < champ_thresh:
            c24.add(ts, amt)
        if amt < chall_thresh:
            x24.add(ts, amt)
        if champ_min_sub <= amt < champ_thresh:
            c7.add(ts, amt)
        if chall_min_sub <= amt < chall_thresh:
            x7.add(ts, amt)

        champ_hit, _ = evaluate_rule_on_tx_row(
            norm_rule, champion_cfg, tx, c24.total, c7.count, c7.total
        )
        chall_hit, chall_reason = evaluate_rule_on_tx_row(
            norm_rule, challenger_cfg, tx, x24.total, x7.count, x7.total
        )

        if champ_hit:
            champion_hits += 1
        if chall_hit:
            challenger_hits += 1

        hist_status = (tx.get("historical_alert_status") or "").upper()
        if hist_status == "CLOSED_SAR":
            if chall_hit:
                captured_historical_sars += 1
            elif champ_hit and not chall_hit:
                missed_historical_sars += 1
        elif hist_status == "CLOSED_FALSE_POSITIVE" and champ_hit and not chall_hit:
            avoided_false_positives += 1

        if chall_hit and not champ_hit and len(newly_triggered) < 10:
            newly_triggered.append({
                "transaction_id": str(tx["id"]),
                "amount_base_usd": float(amt),
                "currency": tx.get("currency") or "USD",
                "reason": chall_reason,
                "timestamp": ts.isoformat(),
            })
        elif champ_hit and not chall_hit and len(suppressed) < 10:
            suppressed.append({
                "transaction_id": str(tx["id"]),
                "amount_base_usd": float(amt),
                "currency": tx.get("currency") or "USD",
                "historical_status": hist_status or "NONE",
                "timestamp": ts.isoformat(),
            })

    delta_hits = challenger_hits - champion_hits
    delta_pct = round((delta_hits / champion_hits) * 100.0, 2) if champion_hits > 0 else (100.0 if challenger_hits > 0 else 0.0)

    return {
        "rule_name": norm_rule,
        "lookback_days": lookback_days,
        "transactions_evaluated": len(tx_list),
        "champion_config": champion_cfg,
        "challenger_config": challenger_cfg,
        "champion_hits": champion_hits,
        "challenger_hits": challenger_hits,
        "delta_hits": delta_hits,
        "delta_pct": delta_pct,
        "captured_historical_sars": captured_historical_sars,
        "missed_historical_sars": missed_historical_sars,
        "avoided_false_positives": avoided_false_positives,
        "sample_newly_triggered": newly_triggered,
        "sample_suppressed": suppressed,
    }


async def backtest_rule_config(
    tenant_id: str,
    rule_name: str,
    candidate_config: Dict[str, Any],
    lookback_days: int = 30,
    sample_limit: int = 2000,
) -> Dict[str, Any]:
    """
    Executes read-only Champion vs. Challenger replay across historical tenant
    transactions to measure volume delta and precision impact before rule promotion.
    """
    norm_rule = rule_name.upper().strip()
    lookback_days = max(1, min(int(lookback_days), 180))
    sample_limit = max(10, min(int(sample_limit), 5000))
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

    default_rules = get_rules_config().get("rules", {})
    champion_cfg: Dict[str, Any] = dict(default_rules.get(norm_rule, {"enabled": True}))

    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        row_cfg = await conn.fetchrow(
            "SELECT enabled, config FROM rule_configs WHERE rule_name = $1;",
            norm_rule,
        )
        if row_cfg:
            raw_c = row_cfg["config"]
            parsed_c = raw_c if isinstance(raw_c, dict) else json.loads(raw_c or "{}")
            champion_cfg.update(parsed_c)
            champion_cfg["enabled"] = bool(row_cfg["enabled"])

        tx_rows = await conn.fetch(
            """
            SELECT t.id,
                   t.sender_account_id,
                   t.amount,
                   COALESCE(t.amount_base_usd, t.amount) AS amount_base_usd,
                   t.currency,
                   t.country,
                   t.channel,
                   t.timestamp,
                   a.status AS historical_alert_status
            FROM transactions t
            LEFT JOIN LATERAL (
                SELECT status
                FROM alerts
                WHERE transaction_id = t.id
                ORDER BY created_at DESC
                LIMIT 1
            ) a ON TRUE
            WHERE t.timestamp >= $1
            ORDER BY t.timestamp ASC
            LIMIT $2;
            """,
            cutoff,
            sample_limit,
        )

    challenger_cfg = dict(champion_cfg)
    challenger_cfg.update(candidate_config or {})
    tx_list = [dict(r) for r in (tx_rows or [])]

    return await run_analytics_compute(
        _run_backtest_replay_sync,
        norm_rule,
        lookback_days,
        champion_cfg,
        challenger_cfg,
        tx_list,
        timeout=15.0,
    )


async def evaluate_shadow_rules(
    conn: Any,
    tenant_id: str | uuid.UUID,
    transaction_id: str | uuid.UUID,
    sender_account_id: str | uuid.UUID | None,
    amount_base_usd: float | Decimal,
    country: Optional[str] = None,
    channel: Optional[str] = None,
) -> List[str]:
    """
    Evaluates tenant rules in `SHADOW` mode (or with a non-null `shadow_config`)
    and writes matches into `rule_shadow_hits` without emitting live analyst alerts.
    """
    matched_shadow_rules: List[str] = []
    try:
        rows = await conn.fetch(
            """
            SELECT rule_name, version, mode, config, shadow_config
            FROM rule_configs
            WHERE mode = 'SHADOW' OR shadow_config IS NOT NULL;
            """
        )
        if not rows:
            return []

        amt_dec = _dec(amount_base_usd, "0")
        tx_row = {
            "amount_base_usd": amt_dec,
            "country": country,
            "channel": channel,
        }
        tenant_uuid = uuid.UUID(str(tenant_id))
        tx_uuid = uuid.UUID(str(transaction_id))
        sender_uuid = uuid.UUID(str(sender_account_id)) if sender_account_id else None

        hit_rule_names: list[str] = []
        hit_rule_versions: list[int] = []
        hit_reasons: list[str] = []

        for r in rows:
            raw_cfg = r["shadow_config"] if r["shadow_config"] is not None else r["config"]
            cfg = raw_cfg if isinstance(raw_cfg, dict) else json.loads(raw_cfg or "{}")
            cfg["enabled"] = True
            hit, reason = evaluate_rule_on_tx_row(r["rule_name"], cfg, tx_row)
            if hit:
                matched_shadow_rules.append(r["rule_name"])
                hit_rule_names.append(str(r["rule_name"]))
                hit_rule_versions.append(int(r["version"] or 1))
                hit_reasons.append(str(reason))

        if hit_rule_names:
            await conn.execute(
                """
                INSERT INTO rule_shadow_hits (
                    tenant_id, rule_name, transaction_id, sender_account_id,
                    amount_base_usd, rule_version, matched_reason
                )
                SELECT $1, v.rule_name, $2, $3, $4, v.rule_version, v.matched_reason
                FROM unnest($5::text[], $6::integer[], $7::text[])
                     AS v(rule_name, rule_version, matched_reason);
                """,
                tenant_uuid,
                tx_uuid,
                sender_uuid,
                amt_dec,
                hit_rule_names,
                hit_rule_versions,
                hit_reasons,
            )
    except Exception as exc:
        logger.debug("Shadow rule evaluation skipped: %s", exc)

    return matched_shadow_rules
