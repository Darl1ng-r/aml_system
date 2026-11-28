"""
Rule Backtesting, Shadow-Mode Evaluation & SR 11-7 Champion/Challenger Engine
==============================================================================
1. **Champion vs. Challenger Backtesting:** Replays candidate rule configurations
   against the most recent historical tenant transactions (with a 7-day sliding-window
   warm-up prefix to prevent cold-start bias) by delegating directly to the pure domain
   evaluators in `domain/rules_core.py` (100% production math parity).
2. **Shadow Mode Evaluation:** Evaluates rules in `SHADOW` mode (or with non-null
   `shadow_config`) during live ingestion, loading live 24h/7d sub-threshold aggregates
   only when a structuring shadow rule is active, and writing telemetry to `rule_shadow_hits`.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Deque, Dict, List, Optional, Tuple

from database.postgres import get_async_db_read_conn
from domain.money import quantize_amount, to_decimal
from domain.rules_core import (
    AccountRuleSnapshot,
    check_amount_anomaly_pure,
    check_large_transaction_pure,
    check_structuring_extended_7d_pure,
    check_structuring_smurfing_pure,
    check_tbml_pure,
    is_vasp_transaction,
)
from services.compute_executor import run_analytics_compute
from services.rules import get_rules_config

logger = logging.getLogger("aml.rule_backtest")

_UNSUPPORTED_SNAPSHOT_RULES: frozenset[str] = frozenset({
    "DORMANT_ACCOUNT",
    "NEWLY_INCORPORATED_HIGH_VALUE",
    "RAPID_MOVEMENT_FUNDS",
    "VELOCITY_MONITORING",
    "ROUND_TRIP_DETECTION",
    "CONDUIT_RAPID_PASSTHROUGH",
})

_STRUCTURING_RULES: frozenset[str] = frozenset({
    "STRUCTURING_SMURFING",
    "STRUCTURING_EXTENDED_7D",
    "AMOUNT_ANOMALY_HEURISTICS",
})


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
    sender_24h_sum: Decimal | float = Decimal("0"),
    sender_7d_sub_count: int = 0,
    sender_7d_sub_sum: Decimal | float = Decimal("0"),
    *,
    sender_24h_count: int | None = None,
    sender_24h_prior_amounts: Optional[List[Decimal]] = None,
) -> Tuple[bool, str]:
    """
    Pure single-rule evaluator delegating to `domain/rules_core.py` for 100% math
    parity (exact Decimal ROUND_HALF_UP thresholds, min_tx_count, abs() TBML variance).
    Rules requiring account lifecycle snapshots (`DORMANT_ACCOUNT`, etc.) explicitly
    report `UNSUPPORTED_IN_BACKTEST` instead of fabricating amount-only approximations.
    """
    if cfg.get("enabled") is False:
        return False, ""

    raw_base = tx.get("amount_base_usd")
    raw_amt = raw_base if raw_base is not None else tx.get("amount")
    amount_raw = _dec(raw_amt, "0")
    if amount_raw < Decimal("0"):
        return False, ""
    amount = quantize_amount(amount_raw, "USD", rounding=ROUND_HALF_UP)

    sum_24h = _dec(sender_24h_sum, "0")
    sum_7d = _dec(sender_7d_sub_sum, "0")
    country = str(tx.get("country") or "").upper().strip()
    channel = str(tx.get("channel") or "").upper().strip()
    rname = rule_name.upper().strip()
    wrapped_cfg = {"rules": {rname: {**cfg, "enabled": True}}}

    if rname == "LARGE_TRANSACTION":
        hits = check_large_transaction_pure(wrapped_cfg, amount_raw)
        if hits:
            threshold = _dec(cfg.get("threshold", "10000.00"), "10000.00")
            return True, f"amount_usd={amount:.2f} >= threshold={threshold:.2f}"
        return False, ""

    if rname == "STRUCTURING_SMURFING":
        threshold = _dec(cfg.get("threshold", "10000.00"), "10000.00")
        min_tx_count = max(1, int(cfg.get("min_tx_count", 2)))
        if sender_24h_prior_amounts is not None:
            priors = list(sender_24h_prior_amounts)
            hits, total_ent, ent_below = check_structuring_smurfing_pure(
                wrapped_cfg, amount_raw, priors, priors
            )
            if hits:
                return True, f"24h_sum={total_ent:.2f} >= threshold={threshold:.2f} count={len(ent_below)} >= {min_tx_count}"
            return False, ""

        # Aggregate-only call path (when caller supplies rolling sum + count)
        effective_count = (
            int(sender_24h_count)
            if sender_24h_count is not None
            else (2 if sum_24h > amount else 1)
        )
        if Decimal("0") < amount < threshold and sum_24h >= threshold and effective_count >= min_tx_count:
            return True, f"24h_sum={sum_24h:.2f} >= threshold={threshold:.2f} count={effective_count} >= {min_tx_count}"
        return False, ""

    if rname == "STRUCTURING_EXTENDED_7D":
        # Note: sender_7d_sub_count & sender_7d_sub_sum may already include the current tx when called from replay
        prior_count = max(0, int(sender_7d_sub_count) - 1) if sender_7d_sub_count > 0 else 0
        prior_sum = max(Decimal("0"), sum_7d - amount) if sum_7d >= amount else sum_7d
        snap = AccountRuleSnapshot(sub_7d_count=prior_count, sub_7d_amount_usd=prior_sum)
        hits = check_structuring_extended_7d_pure(wrapped_cfg, amount, Decimal("1.00"), snap)
        if hits:
            return True, f"7d_sub_count={prior_count + 1} sum={(prior_sum + amount):.2f}"
        return False, ""

    if rname == "AMOUNT_ANOMALY_HEURISTICS":
        priors = list(sender_24h_prior_amounts or [])
        threshold_ref = _dec(cfg.get("just_below_max", "10000.00"), "10000.00")
        ent_below = ([amount] if Decimal("0") < amount < threshold_ref else []) + [
            p for p in priors if Decimal("0") < p < threshold_ref
        ]
        total_ent = sum(ent_below, Decimal("0"))
        hits = check_amount_anomaly_pure(wrapped_cfg, amount_raw, total_ent, ent_below)
        if hits:
            return True, f"amount_anomaly={','.join(hits)} amount={amount:.2f}"
        return False, ""

    if rname == "GEOGRAPHIC_SANCTIONS":
        high_risk = {str(c).upper() for c in cfg.get("high_risk_countries", ["RU", "IR", "KP", "SY"])}
        if country and country in high_risk:
            return True, f"high_risk_country={country}"
        return False, ""

    if rname == "CRYPTO_FIAT_VASP_STRUCTURING":
        threshold = _dec(cfg.get("travel_rule_threshold", "1000.00"), "1000.00")
        meta = tx.get("metadata") if isinstance(tx.get("metadata"), dict) else {}
        is_vasp = channel in ("CRYPTO", "VASP", "DIGITAL_ASSET") or is_vasp_transaction(meta, None, None)
        if is_vasp and amount >= threshold:
            return True, f"vasp_channel={channel or 'VASP'} amount={amount:.2f} >= {threshold:.2f}"
        return False, ""

    if rname == "TRADE_BASED_ML_OVER_UNDER_INVOICING":
        meta = tx.get("metadata") if isinstance(tx.get("metadata"), dict) else {}
        if not meta:
            return False, "UNSUPPORTED_IN_BACKTEST: requires trade invoice metadata"
        hits = check_tbml_pure(wrapped_cfg, amount, meta)
        if hits:
            return True, f"tbml_hit goods={meta.get('goods_category')} amount={amount:.2f}"
        return False, ""

    if rname in _UNSUPPORTED_SNAPSHOT_RULES:
        return False, f"UNSUPPORTED_IN_BACKTEST: {rname} requires historical account lifecycle snapshot"

    if "threshold" in cfg:
        threshold = _dec(cfg["threshold"], "0")
        if amount >= threshold:
            return True, f"amount={amount:.2f} >= threshold={threshold:.2f}"
    return False, ""


class _SlidingDecimalWindow:
    """O(1)-amortized sliding time window maintaining exact Decimal running sum & entries."""

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

    def prior_amounts(self) -> List[Decimal]:
        return [amt for _, amt in self._entries]


def _compute_classification_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, Any]:
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else None
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else None
    f1 = (
        round((2.0 * precision * recall) / (precision + recall), 4)
        if (precision is not None and recall is not None and (precision + recall) > 0)
        else None
    )
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _run_backtest_replay_sync(
    norm_rule: str,
    lookback_days: int,
    champion_cfg: Dict[str, Any],
    challenger_cfg: Dict[str, Any],
    tx_list: List[Dict[str, Any]],
    *,
    eval_start: Optional[datetime] = None,
) -> Dict[str, Any]:
    """O(N) pure-CPU Champion vs Challenger replay with configurable windows, warm-up & F1 metrics."""
    champ_thresh = _dec(champion_cfg.get("threshold", "10000.00"), "10000.00")
    chall_thresh = _dec(challenger_cfg.get("threshold", "10000.00"), "10000.00")
    champ_min_sub = _dec(champion_cfg.get("min_sub_amount", "2500.00"), "2500.00")
    chall_min_sub = _dec(challenger_cfg.get("min_sub_amount", "2500.00"), "2500.00")

    champ_win_h = max(1, int(champion_cfg.get("window_hours", 24)))
    chall_win_h = max(1, int(challenger_cfg.get("window_hours", 24)))
    champ_win_d = max(1, int(champion_cfg.get("window_days", 7)))
    chall_win_d = max(1, int(challenger_cfg.get("window_days", 7)))

    champ_24h_windows: Dict[str, _SlidingDecimalWindow] = defaultdict(
        lambda: _SlidingDecimalWindow(timedelta(hours=champ_win_h))
    )
    chall_24h_windows: Dict[str, _SlidingDecimalWindow] = defaultdict(
        lambda: _SlidingDecimalWindow(timedelta(hours=chall_win_h))
    )
    champ_7d_windows: Dict[str, _SlidingDecimalWindow] = defaultdict(
        lambda: _SlidingDecimalWindow(timedelta(days=champ_win_d))
    )
    chall_7d_windows: Dict[str, _SlidingDecimalWindow] = defaultdict(
        lambda: _SlidingDecimalWindow(timedelta(days=chall_win_d))
    )

    champion_hits = 0
    challenger_hits = 0
    evaluated_count = 0
    warmup_count = 0
    newly_triggered: List[Dict[str, Any]] = []
    suppressed: List[Dict[str, Any]] = []
    captured_historical_sars = 0
    missed_historical_sars = 0
    avoided_false_positives = 0

    champ_tp = champ_fp = champ_tn = champ_fn = 0
    chall_tp = chall_fp = chall_tn = chall_fn = 0

    coverage = "UNSUPPORTED_REQUIRES_SNAPSHOT" if norm_rule in _UNSUPPORTED_SNAPSHOT_RULES else "FULL"

    for tx in tx_list:
        sender_key = str(tx.get("sender_account_id") or "")
        ts = tx.get("timestamp") or datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        raw_base = tx.get("amount_base_usd")
        amt_raw = _dec(raw_base if raw_base is not None else tx.get("amount"), "0")
        amt = quantize_amount(amt_raw, "USD", rounding=ROUND_HALF_UP) if amt_raw >= Decimal("0") else Decimal("0")

        c24 = champ_24h_windows[sender_key]
        x24 = chall_24h_windows[sender_key]
        c7 = champ_7d_windows[sender_key]
        x7 = chall_7d_windows[sender_key]

        c24.evict_before(ts)
        x24.evict_before(ts)
        c7.evict_before(ts)
        x7.evict_before(ts)

        # Snapshot prior amounts BEFORE adding current tx so rules_core pure functions receive priors cleanly
        c24_priors = c24.prior_amounts()
        x24_priors = x24.prior_amounts()

        if Decimal("0") < amt < champ_thresh:
            c24.add(ts, amt)
        if Decimal("0") < amt < chall_thresh:
            x24.add(ts, amt)
        if champ_min_sub <= amt < champ_thresh:
            c7.add(ts, amt)
        if chall_min_sub <= amt < chall_thresh:
            x7.add(ts, amt)

        # Warm-up prefix populates rolling windows without scoring
        if eval_start is not None and ts < eval_start:
            warmup_count += 1
            continue

        evaluated_count += 1
        champ_hit, _ = evaluate_rule_on_tx_row(
            norm_rule,
            champion_cfg,
            tx,
            c24.total,
            c7.count,
            c7.total,
            sender_24h_count=c24.count,
            sender_24h_prior_amounts=c24_priors,
        )
        chall_hit, chall_reason = evaluate_rule_on_tx_row(
            norm_rule,
            challenger_cfg,
            tx,
            x24.total,
            x7.count,
            x7.total,
            sender_24h_count=x24.count,
            sender_24h_prior_amounts=x24_priors,
        )

        if champ_hit:
            champion_hits += 1
        if chall_hit:
            challenger_hits += 1

        hist_status = (tx.get("historical_alert_status") or "").upper()
        if hist_status == "CLOSED_SAR":
            if champ_hit:
                champ_tp += 1
            else:
                champ_fn += 1
            if chall_hit:
                chall_tp += 1
                captured_historical_sars += 1
            else:
                chall_fn += 1
                if champ_hit:
                    missed_historical_sars += 1
        elif hist_status == "CLOSED_FALSE_POSITIVE":
            if champ_hit:
                champ_fp += 1
            else:
                champ_tn += 1
            if chall_hit:
                chall_fp += 1
            else:
                chall_tn += 1
                if champ_hit:
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
    delta_pct = (
        round((delta_hits / champion_hits) * 100.0, 2)
        if champion_hits > 0
        else (100.0 if challenger_hits > 0 else 0.0)
    )

    return {
        "rule_name": norm_rule,
        "coverage": coverage,
        "lookback_days": lookback_days,
        "transactions_evaluated": evaluated_count,
        "warmup_transactions_loaded": warmup_count,
        "champion_config": champion_cfg,
        "challenger_config": challenger_cfg,
        "champion_hits": champion_hits,
        "challenger_hits": challenger_hits,
        "delta_hits": delta_hits,
        "delta_pct": delta_pct,
        "captured_historical_sars": captured_historical_sars,
        "missed_historical_sars": missed_historical_sars,
        "avoided_false_positives": avoided_false_positives,
        "champion_metrics": _compute_classification_metrics(champ_tp, champ_fp, champ_tn, champ_fn),
        "challenger_metrics": _compute_classification_metrics(chall_tp, chall_fp, chall_tn, chall_fn),
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
    Executes read-only Champion vs. Challenger replay across the most recent historical
    tenant transactions (plus 7-day warm-up prefix) to measure precision, recall, F1,
    and alert volume impact prior to rule promotion.
    """
    norm_rule = rule_name.upper().strip()
    lookback_days = max(1, min(int(lookback_days), 180))
    sample_limit = max(10, min(int(sample_limit), 5000))

    now_utc = datetime.now(timezone.utc)
    eval_start = now_utc - timedelta(days=lookback_days)
    warmup_cutoff = eval_start - timedelta(days=7)

    default_rules = get_rules_config().get("rules", {})
    champion_cfg: Dict[str, Any] = dict(default_rules.get(norm_rule, {"enabled": True}))

    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        row_cfg = await conn.fetchrow(
            "SELECT enabled, mode, config FROM rule_configs WHERE rule_name = $1;",
            norm_rule,
        )
        if row_cfg:
            raw_c = row_cfg["config"]
            parsed_c = raw_c if isinstance(raw_c, dict) else json.loads(raw_c or "{}")
            champion_cfg.update(parsed_c)
            mode = str(row_cfg.get("mode") or "ACTIVE").upper() if hasattr(row_cfg, "get") else str(row_cfg["mode"] or "ACTIVE").upper()
            # Shadow-only rules are NOT live champions (matches services/rules.py:102)
            champion_cfg["enabled"] = bool(row_cfg["enabled"]) and (mode == "ACTIVE")

        # Select MOST RECENT N rows (ORDER BY timestamp DESC) then reverse chronologically
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
              AND t.status NOT IN ('FAILED', 'CANCELLED', 'REJECTED')
            ORDER BY t.timestamp DESC
            LIMIT $2;
            """,
            warmup_cutoff,
            sample_limit,
        )

    challenger_cfg = dict(champion_cfg)
    challenger_cfg.update(candidate_config or {})

    # Reverse into chronological ascending order for O(N) sliding-window replay
    tx_list = list(reversed([dict(r) for r in (tx_rows or [])]))

    return await run_analytics_compute(
        _run_backtest_replay_sync,
        norm_rule,
        lookback_days,
        champion_cfg,
        challenger_cfg,
        tx_list,
        eval_start=eval_start,
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
    Loads live 24h & 7d sub-threshold aggregates in ONE query ONLY when a structuring
    shadow rule is present.
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

        # Only fetch rolling structuring aggregates if a structuring shadow rule exists
        needs_structuring = any(
            str(r["rule_name"] or "").upper().strip() in _STRUCTURING_RULES for r in rows
        )
        sum_24h = amt_dec
        cnt_24h = 1
        sum_7d = amt_dec
        cnt_7d = 1
        if needs_structuring and sender_uuid is not None:
            try:
                agg_row = await conn.fetchrow(
                    """
                    SELECT
                        COALESCE(SUM(COALESCE(amount_base_usd, amount)) FILTER (
                            WHERE timestamp >= NOW() - INTERVAL '24 hours'
                              AND COALESCE(amount_base_usd, amount) < 10000
                        ), 0) AS prior_24h_sum,
                        COUNT(*) FILTER (
                            WHERE timestamp >= NOW() - INTERVAL '24 hours'
                              AND COALESCE(amount_base_usd, amount) < 10000
                        ) AS prior_24h_count,
                        COALESCE(SUM(COALESCE(amount_base_usd, amount)) FILTER (
                            WHERE COALESCE(amount_base_usd, amount) >= 2500
                              AND COALESCE(amount_base_usd, amount) < 10000
                        ), 0) AS prior_7d_sum,
                        COUNT(*) FILTER (
                            WHERE COALESCE(amount_base_usd, amount) >= 2500
                              AND COALESCE(amount_base_usd, amount) < 10000
                        ) AS prior_7d_count
                    FROM transactions
                    WHERE sender_account_id = $1
                      AND id != $2
                      AND timestamp >= NOW() - INTERVAL '7 days'
                      AND status NOT IN ('FAILED', 'CANCELLED', 'REJECTED');
                    """,
                    sender_uuid,
                    tx_uuid,
                )
                if agg_row:
                    sum_24h = _dec(agg_row["prior_24h_sum"], "0") + (amt_dec if amt_dec < Decimal("10000") else Decimal("0"))
                    cnt_24h = int(agg_row["prior_24h_count"] or 0) + (1 if Decimal("0") < amt_dec < Decimal("10000") else 0)
                    sum_7d = _dec(agg_row["prior_7d_sum"], "0") + (amt_dec if Decimal("2500") <= amt_dec < Decimal("10000") else Decimal("0"))
                    cnt_7d = int(agg_row["prior_7d_count"] or 0) + (1 if Decimal("2500") <= amt_dec < Decimal("10000") else 0)
            except Exception as agg_err:
                logger.debug("Shadow structuring aggregate query bypassed: %s", agg_err)

        hit_rule_names: list[str] = []
        hit_rule_versions: list[int] = []
        hit_reasons: list[str] = []

        for r in rows:
            raw_cfg = r["shadow_config"] if r["shadow_config"] is not None else r["config"]
            cfg = raw_cfg if isinstance(raw_cfg, dict) else json.loads(raw_cfg or "{}")
            cfg["enabled"] = True
            hit, reason = evaluate_rule_on_tx_row(
                r["rule_name"],
                cfg,
                tx_row,
                sender_24h_sum=sum_24h,
                sender_7d_sub_count=cnt_7d,
                sender_7d_sub_sum=sum_7d,
                sender_24h_count=cnt_24h,
            )
            if hit:
                matched_shadow_rules.append(r["rule_name"])
                hit_rule_names.append(str(r["rule_name"]))
                hit_rule_versions.append(int(r.get("version") or 1) if hasattr(r, "get") else int(r["version"] or 1))
                hit_reasons.append(str(reason))

        if hit_rule_names:
            await conn.execute(
                """
                INSERT INTO rule_shadow_hits (
                    tenant_id, transaction_id, sender_account_id,
                    rule_name, rule_version, amount_base_usd, match_reason
                )
                SELECT $1, $2, $3, v.rule_name, v.rule_version, $4, v.match_reason
                FROM unnest($5::text[], $6::int[], $7::text[])
                     AS v(rule_name, rule_version, match_reason)
                ON CONFLICT DO NOTHING;
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
        logger.warning("Shadow-mode rule evaluation bypassed: %s", exc)

    return matched_shadow_rules
