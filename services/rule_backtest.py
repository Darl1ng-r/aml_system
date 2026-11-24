"""
Historical Rule Backtesting & Champion-Challenger Shadow Mode Service (P1-2)
=============================================================================
1. Read-Only Backtesting: Replays proposed rule thresholds against historical
   transactions on the read replica to quantify projected alert deltas, true-positive
   SAR capture, and avoided false positives BEFORE saving rule changes.
2. Shadow Challenger Evaluation: Silently evaluates rules configured in `SHADOW`
   mode (or with `shadow_config`) on live transactions and persists hits to
   `rule_shadow_hits` without alerting analysts.
"""

import json
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from database.postgres import get_async_db_read_conn
from services.rules import get_rules_config

logger = logging.getLogger("aml.rule_backtest")


def evaluate_rule_on_tx_row(
    rule_name: str,
    cfg: Dict[str, Any],
    tx: Dict[str, Any],
    sender_24h_sum: float = 0.0,
    sender_7d_sub_count: int = 0,
    sender_7d_sub_sum: float = 0.0,
) -> Tuple[bool, str]:
    """
    Pure, deterministic rule evaluator over a historical/live transaction row
    using FX-normalized `amount_base_usd`.
    """
    if cfg.get("enabled") is False:
        return False, ""

    raw_base = tx.get("amount_base_usd")
    amount = float(raw_base if raw_base is not None else (tx.get("amount") if tx.get("amount") is not None else 0.0))
    country = str(tx.get("country") or "").upper().strip()
    channel = str(tx.get("channel") or "").upper().strip()
    rname = rule_name.upper().strip()

    if rname == "LARGE_TRANSACTION":
        threshold = float(cfg.get("threshold", 10000.0))
        if amount >= threshold:
            return True, f"amount_usd={amount:.2f} >= threshold={threshold:.2f}"
        return False, ""

    if rname == "STRUCTURING_SMURFING":
        threshold = float(cfg.get("threshold", 10000.0))
        if amount < threshold and (sender_24h_sum >= threshold):
            return True, f"24h_sum={sender_24h_sum:.2f} >= threshold={threshold:.2f} with sub-threshold tx={amount:.2f}"
        return False, ""

    if rname == "STRUCTURING_EXTENDED_7D":
        threshold = float(cfg.get("threshold", 10000.0))
        min_sub = float(cfg.get("min_sub_amount", 2500.0))
        min_count = int(cfg.get("min_count", 3))
        if min_sub <= amount < threshold and sender_7d_sub_count >= min_count and sender_7d_sub_sum >= threshold:
            return True, f"7d_sub_count={sender_7d_sub_count} sum={sender_7d_sub_sum:.2f}"
        return False, ""

    if rname == "AMOUNT_ANOMALY_HEURISTICS":
        jb_min = float(cfg.get("just_below_min", 9000.0))
        jb_max = float(cfg.get("just_below_max", 10000.0))
        rnd_min = float(cfg.get("round_number_min", 3000.0))
        divisor = max(1.0, float(cfg.get("round_divisor", 1000.0)))
        if jb_min <= amount < jb_max:
            return True, f"just_below_threshold amount={amount:.2f} in [{jb_min:.0f}, {jb_max:.0f})"
        if amount >= rnd_min and (int(round(amount * 100)) % int(round(divisor * 100)) == 0):
            return True, f"round_number amount={amount:.2f} divisible by {divisor:.0f}"
        return False, ""

    if rname == "GEOGRAPHIC_SANCTIONS":
        high_risk = {str(c).upper() for c in cfg.get("high_risk_countries", ["RU", "IR", "KP", "SY"])}
        if country and country in high_risk:
            return True, f"high_risk_country={country}"
        return False, ""

    if rname == "CRYPTO_FIAT_VASP_STRUCTURING":
        threshold = float(cfg.get("travel_rule_threshold", 1000.0))
        if channel in ("CRYPTO", "VASP", "DIGITAL_ASSET") and amount >= threshold:
            return True, f"vasp_channel={channel} amount={amount:.2f} >= {threshold:.2f}"
        return False, ""

    if rname == "NEWLY_INCORPORATED_HIGH_VALUE":
        threshold = float(cfg.get("high_value_threshold", 50000.0))
        if amount >= threshold:
            return True, f"high_value={amount:.2f} >= {threshold:.2f}"
        return False, ""

    if rname == "DORMANT_ACCOUNT":
        threshold = float(cfg.get("activation_threshold", 50000.0))
        if amount >= threshold:
            return True, f"activation_amount={amount:.2f} >= {threshold:.2f}"
        return False, ""

    if rname == "TRADE_BASED_ML_OVER_UNDER_INVOICING":
        threshold = float(cfg.get("invoice_amount_threshold", 100000.0))
        if amount >= threshold:
            return True, f"invoice_amount={amount:.2f} >= {threshold:.2f}"
        return False, ""

    # Generic fallback for custom threshold-based rules
    if "threshold" in cfg:
        threshold = float(cfg["threshold"])
        if amount >= threshold:
            return True, f"amount={amount:.2f} >= threshold={threshold:.2f}"
    return False, ""


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

    # Pre-compute lightweight per-sender rolling sums for structuring rules
    tx_list = [dict(r) for r in (tx_rows or [])]
    sender_history: Dict[str, List[Tuple[datetime, float]]] = defaultdict(list)

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
        amt = float(raw_base if raw_base is not None else (tx.get("amount") if tx.get("amount") is not None else 0.0))

        hist = sender_history[sender_key]
        hist.append((ts, amt))

        cutoff_24h = ts - timedelta(hours=24)
        cutoff_7d = ts - timedelta(days=7)

        # Compute independent Champion vs Challenger sub-threshold windows so Challenger
        # thresholds never contaminate the Champion baseline metrics.
        champ_thresh = float(champion_cfg.get("threshold", 10000.0))
        chall_thresh = float(challenger_cfg.get("threshold", 10000.0))
        champ_sum_24h = sum(a for t0, a in hist if t0 >= cutoff_24h and a < champ_thresh)
        chall_sum_24h = sum(a for t0, a in hist if t0 >= cutoff_24h and a < chall_thresh)

        champ_min_sub = float(champion_cfg.get("min_sub_amount", 2500.0))
        chall_min_sub = float(challenger_cfg.get("min_sub_amount", 2500.0))
        champ_sub_7d = [a for t0, a in hist if t0 >= cutoff_7d and champ_min_sub <= a < champ_thresh]
        chall_sub_7d = [a for t0, a in hist if t0 >= cutoff_7d and chall_min_sub <= a < chall_thresh]

        champ_hit, _ = evaluate_rule_on_tx_row(
            norm_rule, champion_cfg, tx, champ_sum_24h, len(champ_sub_7d), sum(champ_sub_7d)
        )
        chall_hit, chall_reason = evaluate_rule_on_tx_row(
            norm_rule, challenger_cfg, tx, chall_sum_24h, len(chall_sub_7d), sum(chall_sub_7d)
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
                "amount_base_usd": amt,
                "currency": tx.get("currency") or "USD",
                "reason": chall_reason,
                "timestamp": ts.isoformat(),
            })
        elif champ_hit and not chall_hit and len(suppressed) < 10:
            suppressed.append({
                "transaction_id": str(tx["id"]),
                "amount_base_usd": amt,
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


async def evaluate_shadow_rules(
    conn: Any,
    tenant_id: str | uuid.UUID,
    transaction_id: str | uuid.UUID,
    sender_account_id: str | uuid.UUID | None,
    amount_base_usd: float,
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

        tx_row = {
            "amount_base_usd": float(amount_base_usd),
            "country": country,
            "channel": channel,
        }
        tenant_uuid = uuid.UUID(str(tenant_id))
        tx_uuid = uuid.UUID(str(transaction_id))
        sender_uuid = uuid.UUID(str(sender_account_id)) if sender_account_id else None

        for r in rows:
            raw_cfg = r["shadow_config"] if r["shadow_config"] is not None else r["config"]
            cfg = raw_cfg if isinstance(raw_cfg, dict) else json.loads(raw_cfg or "{}")
            cfg["enabled"] = True
            hit, reason = evaluate_rule_on_tx_row(r["rule_name"], cfg, tx_row)
            if hit:
                matched_shadow_rules.append(r["rule_name"])
                await conn.execute(
                    """
                    INSERT INTO rule_shadow_hits (
                        tenant_id, rule_name, transaction_id, sender_account_id,
                        amount_base_usd, rule_version, matched_reason
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7);
                    """,
                    tenant_uuid,
                    r["rule_name"],
                    tx_uuid,
                    sender_uuid,
                    round(float(amount_base_usd), 2),
                    int(r["version"] or 1),
                    reason,
                )
    except Exception as exc:
        logger.debug(f"Shadow rule evaluation skipped: {exc}")

    return matched_shadow_rules
