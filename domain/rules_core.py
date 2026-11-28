"""
Pure Functional AML Rule, CTR, Travel Rule & Decision Core
==========================================================
Zero-I/O, deterministic calculation engine (Functional Core).
Every function accepts explicit immutable inputs, exact `Decimal` amounts,
and an injected UTC `evaluated_at` clock so compliance outcomes are 100%
reproducible for regulatory audits and SR 11-7 backtesting.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP, localcontext
from typing import Any, Mapping, Sequence

from domain.money import normalize_currency, quantize_amount, to_decimal

logger = logging.getLogger(__name__)

# Statutory FinCEN BSA / EU TFR thresholds (exact fixed-point Decimal)
CTR_REPORTING_THRESHOLD_USD = Decimal("10000.00")
CTR_STRUCTURING_LOW_USD = Decimal("9000.00")
CTR_STRUCTURING_AGG_USD = Decimal("9500.00")
TRAVEL_RULE_THRESHOLD_USD = Decimal("3000.00")
TRAVEL_RULE_THRESHOLD_EUR = Decimal("1000.00")

DEFAULT_HARD_HOLD_TRIGGERS: frozenset[str] = frozenset({
    "SANCTIONS_HIT",
    "ACCOUNT_FROZEN",
    "OFAC_SANCTIONS_MATCH",
    "SANCTIONS_SCREENING_UNAVAILABLE",
    "FX_RATE_UNAVAILABLE",
})


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _amount_dec(val: Any, field: str = "amount") -> Decimal:
    """Strict fail-closed monetary parser: rejects None, NaN, ±Inf, negative, and garbage."""
    return to_decimal(val, allow_negative=False, field_name=field)


def _cfg_dec(val: Any, default: str = "0") -> Decimal:
    """Permissive parser strictly for optional rule-configuration numbers (logs warning on malformed config)."""
    if val is None:
        return Decimal(default)
    try:
        return to_decimal(val)
    except Exception:
        logger.warning("Malformed numeric rule config value %r; falling back to default %s", val, default)
        return Decimal(default)


# Backward-compatible alias for optional config fields
_dec = _cfg_dec


def _coerce_bool(val: Any, default: bool = True) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    s = str(val).strip().lower()
    if s in ("true", "1", "yes", "y", "on"):
        return True
    if s in ("false", "0", "no", "n", "off", ""):
        return False
    return default


def _coerce_int(val: Any, default: int = 0) -> int:
    if val is None or isinstance(val, bool):
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def compute_ruleset_hash(config: Mapping[str, Any]) -> str:
    """Computes a canonical SHA-256 fingerprint of the active rules configuration."""
    canonical = json.dumps(config or {}, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class TransactionInput:
    amount_original: Decimal
    currency: str
    amount_base_usd: Decimal
    fx_rate_applied: Decimal
    sender_id: str
    receiver_id: str
    tx_timestamp: datetime
    evaluated_at: datetime
    sender_name: str | None = None
    receiver_name: str | None = None
    sender_bic: str | None = None
    receiver_bic: str | None = None
    country: str | None = None
    channel: str | None = None
    merchant: str | None = None
    kyc_risk_tier: str = "STANDARD"
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AccountRuleSnapshot:
    """Point-in-time read-only behavioral & ledger facts loaded by the Imperative Shell."""

    velocity_avg_count: Decimal = Decimal("0")
    velocity_std_count: Decimal = Decimal("0")
    velocity_avg_amount_usd: Decimal = Decimal("0")
    velocity_std_amount_usd: Decimal = Decimal("0")
    today_count: int = 0
    today_amount_usd: Decimal = Decimal("0")
    last_incoming_amount_usd: Decimal | None = None
    last_incoming_at: datetime | None = None
    last_outgoing_at: datetime | None = None
    has_reverse_tx: bool = False
    account_created_at: datetime | None = None
    sub_7d_count: int = 0
    sub_7d_amount_usd: Decimal = Decimal("0")
    conduit_inflow_24h_usd: Decimal = Decimal("0")
    conduit_outflow_24h_usd: Decimal = Decimal("0")
    structuring_24h_account_amounts: tuple[Decimal, ...] = ()
    structuring_24h_entity_amounts: tuple[Decimal, ...] = ()
    prior_24h_cash_usd: Decimal = Decimal("0")
    prior_24h_cash_count: int = 0
    sanctions_hit: bool = False
    sanctions_degraded: bool = False
    geo_whitelisted: bool = False
    degraded_rules: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleProvenance:
    """Immutable audit record capturing exact rule evaluation provenance."""

    ruleset_hash: str
    evaluated_at: datetime
    triggered_rules: tuple[str, ...]
    degraded_rules: tuple[str, ...]
    tier_discount: Decimal


@dataclass(frozen=True, slots=True)
class CTRDecision:
    """Pure BSA 31 CFR 1010.311 / 1010.313 CTR and cash structuring outcome."""

    is_cash_channel: bool
    requires_ctr_filing: bool
    structuring_detected: bool
    tx_amount_usd: Decimal
    prior_24h_cash_usd: Decimal
    total_aggregate_cash_usd: Decimal
    prior_24h_cash_count: int


@dataclass(frozen=True, slots=True)
class DecisionClassification:
    """Authoritative compliance hold, alert, and threat-level determination."""

    decision: str       # HELD | APPROVED
    tx_status: str      # HELD | COMPLETED
    alert_triggered: bool
    threat_level: str   # NONE | MEDIUM | HIGH | CRITICAL
    is_hard_hold: bool


def is_high_risk_geo_bic(
    sender_bic: str | None,
    receiver_bic: str | None,
    high_risk_countries: Sequence[str] = ("RU", "IR", "KP", "SY"),
) -> bool:
    high_risk_set = {str(c).upper() for c in high_risk_countries}
    for bic in (sender_bic, receiver_bic):
        if bic and len(bic) >= 6 and bic[4:6].upper() in high_risk_set:
            return True
    return False


def is_vasp_transaction(meta: Mapping[str, Any], sender_bic: str | None, receiver_bic: str | None) -> bool:
    if meta.get("is_vasp_transfer"):
        return True
    if str(meta.get("counterparty_type", "")).upper() == "VASP":
        return True
    for bic in (sender_bic, receiver_bic):
        if bic and "VASP" in bic.upper():
            return True
    return False


def check_large_transaction_pure(config: Mapping[str, Any], amount_usd: Decimal) -> list[str]:
    cfg = config.get("rules", {}).get("LARGE_TRANSACTION", {})
    if not cfg.get("enabled", True):
        return []
    threshold = _dec(cfg.get("threshold", "10000.00"), "10000.00")
    # Conservative regulatory rounding (ROUND_HALF_UP) on reporting threshold boundary
    amt_checked = quantize_amount(amount_usd, "USD", rounding=ROUND_HALF_UP)
    if amt_checked >= threshold:
        return ["LARGE_TRANSACTION_THRESHOLD"]
    return []


def check_structuring_smurfing_pure(
    config: Mapping[str, Any],
    amount_usd: Decimal,
    account_prior_amounts: Sequence[Decimal],
    entity_prior_amounts: Sequence[Decimal],
) -> tuple[list[str], Decimal, list[Decimal]]:
    cfg = config.get("rules", {}).get("STRUCTURING_SMURFING", {})
    threshold = _cfg_dec(cfg.get("threshold", "10000.00"), "10000.00")
    min_tx_count = max(1, _coerce_int(cfg.get("min_tx_count", 2), 2))
    amt_checked = quantize_amount(_amount_dec(amount_usd, "amount_usd"), "USD", rounding=ROUND_HALF_UP)

    def _quantize_prior_list(items: Sequence[Decimal]) -> list[Decimal]:
        out: list[Decimal] = []
        for a in items:
            try:
                q = quantize_amount(_amount_dec(a, "prior_amount_usd"), "USD", rounding=ROUND_HALF_UP)
                if Decimal("0") < q < threshold:
                    out.append(q)
            except Exception:
                continue
        return out

    entity_below = ([amt_checked] if Decimal("0") < amt_checked < threshold else []) + _quantize_prior_list(entity_prior_amounts)
    total_entity = sum(entity_below, Decimal("0"))

    if not cfg.get("enabled", True):
        return [], total_entity, entity_below

    account_below = ([amt_checked] if Decimal("0") < amt_checked < threshold else []) + _quantize_prior_list(account_prior_amounts)
    total_account = sum(account_below, Decimal("0"))

    triggered: list[str] = []
    # Structuring only triggers on sub-threshold transactions (0 < tx < threshold);
    # transparent above-threshold transfers are captured by LARGE_TRANSACTION_THRESHOLD / CTR.
    if Decimal("0") < amt_checked < threshold:
        if (total_entity >= threshold and len(entity_below) >= min_tx_count) or (
            total_account >= threshold and len(account_below) >= min_tx_count
        ):
            triggered.append("STRUCTURING_VELOCITY_24H")

    return triggered, total_entity, entity_below


def check_velocity_monitoring_pure(
    config: Mapping[str, Any],
    amount_usd: Decimal,
    snap: AccountRuleSnapshot,
) -> list[str]:
    cfg = config.get("rules", {}).get("VELOCITY_MONITORING", {})
    if not cfg.get("enabled", True):
        return []
    if snap.velocity_avg_count <= Decimal("0"):
        return []

    dev_threshold = _dec(cfg.get("deviation_threshold", "3.0"), "3.0")
    today_count = Decimal(snap.today_count + 1)
    today_amount = snap.today_amount_usd + amount_usd

    std_count = max(snap.velocity_std_count, Decimal("1.0"))
    min_std_amount = max(snap.velocity_avg_amount_usd * Decimal("0.10"), Decimal("1.0"))
    std_amount = max(snap.velocity_std_amount_usd, min_std_amount)

    count_z = (today_count - snap.velocity_avg_count) / std_count
    amount_z = (today_amount - snap.velocity_avg_amount_usd) / std_amount

    if count_z > dev_threshold or amount_z > dev_threshold:
        return ["VELOCITY_MONITORING_SPIKE"]
    return []


def check_rapid_movement_pure(
    config: Mapping[str, Any],
    amount_usd: Decimal,
    tx_timestamp: datetime,
    snap: AccountRuleSnapshot,
) -> list[str]:
    cfg = config.get("rules", {}).get("RAPID_MOVEMENT_FUNDS", {})
    if not cfg.get("enabled", True):
        return []
    if (
        snap.last_incoming_amount_usd is None
        or snap.last_incoming_at is None
        or snap.last_incoming_amount_usd <= Decimal("0")
        or amount_usd <= Decimal("0")
    ):
        return []

    window_minutes = _coerce_int(cfg.get("window_minutes", 10), 10)
    ratio_thresh = _cfg_dec(cfg.get("amount_ratio_threshold", "0.90"), "0.90")
    tx_utc = _ensure_utc(tx_timestamp)
    inc_utc = _ensure_utc(snap.last_incoming_at)
    elapsed_seconds = Decimal(str((tx_utc - inc_utc).total_seconds()))

    if Decimal("0") <= elapsed_seconds <= Decimal(window_minutes * 60):
        if amount_usd >= snap.last_incoming_amount_usd * ratio_thresh:
            return ["RAPID_MOVEMENT_FUNDS"]
    return []


def check_dormant_account_pure(
    config: Mapping[str, Any],
    amount_usd: Decimal,
    tx_timestamp: datetime,
    snap: AccountRuleSnapshot,
) -> list[str]:
    cfg = config.get("rules", {}).get("DORMANT_ACCOUNT", {})
    if not cfg.get("enabled", True) or snap.last_outgoing_at is None:
        return []

    dormant_days = int(cfg.get("dormant_period_days", 90))
    activation_threshold = _dec(cfg.get("activation_threshold", "50000.00"), "50000.00")
    inactivity_days = (_ensure_utc(tx_timestamp) - _ensure_utc(snap.last_outgoing_at)).days

    if inactivity_days >= dormant_days and amount_usd > activation_threshold:
        return ["DORMANT_ACCOUNT_ACTIVATION"]
    return []


def check_geographic_sanctions_pure(
    config: Mapping[str, Any],
    tx: TransactionInput,
    snap: AccountRuleSnapshot,
    *,
    fail_closed_sanctions: bool = False,
) -> list[str]:
    cfg = config.get("rules", {}).get("GEOGRAPHIC_SANCTIONS", {})
    if not cfg.get("enabled", True):
        return []

    triggered: list[str] = []
    high_risk = cfg.get("high_risk_countries", ["RU", "IR", "KP", "SY"])
    if is_high_risk_geo_bic(tx.sender_bic, tx.receiver_bic, high_risk) and not snap.geo_whitelisted:
        triggered.append("GEOGRAPHIC_RISK")

    if snap.sanctions_hit:
        triggered.append("SANCTIONS_HIT")
    elif snap.sanctions_degraded and fail_closed_sanctions:
        triggered.append("SANCTIONS_SCREENING_UNAVAILABLE")

    return triggered


def check_round_trip_pure(config: Mapping[str, Any], snap: AccountRuleSnapshot) -> list[str]:
    cfg = config.get("rules", {}).get("ROUND_TRIP_DETECTION", {})
    if not cfg.get("enabled", True):
        return []
    return ["ROUND_TRIP_DETECTION"] if snap.has_reverse_tx else []


def check_newly_incorporated_pure(
    config: Mapping[str, Any],
    amount_usd: Decimal,
    tx_timestamp: datetime,
    snap: AccountRuleSnapshot,
) -> list[str]:
    cfg = config.get("rules", {}).get("NEWLY_INCORPORATED_HIGH_VALUE", {})
    if not cfg.get("enabled", True) or snap.account_created_at is None:
        return []
    threshold = _cfg_dec(cfg.get("high_value_threshold", "50000.00"), "50000.00")
    if amount_usd < threshold:
        return []
    account_age_days = max(0, _coerce_int(cfg.get("account_age_days", cfg.get("newly_incorporated_days", 90)), 90))
    age_seconds = (_ensure_utc(tx_timestamp) - _ensure_utc(snap.account_created_at)).total_seconds()
    if 0.0 <= age_seconds <= float(account_age_days * 86400):
        return ["NEWLY_INCORPORATED_HIGH_VALUE"]
    return []


def check_tbml_pure(config: Mapping[str, Any], amount_usd: Decimal, meta: Mapping[str, Any]) -> list[str]:
    cfg = config.get("rules", {}).get("TRADE_BASED_ML_OVER_UNDER_INVOICING", {})
    if not cfg.get("enabled", True):
        return []
    var_thresh = _cfg_dec(cfg.get("unit_price_variance_threshold_pct", "35.0"), "35.0")
    inv_thresh = _cfg_dec(cfg.get("invoice_amount_threshold", "100000.0"), "100000.0")
    high_risk_goods = {
        str(g).upper()
        for g in cfg.get(
            "high_risk_goods",
            ["PRECIOUS_METALS", "ELECTRONICS", "PETROLEUM", "PHARMACEUTICALS", "LUXURY_GOODS"],
        )
    }

    declared_goods = str(meta.get("goods_category", "")).upper()
    unit_price_variance = _cfg_dec(meta.get("unit_price_variance_pct", "0"), "0")
    invoice_val = _cfg_dec(meta.get("invoice_amount", "0"), "0")

    is_high_risk = declared_goods in high_risk_goods
    # Both over-invoicing (+%) and under-invoicing (-%) violate TBML controls
    has_price_var = abs(unit_price_variance) >= var_thresh
    has_inv_disc = invoice_val >= inv_thresh and (
        abs(amount_usd - invoice_val) / max(invoice_val, Decimal("1")) >= Decimal("0.20")
    )

    if is_high_risk and (has_price_var or has_inv_disc):
        return ["TRADE_BASED_ML_OVER_UNDER_INVOICING"]
    return []


def check_vasp_crypto_pure(
    config: Mapping[str, Any],
    amount_usd: Decimal,
    sender_bic: str | None,
    receiver_bic: str | None,
    meta: Mapping[str, Any],
) -> list[str]:
    cfg = config.get("rules", {}).get("CRYPTO_FIAT_VASP_STRUCTURING", {})
    if not cfg.get("enabled", True):
        return []
    if not is_vasp_transaction(meta, sender_bic, receiver_bic):
        return []

    travel_thresh = _cfg_dec(cfg.get("travel_rule_threshold", "1000.00"), "1000.00")
    travel_complete = _coerce_bool(meta.get("travel_rule_complete"), default=True)
    if amount_usd >= travel_thresh and not travel_complete:
        return ["CRYPTO_FIAT_VASP_STRUCTURING"]

    rapid_count = _coerce_int(meta.get("rapid_conversion_count"), default=0)
    max_conversions = max(1, _coerce_int(cfg.get("max_consecutive_conversions", 3), 3))
    if rapid_count >= max_conversions:
        return ["CRYPTO_FIAT_VASP_STRUCTURING"]
    return []


def check_structuring_extended_7d_pure(
    config: Mapping[str, Any],
    amount_usd: Decimal,
    tier_discount: Decimal,
    snap: AccountRuleSnapshot,
) -> list[str]:
    cfg = config.get("rules", {}).get("STRUCTURING_EXTENDED_7D", {})
    if not cfg.get("enabled", True):
        return []
    min_sub = _dec(cfg.get("min_sub_amount", "2500.00"), "2500.00") * tier_discount
    target_thresh = _dec(cfg.get("threshold", "10000.00"), "10000.00") * tier_discount
    min_count = int(cfg.get("min_count", 3))

    if min_sub <= amount_usd < target_thresh:
        if (snap.sub_7d_count + 1) >= min_count and (snap.sub_7d_amount_usd + amount_usd) >= target_thresh:
            return ["STRUCTURING_EXTENDED_7D"]
    return []


def check_conduit_passthrough_pure(
    config: Mapping[str, Any],
    amount_usd: Decimal,
    tier_discount: Decimal,
    snap: AccountRuleSnapshot,
) -> list[str]:
    cfg = config.get("rules", {}).get("CONDUIT_RAPID_PASSTHROUGH", {})
    if not cfg.get("enabled", True):
        return []
    min_inflow = _dec(cfg.get("min_inflow", "5000.00"), "5000.00") * tier_discount
    min_ratio = _dec(cfg.get("min_ratio", "0.85"), "0.85")
    max_ratio = _dec(cfg.get("max_ratio", "1.15"), "1.15")

    if snap.conduit_inflow_24h_usd > Decimal("0") and snap.conduit_inflow_24h_usd >= min_inflow:
        total_out = snap.conduit_outflow_24h_usd + amount_usd
        ratio = total_out / snap.conduit_inflow_24h_usd
        if min_ratio <= ratio <= max_ratio:
            return ["CONDUIT_RAPID_PASSTHROUGH"]
    return []


def check_amount_anomaly_pure(
    config: Mapping[str, Any],
    amount_usd: Decimal,
    total_entity_amount: Decimal,
    entity_below: Sequence[Decimal],
) -> list[str]:
    cfg = config.get("rules", {}).get("AMOUNT_ANOMALY_HEURISTICS", {})
    if not cfg.get("enabled", True):
        return []

    triggered: list[str] = []
    jb_min = _cfg_dec(cfg.get("just_below_min", "9000.00"), "9000.00")
    jb_max = _cfg_dec(cfg.get("just_below_max", "10000.00"), "10000.00")
    rnd_min = _cfg_dec(cfg.get("round_number_min", "3000.00"), "3000.00")
    divisor = max(_cfg_dec(cfg.get("round_divisor", "1000.00"), "1000.00"), Decimal("1"))

    amt_checked = quantize_amount(_amount_dec(amount_usd, "amount_usd"), "USD", rounding=ROUND_HALF_UP)

    is_just_below = jb_min <= amt_checked < jb_max
    if (
        not is_just_below
        and amt_checked >= Decimal("500.00")
        and (jb_min <= total_entity_amount < jb_max)
        and len(entity_below) >= 2
    ):
        is_just_below = True

    if is_just_below:
        triggered.append("JUST_BELOW_CTR_THRESHOLD")

    with localcontext() as ctx:
        ctx.prec = 60
        is_round_div = amt_checked >= rnd_min and (amt_checked % divisor == Decimal("0"))
    if is_round_div:
        triggered.append("ROUND_NUMBER_ANOMALY_1K")

    return triggered


def evaluate_all_rules_pure(
    tx: TransactionInput,
    snap: AccountRuleSnapshot,
    config: Mapping[str, Any],
    *,
    fail_closed_sanctions: bool = False,
) -> RuleProvenance:
    """Executes all 13 AML rules purely from immutable inputs + snapshot + injected clock."""
    triggered: list[str] = []
    kyc_tier = str(tx.kyc_risk_tier or tx.metadata.get("kyc_risk_tier", "STANDARD")).upper()
    tier_discount = Decimal("0.50") if kyc_tier in ("HIGH", "CRITICAL") else Decimal("1.00")

    triggered.extend(check_large_transaction_pure(config, tx.amount_base_usd))

    struct_rules, total_entity_amt, entity_below = check_structuring_smurfing_pure(
        config,
        tx.amount_base_usd,
        snap.structuring_24h_account_amounts,
        snap.structuring_24h_entity_amounts,
    )
    triggered.extend(struct_rules)

    triggered.extend(check_velocity_monitoring_pure(config, tx.amount_base_usd, snap))
    triggered.extend(check_rapid_movement_pure(config, tx.amount_base_usd, tx.tx_timestamp, snap))
    triggered.extend(check_dormant_account_pure(config, tx.amount_base_usd, tx.tx_timestamp, snap))
    triggered.extend(
        check_geographic_sanctions_pure(
            config, tx, snap, fail_closed_sanctions=fail_closed_sanctions
        )
    )
    triggered.extend(check_round_trip_pure(config, snap))
    triggered.extend(check_newly_incorporated_pure(config, tx.amount_base_usd, tx.tx_timestamp, snap))
    triggered.extend(check_structuring_extended_7d_pure(config, tx.amount_base_usd, tier_discount, snap))
    triggered.extend(check_conduit_passthrough_pure(config, tx.amount_base_usd, tier_discount, snap))
    triggered.extend(check_tbml_pure(config, tx.amount_base_usd, tx.metadata))
    triggered.extend(check_vasp_crypto_pure(config, tx.amount_base_usd, tx.sender_bic, tx.receiver_bic, tx.metadata))
    triggered.extend(check_amount_anomaly_pure(config, tx.amount_base_usd, total_entity_amt, entity_below))

    degraded = list(snap.degraded_rules)
    if snap.sanctions_degraded and "GEOGRAPHIC_SANCTIONS" not in degraded:
        degraded.append("GEOGRAPHIC_SANCTIONS")

    return RuleProvenance(
        ruleset_hash=compute_ruleset_hash(config),
        evaluated_at=_ensure_utc(tx.evaluated_at),
        triggered_rules=tuple(triggered),
        degraded_rules=tuple(degraded),
        tier_discount=tier_discount,
    )


def evaluate_ctr_and_structuring_pure(
    amount_base_usd: Decimal | str | int | float,
    channel: str | None,
    merchant: str | None,
    prior_24h_cash_usd: Decimal | str | int | float = Decimal("0"),
    prior_24h_cash_count: int = 0,
    *,
    prior_24h_sub_threshold_cash_usd: Decimal | str | int | float | None = None,
    prior_24h_sub_threshold_cash_count: int | None = None,
) -> CTRDecision:
    """
    Pure BSA 31 CFR 1010.311 (CTR >= $10,000) & 31 CFR 1010.313 (structuring) evaluation
    using exact Decimal arithmetic with conservative ROUND_HALF_UP threshold rounding.
    Fails closed (raises InvalidMoneyError) on NaN, ±Inf, negative, or non-numeric amounts.
    """
    is_cash = bool(
        (channel and channel.strip().upper() == "CASH")
        or (merchant and merchant.strip().upper() == "CASH")
    )
    tx_usd = quantize_amount(_amount_dec(amount_base_usd, "amount_base_usd"), "USD", rounding=ROUND_HALF_UP)
    prior_usd = quantize_amount(_amount_dec(prior_24h_cash_usd, "prior_24h_cash_usd"), "USD", rounding=ROUND_HALF_UP)
    total_agg = tx_usd + prior_usd
    prior_count = max(0, _coerce_int(prior_24h_cash_count, 0))

    if not is_cash:
        return CTRDecision(
            is_cash_channel=False,
            requires_ctr_filing=False,
            structuring_detected=False,
            tx_amount_usd=tx_usd,
            prior_24h_cash_usd=prior_usd,
            total_aggregate_cash_usd=total_agg,
            prior_24h_cash_count=prior_count,
        )

    prior_sub_usd = (
        quantize_amount(
            _amount_dec(prior_24h_sub_threshold_cash_usd, "prior_24h_sub_threshold_cash_usd"),
            "USD",
            rounding=ROUND_HALF_UP,
        )
        if prior_24h_sub_threshold_cash_usd is not None
        else prior_usd
    )
    prior_sub_count = (
        max(0, _coerce_int(prior_24h_sub_threshold_cash_count, 0))
        if prior_24h_sub_threshold_cash_count is not None
        else prior_count
    )

    requires_ctr = tx_usd > Decimal("0") and (
        tx_usd >= CTR_REPORTING_THRESHOLD_USD or total_agg >= CTR_REPORTING_THRESHOLD_USD
    )
    # 31 CFR 1010.313 structuring requires the current cash leg to be strictly below $10,000;
    # transparent >= $10,000 cash transactions are CTR-reportable, not structuring.
    is_below_ctr = Decimal("0") < tx_usd < CTR_REPORTING_THRESHOLD_USD
    is_just_below = CTR_STRUCTURING_LOW_USD <= tx_usd < CTR_REPORTING_THRESHOLD_USD
    structuring = bool(
        is_below_ctr
        and (
            (is_just_below and (prior_sub_usd > Decimal("0") or prior_sub_count >= 1))
            or (prior_sub_count >= 1 and (tx_usd + prior_sub_usd) >= CTR_STRUCTURING_AGG_USD)
        )
    )

    return CTRDecision(
        is_cash_channel=True,
        requires_ctr_filing=requires_ctr,
        structuring_detected=structuring,
        tx_amount_usd=tx_usd,
        prior_24h_cash_usd=prior_usd,
        total_aggregate_cash_usd=total_agg,
        prior_24h_cash_count=prior_count,
    )


def evaluate_travel_rule_pure(
    amount: Decimal | str | int | float,
    currency: str,
    channel: str | None,
    originator_info: Mapping[str, Any],
    beneficiary_info: Mapping[str, Any],
    amount_usd: Decimal | str | int | float | None = None,
) -> tuple[bool, list[str]]:
    """
    Pure FATF Recommendation 16 / FinCEN ($3,000) & EU TFR (€1,000) Travel Rule verifier.
    Fails closed on invalid monetary values and fails conservatively when non-USD/EUR
    transfers omit `amount_usd`.
    """
    is_wire = bool(channel and channel.strip().upper() in {"WIRE", "SWIFT", "ACH", "CROSS_BORDER", "SEPA"})
    if not is_wire:
        return True, []

    curr = normalize_currency(currency)
    amt_orig = _amount_dec(amount, "amount")
    if curr == "EUR":
        amt_eur = quantize_amount(amt_orig, "EUR", rounding=ROUND_HALF_UP)
        if amt_eur < TRAVEL_RULE_THRESHOLD_EUR:
            return True, []
    elif curr == "USD":
        amt_usd_checked = quantize_amount(
            _amount_dec(amount_usd, "amount_usd") if amount_usd is not None else amt_orig,
            "USD",
            rounding=ROUND_HALF_UP,
        )
        if amt_usd_checked < TRAVEL_RULE_THRESHOLD_USD:
            return True, []
    elif amount_usd is not None:
        amt_usd_checked = quantize_amount(_amount_dec(amount_usd, "amount_usd"), "USD", rounding=ROUND_HALF_UP)
        if amt_usd_checked < TRAVEL_RULE_THRESHOLD_USD:
            return True, []
    # Else: non-USD/EUR wire without FX-converted `amount_usd` -> fail conservative and require Travel Rule fields

    missing: list[str] = []
    if not originator_info.get("name") or len(str(originator_info["name"]).strip()) < 2:
        missing.append("originator_name")
    if not originator_info.get("account_number"):
        missing.append("originator_account_number")
    if not (
        originator_info.get("address")
        or originator_info.get("date_of_birth")
        or originator_info.get("tax_id")
    ):
        missing.append("originator_address_or_identifier")

    if not beneficiary_info.get("name") or len(str(beneficiary_info["name"]).strip()) < 2:
        missing.append("beneficiary_name")
    if not beneficiary_info.get("account_number"):
        missing.append("beneficiary_account_number")

    return len(missing) == 0, missing


def classify_transaction_decision(
    dynamic_score: Decimal | float,
    triggered_rules: Sequence[str],
    *,
    hard_hold_triggers: frozenset[str] = DEFAULT_HARD_HOLD_TRIGGERS,
) -> DecisionClassification:
    """Single authoritative hold, alert, and threat-level classifier shared by sync & async paths."""
    score = _amount_dec(dynamic_score, "dynamic_score")
    is_hard_hold = any(r in hard_hold_triggers for r in triggered_rules)
    alert_triggered = score >= Decimal("0.75") or len(triggered_rules) > 0
    decision = "HELD" if is_hard_hold else "APPROVED"
    tx_status = "HELD" if is_hard_hold else "COMPLETED"

    if not alert_triggered:
        threat_level = "NONE"
    elif score >= Decimal("0.90"):
        threat_level = "CRITICAL"
    elif score >= Decimal("0.75"):
        threat_level = "HIGH"
    else:
        threat_level = "MEDIUM"

    return DecisionClassification(
        decision=decision,
        tx_status=tx_status,
        alert_triggered=alert_triggered,
        threat_level=threat_level,
        is_hard_hold=is_hard_hold,
    )
