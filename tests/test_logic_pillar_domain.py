"""
Pure Functional Domain Core Test Suite (Workstream 6)
=====================================================
Zero DB, zero Redis, zero HTTP, zero network mocks — executes in milliseconds.
Verifies strict architectural purity (`domain/` has zero framework/I/O imports),
exact ISO-4217 Decimal arithmetic, deterministic AML rules, CTR/Travel Rule
statutory boundaries, and all 5 compliance finite state machines.
"""

from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_EVEN, ROUND_HALF_UP
from pathlib import Path

import pytest

from domain.money import (
    InvalidMoneyError,
    Money,
    convert_money,
    get_currency_exponent,
    invert_fx_rate,
    parse_decimal_amount,
    quantize_amount,
    to_decimal,
)
from domain.rules_core import (
    AccountRuleSnapshot,
    TransactionInput,
    classify_transaction_decision,
    compute_ruleset_hash,
    evaluate_all_rules_pure,
    evaluate_ctr_and_structuring_pure,
    evaluate_travel_rule_pure,
)
from domain.state_machine import (
    AlertStatus,
    CTRFilingStatus,
    CaseStatus,
    CorruptedDomainStateError,
    DomainStateTransitionError,
    RFIStatus,
    SARDraftStatus,
    validate_alert_transition_pure,
    validate_case_transition_pure,
    validate_ctr_transition_pure,
    validate_rfi_transition_pure,
    validate_sar_draft_transition_pure,
)

ROOT = Path(__file__).resolve().parent.parent


# ── 1. Architectural Purity Guard ─────────────────────────────────────────────

def test_domain_package_has_zero_framework_or_io_imports():
    """Functional Core invariant: `domain/*.py` must never import FastAPI, DB, Redis, or HTTP libraries."""
    forbidden = {
        "fastapi",
        "starlette",
        "asyncpg",
        "redis",
        "httpx",
        "sqlalchemy",
        "aiokafka",
        "neo4j",
        "elasticsearch",
        "database",
        "config",
        "routers",
    }
    domain_files = sorted((ROOT / "domain").glob("*.py"))
    assert domain_files, "Expected pure domain modules under domain/"

    violations: list[tuple[str, str]] = []
    for path in domain_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in forbidden:
                        violations.append((path.name, alias.name))
            elif isinstance(node, ast.ImportFrom) and node.module:
                top = node.module.split(".")[0]
                if top in forbidden:
                    violations.append((path.name, node.module))

    assert not violations, f"Forbidden I/O or framework imports in domain/: {violations}"


# ── 2. Exact Decimal & ISO 4217 Money Precision ───────────────────────────────

def test_decimal_money_eliminates_ieee754_float_drift():
    m1 = Money.of("0.10", "USD")
    m2 = Money.of("0.20", "USD")
    total = m1 + m2
    assert total.amount == Decimal("0.30")
    assert total.to_minor_units() == 30
    assert Money.from_minor_units(30, "USD") == total

    with pytest.raises(InvalidMoneyError):
        _ = Money.of("100.00", "USD") + Money.of("100.00", "EUR")


def test_iso4217_currency_exponents_and_minor_units():
    assert get_currency_exponent("JPY") == 0
    assert get_currency_exponent("KRW") == 0
    assert get_currency_exponent("USD") == 2
    assert get_currency_exponent("EUR") == 2
    assert get_currency_exponent("KWD") == 3
    assert get_currency_exponent("BHD") == 3

    assert Money.of("15000", "JPY").to_minor_units() == 15000
    assert Money.from_minor_units(10125, "KWD").amount == Decimal("10.125")
    assert quantize_amount("10.1256", "KWD", rounding=ROUND_HALF_EVEN) == Decimal("10.126")
    assert quantize_amount("15000.6", "JPY", rounding=ROUND_HALF_EVEN) == Decimal("15001")


def test_hybrid_rounding_policy_bankers_vs_regulatory_half_up():
    # Banker's rounding (ROUND_HALF_EVEN) for accounting/ledger neutrality
    assert quantize_amount("100.005", "USD", rounding=ROUND_HALF_EVEN) == Decimal("100.00")
    assert quantize_amount("100.015", "USD", rounding=ROUND_HALF_EVEN) == Decimal("100.02")

    # Conservative regulatory rounding (ROUND_HALF_UP) never understates thresholds
    assert quantize_amount("100.005", "USD", rounding=ROUND_HALF_UP) == Decimal("100.01")
    assert quantize_amount("9999.995", "USD", rounding=ROUND_HALF_UP) == Decimal("10000.00")
    assert quantize_amount("9999.994", "USD", rounding=ROUND_HALF_UP) == Decimal("9999.99")


def test_money_rejects_nan_inf_bool_negative_and_excess_scale():
    for bad in [float("nan"), float("inf"), float("-inf"), True, False, None, "", "-10.00", "0", "10.12345"]:
        with pytest.raises(InvalidMoneyError):
            parse_decimal_amount(bad, allow_zero=False)

    assert parse_decimal_amount("10.125", currency="KWD") == Decimal("10.125")
    assert parse_decimal_amount("9999.9999") == Decimal("9999.9999")
    assert invert_fx_rate("0.92592593") == Decimal("1.08000000")

    now = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
    fx = convert_money("1000.00", "EUR", "1.08", base_currency="USD", source="ECB_LIVE", quoted_at=now)
    assert fx.amount_base == Decimal("1080.00")
    assert fx.source == "ECB_LIVE"
    assert fx.quoted_at == now


# ── 3. Pure AML Rules, CTR, Travel Rule & Determinism ─────────────────────────

def test_ctr_and_structuring_exact_decimal_statutory_boundaries():
    # Non-cash wire does not trigger CTR even above $10k
    wire = evaluate_ctr_and_structuring_pure(Decimal("25000.00"), "WIRE", None)
    assert wire.is_cash_channel is False
    assert wire.requires_ctr_filing is False

    # Exact $9,999.99 single cash deposit -> no CTR, no structuring without prior cash
    just_under = evaluate_ctr_and_structuring_pure(Decimal("9999.99"), "CASH", None)
    assert just_under.requires_ctr_filing is False
    assert just_under.structuring_detected is False

    # $9,999.995 rounds conservatively UP to $10,000.00 -> requires CTR
    half_cent_boundary = evaluate_ctr_and_structuring_pure(Decimal("9999.995"), "CASH", None)
    assert half_cent_boundary.requires_ctr_filing is True

    # Two sub-threshold cash deposits ($5,000 + $4,600 = $9,600 >= $9,500) -> structuring detected
    smurf = evaluate_ctr_and_structuring_pure(
        Decimal("4600.00"), "CASH", None, prior_24h_cash_usd=Decimal("5000.00"), prior_24h_cash_count=1
    )
    assert smurf.requires_ctr_filing is False
    assert smurf.structuring_detected is True

    # Aggregate cash crossing $10,000 ($6,000 + $4,000 = $10,000) -> CTR + structuring
    agg_ctr = evaluate_ctr_and_structuring_pure(
        Decimal("4000.00"), "CASH", None, prior_24h_cash_usd=Decimal("6000.00"), prior_24h_cash_count=1
    )
    assert agg_ctr.requires_ctr_filing is True
    assert agg_ctr.structuring_detected is True


def test_travel_rule_exact_thresholds_usd_and_eur():
    incomplete = {"name": "Alice"}
    complete_orig = {"name": "Alice Smith", "account_number": "ACC-1", "address": "123 Main"}
    complete_bene = {"name": "Bob Jones", "account_number": "ACC-2"}

    ok_low_eur, _ = evaluate_travel_rule_pure("999.99", "EUR", "SEPA", incomplete, {})
    assert ok_low_eur is True

    ok_high_eur, missing_eur = evaluate_travel_rule_pure("1000.00", "EUR", "SEPA", incomplete, {})
    assert ok_high_eur is False
    assert "originator_account_number" in missing_eur

    ok_high_usd, missing_usd = evaluate_travel_rule_pure(
        "3000.00", "USD", "WIRE", complete_orig, complete_bene, amount_usd="3000.00"
    )
    assert ok_high_usd is True
    assert missing_usd == []


def test_evaluate_all_rules_pure_deterministic_replay_and_fail_closed_sanctions():
    eval_ts = datetime(2026, 5, 10, 14, 30, tzinfo=timezone.utc)
    cfg = {
        "rules": {
            "LARGE_TRANSACTION": {"enabled": True, "threshold": 10000.0},
            "STRUCTURING_SMURFING": {"enabled": True, "threshold": 10000.0, "window_hours": 24},
            "VELOCITY_MONITORING": {"enabled": True, "history_days": 30, "deviation_threshold": 3.0},
            "RAPID_MOVEMENT_FUNDS": {"enabled": True, "window_minutes": 10, "amount_ratio_threshold": 0.90},
            "DORMANT_ACCOUNT": {"enabled": True, "dormant_period_days": 90, "activation_threshold": 50000.0},
            "GEOGRAPHIC_SANCTIONS": {"enabled": True, "high_risk_countries": ["RU", "IR"]},
            "ROUND_TRIP_DETECTION": {"enabled": True, "window_hours": 72},
            "NEWLY_INCORPORATED_HIGH_VALUE": {"enabled": True, "account_age_days": 90, "high_value_threshold": 50000.0},
            "TRADE_BASED_ML_OVER_UNDER_INVOICING": {"enabled": True, "unit_price_variance_threshold_pct": 35.0, "invoice_amount_threshold": 100000.0},
            "CRYPTO_FIAT_VASP_STRUCTURING": {"enabled": True, "travel_rule_threshold": 1000.0},
            "STRUCTURING_EXTENDED_7D": {"enabled": True, "min_sub_amount": 2500.0, "threshold": 10000.0, "min_count": 3},
            "CONDUIT_RAPID_PASSTHROUGH": {"enabled": True, "min_inflow": 5000.0, "min_ratio": 0.85, "max_ratio": 1.15},
            "AMOUNT_ANOMALY_HEURISTICS": {"enabled": True, "just_below_min": 9000.0, "just_below_max": 10000.0, "round_number_min": 3000.0, "round_divisor": 1000.0},
        }
    }

    tx = TransactionInput(
        amount_original=Decimal("60000.00"),
        currency="USD",
        amount_base_usd=Decimal("60000.00"),
        fx_rate_applied=Decimal("1"),
        sender_id="s1",
        receiver_id="r1",
        tx_timestamp=eval_ts,
        evaluated_at=eval_ts,
        sender_bic="SBER" + "RU" + "MM",
        metadata={
            "goods_category": "PRECIOUS_METALS",
            "unit_price_variance_pct": 45.0,
            "is_vasp_transfer": True,
            "travel_rule_complete": False,
        },
    )
    snap = AccountRuleSnapshot(
        velocity_avg_count=Decimal("1"),
        velocity_std_count=Decimal("1"),
        velocity_avg_amount_usd=Decimal("500"),
        velocity_std_amount_usd=Decimal("100"),
        today_count=5,
        today_amount_usd=Decimal("10000"),
        last_incoming_amount_usd=Decimal("60000"),
        last_incoming_at=eval_ts - timedelta(minutes=5),
        last_outgoing_at=eval_ts - timedelta(days=120),
        has_reverse_tx=True,
        account_created_at=eval_ts - timedelta(days=15),
        conduit_inflow_24h_usd=Decimal("60000"),
        conduit_outflow_24h_usd=Decimal("0"),
        sanctions_degraded=True,
    )

    p1 = evaluate_all_rules_pure(tx, snap, cfg, fail_closed_sanctions=True)
    p2 = evaluate_all_rules_pure(tx, snap, cfg, fail_closed_sanctions=True)
    assert p1 == p2
    assert p1.ruleset_hash == compute_ruleset_hash(cfg)
    assert p1.evaluated_at == eval_ts
    assert "LARGE_TRANSACTION_THRESHOLD" in p1.triggered_rules
    assert "VELOCITY_MONITORING_SPIKE" in p1.triggered_rules
    assert "RAPID_MOVEMENT_FUNDS" in p1.triggered_rules
    assert "DORMANT_ACCOUNT_ACTIVATION" in p1.triggered_rules
    assert "GEOGRAPHIC_RISK" in p1.triggered_rules
    assert "SANCTIONS_SCREENING_UNAVAILABLE" in p1.triggered_rules
    assert "ROUND_TRIP_DETECTION" in p1.triggered_rules
    assert "NEWLY_INCORPORATED_HIGH_VALUE" in p1.triggered_rules
    assert "CONDUIT_RAPID_PASSTHROUGH" in p1.triggered_rules
    assert "TRADE_BASED_ML_OVER_UNDER_INVOICING" in p1.triggered_rules
    assert "CRYPTO_FIAT_VASP_STRUCTURING" in p1.triggered_rules
    assert "ROUND_NUMBER_ANOMALY_1K" in p1.triggered_rules
    assert "GEOGRAPHIC_SANCTIONS" in p1.degraded_rules

    # Fail-closed SANCTIONS_SCREENING_UNAVAILABLE triggers hard HOLD
    cls = classify_transaction_decision(0.40, p1.triggered_rules)
    assert cls.decision == "HELD"
    assert cls.tx_status == "HELD"
    assert cls.is_hard_hold is True


# ── 4. All 5 Pure Compliance Finite State Machines ────────────────────────────

def test_all_five_compliance_state_machines():
    # Alert & Case
    assert validate_alert_transition_pure("OPEN", "IN_REVIEW") == AlertStatus.IN_REVIEW
    assert validate_case_transition_pure("OPEN", "INVESTIGATING") == CaseStatus.INVESTIGATING

    # SAR Draft
    assert validate_sar_draft_transition_pure("DRAFT", "PENDING_MLRO_REVIEW") == SARDraftStatus.PENDING_MLRO_REVIEW
    assert validate_sar_draft_transition_pure("PENDING_MLRO_REVIEW", "APPROVED", allow_noop=False) == SARDraftStatus.APPROVED
    assert validate_sar_draft_transition_pure("APPROVED", "FILED") == SARDraftStatus.FILED
    with pytest.raises(DomainStateTransitionError):
        validate_sar_draft_transition_pure("APPROVED", "APPROVED", allow_noop=False)
    with pytest.raises(DomainStateTransitionError):
        validate_sar_draft_transition_pure("FILED", "DRAFT")

    # CTR Filing (prevents duplicate tracking ID overwrites)
    assert validate_ctr_transition_pure("PENDING", "FILED") == CTRFilingStatus.FILED
    with pytest.raises(DomainStateTransitionError):
        validate_ctr_transition_pure("FILED", "FILED")
    with pytest.raises(DomainStateTransitionError):
        validate_ctr_transition_pure("EXEMPT", "FILED")

    # RFI
    assert validate_rfi_transition_pure("OPEN", "SUBMITTED") == RFIStatus.SUBMITTED
    with pytest.raises(DomainStateTransitionError):
        validate_rfi_transition_pure("CANCELLED", "SUBMITTED")

    # Corrupted persisted state fails closed with CorruptedDomainStateError
    with pytest.raises(CorruptedDomainStateError):
        validate_ctr_transition_pure("UNKNOWN_LEGACY", "FILED")
