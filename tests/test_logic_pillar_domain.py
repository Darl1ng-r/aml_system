"""
Pure Functional Domain Core Test Suite (Workstream 6 — 100% Mock-Free Coverage)
===============================================================================
Zero DB, zero Redis, zero HTTP, zero network mocks — executes in milliseconds.
Verifies strict architectural purity (`domain/` has zero framework/I/O imports)
and achieves 100% statement coverage across ALL modules in `domain/`:
  - domain/money.py
  - domain/rules_core.py
  - domain/scoring_core.py
  - domain/state_machine.py
  - domain/ubo_core.py
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
    normalize_currency,
    parse_decimal_amount,
    quantize_amount,
    to_decimal,
)
from domain.rules_core import (
    AccountRuleSnapshot,
    TransactionInput,
    _dec,
    _ensure_utc,
    check_amount_anomaly_pure,
    check_conduit_passthrough_pure,
    check_dormant_account_pure,
    check_geographic_sanctions_pure,
    check_large_transaction_pure,
    check_newly_incorporated_pure,
    check_rapid_movement_pure,
    check_round_trip_pure,
    check_structuring_extended_7d_pure,
    check_structuring_smurfing_pure,
    check_tbml_pure,
    check_vasp_crypto_pure,
    check_velocity_monitoring_pure,
    classify_transaction_decision,
    compute_ruleset_hash,
    evaluate_all_rules_pure,
    evaluate_ctr_and_structuring_pure,
    evaluate_travel_rule_pure,
    is_high_risk_geo_bic,
    is_vasp_transaction,
)
from domain.scoring_core import compute_dynamic_risk_pure
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
from domain.ubo_core import resolve_ubo_ownership_tree_pure

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


# ── 2. Exact Decimal & ISO 4217 Money Precision (100% domain/money.py) ────────

def test_decimal_money_eliminates_ieee754_float_drift():
    m1 = Money.of("0.10", "USD")
    m2 = Money.of("0.20", "USD")
    total = m1 + m2
    assert total.amount == Decimal("0.30")
    assert (total - m1).amount == Decimal("0.20")
    assert total.to_minor_units() == 30
    assert Money.from_minor_units(30, "USD") == total

    with pytest.raises(InvalidMoneyError):
        _ = Money.of("100.00", "USD") + Money.of("100.00", "EUR")
    with pytest.raises(InvalidMoneyError):
        Money.from_minor_units(True, "USD")  # type: ignore[arg-type]
    with pytest.raises(InvalidMoneyError):
        normalize_currency("US1")


def test_iso4217_currency_exponents_and_minor_units():
    assert get_currency_exponent("JPY") == 0
    assert get_currency_exponent("KRW") == 0
    assert get_currency_exponent("USD") == 2
    assert get_currency_exponent("EUR") == 2
    assert get_currency_exponent("KWD") == 3
    assert get_currency_exponent("BHD") == 3

    assert Money.of(15000, "JPY").to_minor_units() == 15000
    assert Money.from_minor_units(10125, "KWD").amount == Decimal("10.125")
    assert quantize_amount("10.1256", "KWD", rounding=ROUND_HALF_EVEN) == Decimal("10.126")
    assert quantize_amount("15000.6", "JPY", rounding=ROUND_HALF_EVEN) == Decimal("15001")

    class _NumLike:
        def __str__(self) -> str:
            return "42.50"

    assert to_decimal(_NumLike()) == Decimal("42.50")


def test_hybrid_rounding_policy_bankers_vs_regulatory_half_up():
    assert quantize_amount("100.005", "USD", rounding=ROUND_HALF_EVEN) == Decimal("100.00")
    assert quantize_amount("100.015", "USD", rounding=ROUND_HALF_EVEN) == Decimal("100.02")

    assert quantize_amount("100.005", "USD", rounding=ROUND_HALF_UP) == Decimal("100.01")
    assert quantize_amount("9999.995", "USD", rounding=ROUND_HALF_UP) == Decimal("10000.00")
    assert quantize_amount("9999.994", "USD", rounding=ROUND_HALF_UP) == Decimal("9999.99")


def test_money_rejects_nan_inf_bool_negative_and_excess_scale():
    for bad in [float("nan"), float("inf"), float("-inf"), True, False, None, "", "-10.00", "0", "10.12345", "not-a-num"]:
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

    # Same-currency fast path
    same = convert_money("250.005", "USD", "1", base_currency="USD", source="SAME_CURRENCY", quoted_at=now)
    assert same.source == "SAME_CURRENCY"
    assert same.amount_base == Decimal("250.00")
    assert same.fx_rate_applied == Decimal("1")


# ── 3. Pure AML Rules, CTR, Travel Rule & Determinism (100% domain/rules_core.py) ─

def test_ctr_and_structuring_exact_decimal_statutory_boundaries():
    wire = evaluate_ctr_and_structuring_pure(Decimal("25000.00"), "WIRE", None)
    assert wire.is_cash_channel is False
    assert wire.requires_ctr_filing is False

    just_under = evaluate_ctr_and_structuring_pure(Decimal("9999.99"), "CASH", None)
    assert just_under.requires_ctr_filing is False
    assert just_under.structuring_detected is False

    half_cent_boundary = evaluate_ctr_and_structuring_pure(Decimal("9999.995"), "CASH", None)
    assert half_cent_boundary.requires_ctr_filing is True

    smurf = evaluate_ctr_and_structuring_pure(
        Decimal("4600.00"), "CASH", None, prior_24h_cash_usd=Decimal("5000.00"), prior_24h_cash_count=1
    )
    assert smurf.requires_ctr_filing is False
    assert smurf.structuring_detected is True

    agg_ctr = evaluate_ctr_and_structuring_pure(
        Decimal("4000.00"), "CASH", None, prior_24h_cash_usd=Decimal("6000.00"), prior_24h_cash_count=1
    )
    assert agg_ctr.requires_ctr_filing is True
    assert agg_ctr.structuring_detected is True


def test_travel_rule_exact_thresholds_usd_and_eur():
    incomplete = {"name": "Alice"}
    complete_orig = {"name": "Alice Smith", "account_number": "ACC-1", "address": "123 Main"}
    complete_bene = {"name": "Bob Jones", "account_number": "ACC-2"}

    # Non-wire channel bypassed
    assert evaluate_travel_rule_pure("50000.00", "USD", "CARD", {}, {}) == (True, [])
    # Below USD threshold
    assert evaluate_travel_rule_pure("2999.99", "USD", "WIRE", {}, {}, amount_usd="2999.99") == (True, [])
    # Missing all fields on wire >= $3,000
    ok_missing, missing_all = evaluate_travel_rule_pure("3500.00", "USD", "WIRE", {}, {}, amount_usd="3500.00")
    assert ok_missing is False
    assert set(missing_all) == {
        "originator_name",
        "originator_account_number",
        "originator_address_or_identifier",
        "beneficiary_name",
        "beneficiary_account_number",
    }

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


def test_all_rules_core_branches_disabled_negative_and_positive():
    naive_dt = datetime(2026, 5, 10, 14, 30)
    utc_dt = _ensure_utc(naive_dt)
    assert utc_dt.tzinfo == timezone.utc
    assert _dec(None, "5") == Decimal("5")
    assert _dec("bad_number", "7") == Decimal("7")

    assert is_high_risk_geo_bic("CHASUS33", "BOFAUS3N", ["RU"]) is False
    assert is_vasp_transaction({"counterparty_type": "VASP"}, None, None) is True
    assert is_vasp_transaction({}, "COINBVASP", None) is True
    assert is_vasp_transaction({}, "CHASUS33", "BOFAUS3N") is False

    disabled = {
        "rules": {
            "LARGE_TRANSACTION": {"enabled": False},
            "STRUCTURING_SMURFING": {"enabled": False},
            "VELOCITY_MONITORING": {"enabled": False},
            "RAPID_MOVEMENT_FUNDS": {"enabled": False},
            "DORMANT_ACCOUNT": {"enabled": False},
            "GEOGRAPHIC_SANCTIONS": {"enabled": False},
            "ROUND_TRIP_DETECTION": {"enabled": False},
            "NEWLY_INCORPORATED_HIGH_VALUE": {"enabled": False},
            "TRADE_BASED_ML_OVER_UNDER_INVOICING": {"enabled": False},
            "CRYPTO_FIAT_VASP_STRUCTURING": {"enabled": False},
            "STRUCTURING_EXTENDED_7D": {"enabled": False},
            "CONDUIT_RAPID_PASSTHROUGH": {"enabled": False},
            "AMOUNT_ANOMALY_HEURISTICS": {"enabled": False},
        }
    }
    empty_snap = AccountRuleSnapshot()
    base_tx = TransactionInput(
        amount_original=Decimal("500.00"),
        currency="USD",
        amount_base_usd=Decimal("500.00"),
        fx_rate_applied=Decimal("1"),
        sender_id="s1",
        receiver_id="r1",
        tx_timestamp=utc_dt,
        evaluated_at=utc_dt,
    )
    assert check_large_transaction_pure(disabled, Decimal("50000")) == []
    assert check_large_transaction_pure({"rules": {}}, Decimal("500")) == []
    assert check_structuring_smurfing_pure(disabled, Decimal("5000"), [], [])[0] == []
    assert check_structuring_smurfing_pure({"rules": {}}, Decimal("6000"), [Decimal("4500")], [Decimal("4500")])[0] == ["STRUCTURING_VELOCITY_24H"]
    assert check_velocity_monitoring_pure(disabled, Decimal("500"), empty_snap) == []
    assert check_velocity_monitoring_pure({"rules": {}}, Decimal("500"), empty_snap) == []
    assert check_velocity_monitoring_pure(
        {"rules": {}},
        Decimal("500"),
        AccountRuleSnapshot(velocity_avg_count=Decimal("5"), velocity_avg_amount_usd=Decimal("5000")),
    ) == []
    assert check_rapid_movement_pure(disabled, Decimal("500"), utc_dt, empty_snap) == []
    assert check_rapid_movement_pure({"rules": {}}, Decimal("500"), utc_dt, empty_snap) == []
    assert check_rapid_movement_pure(
        {"rules": {}},
        Decimal("100"),
        utc_dt,
        AccountRuleSnapshot(last_incoming_amount_usd=Decimal("1000"), last_incoming_at=utc_dt - timedelta(minutes=2)),
    ) == []
    assert check_dormant_account_pure(disabled, Decimal("60000"), utc_dt, empty_snap) == []
    assert check_dormant_account_pure(
        {"rules": {}},
        Decimal("1000"),
        utc_dt,
        AccountRuleSnapshot(last_outgoing_at=utc_dt - timedelta(days=5)),
    ) == []
    assert check_geographic_sanctions_pure(disabled, base_tx, empty_snap) == []
    assert check_geographic_sanctions_pure({"rules": {}}, base_tx, AccountRuleSnapshot(sanctions_hit=True)) == ["SANCTIONS_HIT"]
    assert check_round_trip_pure(disabled, empty_snap) == []
    assert check_newly_incorporated_pure(disabled, Decimal("60000"), utc_dt, empty_snap) == []
    assert check_newly_incorporated_pure(
        {"rules": {}},
        Decimal("100"),
        utc_dt,
        AccountRuleSnapshot(account_created_at=utc_dt - timedelta(days=10)),
    ) == []
    assert check_newly_incorporated_pure(
        {"rules": {}},
        Decimal("60000"),
        utc_dt,
        AccountRuleSnapshot(account_created_at=utc_dt - timedelta(days=365)),
    ) == []
    assert check_tbml_pure(disabled, Decimal("100000"), {}) == []
    assert check_tbml_pure({"rules": {}}, Decimal("1000"), {}) == []
    assert check_tbml_pure(
        {"rules": {}},
        Decimal("150000"),
        {"goods_category": "PRECIOUS_METALS", "invoice_amount": "100000"},
    ) == ["TRADE_BASED_ML_OVER_UNDER_INVOICING"]
    assert check_vasp_crypto_pure(disabled, Decimal("5000"), None, None, {"is_vasp_transfer": True}) == []
    assert check_vasp_crypto_pure({"rules": {}}, Decimal("5000"), None, None, {}) == []
    assert check_vasp_crypto_pure(
        {"rules": {}}, Decimal("500"), None, None, {"is_vasp_transfer": True, "rapid_conversion_count": 3}
    ) == ["CRYPTO_FIAT_VASP_STRUCTURING"]
    assert check_vasp_crypto_pure(
        {"rules": {}}, Decimal("500"), None, None, {"is_vasp_transfer": True, "rapid_conversion_count": 1}
    ) == []
    assert check_structuring_extended_7d_pure(disabled, Decimal("4000"), Decimal("1"), empty_snap) == []
    assert check_structuring_extended_7d_pure(
        {"rules": {}},
        Decimal("4000"),
        Decimal("1"),
        AccountRuleSnapshot(sub_7d_count=2, sub_7d_amount_usd=Decimal("7000")),
    ) == ["STRUCTURING_EXTENDED_7D"]
    assert check_conduit_passthrough_pure(disabled, Decimal("5000"), Decimal("1"), empty_snap) == []
    assert check_conduit_passthrough_pure({"rules": {}}, Decimal("100"), Decimal("1"), empty_snap) == []
    assert check_amount_anomaly_pure(disabled, Decimal("9500"), Decimal("9500"), [Decimal("9500")]) == []
    # Cumulative sub-CTR just-below trigger (current >= $500, total in [9000, 10000), >=2 txs)
    assert "JUST_BELOW_CTR_THRESHOLD" in check_amount_anomaly_pure(
        {"rules": {}}, Decimal("4500"), Decimal("9200"), [Decimal("4500"), Decimal("4700")]
    )

    # Threat level matrix: NONE, MEDIUM, HIGH, CRITICAL
    assert classify_transaction_decision(0.20, []).threat_level == "NONE"
    assert classify_transaction_decision(0.50, ["ROUND_NUMBER_ANOMALY_1K"]).threat_level == "MEDIUM"
    assert classify_transaction_decision(0.80, []).threat_level == "HIGH"
    assert classify_transaction_decision(0.95, []).threat_level == "CRITICAL"


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
        sender_bic="SBERRUMM",
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
    assert "SANCTIONS_SCREENING_UNAVAILABLE" in p1.triggered_rules
    assert "GEOGRAPHIC_SANCTIONS" in p1.degraded_rules

    cls = classify_transaction_decision(0.40, p1.triggered_rules)
    assert cls.decision == "HELD"
    assert cls.is_hard_hold is True


# ── 4. Pure RBA Dynamic Scoring Core (100% domain/scoring_core.py) ────────────

def test_scoring_core_all_branches_and_sr11_7_efficiency_axiom():
    # Low-risk baseline with std_amount fallback & non-numeric guard
    res_low = compute_dynamic_risk_pure(
        rules_triggered=[],
        ml_score="bad",  # type: ignore[arg-type]
        amount=100.0,
        baseline={"avg_amount": 500.0, "std_amount": 50.0},
        iforest_score=0.1,
    )
    assert 0.0 <= res_low["dynamic_risk_score"] <= 1.0
    assert res_low["explainability"]["efficiency_axiom_verified"] is True

    # Zero variance baseline + empty baseline
    res_empty = compute_dynamic_risk_pure([], 0.2, 500.0, {}, 0.2)
    assert res_empty["explainability"]["amount_zscore"] == 0.0
    res_zero_var = compute_dynamic_risk_pure([], 0.2, 500.0, {"avg_amount": 100.0}, 0.2)
    assert res_zero_var["explainability"]["amount_zscore"] > 0.0

    # PEP tiers + saturation clamp damping (> 1.0 raw sum) + all top drivers
    for tier in ("TIER_1", "TIER_2", "TIER_3", "LOCAL_PEP"):
        res_high = compute_dynamic_risk_pure(
            rules_triggered=["SANCTIONS_HIT", "CONDUIT_RAPID_PASSTHROUGH", "STRUCTURING_EXTENDED_7D", "JUST_BELOW_CTR_THRESHOLD"],
            ml_score=0.95,
            amount=50000.0,
            baseline={"avg_amount": 1000.0, "variance_amount": 10000.0},
            iforest_score=0.90,
            sender_risk=0.8,
            receiver_risk=0.8,
            pep_tier=tier,
            jurisdiction_risk=0.9,
            taint_risk=0.8,
        )
        assert res_high["dynamic_risk_score"] == 1.0
        assert "saturation_clamp_damping" in res_high["explainability"]["reconciled_contributions"]
        assert res_high["explainability"]["efficiency_axiom_verified"] is True
        assert len(res_high["top_drivers"]) >= 8

    # Regulatory floor elevation (low base score elevated by taint >= 0.70)
    res_floor = compute_dynamic_risk_pure(
        rules_triggered=[],
        ml_score=0.05,
        amount=100.0,
        baseline={},
        iforest_score=0.05,
        taint_risk=0.75,
    )
    assert res_floor["dynamic_risk_score"] == 0.75
    assert "regulatory_floor_elevation" in res_floor["explainability"]["reconciled_contributions"]


# ── 5. Pure Multi-Layer Corporate UBO Core (100% domain/ubo_core.py) ──────────

def test_ubo_core_all_branches_split_stakes_cycles_clamping_and_depth():
    # Empty target
    empty = resolve_ubo_ownership_tree_pure([], "  ")
    assert empty["target_company"] == ""

    edges = [
        # Ignored invalid/zero/negative edges
        {"parent_entity_name": "", "child_company_name": "TargetCo", "ownership_pct": 50},
        {"parent_entity_name": "BadPct", "child_company_name": "TargetCo", "ownership_pct": "not-a-number"},
        {"parent_entity_name": "NegPct", "child_company_name": "TargetCo", "ownership_pct": -10},
        # Valid multi-hop split stakes + >100% clamp + cycle
        {"parent_entity_name": "Shell A", "parent_entity_type": "COMPANY", "child_company_name": "TargetCo", "ownership_pct": 50},
        {"parent_entity_name": "Shell B", "parent_entity_type": "COMPANY", "child_company_name": "TargetCo", "ownership_pct": 50},
        {"parent_entity_name": "Alice", "parent_entity_type": "PERSON", "child_company_name": "Shell A", "ownership_pct": 150},  # clamped to 100% -> 50% effective
        {"parent_entity_name": "Alice", "parent_entity_type": "PERSON", "child_company_name": "Shell B", "ownership_pct": 30},   # 15% effective -> total 65%
        {"parent_entity_name": "TargetCo", "parent_entity_type": "COMPANY", "child_company_name": "Shell B", "ownership_pct": 20},  # cycle!
    ]
    res = resolve_ubo_ownership_tree_pure(edges, "TargetCo", threshold_pct=25.0, max_depth=5)
    assert res["cycles_detected"] is True
    assert res["ubo_count_above_threshold"] == 1
    alice = res["ultimate_beneficial_owners"][0]
    assert alice["entity_name"] == "Alice"
    assert alice["effective_ownership_pct"] == 65.0
    assert alice["is_split_ownership"] is True
    assert res["unattributed_ownership_pct"] == 35.0

    # Max depth guard
    depth_zero = resolve_ubo_ownership_tree_pure(edges, "TargetCo", max_depth=0)
    assert depth_zero["ultimate_beneficial_owners"] == []


# ── 6. All 5 Pure Compliance Finite State Machines (100% domain/state_machine.py) ─

def test_all_five_compliance_state_machines():
    assert validate_alert_transition_pure("OPEN", "IN_REVIEW") == AlertStatus.IN_REVIEW
    assert validate_case_transition_pure("OPEN", "INVESTIGATING") == CaseStatus.INVESTIGATING
    assert validate_case_transition_pure("OPEN", "OPEN") == CaseStatus.OPEN

    with pytest.raises(DomainStateTransitionError) as exc_closed:
        validate_case_transition_pure("CLOSED", "OPEN")
    assert "Case is already CLOSED" in str(exc_closed.value)

    with pytest.raises(DomainStateTransitionError) as exc_bad_target:
        validate_case_transition_pure("OPEN", "NOT_A_STATE")
    assert "Invalid target Case status" in str(exc_bad_target.value)

    with pytest.raises(DomainStateTransitionError) as exc_illegal:
        validate_case_transition_pure("PENDING_SAR", "OPEN")
    assert "Illegal Case state transition" in str(exc_illegal.value)

    assert validate_sar_draft_transition_pure("DRAFT", "PENDING_MLRO_REVIEW") == SARDraftStatus.PENDING_MLRO_REVIEW
    assert validate_sar_draft_transition_pure("PENDING_MLRO_REVIEW", "APPROVED", allow_noop=False) == SARDraftStatus.APPROVED
    assert validate_sar_draft_transition_pure("APPROVED", "FILED") == SARDraftStatus.FILED
    with pytest.raises(DomainStateTransitionError):
        validate_sar_draft_transition_pure("APPROVED", "APPROVED", allow_noop=False)
    with pytest.raises(DomainStateTransitionError):
        validate_sar_draft_transition_pure("FILED", "DRAFT")

    assert validate_ctr_transition_pure("PENDING", "FILED") == CTRFilingStatus.FILED
    with pytest.raises(DomainStateTransitionError):
        validate_ctr_transition_pure("FILED", "FILED")
    with pytest.raises(DomainStateTransitionError):
        validate_ctr_transition_pure("EXEMPT", "FILED")

    assert validate_rfi_transition_pure("OPEN", "SUBMITTED") == RFIStatus.SUBMITTED
    with pytest.raises(DomainStateTransitionError):
        validate_rfi_transition_pure("CANCELLED", "SUBMITTED")

    with pytest.raises(CorruptedDomainStateError):
        validate_ctr_transition_pure("UNKNOWN_LEGACY", "FILED")


# ── 7. Architectural Layering Guard (Zero Raw SQL or Direct DB Access in routers/) ─

def test_routers_contain_zero_raw_sql_and_zero_direct_db_connections():
    """Enforces clean layering: HTTP controllers in routers/ must never embed raw SQL or open DB connections."""
    import pathlib
    import re

    routers_dir = pathlib.Path(__file__).resolve().parent.parent / "routers"
    sql_pattern = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b\s+(?:INTO|FROM|SET|DISTINCT|COUNT|\*|[a-zA-Z0-9_]+)")
    direct_db_pattern = re.compile(r"(async\s+with\s+.*get_async_db_|conn\.(fetch|fetchrow|fetchval|execute|transaction)\s*\()")

    violations: list[str] = []
    for py_file in sorted(routers_dir.glob("*.py")):
        src = py_file.read_text(encoding="utf-8")
        tree = ast.parse(src, filename=str(py_file))
        # Inspect every string literal in the AST for raw SQL statements
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value
                # Ignore Cypher queries (Neo4j MATCH/MERGE/RETURN) and human prose messages
                if "MATCH " in val or "MERGE " in val:
                    continue
                if re.search(r"\b(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+[a-z_]+\s+SET|DELETE\s+FROM)\b", val, re.IGNORECASE | re.DOTALL):
                    violations.append(f"{py_file.name}:{node.lineno}: raw SQL string literal")
                if val.strip().upper() == "SELECT 1":
                    violations.append(f"{py_file.name}:{node.lineno}: raw SQL ping literal")
        for idx, line in enumerate(src.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if direct_db_pattern.search(line):
                violations.append(f"{py_file.name}:{idx}: direct DB call/context in controller: {stripped}")

    assert violations == [], f"Architectural layering violations found in routers/: {violations}"
