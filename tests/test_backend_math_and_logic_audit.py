"""
Principal Backend Verification — Hostile & Boundary Case Unit Tests
Covers mathematical and logical invariants across:
  1. services/fx_rates.py (zero, negative, cross-currency, unknown currency, precision)
  2. services/ubo_resolver.py (multi-layer split stakes, cycles, depth limits, empty input)
  3. services/isolation_forest.py (c_factor boundary n<=1/n=2, constant matrix, single row, extremes)
  4. services/rule_backtest.py (all rule evaluators, division-by-zero delta_pct, boundary values)
  5. services/dynamic_scorer.py (NaN, +Inf, -Inf, zero variance, negative amount, max saturation)
"""
import math
import numpy as np
import pytest

from services.fx_rates import get_fallback_fx_rate, convert_to_base_currency_sync
from services.ubo_resolver import resolve_ubo_ownership_tree
from services.isolation_forest import c_factor, IsolationForestScratch
from services.rule_backtest import evaluate_rule_on_tx_row
from services.dynamic_scorer import compute_dynamic_risk


# ── 1. FX Normalization Boundaries ───────────────────────────────────────────
def test_fx_rates_identity_cross_currency_and_boundaries():
    assert get_fallback_fx_rate("USD", "USD") == 1.0
    assert get_fallback_fx_rate("eur", "USD") == 1.08
    # Cross-currency EUR -> GBP = 1.08 / 1.27
    eur_to_gbp = get_fallback_fx_rate("EUR", "GBP")
    assert math.isclose(eur_to_gbp, 1.08 / 1.27, rel_tol=1e-6)
    # Zero amount and unknown currency fallback
    amt_zero, rate_zero = convert_to_base_currency_sync(0.0, "EUR", "USD")
    assert amt_zero == 0.0 and rate_zero == 1.08
    assert get_fallback_fx_rate("ZZZ", "USD") == 1.0


# ── 2. UBO Ownership Tree Math & Cycle Guards ────────────────────────────────
def test_ubo_resolver_split_ownership_and_cycle_termination():
    edges = [
        # Alice owns 30% indirectly via two 50%-owned shells (50%*30% + 50%*30% = 30% >= 25%)
        {"parent_entity_name": "Shell A", "parent_entity_type": "COMPANY", "child_company_name": "Target Co", "ownership_pct": 50.0},
        {"parent_entity_name": "Shell B", "parent_entity_type": "COMPANY", "child_company_name": "Target Co", "ownership_pct": 50.0},
        {"parent_entity_name": "Alice", "parent_entity_type": "PERSON", "child_company_name": "Shell A", "ownership_pct": 30.0},
        {"parent_entity_name": "Alice", "parent_entity_type": "PERSON", "child_company_name": "Shell B", "ownership_pct": 30.0},
        # Circular holding loop: Shell A -> Shell B -> Shell A
        {"parent_entity_name": "Shell B", "parent_entity_type": "COMPANY", "child_company_name": "Shell A", "ownership_pct": 10.0},
        {"parent_entity_name": "Shell A", "parent_entity_type": "COMPANY", "child_company_name": "Shell B", "ownership_pct": 10.0},
    ]
    res = resolve_ubo_ownership_tree(edges, "Target Co", threshold_pct=25.0)
    assert res["cycles_detected"] is True
    alice = next(u for u in res["ultimate_beneficial_owners"] if u["entity_name"] == "Alice")
    assert alice["is_split_ownership"] is True
    assert alice["exceeds_threshold"] is True
    assert alice["effective_ownership_pct"] >= 30.0


def test_ubo_resolver_empty_and_zero_pct_edges():
    empty = resolve_ubo_ownership_tree([], "")
    assert empty["ultimate_beneficial_owners"] == []
    assert empty["cycles_detected"] is False

    zero_edges = [{"parent_entity_name": "Bob", "parent_entity_type": "PERSON", "child_company_name": "Co", "ownership_pct": 0.0}]
    res = resolve_ubo_ownership_tree(zero_edges, "Co")
    assert res["ultimate_beneficial_owners"] == []


# ── 3. Isolation Forest Math & Degenerate Inputs ─────────────────────────────
def test_isolation_forest_c_factor_and_edge_datasets():
    assert c_factor(0) == 0.0
    assert c_factor(1) == 0.0
    assert c_factor(2) == 1.0
    assert c_factor(256) > 8.0

    # Empty dataset must not crash
    empty_if = IsolationForestScratch(n_estimators=5, max_samples=16)
    empty_if.fit(np.empty((0, 5)))
    assert empty_if.compute_anomaly_score(np.array([100.0, 0.1, 0.1, 12.0, 0.0])) == 0.5

    # Single-sample dataset (c_factor(1) == 0 -> guarded)
    one_if = IsolationForestScratch(n_estimators=5, max_samples=16)
    one_if.fit(np.array([[100.0, 0.1, 0.1, 12.0, 0.0]]))
    score_one = one_if.compute_anomaly_score(np.array([99999.0, 0.9, 0.9, 3.0, 1.0]))
    assert 0.0 <= score_one <= 1.0

    # Constant matrix (zero variance across all features)
    const_X = np.tile([500.0, 0.2, 0.2, 10.0, 0.0], (20, 1))
    const_if = IsolationForestScratch(n_estimators=10, max_samples=16)
    const_if.fit(const_X)
    score_const = const_if.compute_anomaly_score(np.array([500.0, 0.2, 0.2, 10.0, 0.0]))
    assert 0.0 <= score_const <= 1.0


# ── 4. Rule Backtest Pure Evaluator Boundaries ───────────────────────────────
def test_rule_backtest_evaluator_boundaries():
    hit_10k, _ = evaluate_rule_on_tx_row("LARGE_TRANSACTION", {"enabled": True, "threshold": 10000.0}, {"amount_base_usd": 10000.0})
    assert hit_10k is True

    hit_sub, _ = evaluate_rule_on_tx_row("LARGE_TRANSACTION", {"enabled": True, "threshold": 10000.0}, {"amount_base_usd": 9999.99})
    assert hit_sub is False

    # Disabled rule must never trigger
    hit_disabled, _ = evaluate_rule_on_tx_row("LARGE_TRANSACTION", {"enabled": False, "threshold": 1.0}, {"amount_base_usd": 500000.0})
    assert hit_disabled is False

    # Just-below CTR band [9000, 10000)
    hit_jb_in, _ = evaluate_rule_on_tx_row("AMOUNT_ANOMALY_HEURISTICS", {"enabled": True}, {"amount_base_usd": 9500.0})
    hit_jb_out, _ = evaluate_rule_on_tx_row("AMOUNT_ANOMALY_HEURISTICS", {"enabled": True}, {"amount_base_usd": 8999.99})
    assert hit_jb_in is True
    assert hit_jb_out is False


# ── 5. Dynamic Risk Scorer Hostile Inputs (NaN, Inf, Negatives) ──────────────
def test_dynamic_scorer_hostile_nan_inf_and_negative_inputs():
    res = compute_dynamic_risk(
        rules_triggered=[],
        ml_score=float("nan"),
        amount=float("-inf"),
        baseline={"avg_amount": float("nan"), "variance_amount": -100.0},
        iforest_score=float("inf"),
        sender_risk=-5.0,
        receiver_risk=99.0,
        pep_tier="TIER_1_HEAD_OF_STATE",
        jurisdiction_risk=float("nan"),
        taint_risk=float("inf"),
    )
    score = res["dynamic_risk_score"]
    assert not math.isnan(score) and not math.isinf(score)
    assert 0.0 <= score <= 1.0
    assert res["explainability"]["efficiency_axiom_verified"] is True


# ── 6. Regression Tests for P0–P2 Audit Fixes ────────────────────────────────
def test_fx_decimal_half_up_and_non_finite_safety():
    # Decimal ROUND_HALF_UP (vs float banker's rounding)
    amt, _ = convert_to_base_currency_sync(100.005, "USD", "USD")
    assert amt == 100.01
    # Non-finite amounts return 0.0 safely instead of propagating NaN/Inf
    amt_inf, _ = convert_to_base_currency_sync(float("inf"), "EUR", "USD")
    assert amt_inf == 0.0


def test_ubo_clamps_over_100_pct_and_reports_unattributed_equity():
    # Edge with >100% must clamp to 100%
    over_edges = [
        {"parent_entity_name": "OverOwner", "parent_entity_type": "PERSON", "child_company_name": "OverCo", "ownership_pct": 250.0}
    ]
    res_over = resolve_ubo_ownership_tree(over_edges, "OverCo")
    assert res_over["ultimate_beneficial_owners"][0]["effective_ownership_pct"] == 100.0
    assert res_over["unattributed_ownership_pct"] == 0.0

    # Partial ownership must surface unattributed_ownership_pct = 60.0
    partial_edges = [
        {"parent_entity_name": "Shell X", "parent_entity_type": "COMPANY", "child_company_name": "OpaqueCo", "ownership_pct": 100.0},
        {"parent_entity_name": "Known Owner", "parent_entity_type": "PERSON", "child_company_name": "Shell X", "ownership_pct": 40.0},
    ]
    res_partial = resolve_ubo_ownership_tree(partial_edges, "OpaqueCo")
    assert res_partial["unattributed_ownership_pct"] == 60.0


def test_isolation_forest_handles_nan_and_inf_in_fit_and_score():
    X = np.array([
        [100.0, 0.1, 0.1, 12.0, 0.0],
        [float("nan"), 0.2, 0.3, 14.0, 0.0],
        [float("inf"), 0.9, 0.8, 3.0, 1.0],
        [250.0, 0.15, 0.2, 9.0, 0.0],
    ])
    model = IsolationForestScratch(n_estimators=10, max_samples=4).fit(X)
    score = model.compute_anomaly_score(np.array([float("nan"), 0.5, float("inf"), 10.0, 0.0]))
    assert math.isfinite(score) and 0.0 <= score <= 1.0


def test_rule_backtest_zero_base_usd_does_not_fallback_to_raw_amount():
    hit, _ = evaluate_rule_on_tx_row(
        "LARGE_TRANSACTION",
        {"enabled": True, "threshold": 10000.0},
        {"amount_base_usd": 0.0, "amount": 50000.0},
    )
    assert hit is False
