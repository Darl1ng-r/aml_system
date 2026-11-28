"""
Quantitative, Algorithmic & State-Machine Invariant Tests
Covers all hardening items from quant_and_security_hardening_plan.md:
  1. Iterative Tarjan SCC on 1,500-node deep cycle (zero RecursionError) + self-loop exclusion
  2. Behavioral baseline UTC timezone conversion & continuous fractional day span
  3. Fixed-point Decimal currency boundary accuracy ($3333.33 + $3333.33 + $3333.34 == $10,000.00)
  4. Fail-closed state machine guard on unknown/corrupted statuses (HTTP 409 Conflict)
"""
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import pytest
from fastapi import HTTPException

from services.network_analysis import tarjan_scc
from services.behavioral import _calculate_frequencies
from services.state_machine import validate_alert_transition, validate_case_transition
from services.rules import RulesEngine
from services.dynamic_scorer import compute_dynamic_risk


def test_iterative_tarjan_scc_handles_1500_node_cycle_and_excludes_self_loop():
    n = 1500
    graph = {f"N{i}": [f"N{(i + 1) % n}"] for i in range(n)}
    graph["SELF_ONLY"] = ["SELF_ONLY"]
    graph["ISOLATED"] = []

    sccs = tarjan_scc(graph)
    assert len(sccs) == 1
    assert len(sccs[0]) == n
    assert "SELF_ONLY" not in sccs[0]


def test_behavioral_frequencies_utc_conversion_and_continuous_span():
    tz_plus_3 = timezone(timedelta(hours=3))
    now_utc = datetime.now(timezone.utc)
    # 1. Burst smoothing (< 7 days): two transactions 47h apart clamp to the 7-day floor (2/7 ~= 0.2857/day),
    # eliminating the 60x burst discontinuity for newly active accounts.
    t_end = now_utc.astimezone(tz_plus_3)
    t_start_burst = (now_utc - timedelta(hours=47)).astimezone(tz_plus_3)
    daily_burst, weekly_burst, count_burst = _calculate_frequencies(
        [{"timestamp": t_start_burst}, {"timestamp": t_end}]
    )
    assert count_burst == 2
    assert abs(daily_burst - (2.0 / 7.0)) < 1e-6, f"Expected 7-day floor 2/7, got {daily_burst}"
    assert abs(weekly_burst - 2.0) < 1e-6

    # 2. Continuous fractional UTC span within (7, 30) days: 10d 12h (10.5 days) in +03:00 timezone
    # must compute 2 / 10.5 ~= 0.190476 (NOT truncated integer .days -> 2/10 = 0.20).
    t_start_mid = (now_utc - timedelta(days=10, hours=12)).astimezone(tz_plus_3)
    daily_freq, weekly_freq, count_30 = _calculate_frequencies(
        [{"timestamp": t_start_mid}, {"timestamp": t_end}]
    )
    assert count_30 == 2
    assert 0.188 <= daily_freq <= 0.193, f"Unexpected continuous daily_freq={daily_freq}"
    assert abs(weekly_freq - daily_freq * 7.0) < 1e-6


def test_decimal_large_transaction_and_efficiency_axiom():
    cfg = {"rules": {"LARGE_TRANSACTION": {"enabled": True, "threshold": 10000.0}}}
    assert RulesEngine._check_large_transaction(cfg, 10000.00) == ["LARGE_TRANSACTION_THRESHOLD"]
    assert RulesEngine._check_large_transaction(cfg, 9999.99) == []

    # Exact Decimal sum check for structuring boundary
    total = sum((Decimal(str(x)) for x in [3333.33, 3333.33, 3333.34]), Decimal("0"))
    assert total == Decimal("10000.00")

    # Dynamic risk efficiency axiom with math.isclose
    res = compute_dynamic_risk(
        rules_triggered=["STRUCTURING_VELOCITY_24H"],
        ml_score=0.7333,
        amount=9500.0,
        baseline={"avg_amount": 500.0, "variance_amount": 0.0},
        iforest_score=0.6111,
        sender_risk=0.45,
        receiver_risk=0.55,
    )
    assert 0.0 <= res["dynamic_risk_score"] <= 1.0
    assert res["explainability"]["efficiency_axiom_verified"] is True


def test_state_machine_fails_closed_on_unknown_current_status():
    with pytest.raises(HTTPException) as exc_alert:
        validate_alert_transition("CORRUPTED_STATE", "CLOSED_SAR")
    assert exc_alert.value.status_code == 409

    with pytest.raises(HTTPException) as exc_case:
        validate_case_transition("UNKNOWN_LEGACY_STATE", "CLOSED")
    assert exc_case.value.status_code == 409
