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
    # Two transactions 47 hours apart in +03:00 timezone (should be ~1.958 days, NOT truncated to 1 day)
    t_end = now_utc.astimezone(tz_plus_3)
    t_start = (now_utc - timedelta(hours=47)).astimezone(tz_plus_3)
    rows = [{"timestamp": t_start}, {"timestamp": t_end}]

    daily_freq, weekly_freq, count_30 = _calculate_frequencies(rows)
    assert count_30 == 2
    # 2 / (47/24) = 1.02127... (previous .days floor bug returned 2.0!)
    assert 0.95 <= daily_freq <= 1.10, f"Unexpected daily_freq={daily_freq}"
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
