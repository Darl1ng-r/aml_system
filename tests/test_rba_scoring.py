import pytest
from services.dynamic_scorer import compute_dynamic_risk


def test_rba_dynamic_risk_score_baseline_blend():
    """Verify that ML score, Isolation Forest, Z-score, CRR, and Jurisdiction risk blend correctly."""
    res = compute_dynamic_risk(
        rules_triggered=[],
        ml_score=0.20,
        amount=100.0,
        baseline={"avg_amount": 100.0, "variance_amount": 100.0},
        iforest_score=0.20,
        sender_risk=0.10,
        receiver_risk=0.10,
        jurisdiction_risk=0.10
    )
    # 0.30*0.2 + 0.30*0.2 + 0.10*0.0 + 0.10*0.1 + 0.10*0.1 + 0.10*0.1 = 0.06 + 0.06 + 0.0 + 0.01 + 0.01 + 0.01 = 0.15
    assert res["dynamic_risk_score"] == 0.15
    assert res["explainability"]["pep_elevation"] == 0.0


def test_rba_dynamic_risk_score_pep_tier_1_elevation():
    """Verify PEP Tier 1 adds 0.25 elevation to dynamic risk score."""
    res = compute_dynamic_risk(
        rules_triggered=[],
        ml_score=0.20,
        amount=100.0,
        baseline={"avg_amount": 100.0, "variance_amount": 100.0},
        iforest_score=0.20,
        sender_risk=0.10,
        receiver_risk=0.10,
        pep_tier="TIER_1_HEAD_OF_STATE"
    )
    assert res["explainability"]["pep_elevation"] == 0.25
    assert res["dynamic_risk_score"] == 0.40


def test_rba_dynamic_risk_score_rule_floor_escalation():
    """Verify triggering deterministic rule forces dynamic risk score to minimum 0.80 floor."""
    res = compute_dynamic_risk(
        rules_triggered=["LARGE_TRANSACTION_THRESHOLD"],
        ml_score=0.10,
        amount=15000.0,
        baseline={"avg_amount": 1000.0, "variance_amount": 10000.0},
        iforest_score=0.10,
        sender_risk=0.10,
        receiver_risk=0.10
    )
    assert res["dynamic_risk_score"] >= 0.80
    assert res["explainability"]["rule_escalated"] is True
