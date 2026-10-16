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


def test_rba_scoring_top_drivers_extraction():
    """Verify top_drivers generates clear compliance flags for auditing."""
    res = compute_dynamic_risk(
        rules_triggered=["STRUCTURING_DETECTED"],
        ml_score=0.85,
        amount=50000.0,
        baseline={"avg_amount": 1000.0, "variance_amount": 10000.0},
        iforest_score=0.75,
        sender_risk=0.50,
        receiver_risk=0.50,
        jurisdiction_risk=0.90,
        pep_tier="TIER_1_HEAD_OF_STATE"
    )

    drivers = res["top_drivers"]
    assert any("RULES_TRIGGERED" in d for d in drivers)
    assert any("BEHAVIORAL_AMOUNT_SPIKE" in d for d in drivers)
    assert any("HIGH_RISK_JURISDICTION" in d for d in drivers)
    assert any("AI_ANOMALY_CONFIDENCE" in d for d in drivers)
    assert any("POLITICALLY_EXPOSED_PERSON" in d for d in drivers)


def test_rba_scoring_negative_amount_and_zero_variance_safety():
    """Verify negative amount is safely clamped to 0 and zero variance sets a robust floor."""
    res = compute_dynamic_risk(
        rules_triggered=[],
        ml_score=0.20,
        amount=-500.0,
        baseline={"avg_amount": 100.0, "variance_amount": 0.0},
        iforest_score=0.20,
        sender_risk=0.10,
        receiver_risk=0.10,
        jurisdiction_risk=0.10
    )
    # Negative amount -> safe_amount = 0.0 -> amount <= avg_amount -> z_score_prob = 0.0
    assert res["dynamic_risk_score"] == 0.15
    assert res["explainability"]["baseline_zscore_contribution"] == 0.0


def test_rba_scoring_efficiency_axiom_reconciliation():
    """
    OCC SR 11-7 / Model Risk Management Mandate:
    Verify that the sum of reconciled feature attributions strictly equals the
    final reported decision score (Efficiency Axiom: sum(phi_i) == Score).
    """
    # Scenario A: Baseline convex combination
    res_a = compute_dynamic_risk(
        rules_triggered=[],
        ml_score=0.45,
        amount=5000.0,
        baseline={"avg_amount": 2500.0, "variance_amount": 1000000.0},
        iforest_score=0.60,
        sender_risk=0.30,
        receiver_risk=0.20,
        jurisdiction_risk=0.40
    )
    assert res_a["explainability"]["efficiency_axiom_verified"] is True
    assert res_a["explainability"]["attribution_sum"] == res_a["dynamic_risk_score"]

    # Scenario B: Rule floor escalation (0.80 regulatory floor overrides lower raw score)
    res_b = compute_dynamic_risk(
        rules_triggered=["LARGE_TRANSACTION_THRESHOLD"],
        ml_score=0.10,
        amount=15000.0,
        baseline={"avg_amount": 1000.0, "variance_amount": 10000.0},
        iforest_score=0.10,
        sender_risk=0.10,
        receiver_risk=0.10
    )
    assert res_b["dynamic_risk_score"] >= 0.80
    assert res_b["explainability"]["efficiency_axiom_verified"] is True
    assert res_b["explainability"]["attribution_sum"] == res_b["dynamic_risk_score"]
    assert "regulatory_floor_elevation" in res_b["explainability"]["reconciled_contributions"]

    # Scenario C: Saturation clamp (multiple rules + PEP push raw score > 1.0)
    res_c = compute_dynamic_risk(
        rules_triggered=["SANCTIONS_HIT", "CONDUIT_RAPID_PASSTHROUGH", "STRUCTURING_EXTENDED_7D"],
        ml_score=0.95,
        amount=100000.0,
        baseline={"avg_amount": 1000.0, "variance_amount": 10000.0},
        iforest_score=0.95,
        sender_risk=0.90,
        receiver_risk=0.90,
        pep_tier="TIER_1_HEAD_OF_STATE"
    )
    assert res_c["dynamic_risk_score"] == 1.0
    assert res_c["explainability"]["efficiency_axiom_verified"] is True
    assert res_c["explainability"]["attribution_sum"] == 1.0
    assert "saturation_clamp_damping" in res_c["explainability"]["reconciled_contributions"]


