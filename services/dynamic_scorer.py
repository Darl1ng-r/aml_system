import math
import logging

logger = logging.getLogger(__name__)

def compute_dynamic_risk(
    rules_triggered: list[str],
    ml_score: float,
    amount: float,
    baseline: dict,
    iforest_score: float,
    sender_risk: float = 0.1,
    receiver_risk: float = 0.1,
    pep_tier: str | None = None,
    jurisdiction_risk: float = 0.1
) -> dict:
    """
    Computes a unified dynamic risk score [0.0, 1.0] using FATF Risk-Based Approach (RBA):
    - Base ML Blend (60%): Logistic Regression (30%) + Isolation Forest (30%)
    - Behavioral & Velocity Deviation (20%): Baseline Z-Score (10%) + Jurisdiction Risk (10%)
    - Customer Risk Rating / CRR (20%): Sender Risk (10%) + Receiver Risk (10%)
    - Dynamic Multipliers: PEP Tier Risk Elevation & Rule Floor Escalation
    """
    # 1. Input safety & Z-score calculation for transaction amount
    safe_amount = max(float(amount), 0.0)
    avg_amount = float(baseline.get("avg_amount", 0.0))
    var_amount = float(baseline.get("variance_amount", 0.0))
    if var_amount > 0.0:
        std_amount = math.sqrt(var_amount)
    elif "std_amount" in baseline and float(baseline.get("std_amount", 0.0)) > 0.0:
        std_amount = float(baseline.get("std_amount"))
    else:
        std_amount = 0.0
    
    if avg_amount > 0.0:
        min_std = max(avg_amount * 0.1, 1.0)
        effective_std = std_amount if std_amount > 0.0 else min_std
        z_score = (safe_amount - avg_amount) / effective_std
        
        if safe_amount > avg_amount:
            z_score_prob = min(max((safe_amount - avg_amount) / (3.0 * effective_std), 0.0), 1.0)
        else:
            z_score_prob = 0.0
    else:
        z_score = 0.0
        z_score_prob = 0.0

    # 2. Weighted RBA Score Blend
    # 60% Model Probability + 20% Behavioral/Jurisdiction + 20% Counterparty CRR
    base_ml_component = (0.30 * min(max(ml_score, 0.0), 1.0)) + (0.30 * min(max(iforest_score, 0.0), 1.0))
    behavioral_component = (0.10 * z_score_prob) + (0.10 * min(max(jurisdiction_risk, 0.0), 1.0))
    crr_component = (0.10 * min(max(sender_risk, 0.0), 1.0)) + (0.10 * min(max(receiver_risk, 0.0), 1.0))

    dynamic_score = base_ml_component + behavioral_component + crr_component

    # 3. PEP Tier Multiplier / Risk Elevation
    pep_elevation = 0.0
    if pep_tier:
        tier_str = str(pep_tier).upper()
        if "TIER_1" in tier_str or "HEAD_OF_STATE" in tier_str:
            pep_elevation = 0.25
        elif "TIER_2" in tier_str or "MINISTER" in tier_str or "GOVERNMENT" in tier_str:
            pep_elevation = 0.15
        elif "TIER_3" in tier_str or "JUDICIARY" in tier_str:
            pep_elevation = 0.10
        else:
            pep_elevation = 0.05
    dynamic_score += pep_elevation
    
    # 4. Rule trigger scaling / escalations (M4)
    # Scale proportionally with triggered rules while enforcing the regulatory >= 0.80 floor
    rule_applied = False
    rule_elevation = 0.0
    if rules_triggered:
        rule_elevation = 0.25 * len(rules_triggered)
        dynamic_score = max(dynamic_score + rule_elevation, 0.80)
        rule_applied = True
        
    dynamic_score = min(max(dynamic_score, 0.0), 1.0)

    # 5. Institutional Top Drivers for Compliance Examination (Verafin standard)
    top_drivers = []
    if rules_triggered:
        top_drivers.append(f"RULES_TRIGGERED: {', '.join(rules_triggered)}")
    if z_score >= 2.0:
        top_drivers.append(f"BEHAVIORAL_AMOUNT_SPIKE (Z={round(z_score, 2)})")
    if jurisdiction_risk >= 0.70:
        top_drivers.append(f"HIGH_RISK_JURISDICTION ({round(jurisdiction_risk, 2)})")
    if ml_score >= 0.70:
        top_drivers.append(f"AI_ANOMALY_CONFIDENCE ({round(ml_score, 2)})")
    if pep_tier:
        top_drivers.append(f"POLITICALLY_EXPOSED_PERSON ({pep_tier})")

    # 6. Generate attributions/explainability payload
    attributions = {
        "ml_model_contribution": round(0.30 * ml_score, 4),
        "isolation_forest_contribution": round(0.30 * iforest_score, 4),
        "baseline_zscore_contribution": round(0.10 * z_score_prob, 4),
        "jurisdiction_risk_contribution": round(0.10 * jurisdiction_risk, 4),
        "crr_sender_contribution": round(0.10 * sender_risk, 4),
        "crr_receiver_contribution": round(0.10 * receiver_risk, 4),
        "pep_elevation": round(pep_elevation, 4),
        "rule_elevation": round(rule_elevation, 4),
        "amount_zscore": round(z_score, 4),
        "rule_escalated": rule_applied
    }

    return {
        "dynamic_risk_score": round(dynamic_score, 4),
        "top_drivers": top_drivers,
        "explainability": attributions
    }
