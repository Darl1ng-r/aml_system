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
    # 1. Z-score calculation for the transaction amount
    avg_amount = float(baseline.get("avg_amount", 0.0))
    var_amount = float(baseline.get("variance_amount", 0.0))
    std_amount = math.sqrt(var_amount)
    
    if avg_amount > 0.0:
        min_std = avg_amount * 0.1
        effective_std = std_amount if std_amount > 0.0 else min_std
        z_score = (amount - avg_amount) / effective_std
        
        if amount > avg_amount:
            z_score_prob = min(max((amount - avg_amount) / (3.0 * effective_std), 0.0), 1.0)
        else:
            z_score_prob = 0.0
    else:
        z_score = 0.0
        z_score_prob = 0.0

    # 2. Weighted RBA Score Blend
    # 60% Model Probability + 20% Behavioral/Jurisdiction + 20% Counterparty CRR
    base_ml_component = (0.30 * ml_score) + (0.30 * iforest_score)
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
    
    # 4. Rule trigger scaling / escalations
    rule_applied = False
    if rules_triggered:
        dynamic_score = max(dynamic_score, 0.80)
        rule_applied = True
        
    dynamic_score = min(max(dynamic_score, 0.0), 1.0)

    # 5. Generate attributions/explainability payload
    attributions = {
        "ml_model_contribution": round(0.30 * ml_score, 4),
        "isolation_forest_contribution": round(0.30 * iforest_score, 4),
        "baseline_zscore_contribution": round(0.10 * z_score_prob, 4),
        "jurisdiction_risk_contribution": round(0.10 * jurisdiction_risk, 4),
        "crr_sender_contribution": round(0.10 * sender_risk, 4),
        "crr_receiver_contribution": round(0.10 * receiver_risk, 4),
        "pep_elevation": round(pep_elevation, 4),
        "amount_zscore": round(z_score, 4),
        "rule_escalated": rule_applied
    }

    return {
        "dynamic_risk_score": round(dynamic_score, 4),
        "explainability": attributions
    }
