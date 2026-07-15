import math
import logging

logger = logging.getLogger(__name__)

def compute_dynamic_risk(
    rules_triggered: list[str],
    ml_score: float,
    amount: float,
    baseline: dict,
    iforest_score: float
) -> dict:
    """
    Computes a unified dynamic risk score [0.0, 1.0] by blending:
    - Rule-based alerts.
    - Logistic Regression ML anomaly score.
    - Customer baseline amount Z-score.
    - Isolation Forest structural anomaly score.
    """
    # 1. Z-score calculation for the transaction amount
    avg_amount = float(baseline.get("avg_amount", 0.0))
    var_amount = float(baseline.get("variance_amount", 0.0))
    std_amount = math.sqrt(var_amount)
    
    # Establish a minimum standard deviation to avoid division by zero and handle constant history
    min_std = avg_amount * 0.1 if avg_amount > 0.0 else 1.0
    effective_std = std_amount if std_amount > 0.0 else min_std
    
    z_score = (amount - avg_amount) / effective_std
    
    # Map Z-score to a [0.0, 1.0] probability-like space
    # We focus on positive deviations (amount larger than average)
    if amount > avg_amount:
        # Linear scaling: Z-score of 3.0 or higher maps to 1.0
        z_score_prob = min(max((amount - avg_amount) / (3.0 * effective_std), 0.0), 1.0)
    else:
        z_score_prob = 0.0

    # 2. Blend scores
    # Weights: ML Model (35%), Isolation Forest (35%), Z-score Baseline Deviation (30%)
    dynamic_score = (0.35 * ml_score) + (0.35 * iforest_score) + (0.30 * z_score_prob)
    
    # 3. Rule trigger scaling / escalations
    # If any deterministic rules triggered, establish a high baseline risk floor (e.g. 0.80)
    # and elevate the final score to ensure compliance visibility.
    rule_applied = False
    if rules_triggered:
        dynamic_score = max(dynamic_score, 0.80)
        rule_applied = True
        
    dynamic_score = min(max(dynamic_score, 0.0), 1.0)

    # 4. Generate attributions/explainability payload
    attributions = {
        "ml_model_contribution": round(0.35 * ml_score, 4),
        "isolation_forest_contribution": round(0.35 * iforest_score, 4),
        "baseline_zscore_contribution": round(0.30 * z_score_prob, 4),
        "amount_zscore": round(z_score, 4),
        "rule_escalated": rule_applied
    }

    return {
        "dynamic_risk_score": round(dynamic_score, 4),
        "explainability": attributions
    }
