import math
import logging

logger = logging.getLogger(__name__)

def _safe_float(val: any, default: float = 0.0) -> float:
    """Guards against NaN, Inf, and type-cast failures."""
    try:
        f = float(val)
        return default if (math.isnan(f) or math.isinf(f)) else f
    except (ValueError, TypeError):
        return default


def _calc_z_score(safe_amount: float, baseline: dict) -> tuple[float, float]:
    avg_amount = max(_safe_float(baseline.get("avg_amount", 0.0)), 0.0)
    var_amount = max(_safe_float(baseline.get("variance_amount", 0.0)), 0.0)
    if var_amount > 0.0:
        std_amount = math.sqrt(var_amount)
    elif "std_amount" in baseline and _safe_float(baseline.get("std_amount", 0.0)) > 0.0:
        std_amount = _safe_float(baseline.get("std_amount"))
    else:
        std_amount = 0.0

    if avg_amount > 0.0:
        min_std = max(avg_amount * 0.1, 1.0)
        effective_std = max(std_amount, min_std)
        z_score = (safe_amount - avg_amount) / effective_std
        z_score_prob = (
            min(max((safe_amount - avg_amount) / (3.0 * effective_std), 0.0), 1.0)
            if safe_amount > avg_amount
            else 0.0
        )
        return z_score, z_score_prob
    return 0.0, 0.0


def _compute_pep_elevation(pep_tier: str | None) -> float:
    if not pep_tier:
        return 0.0
    tier_str = str(pep_tier).upper()
    if "TIER_1" in tier_str or "HEAD_OF_STATE" in tier_str:
        return 0.25
    if "TIER_2" in tier_str or "MINISTER" in tier_str or "GOVERNMENT" in tier_str:
        return 0.15
    if "TIER_3" in tier_str or "JUDICIARY" in tier_str:
        return 0.10
    return 0.05


def _apply_floors(dynamic_score: float, z_score: float, c_taint: float, rules_triggered: list[str]) -> float:
    score = dynamic_score
    if rules_triggered:
        score = max(score, 0.80)
    if z_score >= 3.5:
        score = max(score, 0.80)
    if c_taint >= 0.70:
        score = max(score, c_taint)
    critical_rules = {"SANCTIONS_HIT", "CONDUIT_RAPID_PASSTHROUGH", "STRUCTURING_EXTENDED_7D"}
    if any(r in critical_rules for r in rules_triggered):
        score = max(score, 0.85)
    return score


def _extract_top_drivers(
    rules_triggered: list[str],
    z_score: float,
    c_jurisdiction: float,
    c_ml: float,
    pep_tier: str | None,
    c_taint: float,
) -> list[str]:
    top_drivers = []
    if rules_triggered:
        top_drivers.append(f"RULES_TRIGGERED: {', '.join(rules_triggered)}")
    if z_score >= 2.0:
        top_drivers.append(f"BEHAVIORAL_AMOUNT_SPIKE (Z={round(z_score, 2)})")
    if c_jurisdiction >= 0.70:
        top_drivers.append(f"HIGH_RISK_JURISDICTION ({round(c_jurisdiction, 2)})")
    if c_ml >= 0.70:
        top_drivers.append(f"AI_ANOMALY_CONFIDENCE ({round(c_ml, 2)})")
    if pep_tier:
        top_drivers.append(f"POLITICALLY_EXPOSED_PERSON ({pep_tier})")
    if c_taint >= 0.50:
        top_drivers.append(f"TRANSITIVE_TAINT_PROPAGATION ({round(c_taint, 2)})")
    if any("CONDUIT" in r for r in rules_triggered):
        top_drivers.append("CONDUIT_FUNDS_FLOW_THROUGH")
    if any("STRUCTURING_EXTENDED" in r for r in rules_triggered):
        top_drivers.append("EXTENDED_7D_STRUCTURING_CLUSTER")
    if any("JUST_BELOW" in r for r in rules_triggered):
        top_drivers.append("JUST_BELOW_CTR_REPORTING_THRESHOLD")
    return top_drivers


def compute_dynamic_risk(
    rules_triggered: list[str],
    ml_score: float,
    amount: float,
    baseline: dict,
    iforest_score: float,
    sender_risk: float = 0.1,
    receiver_risk: float = 0.1,
    pep_tier: str | None = None,
    jurisdiction_risk: float = 0.1,
    taint_risk: float = 0.0
) -> dict:
    """
    Computes a unified dynamic risk score [0.0, 1.0] using FATF Risk-Based Approach (RBA):
    - Base ML Blend (60%): Logistic Regression (30%) + Isolation Forest (30%)
    - Behavioral & Velocity Deviation (20%): Baseline Z-Score (10%) + Jurisdiction Risk (10%)
    - Customer Risk Rating / CRR (20%): Sender Risk (10%) + Receiver Risk (10%)
    - Dynamic Multipliers: PEP Tier Risk Elevation & Rule Floor Escalation
    - Non-Compensatory Floors: Prevents low ML scores from suppressing extreme behavioral or taint spikes
    """
    # 1. Input safety & Z-score calculation for transaction amount
    safe_amount = max(_safe_float(amount), 0.0)
    z_score, z_score_prob = _calc_z_score(safe_amount, baseline)

    # 2. Clamped Quant Inputs
    c_ml = min(max(_safe_float(ml_score), 0.0), 1.0)
    c_iforest = min(max(_safe_float(iforest_score), 0.0), 1.0)
    c_jurisdiction = min(max(_safe_float(jurisdiction_risk, 0.1), 0.0), 1.0)
    c_sender = min(max(_safe_float(sender_risk, 0.1), 0.0), 1.0)
    c_receiver = min(max(_safe_float(receiver_risk, 0.1), 0.0), 1.0)
    c_taint = min(max(_safe_float(taint_risk, 0.0), 0.0), 1.0)

    # 3. Weighted RBA Score Blend
    # 60% Model Probability + 20% Behavioral/Jurisdiction + 20% Counterparty CRR
    base_ml_component = (0.30 * c_ml) + (0.30 * c_iforest)
    behavioral_component = (0.10 * z_score_prob) + (0.10 * c_jurisdiction)
    crr_component = (0.10 * c_sender) + (0.10 * c_receiver)

    base_score = base_ml_component + behavioral_component + crr_component

    # 4. PEP Tier Multiplier / Risk Elevation
    pep_elevation = _compute_pep_elevation(pep_tier)

    # 5. Rule trigger scaling / escalations (M4)
    rule_applied = bool(rules_triggered)
    rule_elevation = 0.25 * len(rules_triggered) if rules_triggered else 0.0

    # Pre-floor additive score
    unclamped_score = base_score + pep_elevation + rule_elevation
    dynamic_score = _apply_floors(unclamped_score, z_score, c_taint, rules_triggered)
    final_score = round(min(max(dynamic_score, 0.0), 1.0), 4)

    # 6. Institutional Top Drivers for Compliance Examination (Verafin standard)
    top_drivers = _extract_top_drivers(rules_triggered, z_score, c_jurisdiction, c_ml, pep_tier, c_taint)

    # 8. Reconciled Attributions satisfying the Efficiency Axiom (OCC / Federal Reserve SR 11-7)
    # The sum of all additive factor contributions strictly equals final_score.
    base_contributions = {
        "ml_model_contribution": round(0.30 * c_ml, 4),
        "isolation_forest_contribution": round(0.30 * c_iforest, 4),
        "baseline_zscore_contribution": round(0.10 * z_score_prob, 4),
        "jurisdiction_risk_contribution": round(0.10 * c_jurisdiction, 4),
        "crr_sender_contribution": round(0.10 * c_sender, 4),
        "crr_receiver_contribution": round(0.10 * c_receiver, 4),
        "pep_elevation": round(pep_elevation, 4),
        "rule_elevation": round(rule_elevation, 4),
    }

    reconciled_contributions = dict(base_contributions)
    raw_sum = round(sum(base_contributions.values()), 4)

    # Reconcile floor elevation or clamp damping
    if final_score > raw_sum:
        reconciled_contributions["regulatory_floor_elevation"] = round(final_score - raw_sum, 4)
    elif final_score < raw_sum:
        reconciled_contributions["saturation_clamp_damping"] = round(final_score - raw_sum, 4)

    attribution_sum = round(sum(reconciled_contributions.values()), 4)

    attributions = {
        **base_contributions,
        "taint_risk_contribution": round(c_taint, 4),
        "amount_zscore": round(z_score, 4),
        "rule_escalated": rule_applied,
        "reconciled_contributions": reconciled_contributions,
        "attribution_sum": attribution_sum,
        "efficiency_axiom_verified": (attribution_sum == final_score),
    }

    return {
        "dynamic_risk_score": final_score,
        "top_drivers": top_drivers,
        "explainability": attributions
    }
