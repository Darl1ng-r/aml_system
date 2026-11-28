"""
Pure Dynamic Risk-Based Approach (RBA) Scoring Core
===================================================
Zero-I/O, deterministic FATF Risk-Based Approach scoring engine with
non-compensatory regulatory floors and OCC / Federal Reserve SR 11-7
Efficiency Axiom attribution reconciliation.
"""

from __future__ import annotations

import math
from typing import Any, Mapping, Sequence

# Minimum transitive taint score required to elevate the non-compensatory risk floor.
# Aligned with default 1-hop decay_factor=0.65 (upstream_risk >= 0.923 -> taint >= 0.60).
TAINT_FLOOR_THRESHOLD: float = 0.60

_NULL_PEP_TOKENS: frozenset[str] = frozenset({"", "NONE", "N/A", "NA", "NULL", "FALSE", "0", "-"})


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Guards against NaN, Inf, and type-cast failures."""
    try:
        f = float(val)
        return default if (math.isnan(f) or math.isinf(f)) else f
    except (ValueError, TypeError):
        return default


def _normalize_pep_tier(pep_tier: str | None) -> str | None:
    if pep_tier is None:
        return None
    cleaned = str(pep_tier).strip()
    if cleaned.upper() in _NULL_PEP_TOKENS:
        return None
    return cleaned


def _apportion_basis_points(raw_values: Mapping[str, float], target_bps: int) -> dict[str, int]:
    """
    Hamilton (largest-remainder) basis-points apportionment (10,000 bps = 1.0000).
    Guarantees sum(result.values()) == target_bps with zero rounding residual drift.
    """
    scaled = {k: v * 10_000.0 for k, v in raw_values.items()}
    floors = {k: math.floor(sv) for k, sv in scaled.items()}
    remainder = target_bps - sum(floors.values())
    if remainder > 0:
        ranked = sorted(raw_values.keys(), key=lambda k: (scaled[k] - floors[k]), reverse=True)
        for k in ranked[:remainder]:
            floors[k] += 1
    elif remainder < 0:
        ranked = sorted(raw_values.keys(), key=lambda k: (scaled[k] - floors[k]))
        for k in ranked[: abs(remainder)]:
            floors[k] -= 1
    return floors


def _calc_z_score(safe_amount: float, baseline: Mapping[str, Any]) -> tuple[float, float]:
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
    norm_pep = _normalize_pep_tier(pep_tier)
    if not norm_pep:
        return 0.0
    tier_str = norm_pep.upper()
    if "TIER_1" in tier_str or "HEAD_OF_STATE" in tier_str:
        return 0.25
    if "TIER_2" in tier_str or "MINISTER" in tier_str or "GOVERNMENT" in tier_str:
        return 0.15
    if "TIER_3" in tier_str or "JUDICIARY" in tier_str:
        return 0.10
    return 0.05


def _apply_floors(
    dynamic_score: float,
    z_score: float,
    c_taint: float,
    rules_triggered: Sequence[str],
) -> tuple[float, float]:
    score = dynamic_score
    if rules_triggered:
        score = max(score, 0.80)
    if z_score >= 3.5:
        score = max(score, 0.80)
    taint_elevation = 0.0
    if c_taint >= TAINT_FLOOR_THRESHOLD and c_taint > score:
        taint_elevation = c_taint - score
        score = c_taint
    critical_rules = {
        "SANCTIONS_HIT",
        "SANCTIONS_SCREENING_UNAVAILABLE",
        "CONDUIT_RAPID_PASSTHROUGH",
        "STRUCTURING_EXTENDED_7D",
    }
    if any(r in critical_rules for r in rules_triggered):
        score = max(score, 0.85)
    return score, taint_elevation


def _extract_top_drivers(
    rules_triggered: Sequence[str],
    z_score: float,
    c_jurisdiction: float,
    c_ml: float,
    pep_tier: str | None,
    c_taint: float,
) -> list[str]:
    norm_pep = _normalize_pep_tier(pep_tier)
    top_drivers: list[str] = []
    if rules_triggered:
        top_drivers.append(f"RULES_TRIGGERED: {', '.join(rules_triggered)}")
    if z_score >= 2.0:
        top_drivers.append(f"BEHAVIORAL_AMOUNT_SPIKE (Z={round(z_score, 2)})")
    if c_jurisdiction >= 0.70:
        top_drivers.append(f"HIGH_RISK_JURISDICTION ({round(c_jurisdiction, 2)})")
    if c_ml >= 0.70:
        top_drivers.append(f"AI_ANOMALY_CONFIDENCE ({round(c_ml, 2)})")
    if norm_pep:
        top_drivers.append(f"POLITICALLY_EXPOSED_PERSON ({norm_pep})")
    if c_taint >= TAINT_FLOOR_THRESHOLD:
        top_drivers.append(f"TRANSITIVE_TAINT_PROPAGATION ({round(c_taint, 2)})")
    if any("CONDUIT" in r for r in rules_triggered):
        top_drivers.append("CONDUIT_FUNDS_FLOW_THROUGH")
    if any("STRUCTURING_EXTENDED" in r for r in rules_triggered):
        top_drivers.append("EXTENDED_7D_STRUCTURING_CLUSTER")
    if any("JUST_BELOW" in r for r in rules_triggered):
        top_drivers.append("JUST_BELOW_CTR_REPORTING_THRESHOLD")
    return top_drivers


def compute_dynamic_risk_pure(
    rules_triggered: Sequence[str],
    ml_score: float,
    amount: float,
    baseline: Mapping[str, Any],
    iforest_score: float,
    sender_risk: float = 0.1,
    receiver_risk: float = 0.1,
    pep_tier: str | None = None,
    jurisdiction_risk: float = 0.1,
    taint_risk: float = 0.0,
) -> dict[str, Any]:
    """
    Pure FATF Risk-Based Approach (RBA) unified risk score [0.0, 1.0]:
      - 60% Model Probability (30% ML + 30% Isolation Forest)
      - 20% Behavioral & Jurisdiction (10% Z-score + 10% Jurisdiction)
      - 20% Counterparty CRR (10% Sender + 10% Receiver)
      - PEP elevation + rule escalation + non-compensatory floors
      - Exact SR 11-7 Efficiency Axiom verified attributions via largest-remainder bps apportionment.
    """
    safe_amount = max(_safe_float(amount), 0.0)
    z_score, z_score_prob = _calc_z_score(safe_amount, baseline or {})

    c_ml = min(max(_safe_float(ml_score), 0.0), 1.0)
    c_iforest = min(max(_safe_float(iforest_score), 0.0), 1.0)
    c_jurisdiction = min(max(_safe_float(jurisdiction_risk, 0.1), 0.0), 1.0)
    c_sender = min(max(_safe_float(sender_risk, 0.1), 0.0), 1.0)
    c_receiver = min(max(_safe_float(receiver_risk, 0.1), 0.0), 1.0)
    c_taint = min(max(_safe_float(taint_risk, 0.0), 0.0), 1.0)

    raw_base_contributions = {
        "ml_model_contribution": 0.30 * c_ml,
        "isolation_forest_contribution": 0.30 * c_iforest,
        "baseline_zscore_contribution": 0.10 * z_score_prob,
        "jurisdiction_risk_contribution": 0.10 * c_jurisdiction,
        "crr_sender_contribution": 0.10 * c_sender,
        "crr_receiver_contribution": 0.10 * c_receiver,
        "pep_elevation": _compute_pep_elevation(pep_tier),
        "rule_elevation": 0.25 * len(rules_triggered) if rules_triggered else 0.0,
    }
    rule_applied = bool(rules_triggered)
    unclamped_score = sum(raw_base_contributions.values())

    dynamic_score, taint_floor_elevation = _apply_floors(unclamped_score, z_score, c_taint, rules_triggered)
    clamped_score = min(max(dynamic_score, 0.0), 1.0)

    unclamped_bps = int(round(unclamped_score * 10_000.0))
    final_bps = int(round(clamped_score * 10_000.0))
    final_score = round(final_bps / 10_000.0, 4)

    top_drivers = _extract_top_drivers(rules_triggered, z_score, c_jurisdiction, c_ml, pep_tier, c_taint)

    # Apportion raw base components in integer basis points so sum(base) == unclamped_bps exactly.
    # This eliminates spurious +/-0.0002 rounding drift masquerading as a regulatory floor or clamp.
    base_bps = _apportion_basis_points(raw_base_contributions, unclamped_bps)
    base_contributions = {k: round(bps / 10_000.0, 4) for k, bps in base_bps.items()}

    reconciled_bps = dict(base_bps)
    diff_bps = final_bps - unclamped_bps
    if diff_bps > 0:
        reconciled_bps["regulatory_floor_elevation"] = diff_bps
    elif diff_bps < 0:
        reconciled_bps["saturation_clamp_damping"] = diff_bps

    reconciled_contributions = {k: round(bps / 10_000.0, 4) for k, bps in reconciled_bps.items()}
    attribution_sum = round(sum(reconciled_bps.values()) / 10_000.0, 4)

    attributions: dict[str, Any] = {
        **base_contributions,
        "taint_risk_contribution": round(c_taint, 4),
        "taint_floor_elevation": round(taint_floor_elevation, 4),
        "amount_zscore": round(z_score, 4),
        "rule_escalated": rule_applied,
        "reconciled_contributions": reconciled_contributions,
        "attribution_sum": attribution_sum,
        "efficiency_axiom_verified": sum(reconciled_bps.values()) == final_bps,
    }

    return {
        "dynamic_risk_score": final_score,
        "top_drivers": top_drivers,
        "explainability": attributions,
    }
