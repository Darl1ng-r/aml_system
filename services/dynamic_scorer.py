"""
Dynamic Risk-Based Approach (RBA) Scoring Service Facade
========================================================
Thin re-export adapter over the pure, zero-I/O domain scoring engine in
`domain/scoring_core.py`.
"""

from domain.scoring_core import (
    _apply_floors,
    _calc_z_score,
    _compute_pep_elevation,
    _extract_top_drivers,
    _safe_float,
    compute_dynamic_risk_pure as compute_dynamic_risk,
)

__all__ = [
    "_apply_floors",
    "_calc_z_score",
    "_compute_pep_elevation",
    "_extract_top_drivers",
    "_safe_float",
    "compute_dynamic_risk",
]
