"""
Pure Multi-Layer Corporate UBO Ownership Tree Core
==================================================
Zero-I/O, exact fixed-point Decimal recursive equity ownership resolution with
cycle protection, >100% edge clamping, split-stake aggregation, and unattributed
opacity tracking (>25% FATF / FinCEN CDD Beneficial Ownership rule).
"""

from __future__ import annotations

from collections import defaultdict
from decimal import Decimal, ROUND_HALF_EVEN
from typing import Any, Dict, List, Mapping, Sequence, Set, Tuple

from domain.money import to_decimal


def _safe_pct(val: Any) -> Decimal:
    try:
        d = to_decimal(val, field_name="ownership_pct")
    except Exception:
        return Decimal("0")
    if d < Decimal("0"):
        return Decimal("0")
    if d > Decimal("100"):
        return Decimal("100")
    return d


def resolve_ubo_ownership_tree_pure(
    edges: Sequence[Mapping[str, Any]],
    target_company: str,
    threshold_pct: float | Decimal = Decimal("25.0"),
    max_depth: int = 10,
) -> Dict[str, Any]:
    """
    Pure multi-layer indirect equity ownership tree resolver for `target_company`.
    """
    target_norm = (target_company or "").strip()
    thresh_dec = _safe_pct(threshold_pct)
    if not target_norm:
        return {
            "target_company": "",
            "threshold_pct": float(thresh_dec),
            "ultimate_beneficial_owners": [],
            "nodes": [],
            "edges": [],
            "cycles_detected": False,
        }

    parents_by_child: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    canonical_name: Dict[str, str] = {target_norm.lower(): target_norm}

    for edge in edges:
        child = str(edge.get("child_company_name") or "").strip()
        parent = str(edge.get("parent_entity_name") or "").strip()
        pct = _safe_pct(edge.get("ownership_pct"))
        if not child or not parent or pct <= Decimal("0"):
            continue
        canonical_name.setdefault(child.lower(), child)
        canonical_name.setdefault(parent.lower(), parent)
        parents_by_child[child.lower()].append({
            "parent_name": parent,
            "parent_key": parent.lower(),
            "parent_type": str(edge.get("parent_entity_type") or "PERSON").upper(),
            "child_name": child,
            "child_key": child.lower(),
            "ownership_pct": pct,
            "jurisdiction": edge.get("jurisdiction") or "US",
            "tax_id": edge.get("tax_id"),
        })

    effective_stakes: Dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    entity_types: Dict[str, str] = {target_norm.lower(): "COMPANY"}
    entity_jurisdictions: Dict[str, str] = {}
    ownership_paths: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    visited_nodes: Set[str] = {target_norm.lower()}
    tree_edges: List[Dict[str, Any]] = []
    seen_edge_keys: Set[Tuple[str, str, Decimal]] = set()
    cycles_detected = False

    def _dfs(current_key: str, cumulative_factor: Decimal, path_keys: List[str], depth: int) -> None:
        nonlocal cycles_detected
        if depth >= max_depth:
            return
        for pe in parents_by_child.get(current_key, []):
            pkey = pe["parent_key"]
            pct: Decimal = pe["ownership_pct"]
            ek = (pkey, current_key, pct)
            if ek not in seen_edge_keys:
                seen_edge_keys.add(ek)
                tree_edges.append({
                    "parent": pe["parent_name"],
                    "parent_type": pe["parent_type"],
                    "child": canonical_name.get(current_key, pe["child_name"]),
                    "ownership_pct": float(pct.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)),
                    "jurisdiction": pe["jurisdiction"],
                })
            entity_types[pkey] = pe["parent_type"]
            entity_jurisdictions[pkey] = pe["jurisdiction"]
            visited_nodes.add(pkey)

            if pkey in path_keys:
                cycles_detected = True
                continue

            next_factor = cumulative_factor * (pct / Decimal("100"))
            next_path = path_keys + [pkey]

            is_leaf_owner = pe["parent_type"] == "PERSON" or not parents_by_child.get(pkey)
            if is_leaf_owner:
                effective_pct = next_factor * Decimal("100")
                effective_stakes[pkey] += effective_pct
                ownership_paths[pkey].append({
                    "chain": [canonical_name.get(k, k) for k in reversed(next_path)],
                    "effective_pct": float(effective_pct.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)),
                })
            else:
                _dfs(pkey, next_factor, next_path, depth + 1)

    _dfs(target_norm.lower(), Decimal("1"), [target_norm.lower()], 0)

    ubos: List[Dict[str, Any]] = []
    for entity_key, total_pct in sorted(effective_stakes.items(), key=lambda kv: kv[1], reverse=True):
        rounded_dec = total_pct.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
        ubos.append({
            "entity_name": canonical_name.get(entity_key, entity_key),
            "entity_type": entity_types.get(entity_key, "PERSON"),
            "jurisdiction": entity_jurisdictions.get(entity_key, "US"),
            "effective_ownership_pct": float(rounded_dec),
            "exceeds_threshold": rounded_dec >= thresh_dec,
            "is_split_ownership": len(ownership_paths[entity_key]) > 1,
            "paths": ownership_paths[entity_key],
        })

    nodes = [
        {
            "id": k,
            "label": canonical_name.get(k, k),
            "type": entity_types.get(k, "COMPANY"),
            "jurisdiction": entity_jurisdictions.get(k, "US"),
            "effective_ownership_pct": (
                float(effective_stakes[k].quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN))
                if k in effective_stakes
                else None
            ),
        }
        for k in sorted(visited_nodes)
    ]

    total_attributed = sum(effective_stakes.values(), Decimal("0"))
    unattributed_dec = max(Decimal("0"), Decimal("100") - total_attributed).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_EVEN
    )

    return {
        "target_company": canonical_name.get(target_norm.lower(), target_norm),
        "threshold_pct": float(thresh_dec),
        "ubo_count_above_threshold": sum(1 for u in ubos if u["exceeds_threshold"]),
        "unattributed_ownership_pct": float(unattributed_dec),
        "ultimate_beneficial_owners": ubos,
        "nodes": nodes,
        "edges": tree_edges,
        "cycles_detected": cycles_detected,
    }
