"""
Pure Multi-Layer Corporate UBO Ownership Tree Core
==================================================
Zero-I/O, exact fixed-point Decimal absorbing Markov-chain equity ownership solver
(Leontief inverse via sparse Gauss-Seidel in 40-digit Decimal arithmetic) with:
  - Duplicate (parent, child) edge deduplication & over-100% proportional normalization
  - Exact cyclic cross-ownership resolution: x = e_target + Q^T x
  - Non-convergent closed-loop detection (`ownership_loop_unresolved`)
  - Exact unrounded threshold comparisons (>25% FATF / FinCEN CDD rule)
  - Bounded display path extraction independent of equity math (`paths_truncated`).
"""

from __future__ import annotations

from collections import defaultdict, deque
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
from typing import Any, Dict, List, Mapping, Sequence, Set, Tuple

from domain.money import to_decimal

_SOLVER_PREC = 40
_SOLVER_TOL = Decimal("1e-12")
_SOLVER_MAX_ITER = 10_000
_SOLVER_DIVERGE_CEILING = Decimal("1e6")
_MAX_DISPLAY_PATHS = 200


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


def _detect_reachable_cycles(
    target_key: str,
    parents_by_child: Mapping[str, Sequence[Dict[str, Any]]],
    reachable: Set[str],
) -> bool:
    """3-color iterative DFS cycle detector restricted to the reachable subgraph."""
    # 0 = unvisited, 1 = on recursion stack, 2 = completed
    color: Dict[str, int] = {}
    for start in (target_key, *sorted(reachable - {target_key})):
        if color.get(start, 0) != 0:
            continue
        stack: List[Tuple[str, int]] = [(start, 0)]
        color[start] = 1
        while stack:
            node, idx = stack[-1]
            plist = parents_by_child.get(node, ())
            if idx < len(plist):
                stack[-1] = (node, idx + 1)
                nxt = plist[idx]["parent_key"]
                if nxt not in reachable:
                    continue
                c = color.get(nxt, 0)
                if c == 1:
                    return True
                if c == 0:
                    color[nxt] = 1
                    stack.append((nxt, 0))
            else:
                color[node] = 2
                stack.pop()
    return False


def resolve_ubo_ownership_tree_pure(
    edges: Sequence[Mapping[str, Any]],
    target_company: str,
    threshold_pct: float | Decimal = Decimal("25.0"),
    max_depth: int = 10,
) -> Dict[str, Any]:
    """
    Pure multi-layer indirect equity ownership resolver for `target_company`.
    Computes exact absorbing Markov-chain stakes even in the presence of
    cross-holding cycles, while bounding visualization paths via `max_depth`.
    """
    target_norm = (target_company or "").strip()
    thresh_dec = _safe_pct(threshold_pct)
    if not target_norm:
        return {
            "target_company": "",
            "threshold_pct": float(thresh_dec),
            "ubo_count_above_threshold": 0,
            "unattributed_ownership_pct": 100.0,
            "ultimate_beneficial_owners": [],
            "nodes": [],
            "edges": [],
            "cycles_detected": False,
            "duplicate_edges_collapsed": 0,
            "over_allocated_entities": [],
            "paths_truncated": False,
            "ownership_loop_unresolved": False,
        }

    target_key = target_norm.lower()
    canonical_name: Dict[str, str] = {target_key: target_norm}
    entity_types: Dict[str, str] = {target_key: "COMPANY"}
    entity_jurisdictions: Dict[str, str] = {}

    # 1. Deduplicate (parent_key, child_key) edges so duplicate records never double-count equity.
    dedup_edges: Dict[Tuple[str, str], Dict[str, Any]] = {}
    duplicate_edges_collapsed = 0

    for edge in edges:
        child = str(edge.get("child_company_name") or "").strip()
        parent = str(edge.get("parent_entity_name") or "").strip()
        pct = _safe_pct(edge.get("ownership_pct"))
        if not child or not parent or pct <= Decimal("0"):
            continue
        ckey = child.lower()
        pkey = parent.lower()
        canonical_name.setdefault(ckey, child)
        canonical_name.setdefault(pkey, parent)

        pair = (pkey, ckey)
        entry = {
            "parent_name": parent,
            "parent_key": pkey,
            "parent_type": str(edge.get("parent_entity_type") or "PERSON").upper(),
            "child_name": child,
            "child_key": ckey,
            "ownership_pct": pct,
            "jurisdiction": edge.get("jurisdiction") or "US",
            "tax_id": edge.get("tax_id"),
        }
        if pair in dedup_edges:
            duplicate_edges_collapsed += 1
            if pct > dedup_edges[pair]["ownership_pct"]:
                dedup_edges[pair] = entry
        else:
            dedup_edges[pair] = entry

    parents_by_child: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for entry in dedup_edges.values():
        parents_by_child[entry["child_key"]].append(entry)

    # max_depth <= 0 explicitly requests zero hop expansion
    if max_depth <= 0:
        return {
            "target_company": canonical_name.get(target_key, target_norm),
            "threshold_pct": float(thresh_dec),
            "ubo_count_above_threshold": 0,
            "unattributed_ownership_pct": 100.0,
            "ultimate_beneficial_owners": [],
            "nodes": [
                {
                    "id": target_key,
                    "label": canonical_name.get(target_key, target_norm),
                    "type": "COMPANY",
                    "jurisdiction": entity_jurisdictions.get(target_key, "US"),
                    "effective_ownership_pct": None,
                }
            ],
            "edges": [],
            "cycles_detected": False,
            "duplicate_edges_collapsed": duplicate_edges_collapsed,
            "over_allocated_entities": [],
            "paths_truncated": bool(parents_by_child.get(target_key)),
            "ownership_loop_unresolved": False,
        }

    # 2. Discover reachable ownership graph from target_key (BFS)
    visited_nodes: Set[str] = {target_key}
    queue: deque[str] = deque([target_key])
    tree_edges: List[Dict[str, Any]] = []
    seen_tree_pairs: Set[Tuple[str, str]] = set()

    while queue:
        curr = queue.popleft()
        # Do not expand upward past a natural person even if malformed edges list parents for a PERSON
        if curr != target_key and entity_types.get(curr) == "PERSON":
            continue
        for pe in parents_by_child.get(curr, []):
            pkey = pe["parent_key"]
            pct = pe["ownership_pct"]
            entity_types[pkey] = pe["parent_type"]
            entity_jurisdictions[pkey] = pe["jurisdiction"]
            if (pkey, curr) not in seen_tree_pairs:
                seen_tree_pairs.add((pkey, curr))
                tree_edges.append({
                    "parent": pe["parent_name"],
                    "parent_type": pe["parent_type"],
                    "child": canonical_name.get(curr, pe["child_name"]),
                    "ownership_pct": float(pct.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)),
                    "jurisdiction": pe["jurisdiction"],
                })
            if pkey not in visited_nodes:
                visited_nodes.add(pkey)
                queue.append(pkey)

    cycles_detected = _detect_reachable_cycles(target_key, parents_by_child, visited_nodes)

    # 3. Partition reachable nodes into transient (corporate) nodes C and absorbing (leaf) owners L.
    corp_nodes: List[str] = []
    corp_set: Set[str] = set()
    leaf_set: Set[str] = set()
    for node in sorted(visited_nodes):
        if node == target_key:
            corp_nodes.append(node)
            corp_set.add(node)
        elif entity_types.get(node) == "PERSON" or not parents_by_child.get(node):
            leaf_set.add(node)
        else:
            corp_nodes.append(node)
            corp_set.add(node)

    # 4. Build normalized transition weights Q (corp -> corp) and R (corp -> leaf) in 40-digit Decimal.
    over_allocated_entities: List[str] = []
    incoming_corp: Dict[str, List[Tuple[str, Decimal]]] = defaultdict(list)  # parent_corp -> [(child_corp, w)]
    leaf_weights: Dict[str, List[Tuple[str, Decimal]]] = defaultdict(list)   # leaf -> [(child_corp, w)]

    with localcontext() as ctx:
        ctx.prec = _SOLVER_PREC
        hundred = Decimal("100")

        for child in corp_nodes:
            plist = parents_by_child.get(child, [])
            if not plist:
                continue
            total_pct = sum((pe["ownership_pct"] for pe in plist), Decimal("0"))
            denom = hundred
            if total_pct > hundred:
                over_allocated_entities.append(canonical_name.get(child, child))
                denom = total_pct

            for pe in plist:
                pkey = pe["parent_key"]
                w = pe["ownership_pct"] / denom
                if pkey in corp_set:
                    incoming_corp[pkey].append((child, w))
                elif pkey in leaf_set:
                    leaf_weights[pkey].append((child, w))

        # 5. Solve x = e_target + Q^T x via sparse Gauss-Seidel iteration.
        x: Dict[str, Decimal] = {c: (Decimal("1") if c == target_key else Decimal("0")) for c in corp_nodes}
        ownership_loop_unresolved = False

        if any(incoming_corp.values()):
            converged = False
            for _ in range(_SOLVER_MAX_ITER):
                max_diff = Decimal("0")
                for k in corp_nodes:
                    new_val = Decimal("1") if k == target_key else Decimal("0")
                    for child, w in incoming_corp.get(k, ()):
                        new_val += w * x[child]
                    diff = abs(new_val - x[k])
                    if diff > max_diff:
                        max_diff = diff
                    x[k] = new_val
                    if new_val > _SOLVER_DIVERGE_CEILING:
                        ownership_loop_unresolved = True
                        break
                if ownership_loop_unresolved:
                    break
                if max_diff <= _SOLVER_TOL:
                    converged = True
                    break
            if not converged:
                ownership_loop_unresolved = True

        # 6. Compute ultimate owner effective stakes (in percentage points 0..100).
        effective_stakes: Dict[str, Decimal] = {}
        if not ownership_loop_unresolved:
            for leaf in sorted(leaf_set):
                stake_frac = sum((w * x[child] for child, w in leaf_weights.get(leaf, ())), Decimal("0"))
                if stake_frac > Decimal("0"):
                    effective_stakes[leaf] = min(stake_frac * hundred, hundred)

    # 7. Extract bounded simple visualization paths (does NOT affect computed equity stakes).
    ownership_paths: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    paths_truncated = False
    total_paths_recorded = 0

    def _collect_paths(current_key: str, cumulative_factor: Decimal, path_keys: List[str], depth: int) -> None:
        nonlocal paths_truncated, total_paths_recorded
        if total_paths_recorded >= _MAX_DISPLAY_PATHS:
            paths_truncated = True
            return
        if depth >= max_depth:
            if parents_by_child.get(current_key):
                paths_truncated = True
            return

        plist = parents_by_child.get(current_key, [])
        if not plist:
            return
        total_pct = sum((pe["ownership_pct"] for pe in plist), Decimal("0"))
        denom = total_pct if total_pct > Decimal("100") else Decimal("100")

        for pe in plist:
            if total_paths_recorded >= _MAX_DISPLAY_PATHS:
                paths_truncated = True
                return
            pkey = pe["parent_key"]
            if pkey in path_keys:
                continue
            next_factor = cumulative_factor * (pe["ownership_pct"] / denom)
            next_path = path_keys + [pkey]
            if pkey in leaf_set:
                eff_pct = next_factor * Decimal("100")
                ownership_paths[pkey].append({
                    "chain": [canonical_name.get(k, k) for k in reversed(next_path)],
                    "effective_pct": float(eff_pct.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)),
                })
                total_paths_recorded += 1
            else:
                _collect_paths(pkey, next_factor, next_path, depth + 1)

    _collect_paths(target_key, Decimal("1"), [target_key], 0)

    # If the Markov solver diverged on a pure closed loop (rho(Q) == 1),
    # fall back to non-cyclic simple path stakes for any acyclic leaf branches.
    if ownership_loop_unresolved:
        for leaf, plist in ownership_paths.items():
            path_sum = sum((Decimal(str(p["effective_pct"])) for p in plist), Decimal("0"))
            if path_sum > Decimal("0"):
                effective_stakes[leaf] = min(path_sum, Decimal("100"))

    # 8. Build output sorted by descending stake; compare unrounded Decimal against threshold!
    ubos: List[Dict[str, Any]] = []
    for entity_key, total_pct in sorted(effective_stakes.items(), key=lambda kv: kv[1], reverse=True):
        rounded_dec = total_pct.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
        ubos.append({
            "entity_name": canonical_name.get(entity_key, entity_key),
            "entity_type": entity_types.get(entity_key, "PERSON"),
            "jurisdiction": entity_jurisdictions.get(entity_key, "US"),
            "effective_ownership_pct": float(rounded_dec),
            "exceeds_threshold": total_pct >= thresh_dec,
            "is_split_ownership": len(ownership_paths[entity_key]) > 1 or len(leaf_weights.get(entity_key, ())) > 1,
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
        "target_company": canonical_name.get(target_key, target_norm),
        "threshold_pct": float(thresh_dec),
        "ubo_count_above_threshold": sum(1 for u in ubos if u["exceeds_threshold"]),
        "unattributed_ownership_pct": float(unattributed_dec),
        "ultimate_beneficial_owners": ubos,
        "nodes": nodes,
        "edges": tree_edges,
        "cycles_detected": cycles_detected,
        "duplicate_edges_collapsed": duplicate_edges_collapsed,
        "over_allocated_entities": sorted(over_allocated_entities),
        "paths_truncated": paths_truncated,
        "ownership_loop_unresolved": ownership_loop_unresolved,
    }
