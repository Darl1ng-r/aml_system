"""
Multi-Layer Corporate UBO Ownership Tree (>25% Indirect Equity) & Cross-Entity MDM Graph (P2-4)
================================================================================================
1. Recursive Indirect UBO Resolution:
   Traverses arbitrary layers of shell/holding companies with cycle protection,
   multiplying ownership percentages along each chain and aggregating split stakes
   across multiple intermediate entities (e.g., 15% via Shell A + 15% via Shell B =
   30% effective ownership > 25% FATF / FinCEN CDD Beneficial Ownership threshold).
2. Cross-Entity MDM (Master Data Management) Link Discovery:
   Uncovers hidden relationships across accounts sharing the same device fingerprint,
   Tax ID, or rapid mutual counterparty corridors.
"""

import logging
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple

logger = logging.getLogger("aml.ubo_resolver")


def resolve_ubo_ownership_tree(
    edges: List[Dict[str, Any]],
    target_company: str,
    threshold_pct: float = 25.0,
    max_depth: int = 10,
) -> Dict[str, Any]:
    """
    Computes multi-layer indirect equity ownership tree for `target_company`.
    Each edge dict expects:
      `parent_entity_name`, `parent_entity_type` ('PERSON' | 'COMPANY'),
      `child_company_name`, `ownership_pct` (0..100), optional `jurisdiction`, `tax_id`.
    """
    target_norm = (target_company or "").strip()
    if not target_norm:
        return {
            "target_company": "",
            "threshold_pct": threshold_pct,
            "ultimate_beneficial_owners": [],
            "nodes": [],
            "edges": [],
            "cycles_detected": False,
        }

    # Index parents by normalized child company name (case-insensitive)
    parents_by_child: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    canonical_name: Dict[str, str] = {target_norm.lower(): target_norm}

    for edge in edges:
        child = str(edge.get("child_company_name") or "").strip()
        parent = str(edge.get("parent_entity_name") or "").strip()
        pct = float(edge.get("ownership_pct") or 0.0)
        if not child or not parent or pct <= 0.0:
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

    effective_stakes: Dict[str, float] = defaultdict(float)
    entity_types: Dict[str, str] = {target_norm.lower(): "COMPANY"}
    entity_jurisdictions: Dict[str, str] = {}
    ownership_paths: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    visited_nodes: Set[str] = {target_norm.lower()}
    tree_edges: List[Dict[str, Any]] = []
    seen_edge_keys: Set[Tuple[str, str, float]] = set()
    cycles_detected = False

    def _dfs(current_key: str, cumulative_factor: float, path_keys: List[str], depth: int) -> None:
        nonlocal cycles_detected
        if depth >= max_depth:
            return
        parent_edges = parents_by_child.get(current_key, [])
        for pe in parent_edges:
            pkey = pe["parent_key"]
            pct = pe["ownership_pct"]
            ek = (pkey, current_key, pct)
            if ek not in seen_edge_keys:
                seen_edge_keys.add(ek)
                tree_edges.append({
                    "parent": pe["parent_name"],
                    "parent_type": pe["parent_type"],
                    "child": canonical_name.get(current_key, pe["child_name"]),
                    "ownership_pct": round(pct, 2),
                    "jurisdiction": pe["jurisdiction"],
                })
            entity_types[pkey] = pe["parent_type"]
            entity_jurisdictions[pkey] = pe["jurisdiction"]
            visited_nodes.add(pkey)

            if pkey in path_keys:
                cycles_detected = True
                continue

            next_factor = cumulative_factor * (pct / 100.0)
            next_path = path_keys + [pkey]

            # If this parent is a natural person OR a leaf holding company with no parents above it,
            # record its effective ownership contribution along this chain.
            is_leaf_owner = pe["parent_type"] == "PERSON" or not parents_by_child.get(pkey)
            if is_leaf_owner:
                effective_pct = next_factor * 100.0
                effective_stakes[pkey] += effective_pct
                ownership_paths[pkey].append({
                    "chain": [canonical_name.get(k, k) for k in reversed(next_path)],
                    "effective_pct": round(effective_pct, 2),
                })
            else:
                _dfs(pkey, next_factor, next_path, depth + 1)

    _dfs(target_norm.lower(), 1.0, [target_norm.lower()], 0)

    ubos: List[Dict[str, Any]] = []
    for entity_key, total_pct in sorted(effective_stakes.items(), key=lambda kv: kv[1], reverse=True):
        rounded = round(total_pct, 2)
        ubos.append({
            "entity_name": canonical_name.get(entity_key, entity_key),
            "entity_type": entity_types.get(entity_key, "PERSON"),
            "jurisdiction": entity_jurisdictions.get(entity_key, "US"),
            "effective_ownership_pct": rounded,
            "exceeds_threshold": rounded >= threshold_pct,
            "is_split_ownership": len(ownership_paths[entity_key]) > 1,
            "paths": ownership_paths[entity_key],
        })

    nodes = [
        {
            "id": k,
            "label": canonical_name.get(k, k),
            "type": entity_types.get(k, "COMPANY"),
            "jurisdiction": entity_jurisdictions.get(k, "US"),
            "effective_ownership_pct": round(effective_stakes.get(k, 0.0), 2) if k in effective_stakes else None,
        }
        for k in sorted(visited_nodes)
    ]

    return {
        "target_company": canonical_name.get(target_norm.lower(), target_norm),
        "threshold_pct": threshold_pct,
        "ubo_count_above_threshold": sum(1 for u in ubos if u["exceeds_threshold"]),
        "ultimate_beneficial_owners": ubos,
        "nodes": nodes,
        "edges": tree_edges,
        "cycles_detected": cycles_detected,
    }


async def find_cross_entity_mdm_links(
    conn: Any,
    account_number: str,
) -> Dict[str, Any]:
    """
    Uncovers hidden cross-entity Master Data Management (MDM) links for an account:
      1. Shared Tax ID across distinct account numbers
      2. Shared Device fingerprints across distinct accounts' transactions
      3. Shared Counterparty corridors (multiple accounts wiring to the same beneficiary)
    """
    subject = await conn.fetchrow(
        """
        SELECT id, account_number, owner_name, tax_id, swift_bic, status, risk_score
        FROM accounts
        WHERE account_number = $1;
        """,
        account_number,
    )
    if not subject:
        return {"account_number": account_number, "found": False, "links": []}

    acc_id = subject["id"]
    links: List[Dict[str, Any]] = []

    # 1. Shared Tax ID
    if subject.get("tax_id"):
        tax_rows = await conn.fetch(
            """
            SELECT id, account_number, owner_name, status, risk_score
            FROM accounts
            WHERE tax_id = $1 AND id <> $2
            LIMIT 20;
            """,
            subject["tax_id"],
            acc_id,
        )
        for r in (tax_rows or []):
            links.append({
                "link_type": "SHARED_TAX_ID",
                "confidence": 0.98,
                "linked_account_id": str(r["id"]),
                "linked_account_number": r["account_number"],
                "linked_owner_name": r["owner_name"],
                "shared_attribute": "tax_id",
                "risk_score": float(r["risk_score"] or 0.0),
            })

    # 2. Shared Device Fingerprint across transactions
    dev_rows = await conn.fetch(
        """
        WITH subject_devices AS (
            SELECT DISTINCT device
            FROM transactions
            WHERE sender_account_id = $1
              AND device IS NOT NULL
              AND device <> ''
              AND device <> 'UNKNOWN'
        )
        SELECT DISTINCT a.id, a.account_number, a.owner_name, a.risk_score, t.device
        FROM transactions t
        JOIN subject_devices sd ON t.device = sd.device
        JOIN accounts a ON t.sender_account_id = a.id
        WHERE t.sender_account_id <> $1
        LIMIT 20;
        """,
        acc_id,
    )
    for r in (dev_rows or []):
        links.append({
            "link_type": "SHARED_DEVICE",
            "confidence": 0.90,
            "linked_account_id": str(r["id"]),
            "linked_account_number": r["account_number"],
            "linked_owner_name": r["owner_name"],
            "shared_attribute": f"device:{r['device']}",
            "risk_score": float(r["risk_score"] or 0.0),
        })

    # 3. Shared High-Risk Counterparty Corridor (common beneficiary)
    cp_rows = await conn.fetch(
        """
        WITH subject_receivers AS (
            SELECT DISTINCT receiver_account_id
            FROM transactions
            WHERE sender_account_id = $1
            LIMIT 25
        )
        SELECT a.id, a.account_number, a.owner_name, a.risk_score, COUNT(DISTINCT t.receiver_account_id) AS shared_beneficiaries
        FROM transactions t
        JOIN subject_receivers sr ON t.receiver_account_id = sr.receiver_account_id
        JOIN accounts a ON t.sender_account_id = a.id
        WHERE t.sender_account_id <> $1
        GROUP BY a.id, a.account_number, a.owner_name, a.risk_score
        ORDER BY shared_beneficiaries DESC
        LIMIT 15;
        """,
        acc_id,
    )
    for r in (cp_rows or []):
        links.append({
            "link_type": "SHARED_COUNTERPARTY_CORRIDOR",
            "confidence": min(0.85, 0.55 + 0.10 * int(r["shared_beneficiaries"] or 1)),
            "linked_account_id": str(r["id"]),
            "linked_account_number": r["account_number"],
            "linked_owner_name": r["owner_name"],
            "shared_attribute": f"{int(r['shared_beneficiaries'] or 1)} shared beneficiary account(s)",
            "risk_score": float(r["risk_score"] or 0.0),
        })

    return {
        "account_number": subject["account_number"],
        "owner_name": subject["owner_name"],
        "found": True,
        "total_links": len(links),
        "links": links,
    }
