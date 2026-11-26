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
from decimal import Decimal
from typing import Any, Dict, List

from domain.ubo_core import resolve_ubo_ownership_tree_pure

logger = logging.getLogger("aml.ubo_resolver")


def resolve_ubo_ownership_tree(
    edges: List[Dict[str, Any]],
    target_company: str,
    threshold_pct: float | Decimal = 25.0,
    max_depth: int = 10,
) -> Dict[str, Any]:
    """
    Delegates multi-layer indirect equity ownership tree resolution to the pure
    zero-I/O domain engine (`domain/ubo_core.py`).
    """
    return resolve_ubo_ownership_tree_pure(
        edges=edges,
        target_company=target_company,
        threshold_pct=threshold_pct,
        max_depth=max_depth,
    )


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
