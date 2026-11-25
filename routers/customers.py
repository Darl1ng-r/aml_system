"""
Customer 360 Dossier Router
============================
Aggregates customer identity, CIP/KYC verification, dynamic risk scores,
PEP & Sanctions status, adverse media hits, Neo4j UBO graph, and 12-month
transaction activity into a consolidated compliance dossier (Part 3, P-03).
"""

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from database.postgres import get_async_db_conn, get_async_db_read_conn
from database.neo4j_db import get_async_neo4j_driver
from database.elasticsearch_db import get_async_elasticsearch_client
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/customers", tags=["Customer 360"])


def _escape_ilike(val: str) -> str:
    return val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("")
@router.get("/")
async def list_customers(
    page: int = Query(default=1, ge=1, le=1000),
    limit: int = Query(default=25, ge=1, le=100),
    search: Optional[str] = Query(None, max_length=200, description="Search by name, account number, or BIC"),
    risk_tier: Optional[str] = Query(None, max_length=32, description="Filter by risk tier (LOW, MEDIUM, HIGH, CRITICAL)"),
    status: Optional[str] = Query(None, max_length=32, description="Account status (ACTIVE, FROZEN, EDD_REQUIRED)"),
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Lists customer accounts with aggregated risk status and search."""
    tenant_id = enforce_tenant_data_scope(current_user)
    offset = (page - 1) * limit

    conditions = ["tenant_id = $1"]
    params = [uuid.UUID(str(tenant_id))]
    p_idx = 2

    if search:
        safe_search = _escape_ilike(search)
        conditions.append(
            f"(owner_name ILIKE ${p_idx} ESCAPE '\\' OR account_number ILIKE ${p_idx} ESCAPE '\\' OR swift_bic ILIKE ${p_idx} ESCAPE '\\')"
        )
        params.append(f"%{safe_search}%")
        p_idx += 1

    if risk_tier:
        conditions.append(f"risk_category = ${p_idx}")
        params.append(risk_tier.upper())
        p_idx += 1

    if status:
        conditions.append(f"status = ${p_idx}")
        params.append(status.upper())
        p_idx += 1

    where_clause = " AND ".join(conditions)

    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        total = await conn.fetchval(f"SELECT COUNT(*) FROM accounts WHERE {where_clause};", *params)
        query = f"""
            SELECT id, account_number, swift_bic, owner_name, status,
                   risk_score, risk_category, created_at, frozen_reason
            FROM accounts
            WHERE {where_clause}
            ORDER BY risk_score DESC, created_at DESC
            LIMIT ${p_idx} OFFSET ${p_idx + 1};
        """
        rows = await conn.fetch(query, *params, limit, offset)

        items = []
        for r in rows:
            items.append({
                "id": str(r["id"]),
                "account_number": r["account_number"],
                "swift_bic": r["swift_bic"],
                "owner_name": r["owner_name"],
                "status": r["status"] or "ACTIVE",
                "risk_score": float(r["risk_score"] or 0.0),
                "risk_tier": r["risk_category"] or "STANDARD",
                "created_at": r["created_at"].isoformat() if r["created_at"] else "",
                "is_frozen": r["status"] == "FROZEN",
                "frozen_reason": r.get("frozen_reason")
            })

        return {
            "items": items,
            "total": total or 0,
            "page": page,
            "limit": limit
        }


@router.post("/pkyc/rescreen-delta")
async def trigger_pkyc_delta_rescreen(
    limit: int = Query(default=100, ge=1, le=500),
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    """
    Perpetual KYC (pKYC) Delta Rescreening (P1-5):
    Re-screens active customer accounts against OFAC/UN/EU sanctions & PEP watchlists
    and generates EDD alerts + MLRO notifications on material risk changes.
    """
    from services.pkyc_and_qa import run_pkyc_delta_rescreen

    tenant_id = enforce_tenant_data_scope(current_user)
    es = None
    try:
        es = await get_async_elasticsearch_client()
    except Exception:
        es = None

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        return await run_pkyc_delta_rescreen(
            conn=conn,
            tenant_id=tenant_id,
            triggered_by=current_user.get("username", "mlro"),
            limit=limit,
            es_client=es,
        )


@router.get("/pkyc/runs")
async def list_pkyc_rescreen_runs(
    limit: int = Query(default=20, ge=1, le=100),
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "AUDITOR", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Returns audit history of Perpetual KYC delta rescreening sweeps."""
    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, triggered_by, accounts_scanned, material_changes_found,
                   alerts_generated, started_at, completed_at
            FROM pkyc_rescreen_runs
            ORDER BY started_at DESC
            LIMIT $1;
            """,
            limit,
        )
    return [
        {
            "run_id": str(r["id"]),
            "triggered_by": r["triggered_by"],
            "accounts_scanned": int(r["accounts_scanned"] or 0),
            "material_changes_found": int(r["material_changes_found"] or 0),
            "alerts_generated": int(r["alerts_generated"] or 0),
            "started_at": r["started_at"].isoformat() if r["started_at"] else None,
            "completed_at": r["completed_at"].isoformat() if r["completed_at"] else None,
        }
        for r in (rows or [])
    ]


async def _fetch_customer_activity(conn, acc_num: str, acc_uuid: uuid.UUID):
    tx_rows = await conn.fetch(
        """
        SELECT id, amount, currency, timestamp,
               sender_account_id, receiver_account_id
        FROM transactions
        WHERE sender_account_id = $1 OR receiver_account_id = $1
        ORDER BY timestamp DESC
        LIMIT 30;
        """,
        acc_uuid
    )
    recent_txs = [
        {
            "id": str(r["id"]),
            "amount": float(r["amount"]),
            "currency": r["currency"],
            "timestamp": r["timestamp"].isoformat() if r["timestamp"] else "",
            "type": "OUTBOUND" if str(r["sender_account_id"]) in (str(acc_uuid), str(acc_num)) else "INBOUND",
            "counterparty": str(r["receiver_account_id"] if str(r["sender_account_id"]) in (str(acc_uuid), str(acc_num)) else r["sender_account_id"])
        }
        for r in tx_rows
    ]

    monthly_rows = await conn.fetch(
        """
        SELECT TO_CHAR(timestamp, 'YYYY-MM') as month,
               COUNT(*) as tx_count,
               SUM(amount) as total_volume
        FROM transactions
        WHERE (sender_account_id = $1 OR receiver_account_id = $1)
          AND timestamp >= NOW() - INTERVAL '12 months'
        GROUP BY TO_CHAR(timestamp, 'YYYY-MM')
        ORDER BY month ASC;
        """,
        acc_uuid
    )
    monthly_trend = [
        {"month": r["month"], "tx_count": int(r["tx_count"]), "volume": float(r["total_volume"] or 0.0)}
        for r in monthly_rows
    ]

    alert_rows = await conn.fetch(
        """
        SELECT a.id, a.rule_name, a.threat_level, a.ai_risk_score, a.status, a.created_at
        FROM alerts a
        JOIN transactions t ON a.transaction_id = t.id
        WHERE t.sender_account_id = $1 OR t.receiver_account_id = $1
        ORDER BY a.created_at DESC
        LIMIT 15;
        """,
        acc_uuid
    )
    alerts = [
        {
            "id": str(r["id"]),
            "rule_name": r["rule_name"],
            "threat_level": r["threat_level"],
            "score": float(r["ai_risk_score"] or 0.0),
            "status": r["status"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else ""
        }
        for r in alert_rows
    ]

    edd_rows = await conn.fetch(
        """
        SELECT id, trigger_reason, status, mlro_decision, created_at
        FROM edd_requests
        WHERE account_id = $1
        ORDER BY created_at DESC;
        """,
        acc_uuid
    )
    edd_records = [
        {
            "id": str(r["id"]),
            "trigger_reason": r["trigger_reason"],
            "status": r["status"],
            "decision": r["mlro_decision"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else ""
        }
        for r in edd_rows
    ]
    return recent_txs, monthly_trend, alerts, edd_records


async def _fetch_customer_ubo(
    acc_num: str,
    owner_name: str,
    customer_id: str,
    tenant_id: str | None = None,
) -> list[dict]:
    ubo_nodes = []
    try:
        driver = await get_async_neo4j_driver()
        async with driver.session() as session:
            result = await session.run(
                """
                MATCH (p:Person)-[r:OWNS_UBO]->(c:Company)
                WHERE ($tenant_id IS NULL OR (c.tenant_id = $tenant_id AND p.tenant_id = $tenant_id))
                  AND (c.account_number = $acc_num OR c.name = $owner_name)
                RETURN p.name as name, p.tax_id as tax_id, r.percentage as percentage
                LIMIT 10;
                """,
                acc_num=acc_num,
                owner_name=owner_name,
                tenant_id=str(tenant_id) if tenant_id else None,
            )
            records = await result.data()
            for rec in records:
                ubo_nodes.append({
                    "name": rec["name"],
                    "tax_id": rec.get("tax_id") or "N/A",
                    "percentage": float(rec.get("percentage") or 0.0)
                })
    except Exception as ne:
        logger.debug(f"Neo4j UBO lookup bypassed for customer {customer_id}: {ne}")
    return ubo_nodes


def _calculate_customer_risk_factors(
    swift_bic: str | None,
    tx_count: int,
    risk_score: float,
    pep_match_count: int = 0,
    alerts: list[dict] | None = None,
    edd_records: list[dict] | None = None
) -> dict:
    high_risk_bic = bool(swift_bic and len(swift_bic) >= 6 and swift_bic[4:6] in ["RU", "IR", "KP", "SY", "MM", "YE", "VE"])
    alert_rules = [str(a.get("rule_name", "")).upper() for a in (alerts or [])]
    edd_reasons = [str(e.get("trigger_reason", "")).upper() for e in (edd_records or [])]
    has_pep_alert = any("PEP" in r or "SANCTION" in r for r in alert_rules)
    has_pep_edd = any("PEP" in r for r in edd_reasons)
    has_media_alert = any("ADVERSE" in r or "MEDIA" in r or "SANCTION" in r for r in alert_rules)

    if pep_match_count > 0 or has_pep_alert:
        pep_risk = 0.90
    elif has_pep_edd:
        pep_risk = 0.65
    else:
        pep_risk = 0.05

    adverse_media_risk = 0.80 if has_media_alert else 0.05
    geo_risk = 0.85 if high_risk_bic else (round(min(0.75, risk_score * 0.55), 2) if risk_score >= 0.70 else 0.15)
    vel_risk = min(1.0, tx_count * 0.08) if tx_count > 0 else (round(min(0.80, risk_score * 0.70), 2) if risk_score >= 0.70 else 0.0)

    return {
        "jurisdiction_risk": geo_risk,
        "velocity_risk": vel_risk,
        "pep_risk": pep_risk,
        "adverse_media_risk": adverse_media_risk,
        "pep_hits": pep_match_count,
        "composite_score": risk_score
    }


@router.get("/{id}/dossier")
async def get_customer_dossier(
    id: str,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    """
    Retrieves full Customer 360 dossier:
    - Identity profile & CIP verification
    - Dynamic risk factors & breakdown gauge
    - Sanctions / PEP status
    - Beneficial Ownership (UBO) Neo4j graph
    - 12-Month transaction monthly volume & recent transfers
    - Historical alerts & EDD request records
    """
    try:
        acc_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid customer account ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)

    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            """
            SELECT id, account_number, swift_bic, owner_name, status,
                   risk_score, risk_category, created_at, frozen_reason,
                   freezing_order_ref, frozen_at, last_rescreened_at
            FROM accounts
            WHERE id = $1 AND tenant_id = $2;
            """,
            acc_uuid, uuid.UUID(str(tenant_id))
        )
        if not acc:
            raise HTTPException(status_code=404, detail="Customer account not found.")

        acc_num = acc["account_number"]
        owner_name = acc["owner_name"]
        risk_score = float(acc["risk_score"] or 0.15)

        recent_txs, monthly_trend, alerts, edd_records = await _fetch_customer_activity(
            conn, acc_num, acc_uuid
        )
        pep_match_count = 0
        try:
            if owner_name and hasattr(conn, "fetchval"):
                raw_pep = await conn.fetchval(
                    "SELECT COUNT(*) FROM pep_entities WHERE name ILIKE $1;",
                    f"%{owner_name.strip()}%"
                )
                if isinstance(raw_pep, (int, float)):
                    pep_match_count = int(raw_pep)
        except Exception:
            pep_match_count = 0

    ubo_nodes = await _fetch_customer_ubo(acc_num, owner_name, id, tenant_id=str(tenant_id))
    risk_factors = _calculate_customer_risk_factors(
        acc["swift_bic"], len(recent_txs), risk_score,
        pep_match_count=pep_match_count, alerts=alerts, edd_records=edd_records
    )

    # Mask sensitive details if role is AUDITOR
    is_auditor = current_user.get("role") in ["AUDITOR", "GLOBAL_AUDITOR"]
    display_owner = owner_name if not is_auditor else f"{owner_name[:2]}*** {owner_name.split()[-1][:1]}***"

    # Reconcile risk_tier with risk_score so a high/critical score never displays a stale LOW badge
    tier_rank = {"LOW": 0, "STANDARD": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    derived_tier = (
        "CRITICAL" if risk_score >= 0.85
        else ("HIGH" if risk_score >= 0.70 else ("MEDIUM" if risk_score >= 0.40 else "LOW"))
    )
    stored_tier = str(acc["risk_category"] or "").upper()
    risk_tier = stored_tier if tier_rank.get(stored_tier, -1) >= tier_rank[derived_tier] else derived_tier
    screened_ts = acc.get("last_rescreened_at") if hasattr(acc, "get") else None
    updated_at_iso = (
        screened_ts.isoformat() if screened_ts
        else (acc["created_at"].isoformat() if acc["created_at"] else None)
    )

    return {
        "id": str(acc["id"]),
        "account_number": acc_num,
        "swift_bic": acc["swift_bic"],
        "owner_name": display_owner,
        "status": acc["status"] or "ACTIVE",
        "risk_tier": risk_tier,
        "risk_score": risk_score,
        "risk_breakdown": risk_factors,
        "created_at": acc["created_at"].isoformat() if acc["created_at"] else "",
        "updated_at": updated_at_iso,
        "frozen_details": {
            "is_frozen": acc["status"] == "FROZEN",
            "reason": acc.get("frozen_reason"),
            "order_ref": acc.get("freezing_order_ref"),
            "frozen_at": acc.get("frozen_at").isoformat() if acc.get("frozen_at") else None
        },
        "ubos": ubo_nodes,
        "recent_transactions": recent_txs,
        "monthly_trend": monthly_trend,
        "alerts": alerts,
        "edd_history": edd_records
    }
