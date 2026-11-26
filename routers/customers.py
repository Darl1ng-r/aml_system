"""
Customer 360 Dossier Router
============================
Thin HTTP controller for customer listing, Customer 360 dossiers, and
Perpetual KYC (pKYC) delta rescreening.
All PostgreSQL SQL lives in `repositories/customer_privacy_repo.py`.
"""

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from database.elasticsearch_db import get_async_elasticsearch_client
from database.neo4j_db import get_async_neo4j_driver
from database.postgres import get_async_db_conn, get_async_db_read_conn
from repositories.customer_privacy_repo import (
    fetch_customer_activity_tx as _fetch_customer_activity,
    fetch_customer_dossier_db_repo,
    list_customers_repo,
    list_pkyc_rescreen_runs_repo,
    trigger_pkyc_delta_rescreen_repo,
)
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
    total, rows = await list_customers_repo(
        tenant_id=str(tenant_id),
        limit=limit,
        offset=offset,
        search=search,
        risk_tier=risk_tier,
        account_status=status,
        read_conn_factory=get_async_db_read_conn,
    )

    items = [
        {
            "id": str(r["id"]),
            "account_number": r["account_number"],
            "swift_bic": r["swift_bic"],
            "owner_name": r["owner_name"],
            "status": r["status"] or "ACTIVE",
            "risk_score": float(r["risk_score"] or 0.0),
            "risk_tier": r["risk_category"] or "STANDARD",
            "created_at": r["created_at"].isoformat() if r["created_at"] else "",
            "is_frozen": r["status"] == "FROZEN",
            "frozen_reason": r.get("frozen_reason"),
        }
        for r in rows
    ]
    return {"items": items, "total": total, "page": page, "limit": limit}


@router.post("/pkyc/rescreen-delta")
async def trigger_pkyc_delta_rescreen(
    limit: int = Query(default=100, ge=1, le=500),
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    """Perpetual KYC (pKYC) Delta Rescreening (P1-5)."""
    tenant_id = enforce_tenant_data_scope(current_user)
    es = None
    try:
        es = await get_async_elasticsearch_client()
    except Exception:
        es = None

    return await trigger_pkyc_delta_rescreen_repo(
        tenant_id=str(tenant_id),
        triggered_by=current_user.get("username", "mlro"),
        limit=limit,
        es_client=es,
        conn_factory=get_async_db_conn,
    )


@router.get("/pkyc/runs")
async def list_pkyc_rescreen_runs(
    limit: int = Query(default=20, ge=1, le=100),
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "AUDITOR", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Returns audit history of Perpetual KYC delta rescreening sweeps."""
    tenant_id = enforce_tenant_data_scope(current_user)
    rows = await list_pkyc_rescreen_runs_repo(
        tenant_id=str(tenant_id),
        limit=limit,
        read_conn_factory=get_async_db_read_conn,
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
        for r in rows
    ]


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
                ubo_nodes.append(
                    {
                        "name": rec["name"],
                        "tax_id": rec.get("tax_id") or "N/A",
                        "percentage": float(rec.get("percentage") or 0.0),
                    }
                )
    except Exception as ne:
        logger.debug("Neo4j UBO lookup bypassed for customer %s: %s", customer_id, ne)
    return ubo_nodes


def _calculate_customer_risk_factors(
    swift_bic: str | None,
    tx_count: int,
    risk_score: float,
    pep_match_count: int = 0,
    alerts: list[dict] | None = None,
    edd_records: list[dict] | None = None,
) -> dict:
    high_risk_bic = bool(
        swift_bic and len(swift_bic) >= 6 and swift_bic[4:6] in ["RU", "IR", "KP", "SY", "MM", "YE", "VE"]
    )
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
    vel_risk = (
        min(1.0, tx_count * 0.08)
        if tx_count > 0
        else (round(min(0.80, risk_score * 0.70), 2) if risk_score >= 0.70 else 0.0)
    )

    return {
        "jurisdiction_risk": geo_risk,
        "velocity_risk": vel_risk,
        "pep_risk": pep_risk,
        "adverse_media_risk": adverse_media_risk,
        "pep_hits": pep_match_count,
        "composite_score": risk_score,
    }


@router.get("/{id}/dossier")
async def get_customer_dossier(
    id: str,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Retrieves full Customer 360 dossier."""
    try:
        acc_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid customer account ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    dossier = await fetch_customer_dossier_db_repo(
        acc_uuid=acc_uuid,
        tenant_id=str(tenant_id),
        read_conn_factory=get_async_db_read_conn,
    )
    acc = dossier["acc"]
    recent_txs = dossier["recent_txs"]
    monthly_trend = dossier["monthly_trend"]
    alerts = dossier["alerts"]
    edd_records = dossier["edd_records"]
    pep_match_count = dossier["pep_match_count"]

    acc_num = acc["account_number"]
    owner_name = acc["owner_name"]
    risk_score = float(acc["risk_score"] or 0.15)

    ubo_nodes = await _fetch_customer_ubo(acc_num, owner_name, id, tenant_id=str(tenant_id))
    risk_factors = _calculate_customer_risk_factors(
        acc["swift_bic"],
        len(recent_txs),
        risk_score,
        pep_match_count=pep_match_count,
        alerts=alerts,
        edd_records=edd_records,
    )

    is_auditor = current_user.get("role") in ["AUDITOR", "GLOBAL_AUDITOR"]
    display_owner = owner_name if not is_auditor else f"{owner_name[:2]}*** {owner_name.split()[-1][:1]}***"

    tier_rank = {"LOW": 0, "STANDARD": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    derived_tier = (
        "CRITICAL"
        if risk_score >= 0.85
        else ("HIGH" if risk_score >= 0.70 else ("MEDIUM" if risk_score >= 0.40 else "LOW"))
    )
    stored_tier = str(acc["risk_category"] or "").upper()
    risk_tier = stored_tier if tier_rank.get(stored_tier, -1) >= tier_rank[derived_tier] else derived_tier
    screened_ts = acc.get("last_rescreened_at") if hasattr(acc, "get") else None
    updated_at_iso = (
        screened_ts.isoformat()
        if screened_ts
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
            "frozen_at": acc.get("frozen_at").isoformat() if acc.get("frozen_at") else None,
        },
        "ubos": ubo_nodes,
        "recent_transactions": recent_txs,
        "monthly_trend": monthly_trend,
        "alerts": alerts,
        "edd_history": edd_records,
    }
