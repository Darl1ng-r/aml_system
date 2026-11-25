"""
Unified Global Search Router for Cmd+K Command Palette (P1-3)
==============================================================
Executes parallel read-only tenant-RLS searches across Accounts, Cases, Alerts,
and SAR Drafts to power instant keyboard-first navigation (`Cmd+K` / `Ctrl+K`)
across all 14 AML Sentinel workspace pages.
"""

import asyncio
import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query

from database.postgres import get_async_db_read_conn
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter

logger = logging.getLogger("aml.search")

router = APIRouter(prefix="/api/v1/search", tags=["Global Search"])


@router.get("/global")
async def global_search(
    q: str = Query(..., min_length=1, max_length=120),
    limit: int = Query(default=6, ge=1, le=20),
    current_user: dict = Depends(
        RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR", "SUPER_ADMIN"])
    ),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
) -> Dict[str, Any]:
    """Searches Accounts, Cases, Alerts, and SAR Drafts in parallel under strict tenant RLS."""
    tenant_id = enforce_tenant_data_scope(current_user)
    escaped_q = q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{escaped_q}%"

    async def _search_accounts() -> List[Dict[str, Any]]:
        try:
            async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
                rows = await conn.fetch(
                    """
                    SELECT id, account_number, owner_name, swift_bic, status, risk_score
                    FROM accounts
                    WHERE account_number ILIKE $1 OR owner_name ILIKE $1 OR swift_bic ILIKE $1
                    ORDER BY risk_score DESC NULLS LAST
                    LIMIT $2;
                    """,
                    pattern,
                    limit,
                )
                return [
                    {
                        "type": "ACCOUNT",
                        "id": str(r["id"]),
                        "title": r["owner_name"] or r["account_number"],
                        "subtitle": f"{r['account_number']} · {r['status'] or 'ACTIVE'}",
                        "badge": f"Risk {round(float(r['risk_score'] or 0.0) * 100)}%",
                        "url": f"/customers?account={r['account_number']}",
                    }
                    for r in (rows or [])
                ]
        except Exception as exc:
            logger.debug(f"Global search accounts error: {exc}")
            return []

    async def _search_cases() -> List[Dict[str, Any]]:
        try:
            async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
                rows = await conn.fetch(
                    """
                    SELECT id, case_number, title, status, priority
                    FROM cases
                    WHERE case_number ILIKE $1 OR title ILIKE $1
                    ORDER BY created_at DESC
                    LIMIT $2;
                    """,
                    pattern,
                    limit,
                )
                return [
                    {
                        "type": "CASE",
                        "id": str(r["id"]),
                        "title": f"{r['case_number']} — {r['title']}",
                        "subtitle": f"{r['status']} · {r['priority']}",
                        "badge": r["priority"] or "MEDIUM",
                        "url": f"/dashboard?case_id={r['id']}",
                    }
                    for r in (rows or [])
                ]
        except Exception as exc:
            logger.debug(f"Global search cases error: {exc}")
            return []

    async def _search_alerts() -> List[Dict[str, Any]]:
        try:
            async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
                rows = await conn.fetch(
                    """
                    SELECT id, rule_name, threat_level, status, ai_risk_score
                    FROM alerts
                    WHERE rule_name ILIKE $1 OR id::text ILIKE $1
                    ORDER BY created_at DESC
                    LIMIT $2;
                    """,
                    pattern,
                    limit,
                )
                return [
                    {
                        "type": "ALERT",
                        "id": str(r["id"]),
                        "title": f"{r['rule_name'] or 'AML_ALERT'} ({str(r['id'])[:8]})",
                        "subtitle": f"{r['status']} · Risk {round(float(r['ai_risk_score'] or 0.0) * 100)}%",
                        "badge": r["threat_level"] or "HIGH",
                        "url": f"/alerts/triage?search={str(r['id'])[:8]}",
                    }
                    for r in (rows or [])
                ]
        except Exception as exc:
            logger.debug(f"Global search alerts error: {exc}")
            return []

    async def _search_sars() -> List[Dict[str, Any]]:
        try:
            async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
                rows = await conn.fetch(
                    """
                    SELECT id, status, drafted_by_username, fincen_tracking_id
                    FROM sar_drafts
                    WHERE id::text ILIKE $1
                       OR narrative ILIKE $1
                       OR COALESCE(fincen_tracking_id, '') ILIKE $1
                    ORDER BY created_at DESC
                    LIMIT $2;
                    """,
                    pattern,
                    limit,
                )
                return [
                    {
                        "type": "SAR",
                        "id": str(r["id"]),
                        "title": f"SAR {str(r['id'])[:8]} ({r['status']})",
                        "subtitle": r["fincen_tracking_id"] or f"Drafted by {r['drafted_by_username'] or 'Analyst'}",
                        "badge": r["status"] or "DRAFT",
                        "url": f"/sar/editor?draft_id={r['id']}",
                    }
                    for r in (rows or [])
                ]
        except Exception as exc:
            logger.debug(f"Global search sars error: {exc}")
            return []

    accounts, cases, alerts, sars = await asyncio.gather(
        _search_accounts(),
        _search_cases(),
        _search_alerts(),
        _search_sars(),
    )

    items = accounts + cases + alerts + sars
    return {
        "query": q.strip(),
        "total": len(items),
        "accounts": accounts,
        "cases": cases,
        "alerts": alerts,
        "sars": sars,
        "items": items,
    }
