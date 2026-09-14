"""
Regulatory Compliance Reporting Router (GAP-12)
================================================
Delivers audit and examiner dashboards summarizing SAR/CTR filings,
investigation SLAs, false-positive conversion ratios, and periodic KYC compliance.
"""

import logging
import uuid
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from database.postgres import get_async_db_read_conn
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/reports", tags=["Compliance Reporting & Auditing"])


@router.get("/sar-summary")
async def get_sar_summary(
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        stats = await conn.fetchrow(
            """
            SELECT 
                COUNT(*) AS total_drafts,
                COUNT(*) FILTER (WHERE status = 'APPROVED') AS approved_drafts,
                COUNT(*) FILTER (WHERE status = 'SUBMITTED') AS submitted_drafts,
                COUNT(*) FILTER (WHERE status = 'REJECTED') AS rejected_drafts
            FROM sar_drafts
            WHERE tenant_id = $1;
            """,
            uuid.UUID(str(tenant_id))
        )
        return {
            "tenant_id": tenant_id,
            "total_sar_drafts": int(stats["total_drafts"] or 0),
            "approved_sar_drafts": int(stats["approved_drafts"] or 0),
            "submitted_sar_drafts": int(stats["submitted_drafts"] or 0),
            "rejected_sar_drafts": int(stats["rejected_drafts"] or 0)
        }


@router.get("/ctr-summary")
async def get_ctr_summary(
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        stats = await conn.fetchrow(
            """
            SELECT 
                COUNT(*) AS total_ctrs,
                COUNT(*) FILTER (WHERE status = 'FILED') AS filed_ctrs,
                COUNT(*) FILTER (WHERE status = 'PENDING') AS pending_ctrs,
                COALESCE(SUM(amount), 0.0) AS total_cash_volume
            FROM ctr_filings
            WHERE tenant_id = $1;
            """,
            uuid.UUID(str(tenant_id))
        )
        return {
            "tenant_id": tenant_id,
            "total_ctrs": int(stats["total_ctrs"] or 0),
            "filed_ctrs": int(stats["filed_ctrs"] or 0),
            "pending_ctrs": int(stats["pending_ctrs"] or 0),
            "total_cash_volume": float(stats["total_cash_volume"] or 0.0)
        }


@router.get("/conversion-rates")
async def get_conversion_rates(
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        total_alerts = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE tenant_id = $1;", uuid.UUID(str(tenant_id))) or 0
        total_cases = await conn.fetchval("SELECT COUNT(*) FROM cases WHERE tenant_id = $1;", uuid.UUID(str(tenant_id))) or 0
        filed_sars = await conn.fetchval("SELECT COUNT(*) FROM sar_drafts WHERE tenant_id = $1 AND status = 'SUBMITTED';", uuid.UUID(str(tenant_id))) or 0

        alert_to_case_ratio = round((total_cases / total_alerts * 100), 2) if total_alerts > 0 else 0.0
        case_to_sar_ratio = round((filed_sars / total_cases * 100), 2) if total_cases > 0 else 0.0

        return {
            "total_alerts": total_alerts,
            "total_cases": total_cases,
            "filed_sars": filed_sars,
            "alert_to_case_conversion_pct": alert_to_case_ratio,
            "case_to_sar_conversion_pct": case_to_sar_ratio
        }


@router.get("/kyc-status")
async def get_kyc_status(
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        stats = await conn.fetchrow(
            """
            SELECT 
                COUNT(*) AS total_scheduled,
                COUNT(*) FILTER (WHERE status = 'OVERDUE' OR due_date < NOW()) AS overdue_reviews,
                COUNT(*) FILTER (WHERE status = 'COMPLETED') AS completed_reviews
            FROM kyc_reviews
            WHERE tenant_id = $1;
            """,
            uuid.UUID(str(tenant_id))
        )
        return {
            "total_scheduled_kyc": int(stats["total_scheduled"] or 0),
            "overdue_kyc_reviews": int(stats["overdue_reviews"] or 0),
            "completed_kyc_reviews": int(stats["completed_reviews"] or 0)
        }
