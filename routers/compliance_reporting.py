"""
Regulatory Compliance Reporting Router (GAP-12)
================================================
Thin HTTP controller for audit and examiner summary dashboards.
All PostgreSQL SQL lives in `repositories/analytics_repo.py`.
"""

import logging

from fastapi import APIRouter, Depends

from database.postgres import get_async_db_read_conn
from repositories.analytics_repo import (
    fetch_conversion_counts_repo,
    fetch_ctr_summary_repo,
    fetch_kyc_status_repo,
    fetch_sar_summary_repo,
)
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/reports", tags=["Compliance Reporting & Auditing"])


@router.get("/sar-summary")
async def get_sar_summary(
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)
    stats = await fetch_sar_summary_repo(
        tenant_id=str(tenant_id),
        read_conn_factory=get_async_db_read_conn,
    )
    return {
        "tenant_id": tenant_id,
        "total_sar_drafts": int(stats["total_drafts"] or 0),
        "approved_sar_drafts": int(stats["approved_drafts"] or 0),
        "submitted_sar_drafts": int(stats["submitted_drafts"] or 0),
        "rejected_sar_drafts": int(stats["rejected_drafts"] or 0),
    }


@router.get("/ctr-summary")
async def get_ctr_summary(
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)
    stats = await fetch_ctr_summary_repo(
        tenant_id=str(tenant_id),
        read_conn_factory=get_async_db_read_conn,
    )
    return {
        "tenant_id": tenant_id,
        "total_ctrs": int(stats["total_ctrs"] or 0),
        "filed_ctrs": int(stats["filed_ctrs"] or 0),
        "pending_ctrs": int(stats["pending_ctrs"] or 0),
        "total_cash_volume": float(stats["total_cash_volume"] or 0.0),
        "total_cash_volume_str": str(stats["total_cash_volume"] if stats["total_cash_volume"] is not None else "0.0000"),
    }


@router.get("/conversion-rates")
async def get_conversion_rates(
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)
    total_alerts, total_cases, filed_sars = await fetch_conversion_counts_repo(
        tenant_id=str(tenant_id),
        read_conn_factory=get_async_db_read_conn,
    )

    alert_to_case_ratio = round((total_cases / total_alerts * 100), 2) if total_alerts > 0 else 0.0
    case_to_sar_ratio = round((filed_sars / total_cases * 100), 2) if total_cases > 0 else 0.0

    return {
        "total_alerts": total_alerts,
        "total_cases": total_cases,
        "filed_sars": filed_sars,
        "alert_to_case_conversion_pct": alert_to_case_ratio,
        "case_to_sar_conversion_pct": case_to_sar_ratio,
    }


@router.get("/kyc-status")
async def get_kyc_status(
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)
    stats = await fetch_kyc_status_repo(
        tenant_id=str(tenant_id),
        read_conn_factory=get_async_db_read_conn,
    )
    return {
        "total_scheduled_kyc": int(stats["total_scheduled"] or 0),
        "overdue_kyc_reviews": int(stats["overdue_reviews"] or 0),
        "completed_kyc_reviews": int(stats["completed_reviews"] or 0),
    }
