"""
Regulatory Compliance Reporting Router (GAP-12)
================================================
Thin HTTP controller for audit and examiner summary dashboards.
Supports strong ETag / 304 Not Modified conditional revalidation while preserving
`Cache-Control: no-store` & `CDN-Cache-Control: no-store` on all sensitive reports.
All PostgreSQL SQL lives in `repositories/analytics_repo.py`.
"""

import logging

from fastapi import APIRouter, Depends, Request

from database.postgres import get_async_db_read_conn
from database.read_after_write import force_primary_read_var
from repositories.analytics_repo import (
    fetch_conversion_counts_repo,
    fetch_ctr_summary_repo,
    fetch_kyc_status_repo,
    fetch_sar_summary_repo,
)
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.cache_aside import cache_aside
from services.http_cache import build_conditional_json_response
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/reports", tags=["Compliance Reporting & Auditing"])
_REPORT_CACHE_TTL_SECONDS = 30


async def _cached_report(tenant_id: str, report_key: str, loader):
    """Serves hot executive compliance summaries via Cache Redis (30s TTL) unless RAW stickiness is active."""
    if force_primary_read_var.get(False):
        return await loader()
    return await cache_aside.get_or_load(
        namespace="compliance_reports",
        tenant_id=str(tenant_id),
        key=report_key,
        loader=loader,
        base_ttl=_REPORT_CACHE_TTL_SECONDS,
    )


@router.get("/sar-summary")
async def get_sar_summary(
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)

    async def _load():
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

    payload = await _cached_report(str(tenant_id), "sar_summary", _load)
    return build_conditional_json_response(
        request,
        payload,
        extra_headers={"CDN-Cache-Control": "no-store"},
    )


@router.get("/ctr-summary")
async def get_ctr_summary(
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)

    async def _load():
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

    payload = await _cached_report(str(tenant_id), "ctr_summary", _load)
    return build_conditional_json_response(
        request,
        payload,
        extra_headers={"CDN-Cache-Control": "no-store"},
    )


@router.get("/conversion-rates")
async def get_conversion_rates(
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)

    async def _load():
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

    payload = await _cached_report(str(tenant_id), "conversion_rates", _load)
    return build_conditional_json_response(
        request,
        payload,
        extra_headers={"CDN-Cache-Control": "no-store"},
    )


@router.get("/kyc-status")
async def get_kyc_status(
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["AUDITOR", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)

    async def _load():
        stats = await fetch_kyc_status_repo(
            tenant_id=str(tenant_id),
            read_conn_factory=get_async_db_read_conn,
        )
        return {
            "total_scheduled_kyc": int(stats["total_scheduled"] or 0),
            "overdue_kyc_reviews": int(stats["overdue_reviews"] or 0),
            "completed_kyc_reviews": int(stats["completed_reviews"] or 0),
        }

    payload = await _cached_report(str(tenant_id), "kyc_status", _load)
    return build_conditional_json_response(
        request,
        payload,
        extra_headers={"CDN-Cache-Control": "no-store"},
    )
