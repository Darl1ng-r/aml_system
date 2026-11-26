"""
Watchlist Ingestion & Sync API Router
======================================
Thin HTTP controller for syncing OFAC/UN/EU/PEP watchlists, triggering
ongoing CDD rescreening, and reporting provider dataset status.
All PostgreSQL SQL lives in `repositories/ops_repo.py`.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from repositories.ops_repo import fetch_pep_watchlist_status_repo
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter
from services.watchlist_sync import watchlist_sync_engine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/watchlist", tags=["Global Watchlist Management"])


@router.post("/sync-jobs", status_code=status.HTTP_202_ACCEPTED)
@router.post("/sync")
async def sync_watchlists(
    current_user: dict = Depends(RoleChecker(["ADMIN", "MLRO", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=5, window=60)),
):
    """Triggers an on-demand synchronization cycle across global watchlists."""
    try:
        result = await watchlist_sync_engine.sync_all_watchlists()

        from routers.metrics import ws_manager

        await ws_manager.broadcast(
            {
                "event": "WATCHLIST_SYNCED",
                "is_system_broadcast": True,
                "total_records": result["total_records_processed"],
            }
        )
        return result
    except Exception:
        logger.exception("Watchlist synchronization failed")
        raise HTTPException(status_code=500, detail="Watchlist synchronization failed.")


@router.post("/rescreen")
async def trigger_cdd_rescreen(
    current_user: dict = Depends(RoleChecker(["ADMIN", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    """Triggers an immediate CDD re-screening cycle across all active tenant accounts."""
    from services.watchlist_sync import trigger_ongoing_cdd_rescreening

    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        return await trigger_ongoing_cdd_rescreening(tenant_id=str(tenant_id))
    except Exception:
        logger.exception("CDD re-screening invocation failed")
        raise HTTPException(status_code=500, detail="CDD re-screening failed.")


@router.get("/status")
async def get_watchlist_status(
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Returns live watchlist provider statuses and real dataset record statistics."""
    from database.elasticsearch_db import get_async_elasticsearch_client

    tenant_id = enforce_tenant_data_scope(current_user)
    pg_pep_count = 0
    pg_last_sync = None
    pg_status = "UNAVAILABLE"
    try:
        pg_pep_count, pg_last_sync = await fetch_pep_watchlist_status_repo(tenant_id=str(tenant_id))
        pg_status = "SYNCED" if pg_pep_count > 0 else "EMPTY"
    except Exception as e:
        logger.warning("PostgreSQL pep_entities status query failed: %s", e)

    es_sanctions_count = 0
    es_pep_count = 0
    es_status = "OFFLINE"
    try:
        es = await get_async_elasticsearch_client()
        if es:
            try:
                s_res = await es.count(index="sanctions_list")
                es_sanctions_count = int(s_res.get("count", 0))
            except Exception:
                es_sanctions_count = 0
            try:
                p_res = await es.count(index="pep_entities")
                es_pep_count = int(p_res.get("count", 0))
            except Exception:
                es_pep_count = 0
            es_status = "CONNECTED"
    except Exception as e:
        logger.warning("Elasticsearch watchlist count query failed: %s", e)

    overall = "ONLINE" if (pg_status == "SYNCED" or es_status == "CONNECTED") else "DEGRADED"
    return {
        "status": overall,
        "providers": [
            {
                "name": "OFAC / UN / EU Sanctions Index (Elasticsearch)",
                "type": "Live Search Index",
                "status": es_status,
                "active_records": es_sanctions_count,
            },
            {
                "name": "Global PEP Registry (PostgreSQL pg_trgm)",
                "type": "Relational Watchlist",
                "status": pg_status,
                "active_records": pg_pep_count,
            },
            {
                "name": "PEP Search Mirror (Elasticsearch)",
                "type": "Fuzzy Phonetic Index",
                "status": es_status,
                "active_records": es_pep_count,
            },
        ],
        "last_synced_at": pg_last_sync.isoformat() if pg_last_sync else None,
    }
