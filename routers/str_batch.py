"""
Regulatory STR (Suspicious Transaction Report) Batching Router
================================================================
Provides API endpoints for scheduled and batch regulatory compliance filings:

  - POST /api/v1/str/batch/generate:
      Compiles all un-batched CLOSED_SAR alerts into a sealed XML batch package.

  - GET /api/v1/str/batch/list:
      Lists generated regulatory batch packages with totals & checksums.

  - GET /api/v1/str/batch/{batch_id}/download:
      Streams the compiled XML batch container for filing upload.

  - POST /api/v1/str/batch/{batch_id}/transmit:
      Electronically files the full batch package to the regulatory gateway.
"""

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import Response, StreamingResponse
from database.postgres import get_async_db_conn
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.str_batch_engine import str_batch_engine
from services.fincen_efiling import fincen_client
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/str/batch", tags=["STR Regulatory Batching"])


@router.post("/batches", status_code=status.HTTP_201_CREATED)
@router.post("/generate", status_code=status.HTTP_201_CREATED)
async def generate_str_batch(
    response: Response = None,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=5, window=60))
):
    """
    Compiles all pending un-batched CLOSED_SAR alerts into an official STR batch container.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        result = await str_batch_engine.generate_batch(str(tenant_id))

        if result.get("batch_id"):
            if response is not None:
                response.headers["Location"] = f"/api/v1/str/batch/batches/{result['batch_id']}"
            # Broadcast real-time WebSocket update
            from routers.metrics import ws_manager
            await ws_manager.broadcast({
                "event": "STR_BATCH_GENERATED",
                "batch_id": result["batch_id"],
                "record_count": result["record_count"],
                "total_amount": result["total_amount"],
                "generated_by": current_user["username"]
            })

        return result
    except Exception as e:
        logger.error(f"Failed to compile STR batch: {e}")
        raise HTTPException(status_code=500, detail=f"STR batch compilation failed: {str(e)}")


@router.get("/batches")
@router.get("/list")
async def list_str_batches(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """
    Lists all compiled regulatory STR batches with status and record counts.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            rows = await conn.fetch(
                """
                SELECT id, record_count, total_amount, checksum, status, created_at
                FROM str_batches
                ORDER BY created_at DESC
                LIMIT $1 OFFSET $2;
                """,
                limit, offset
            )
            batches = []
            for r in rows:
                batches.append({
                    "batch_id": r["id"],
                    "record_count": r["record_count"],
                    "total_amount": float(r["total_amount"]),
                    "checksum": r["checksum"],
                    "status": r["status"],
                    "created_at": r["created_at"].isoformat()
                })
            return {"batches": batches}
    except Exception as e:
        logger.error(f"Failed to list STR batches: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch batches: {str(e)}")


@router.get("/batches/{batch_id}/file")
@router.get("/batches/{batch_id}")
@router.get("/{batch_id}/download")
async def download_str_batch(
    batch_id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=15, window=60))
):
    """
    Streams the XML batch container for filing uploading.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            row = await conn.fetchrow(
                "SELECT payload_xml FROM str_batches WHERE id = $1;",
                batch_id
            )
            if not row:
                raise HTTPException(status_code=404, detail="STR batch not found.")

            xml_payload = row["payload_xml"]
            filename = f"{batch_id}.xml"
            return Response(
                content=xml_payload,
                media_type="application/xml",
                headers={"Content-Disposition": f"attachment; filename={filename}"}
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"STR batch download failed: {e}")
        raise HTTPException(status_code=500, detail=f"Download failed: {str(e)}")


@router.post("/batches/{batch_id}/transmissions")
@router.patch("/batches/{batch_id}")
@router.post("/{batch_id}/transmit")
async def transmit_str_batch(
    batch_id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=5, window=60))
):
    """
    Electronically transmits the full compiled STR batch package to the regulatory gateway.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            row = await conn.fetchrow(
                "SELECT payload_xml FROM str_batches WHERE id = $1;",
                batch_id
            )
            if not row:
                raise HTTPException(status_code=404, detail="STR batch not found.")

            receipt = await fincen_client.submit_sar(row["payload_xml"], batch_id)

            await conn.execute(
                """
                UPDATE str_batches
                SET status = $1
                WHERE id = $2;
                """,
                receipt["status"], batch_id
            )

            # Broadcast real-time WebSocket update
            from routers.metrics import ws_manager
            await ws_manager.broadcast({
                "event": "STR_BATCH_TRANSMITTED",
                "batch_id": batch_id,
                "status": receipt["status"],
                "fincen_tracking_id": receipt["fincen_tracking_id"]
            })

            return {
                "batch_id": batch_id,
                "status": receipt["status"],
                "fincen_tracking_id": receipt["fincen_tracking_id"],
                "message": "Full STR batch container successfully transmitted to regulatory gateway."
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"STR batch transmission failed: {e}")
        raise HTTPException(status_code=500, detail=f"Transmission failed: {str(e)}")
