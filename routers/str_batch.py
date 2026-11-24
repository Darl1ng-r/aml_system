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
            # Broadcast real-time WebSocket update with strict tenant isolation (B3)
            from routers.metrics import ws_manager
            await ws_manager.broadcast({
                "event": "STR_BATCH_GENERATED",
                "tenant_id": str(tenant_id),
                "batch_id": result["batch_id"],
                "record_count": result["record_count"],
                "total_amount": result["total_amount"],
                "generated_by": current_user["username"]
            }, target_tenant_id=str(tenant_id))

        return result
    except Exception as e:
        logger.exception("Failed to compile STR batch")
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
        logger.exception("Failed to list STR batches")
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
        logger.exception("STR batch download failed")
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
    Electronically transmits the full compiled STR batch package to the regulatory gateway
    using a 3-phase Saga (T-05):
      1. Short DB tx atomically claims `status = 'TRANSMITTING'` (returns 409 Conflict if already claimed/filed).
      2. External FinCEN gateway transmission executes OUTSIDE any PostgreSQL transaction.
      3. Short DB tx commits final receipt status + cryptographic WORM audit_log (or marks FAILED on error).
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        # Phase 1: Atomically claim batch in a short DB transaction (prevents double regulatory filing)
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            claimed = await conn.fetchrow(
                """
                UPDATE str_batches
                SET status = 'TRANSMITTING'
                WHERE id = $1 AND status IN ('GENERATED', 'READY_FOR_SUBMISSION', 'FAILED')
                RETURNING payload_xml;
                """,
                batch_id,
            )
            if not claimed:
                existing = await conn.fetchrow(
                    "SELECT status FROM str_batches WHERE id = $1;",
                    batch_id,
                )
                if not existing:
                    raise HTTPException(status_code=404, detail="STR batch not found.")
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"STR batch {batch_id} cannot be transmitted: current status is '{existing['status']}'.",
                )
            payload_xml = claimed["payload_xml"]

        # Phase 2: External regulatory gateway call OUTSIDE PostgreSQL transaction/lock
        try:
            receipt = await fincen_client.submit_sar(payload_xml, batch_id)
        except Exception as gw_err:
            logger.exception("STR batch gateway transmission failed for %s", batch_id)
            try:
                async with get_async_db_conn(tenant_id=tenant_id) as conn:
                    await conn.execute(
                        "UPDATE str_batches SET status = 'FAILED' WHERE id = $1;",
                        batch_id,
                    )
            except Exception:
                pass
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Regulatory gateway transmission failed: {gw_err}",
            )

        # Phase 3: Commit final receipt status + cryptographic WORM audit_log
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            await conn.execute(
                """
                UPDATE str_batches
                SET status = $1
                WHERE id = $2;
                """,
                receipt["status"], batch_id
            )
            from services.audit import record_audit_event_tx
            await record_audit_event_tx(
                conn=conn,
                action="STR_BATCH_TRANSMITTED",
                actor_id=str(current_user.get("id") or current_user.get("username") or "unknown"),
                actor_username=current_user.get("username", "analyst"),
                actor_role=current_user.get("role", "ANALYST"),
                resource_type="STR_BATCH",
                resource_id=batch_id,
                tenant_id=str(tenant_id) if tenant_id else None,
                details={
                    "batch_id": batch_id,
                    "status": receipt["status"],
                    "fincen_tracking_id": receipt.get("fincen_tracking_id"),
                },
            )

        # Broadcast real-time WebSocket update with strict tenant isolation (B3)
        from routers.metrics import ws_manager
        await ws_manager.broadcast({
            "event": "STR_BATCH_TRANSMITTED",
            "tenant_id": str(tenant_id),
            "batch_id": batch_id,
            "status": receipt["status"],
            "fincen_tracking_id": receipt["fincen_tracking_id"]
        }, target_tenant_id=str(tenant_id))

        return {
            "batch_id": batch_id,
            "status": receipt["status"],
            "fincen_tracking_id": receipt["fincen_tracking_id"],
            "message": "Full STR batch container successfully transmitted to regulatory gateway."
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("STR batch transmission failed")
        raise HTTPException(status_code=500, detail=f"Transmission failed: {str(e)}")
