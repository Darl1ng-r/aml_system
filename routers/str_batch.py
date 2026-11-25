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
import re
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import Response, StreamingResponse
from database.postgres import get_async_db_conn
from services.auth import PermissionChecker, RoleChecker, enforce_tenant_data_scope
from services.str_batch_engine import str_batch_engine
from services.fincen_efiling import fincen_client
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/str/batch", tags=["STR Regulatory Batching"])


@router.post("/batches", status_code=status.HTTP_201_CREATED)
@router.post("/generate", status_code=status.HTTP_201_CREATED)
async def generate_str_batch(
    response: Response = None,
    current_user: dict = Depends(PermissionChecker("sar:submit")),
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
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to compile STR batch")
        raise HTTPException(status_code=500, detail="STR batch compilation failed.")


@router.get("/batches")
@router.get("/list")
async def list_str_batches(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100000),
    current_user: dict = Depends(RoleChecker(["ADMIN", "MLRO", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """
    Lists all compiled regulatory STR batches with status and record counts (tenant-scoped).
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            rows = await conn.fetch(
                """
                SELECT id, record_count, total_amount, checksum, status, created_at
                FROM str_batches
                WHERE tenant_id = $1::uuid
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3;
                """,
                str(tenant_id), limit, offset
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
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to list STR batches")
        raise HTTPException(status_code=500, detail="Failed to fetch STR batches.")


@router.get("/batches/{batch_id}/file")
@router.get("/batches/{batch_id}")
@router.get("/{batch_id}/download")
async def download_str_batch(
    batch_id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "MLRO", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=15, window=60))
):
    """
    Streams the XML batch container for filing uploading (tenant-scoped).
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            row = await conn.fetchrow(
                "SELECT payload_xml FROM str_batches WHERE id = $1 AND tenant_id = $2::uuid;",
                batch_id, str(tenant_id)
            )
            if not row:
                raise HTTPException(status_code=404, detail="STR batch not found.")

            xml_payload = row["payload_xml"]
            safe_batch_id = re.sub(r"[^A-Za-z0-9._-]", "_", str(batch_id))[:80]
            filename = f"{safe_batch_id}.xml"
            return Response(
                content=xml_payload,
                media_type="application/xml",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "X-Content-Type-Options": "nosniff",
                }
            )
    except HTTPException:
        raise
    except Exception:
        logger.exception("STR batch download failed")
        raise HTTPException(status_code=500, detail="STR batch download failed.")


@router.post("/batches/{batch_id}/transmissions")
@router.patch("/batches/{batch_id}")
@router.post("/{batch_id}/transmit")
async def transmit_str_batch(
    batch_id: str,
    current_user: dict = Depends(PermissionChecker("sar:submit")),
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
                WHERE id = $1 AND tenant_id = $2::uuid AND status IN ('GENERATED', 'READY_FOR_SUBMISSION', 'FAILED')
                RETURNING payload_xml;
                """,
                batch_id, str(tenant_id),
            )
            if not claimed:
                existing = await conn.fetchrow(
                    "SELECT status FROM str_batches WHERE id = $1 AND tenant_id = $2::uuid;",
                    batch_id, str(tenant_id),
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
        except Exception:
            logger.exception("STR batch gateway transmission failed for %s", batch_id)
            try:
                async with get_async_db_conn(tenant_id=tenant_id) as conn:
                    await conn.execute(
                        "UPDATE str_batches SET status = 'FAILED' WHERE id = $1 AND tenant_id = $2::uuid;",
                        batch_id, str(tenant_id),
                    )
            except Exception:
                pass
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Regulatory gateway transmission failed.",
            )

        # Phase 3: Commit final receipt status + cryptographic WORM audit_log
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            await conn.execute(
                """
                UPDATE str_batches
                SET status = $1
                WHERE id = $2 AND tenant_id = $3::uuid;
                """,
                receipt["status"], batch_id, str(tenant_id)
            )
            from services.audit import record_audit_event_tx
            await record_audit_event_tx(
                conn=conn,
                action="STR_BATCH_TRANSMITTED",
                actor_id=str(current_user.get("id") or current_user.get("username") or "unknown"),
                actor_username=current_user.get("username", "mlro"),
                actor_role=current_user.get("role", "MLRO"),
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
    except Exception:
        logger.exception("STR batch transmission failed")
        raise HTTPException(status_code=500, detail="STR batch transmission failed.")
