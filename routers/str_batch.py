"""
Regulatory STR (Suspicious Transaction Report) Batching Router
==============================================================
Thin HTTP controller over `repositories/compliance_config_repo.py` and
`services/str_batch_engine.py`. Enforces mandatory `Idempotency-Key` on batch
generation and regulatory gateway transmission mutations.
"""

import logging
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, Response

from database.postgres import get_async_db_conn
from repositories.compliance_config_repo import (
    claim_str_batch_for_transmission_repo,
    fetch_str_batch_xml_repo,
    finalize_str_batch_transmission_atomic,
    list_str_batches_repo,
    mark_str_batch_failed_repo,
)
from services.auth import PermissionChecker, RoleChecker, enforce_tenant_data_scope
from services.fincen_efiling import fincen_client
from services.idempotency import run_idempotent_operation
from services.rate_limiter import RateLimiter
from services.str_batch_engine import str_batch_engine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/str/batch", tags=["STR Regulatory Batching"])


@router.post("/batches", status_code=status.HTTP_201_CREATED)
@router.post("/generate", status_code=status.HTTP_201_CREATED)
async def generate_str_batch(
    request: Request = None,
    response: Response = None,
    current_user: dict = Depends(PermissionChecker("sar:submit")),
    _rate_limit=Depends(RateLimiter(limit=5, window=60)),
):
    """Compiles all pending un-batched CLOSED_SAR alerts into an official STR batch container."""
    tenant_id = enforce_tenant_data_scope(current_user)

    async def _execute_generate():
        try:
            result = await str_batch_engine.generate_batch(str(tenant_id))
            if result.get("batch_id"):
                loc = f"/api/v1/str/batch/batches/{result['batch_id']}"
                if response is not None:
                    response.headers["Location"] = loc
                from routers.metrics import ws_manager

                await ws_manager.broadcast(
                    {
                        "event": "STR_BATCH_GENERATED",
                        "tenant_id": str(tenant_id),
                        "batch_id": result["batch_id"],
                        "record_count": result["record_count"],
                        "total_amount": result["total_amount"],
                        "generated_by": current_user["username"],
                    },
                    target_tenant_id=str(tenant_id),
                )
                return JSONResponse(
                    content=result,
                    status_code=status.HTTP_201_CREATED,
                    headers={"Location": loc},
                )
            return result
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("Failed to compile STR batch")
            raise HTTPException(status_code=500, detail="STR batch compilation failed.") from exc

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope=f"str_batch_generate:{tenant_id}",
        body={"tenant_id": str(tenant_id)},
        handler=_execute_generate,
        success_status_code=status.HTTP_201_CREATED,
        required=True,
    )


@router.get("/batches")
@router.get("/list")
async def list_str_batches(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100000),
    current_user: dict = Depends(RoleChecker(["ADMIN", "MLRO", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Lists all compiled regulatory STR batches with status and record counts (tenant-scoped)."""
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        rows = await list_str_batches_repo(
            str(tenant_id),
            limit,
            offset,
            conn_factory=get_async_db_conn,
        )
        batches = [
            {
                "batch_id": r["id"],
                "record_count": r["record_count"],
                "total_amount": float(r["total_amount"]),
                "total_amount_str": str(r["total_amount"]),
                "checksum": r["checksum"],
                "status": r["status"],
                "created_at": r["created_at"].isoformat(),
            }
            for r in rows
        ]
        return {"batches": batches}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to list STR batches")
        raise HTTPException(status_code=500, detail="Failed to fetch STR batches.") from exc


@router.get("/batches/{batch_id}/file")
@router.get("/batches/{batch_id}")
@router.get("/{batch_id}/download")
async def download_str_batch(
    batch_id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "MLRO", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=15, window=60)),
):
    """Streams the XML batch container for filing upload (tenant-scoped)."""
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        xml_payload = await fetch_str_batch_xml_repo(
            batch_id,
            str(tenant_id),
            conn_factory=get_async_db_conn,
        )
        if xml_payload is None:
            raise HTTPException(status_code=404, detail="STR batch not found.")

        safe_batch_id = re.sub(r"[^A-Za-z0-9._-]", "_", str(batch_id))[:80]
        filename = f"{safe_batch_id}.xml"
        return Response(
            content=xml_payload,
            media_type="application/xml",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Content-Type-Options": "nosniff",
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("STR batch download failed")
        raise HTTPException(status_code=500, detail="STR batch download failed.") from exc


@router.post("/batches/{batch_id}/transmissions")
@router.patch("/batches/{batch_id}")
@router.post("/{batch_id}/transmit")
async def transmit_str_batch(
    batch_id: str,
    request: Request = None,
    current_user: dict = Depends(PermissionChecker("sar:submit")),
    _rate_limit=Depends(RateLimiter(limit=5, window=60)),
):
    """
    Electronically transmits the full compiled STR batch package via a 3-phase Saga (T-05)
    under mandatory `Idempotency-Key` enforcement.
    """
    tenant_id = enforce_tenant_data_scope(current_user)

    async def _execute_transmit():
        try:
            payload_xml, existing_status = await claim_str_batch_for_transmission_repo(
                batch_id,
                str(tenant_id),
                conn_factory=get_async_db_conn,
            )
            if payload_xml is None:
                if existing_status is None:
                    raise HTTPException(status_code=404, detail="STR batch not found.")
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"STR batch {batch_id} cannot be transmitted: current status is '{existing_status}'.",
                )

            try:
                receipt = await fincen_client.submit_sar(payload_xml, batch_id)
            except Exception as exc:
                logger.exception("STR batch gateway transmission failed for %s", batch_id)
                try:
                    await mark_str_batch_failed_repo(batch_id, str(tenant_id), conn_factory=get_async_db_conn)
                except Exception:
                    pass
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Regulatory gateway transmission failed.",
                ) from exc

            await finalize_str_batch_transmission_atomic(
                batch_id=batch_id,
                tenant_id=str(tenant_id),
                receipt_status=receipt["status"],
                fincen_tracking_id=receipt.get("fincen_tracking_id"),
                actor=current_user,
                conn_factory=get_async_db_conn,
            )

            from routers.metrics import ws_manager

            await ws_manager.broadcast(
                {
                    "event": "STR_BATCH_TRANSMITTED",
                    "tenant_id": str(tenant_id),
                    "batch_id": batch_id,
                    "status": receipt["status"],
                    "fincen_tracking_id": receipt["fincen_tracking_id"],
                },
                target_tenant_id=str(tenant_id),
            )

            return {
                "batch_id": batch_id,
                "status": receipt["status"],
                "fincen_tracking_id": receipt["fincen_tracking_id"],
                "message": "Full STR batch container successfully transmitted to regulatory gateway.",
            }
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("STR batch transmission failed")
            raise HTTPException(status_code=500, detail="STR batch transmission failed.") from exc

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope=f"str_batch_transmit:{batch_id}",
        body={"batch_id": batch_id},
        handler=_execute_transmit,
        success_status_code=status.HTTP_200_OK,
        required=True,
    )
