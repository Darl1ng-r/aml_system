"""
FinCEN Regulatory E-Filing Router
==================================
Provides HTTP API endpoints for electronic FinCEN SAR transmission:

  - POST /api/v1/fincen/sar/submit:
      Submits SAR XML electronically to the FinCEN BSA E-Filing System.
      Stores FinCEN Tracking ID, ACK confirmation, and submission timestamps in PostgreSQL.

  - GET /api/v1/fincen/sar/status/{id}:
      Queries filing status and receipt for a target alert.
"""

import logging
import uuid
from pydantic import BaseModel, Field, field_validator
from fastapi import APIRouter, Depends, HTTPException
from database.postgres import get_async_db_conn
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.fincen_efiling import fincen_client
from services.rate_limiter import RateLimiter
from observability.sanitizer import sanitize_text

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/fincen", tags=["FinCEN E-Filing"])


class FinCENSubmissionRequest(BaseModel):
    alert_id: str
    sar_xml: str = Field(..., min_length=10, max_length=100000)

    @field_validator("sar_xml", mode="before")
    @classmethod
    def sanitize_xml(cls, v: str) -> str:
        return sanitize_text(v)


@router.post("/sar/submit")
async def submit_sar_to_fincen(
    payload: FinCENSubmissionRequest,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60))
):
    """
    Submits a Suspicious Activity Report XML electronically to the U.S. FinCEN BSA E-Filing Gateway.
    """
    try:
        alert_uuid = uuid.UUID(payload.alert_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert_id format.")

    tenant_id = enforce_tenant_data_scope(current_user)

    try:
        # Submit electronically to FinCEN BSA E-Filing API
        receipt = await fincen_client.submit_sar(payload.sar_xml, payload.alert_id)

        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            # Store FinCEN tracking columns in PostgreSQL
            await conn.execute(
                """
                UPDATE alerts
                SET fincen_tracking_id = $1,
                    fincen_filing_status = $2,
                    fincen_submitted_at = NOW()
                WHERE id = $3;
                """,
                receipt["fincen_tracking_id"], receipt["status"], alert_uuid
            )

        # Audit logging
        logger.info(
            f"AUDIT LOG: FinCEN SAR electronically filed by '{current_user['username']}' "
            f"for Alert {payload.alert_id} | Tracking ID: {receipt['fincen_tracking_id']} | Status: {receipt['status']}"
        )

        # Broadcast real-time WebSocket notification
        from routers.metrics import ws_manager
        await ws_manager.broadcast({
            "event": "FINCEN_SAR_FILED",
            "alert_id": payload.alert_id,
            "fincen_tracking_id": receipt["fincen_tracking_id"],
            "status": receipt["status"],
            "submitted_by": current_user["username"]
        })

        return {
            "alert_id": payload.alert_id,
            "fincen_tracking_id": receipt["fincen_tracking_id"],
            "status": receipt["status"],
            "ack_code": receipt["fincen_ack_code"],
            "confirmation_message": receipt["fincen_confirmation_message"],
            "submitted_at": receipt["submitted_at"],
            "sandbox": receipt.get("sandbox", True)
        }
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"FinCEN SAR submission failed: {e}")
        raise HTTPException(status_code=500, detail=f"FinCEN filing failed: {str(e)}")


@router.get("/sar/status/{id}")
async def get_fincen_status(
    id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """
    Retrieves electronic FinCEN filing status and tracking information for an alert case.
    """
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert ID.")

    tenant_id = enforce_tenant_data_scope(current_user)

    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            row = await conn.fetchrow(
                """
                SELECT id, status, fincen_tracking_id, fincen_filing_status, fincen_submitted_at
                FROM alerts
                WHERE id = $1;
                """,
                alert_uuid
            )
            if not row:
                raise HTTPException(status_code=404, detail="Alert not found.")

            return {
                "alert_id": str(row["id"]),
                "alert_status": row["status"],
                "fincen_tracking_id": row["fincen_tracking_id"] or "NOT_FILED",
                "fincen_filing_status": row["fincen_filing_status"] or "UNSUBMITTED",
                "fincen_submitted_at": row["fincen_submitted_at"].isoformat() if row["fincen_submitted_at"] else None
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query FinCEN status: {str(e)}")
