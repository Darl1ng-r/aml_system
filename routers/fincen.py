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
from datetime import datetime, timezone
from pydantic import BaseModel, Field, field_validator
from fastapi import APIRouter, Depends, HTTPException, Response, status
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
    draft_id: str | None = None

    @field_validator("sar_xml", mode="before")
    @classmethod
    def sanitize_xml(cls, v: str) -> str:
        return sanitize_text(v)


class SARDraftCreate(BaseModel):
    alert_id: str
    narrative: str = Field(..., min_length=10, max_length=10000)
    xml_payload: str | None = None
    case_id: str | None = None

    @field_validator("narrative", mode="before")
    @classmethod
    def sanitize_narrative(cls, v: str) -> str:
        return sanitize_text(v)


class SARDraftReview(BaseModel):
    action: str = Field(..., pattern=r"^(APPROVE|REJECT)$")
    rejection_reason: str | None = Field(None, max_length=1000)

    @field_validator("rejection_reason", mode="before")
    @classmethod
    def sanitize_reason(cls, v: str | None) -> str | None:
        return sanitize_text(v) if v else None


class SARDraftUpdate(BaseModel):
    narrative: str | None = Field(None, min_length=10, max_length=10000)
    xml_payload: str | None = None
    status: str | None = Field(None, pattern=r"^(DRAFT|PENDING_MLRO_REVIEW)$")

    @field_validator("narrative", mode="before")
    @classmethod
    def sanitize_narrative(cls, v: str | None) -> str | None:
        return sanitize_text(v) if v else None


class SARPreviewRequest(BaseModel):
    alert_id: str | None = None
    narrative: str = Field(..., min_length=5, max_length=10000)
    format: str = Field("FINCEN", pattern=r"^(FINCEN|GOAML)$")
    amount: float | None = None
    currency: str | None = "USD"
    sender_name: str | None = None
    receiver_name: str | None = None


@router.post("/sars", status_code=status.HTTP_201_CREATED)
@router.post("/sar/submit", status_code=status.HTTP_201_CREATED)
async def submit_sar_to_fincen(
    payload: FinCENSubmissionRequest,
    response: Response = None,
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

        if response is not None:
            response.headers["Location"] = f"/api/v1/fincen/sars/{payload.alert_id}"

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


@router.get("/sars/{id}")
@router.get("/sars/{id}/status")
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


@router.post("/sar/drafts", status_code=status.HTTP_201_CREATED)
async def create_sar_draft(
    payload: SARDraftCreate,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """
    Creates a new SAR draft for an alert or case, awaiting MLRO 4-eyes review.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        alert_uuid = uuid.UUID(payload.alert_id)
        case_uuid = uuid.UUID(payload.case_id) if payload.case_id else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert_id or case_id format.")

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        user_uuid = None
        if current_user.get("id"):
            try:
                user_uuid = uuid.UUID(str(current_user["id"]))
            except ValueError:
                user_uuid = None

        draft_id = await conn.fetchval(
            """
            INSERT INTO sar_drafts (
                tenant_id, alert_id, case_id, drafted_by, drafted_by_username,
                status, narrative, xml_payload
            ) VALUES ($1, $2, $3, $4, $5, 'PENDING_MLRO_REVIEW', $6, $7)
            RETURNING id;
            """,
            uuid.UUID(str(tenant_id)), alert_uuid, case_uuid,
            user_uuid,
            current_user.get("username", "analyst"),
            payload.narrative, payload.xml_payload
        )

        return {
            "draft_id": str(draft_id),
            "alert_id": payload.alert_id,
            "status": "PENDING_MLRO_REVIEW",
            "message": "SAR draft created successfully. Awaiting compliance officer / MLRO review."
        }


@router.get("/sar/drafts")
async def list_sar_drafts(
    current_user: dict = Depends(RoleChecker(["ANALYST", "L1_ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN", "AUDITOR"])),
    status_filter: str | None = None,
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        if status_filter:
            rows = await conn.fetch(
                "SELECT * FROM sar_drafts WHERE tenant_id = $1 AND status = $2 ORDER BY created_at DESC LIMIT 100;",
                uuid.UUID(str(tenant_id)), status_filter.upper()
            )
        else:
            rows = await conn.fetch(
                "SELECT * FROM sar_drafts WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100;",
                uuid.UUID(str(tenant_id))
            )
        return [
            {
                "draft_id": str(r["id"]),
                "alert_id": str(r["alert_id"]) if r["alert_id"] else None,
                "case_id": str(r["case_id"]) if r["case_id"] else None,
                "status": r["status"],
                "drafted_by_username": r["drafted_by_username"],
                "narrative": r["narrative"],
                "reviewed_by_username": r["reviewed_by_username"],
                "rejection_reason": r["rejection_reason"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None
            }
            for r in rows
        ]


@router.post("/sar/drafts/{id}/review")
async def review_sar_draft(
    id: str,
    payload: SARDraftReview,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """
    MLRO Four-Eyes Review on a SAR draft. Enforces Segregation of Duties (SOD):
    The reviewer cannot approve or reject a draft they authored themselves.
    """
    try:
        draft_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid draft ID.")

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        draft = await conn.fetchrow("SELECT * FROM sar_drafts WHERE id = $1;", draft_uuid)
        if not draft:
            raise HTTPException(status_code=404, detail="SAR draft not found.")

        if draft["status"] != "PENDING_MLRO_REVIEW":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid state transition: SAR draft is already {draft['status']} and cannot be re-reviewed."
            )

        caller_id = str(current_user.get("id", ""))
        caller_role = current_user.get("role", "")
        if draft["drafted_by"] and str(draft["drafted_by"]) == caller_id and caller_role != "SUPER_ADMIN":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Segregation of Duties Violation: Reviewer cannot approve a SAR draft they authored."
            )

        new_status = "APPROVED" if payload.action == "APPROVE" else "REJECTED"
        user_uuid = None
        if caller_id:
            try:
                user_uuid = uuid.UUID(caller_id)
            except ValueError:
                user_uuid = None

        # Optimistic concurrency locking (RACE-03): update only if still PENDING_MLRO_REVIEW
        updated_id = await conn.fetchval(
            """
            UPDATE sar_drafts
            SET status = $1,
                reviewed_by = $2,
                reviewed_by_username = $3,
                rejection_reason = $4,
                reviewed_at = NOW(),
                updated_at = NOW()
            WHERE id = $5 AND status = 'PENDING_MLRO_REVIEW'
            RETURNING id;
            """,
            new_status,
            user_uuid,
            current_user.get("username", "mlro"),
            payload.rejection_reason,
            draft_uuid
        )

        if not updated_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Concurrent modification conflict: SAR draft was already reviewed or modified by another officer."
            )

        return {
            "draft_id": str(draft_uuid),
            "status": new_status,
            "reviewed_by": current_user.get("username", "mlro"),
            "message": f"SAR draft successfully {new_status.lower()}."
        }


@router.get("/sar/drafts/{id}")
async def get_sar_draft(
    id: str,
    current_user: dict = Depends(RoleChecker(["ANALYST", "L1_ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    """Retrieves full details of a specific SAR draft, including linked alert context."""
    try:
        draft_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid draft ID.")

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        draft = await conn.fetchrow(
            """
            SELECT d.*, 
                   a.rule_name, a.threat_level, a.ai_risk_score,
                   t.amount, t.currency, t.sender_account_id, t.receiver_account_id
            FROM sar_drafts d
            LEFT JOIN alerts a ON d.alert_id = a.id
            LEFT JOIN transactions t ON a.transaction_id = t.id
            WHERE d.id = $1 AND d.tenant_id = $2;
            """,
            draft_uuid, uuid.UUID(str(tenant_id))
        )
        if not draft:
            raise HTTPException(status_code=404, detail="SAR draft not found.")

        return {
            "draft_id": str(draft["id"]),
            "alert_id": str(draft["alert_id"]) if draft["alert_id"] else None,
            "case_id": str(draft["case_id"]) if draft["case_id"] else None,
            "status": draft["status"],
            "drafted_by": str(draft["drafted_by"]) if draft["drafted_by"] else None,
            "drafted_by_username": draft["drafted_by_username"],
            "narrative": draft["narrative"] or "",
            "xml_payload": draft["xml_payload"] or "",
            "reviewed_by_username": draft["reviewed_by_username"],
            "rejection_reason": draft["rejection_reason"],
            "created_at": draft["created_at"].isoformat() if draft["created_at"] else None,
            "updated_at": draft["updated_at"].isoformat() if draft.get("updated_at") else None,
            "alert_details": {
                "rule_name": draft.get("rule_name") or "SUSPICIOUS_ACTIVITY",
                "threat_level": draft.get("threat_level") or "HIGH",
                "risk_score": float(draft.get("ai_risk_score") or 0.85),
                "amount": float(draft.get("amount") or 0.0),
                "currency": draft.get("currency") or "USD",
                "sender_account": draft.get("sender_account_id") or "",
                "receiver_account": draft.get("receiver_account_id") or ""
            }
        }


@router.patch("/sar/drafts/{id}")
async def update_sar_draft(
    id: str,
    payload: SARDraftUpdate,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """Updates narrative or xml_payload of an open or in-progress SAR draft."""
    try:
        draft_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid draft ID.")

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        draft = await conn.fetchrow(
            "SELECT id, status FROM sar_drafts WHERE id = $1 AND tenant_id = $2;",
            draft_uuid, uuid.UUID(str(tenant_id))
        )
        if not draft:
            raise HTTPException(status_code=404, detail="SAR draft not found.")

        if draft["status"] in ["APPROVED", "FILED"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot edit SAR draft in '{draft['status']}' state."
            )

        new_narrative = payload.narrative
        new_xml = payload.xml_payload
        new_status = payload.status or draft["status"]

        await conn.execute(
            """
            UPDATE sar_drafts
            SET narrative = COALESCE($1, narrative),
                xml_payload = COALESCE($2, xml_payload),
                status = $3,
                updated_at = NOW()
            WHERE id = $4;
            """,
            new_narrative, new_xml, new_status, draft_uuid
        )

        return {
            "draft_id": str(draft_uuid),
            "status": new_status,
            "message": "SAR draft updated successfully."
        }


@router.post("/sar/preview")
async def preview_sar_xml(
    payload: SARPreviewRequest,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"]))
):
    """Generates a live preview XML payload in either FinCEN BSA or UNODC EU goAML format."""
    from services.goaml import generate_goaml_xml
    from routers.alerts import generate_sar_xml

    tenant_id = enforce_tenant_data_scope(current_user)
    alert_tuple = None

    if payload.alert_id:
        try:
            alert_uuid = uuid.UUID(payload.alert_id)
            async with get_async_db_conn(tenant_id=tenant_id) as conn:
                row = await conn.fetchrow(
                    """
                    SELECT a.id, a.rule_name, a.threat_level, a.ai_risk_score,
                           COALESCE(t.amount, 10000.0) as amount,
                           COALESCE(t.currency, 'USD') as currency,
                           COALESCE(t.timestamp, NOW()) as timestamp,
                           COALESCE(t.sender_account_id, 'ACC-ORIGINATOR') as s_acc,
                           COALESCE(s_acc.owner_name, 'Sender Entity') as s_owner,
                           COALESCE(t.receiver_account_id, 'ACC-BENEFICIARY') as r_acc,
                           COALESCE(r_acc.owner_name, 'Receiver Entity') as r_owner
                    FROM alerts a
                    LEFT JOIN transactions t ON a.transaction_id = t.id
                    LEFT JOIN accounts s_acc ON t.sender_account_id = s_acc.account_number
                    LEFT JOIN accounts r_acc ON t.receiver_account_id = r_acc.account_number
                    WHERE a.id = $1;
                    """,
                    alert_uuid
                )
                if row:
                    alert_tuple = (
                        row["id"], row["rule_name"], row["threat_level"],
                        float(row["ai_risk_score"] or 0.8), float(row["amount"]),
                        row["currency"], row["timestamp"], row["s_acc"],
                        row["s_owner"], row["r_acc"], row["r_owner"]
                    )
        except Exception as e:
            logger.debug(f"Alert lookup for XML preview fallback to payload values: {e}")

    if not alert_tuple:
        alert_tuple = (
            payload.alert_id or str(uuid.uuid4()),
            "SUSPICIOUS_ACTIVITY",
            "HIGH",
            0.85,
            payload.amount or 15000.0,
            payload.currency or "USD",
            datetime.now(timezone.utc),
            "ORIG-ACCOUNT-001",
            payload.sender_name or "Subject Organization Inc.",
            "DEST-ACCOUNT-002",
            payload.receiver_name or "Counterparty LLC"
        )

    if payload.format.upper() == "GOAML":
        xml_output = generate_goaml_xml(alert_tuple, payload.narrative, report_code="STR")
    else:
        xml_output = generate_sar_xml(alert_tuple, payload.narrative)

    return {
        "format": payload.format.upper(),
        "xml": xml_output
    }


@router.get("/sar/drafts/{id}/export")
async def export_sar_draft_xml(
    id: str,
    format: str = "FINCEN",
    current_user: dict = Depends(RoleChecker(["ANALYST", "L1_ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN", "AUDITOR"]))
):
    """Downloads the generated XML representation for a draft in FinCEN or EU goAML schema."""
    draft_data = await get_sar_draft(id=id, current_user=current_user)
    alert_info = draft_data.get("alert_details", {})

    prev_req = SARPreviewRequest(
        alert_id=draft_data.get("alert_id"),
        narrative=draft_data.get("narrative") or "Suspicious activity detected.",
        format=format.upper(),
        amount=alert_info.get("amount"),
        currency=alert_info.get("currency"),
        sender_name=alert_info.get("sender_account"),
        receiver_name=alert_info.get("receiver_account")
    )

    preview_res = await preview_sar_xml(payload=prev_req, current_user=current_user)
    return Response(
        content=preview_res["xml"],
        media_type="application/xml",
        headers={"Content-Disposition": f"attachment; filename=sar_{id}_{format.lower()}.xml"}
    )

