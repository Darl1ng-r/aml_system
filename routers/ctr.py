"""
Currency Transaction Report (CTR) Regulatory Filing Router
==========================================================
Thin HTTP transport controller over `repositories/ctr_repo.py` and `domain/state_machine.py`.
Enforces:
  - Mandatory `Idempotency-Key` (`400 Bad Request` if missing) on `POST /filings/{id}/submit`
  - Row-level `FOR UPDATE` locking + deterministic `CTRFilingStatus` FSM guard (`PENDING -> FILED`)
  - Atomic cryptographic WORM `audit_log` persistence inside the same ACID transaction.
"""

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from domain.state_machine import CorruptedDomainStateError, DomainStateTransitionError
from repositories.ctr_repo import list_ctr_filings_repo, submit_ctr_filing_atomic
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.idempotency import run_idempotent_operation
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ctr", tags=["Currency Transaction Reports (CTR)"])


@router.get("/filings")
async def list_ctr_filings(
    page: int = Query(default=1, ge=1, le=1000),
    limit: int = Query(default=50, ge=1, le=100),
    status_filter: Optional[str] = None,
    current_user: dict = Depends(RoleChecker(["ANALYST", "L1_ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)
    offset = (page - 1) * limit
    rows = await list_ctr_filings_repo(
        tenant_id=tenant_id,
        limit=limit,
        offset=offset,
        status_filter=status_filter,
    )

    return [
        {
            "ctr_id": str(r["id"]),
            "transaction_id": str(r["transaction_id"]) if r["transaction_id"] else None,
            "account_id": str(r["account_id"]),
            "account_number": r["account_number"],
            "owner_name": r["owner_name"],
            "amount": float(r["amount"]),
            "currency": r["currency"],
            "cash_direction": r["cash_in_out"],
            "status": r["status"],
            "due_date": r["due_date"].isoformat() if r["due_date"] else None,
            "fincen_tracking_id": r["fincen_tracking_id"],
            "filed_at": r["filed_at"].isoformat() if r["filed_at"] else None,
        }
        for r in rows
    ]


@router.post("/filings/{id}/submit")
async def submit_ctr_filing(
    id: str,
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
):
    try:
        ctr_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid CTR ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)

    async def _execute_submit():
        try:
            result = await submit_ctr_filing_atomic(
                ctr_uuid=ctr_uuid,
                tenant_id=tenant_id,
                current_user=current_user,
            )
        except CorruptedDomainStateError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        except DomainStateTransitionError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

        if result is None:
            raise HTTPException(status_code=404, detail="CTR filing record not found.")
        return result

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id) if tenant_id else None,
        scope=f"ctr_submit:{ctr_uuid}",
        body={"ctr_id": str(ctr_uuid)},
        handler=_execute_submit,
        success_status_code=status.HTTP_200_OK,
        required=True,
    )
