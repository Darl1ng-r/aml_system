"""
Dynamic Institutional Risk Appetite & Compliance Thresholds Router
===================================================================
Provides MLRO and Compliance Officer controls to configure institutional risk appetite,
jurisdiction multipliers, SAR SLA deadlines, and EDD mandatory thresholds.
Changes are audit-logged and applied dynamically without codebase re-deployment.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from database.postgres import get_async_db_conn, get_async_db_read_conn
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.audit import record_audit_event_async
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/settings/risk-appetite", tags=["Risk Appetite Settings"])

# Default in-memory cache for fast retrieval
_DEFAULT_APPETITE = {
    "jurisdiction_risk_multiplier": 1.5,
    "high_risk_jurisdictions": ["RU", "IR", "KP", "SY", "MM", "YE", "VE"],
    "pep_sanctions_auto_escalate": True,
    "cash_structuring_threshold": 10000.0,
    "crypto_travel_rule_threshold": 1000.0,
    "max_velocity_deviation_zscore": 3.0,
    "sar_filing_sla_hours": 72,
    "edd_mandatory_score_threshold": 0.85,
    "round_trip_window_hours": 72,
    "updated_at": datetime.now(timezone.utc).isoformat(),
    "updated_by": "SYSTEM"
}

_tenant_appetite_cache = {}


class RiskAppetiteConfig(BaseModel):
    jurisdiction_risk_multiplier: float = Field(default=1.5, ge=1.0, le=5.0)
    high_risk_jurisdictions: List[str] = Field(default=["RU", "IR", "KP", "SY", "MM", "YE", "VE"])
    pep_sanctions_auto_escalate: bool = True
    cash_structuring_threshold: float = Field(default=10000.0, ge=1000.0)
    crypto_travel_rule_threshold: float = Field(default=1000.0, ge=100.0)
    max_velocity_deviation_zscore: float = Field(default=3.0, ge=1.0, le=10.0)
    sar_filing_sla_hours: int = Field(default=72, ge=12, le=720)
    edd_mandatory_score_threshold: float = Field(default=0.85, ge=0.5, le=0.99)
    round_trip_window_hours: int = Field(default=72, ge=1, le=720)


@router.get("")
@router.get("/")
async def get_risk_appetite_settings(
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "AUDITOR", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    """Retrieves current institutional risk appetite parameters for the caller's tenant."""
    tenant_id = enforce_tenant_data_scope(current_user)
    t_key = str(tenant_id)

    if t_key in _tenant_appetite_cache:
        return _tenant_appetite_cache[t_key]

    return dict(_DEFAULT_APPETITE, tenant_id=t_key)


@router.put("")
@router.put("/")
async def update_risk_appetite_settings(
    payload: RiskAppetiteConfig,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60))
):
    """
    Updates institutional risk appetite thresholds.
    Audited with before/after state diff under FFIEC regulatory mandate.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    t_key = str(tenant_id)
    before_state = _tenant_appetite_cache.get(t_key, dict(_DEFAULT_APPETITE))

    updated_data = payload.model_dump()
    updated_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    updated_data["updated_by"] = current_user.get("username", "admin")
    updated_data["tenant_id"] = t_key

    _tenant_appetite_cache[t_key] = updated_data

    # Audit the risk appetite alteration
    await record_audit_event_async(
        action="UPDATE_RISK_APPETITE",
        actor_id=str(current_user.get("sub", current_user.get("username"))),
        actor_role=current_user.get("role", "MLRO"),
        resource_type="RISK_APPETITE",
        resource_id=t_key,
        tenant_id=t_key,
        actor_username=current_user.get("username"),
        before_state=before_state,
        after_state=updated_data,
        details={"sla_hours": payload.sar_filing_sla_hours, "edd_threshold": payload.edd_mandatory_score_threshold}
    )

    logger.info(f"Risk appetite updated for tenant {t_key} by {current_user.get('username')}")

    return {
        "status": "UPDATED",
        "settings": updated_data
    }
