"""
Dynamic Institutional Risk Appetite & Compliance Thresholds Router
===================================================================
Thin HTTP controller over `repositories/compliance_config_repo.py`.
Uses exact `Decimal` monetary thresholds, enforces mandatory `Idempotency-Key`
on PUT mutations, and commits settings + WORM `audit_log` in one ACID transaction.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, List

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field, field_validator

from database.postgres import get_async_db_conn, get_async_db_read_conn
from domain.money import InvalidMoneyError, parse_decimal_amount
from repositories.compliance_config_repo import (
    fetch_risk_appetite_repo,
    upsert_risk_appetite_atomic,
)
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.audit import record_audit_event_async
from services.http_cache import build_conditional_json_response
from services.idempotency import run_idempotent_operation
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/settings/risk-appetite", tags=["Risk Appetite Settings"])

_DEFAULT_APPETITE = {
    "jurisdiction_risk_multiplier": 1.5,
    "high_risk_jurisdictions": ["RU", "IR", "KP", "SY", "MM", "YE", "VE"],
    "pep_sanctions_auto_escalate": True,
    "cash_structuring_threshold": 10000.0,
    "cash_structuring_threshold_str": "10000.00",
    "crypto_travel_rule_threshold": 1000.0,
    "crypto_travel_rule_threshold_str": "1000.00",
    "max_velocity_deviation_zscore": 3.0,
    "sar_filing_sla_hours": 72,
    "edd_mandatory_score_threshold": 0.85,
    "round_trip_window_hours": 72,
    "updated_at": datetime.now(timezone.utc).isoformat(),
    "updated_by": "SYSTEM",
}

_tenant_appetite_cache: dict[str, dict[str, Any]] = {}


class RiskAppetiteConfig(BaseModel):
    jurisdiction_risk_multiplier: float = Field(default=1.5, ge=1.0, le=5.0)
    high_risk_jurisdictions: List[str] = Field(
        default=["RU", "IR", "KP", "SY", "MM", "YE", "VE"],
        max_length=100,
    )
    pep_sanctions_auto_escalate: bool = True
    cash_structuring_threshold: Decimal = Field(
        default=Decimal("10000.00"), ge=Decimal("1000.00"), le=Decimal("10000000.00")
    )
    crypto_travel_rule_threshold: Decimal = Field(
        default=Decimal("1000.00"), ge=Decimal("100.00"), le=Decimal("10000000.00")
    )
    max_velocity_deviation_zscore: float = Field(default=3.0, ge=1.0, le=10.0)
    sar_filing_sla_hours: int = Field(default=72, ge=12, le=720)
    edd_mandatory_score_threshold: float = Field(default=0.85, ge=0.5, le=0.99)
    round_trip_window_hours: int = Field(default=72, ge=1, le=720)

    @field_validator("cash_structuring_threshold", "crypto_travel_rule_threshold", mode="before")
    @classmethod
    def validate_decimal_threshold(cls, v: Any) -> Decimal:
        try:
            return parse_decimal_amount(v, allow_zero=False)
        except InvalidMoneyError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("high_risk_jurisdictions")
    @classmethod
    def sanitize_jurisdictions(cls, v: List[str]) -> List[str]:
        cleaned = []
        for code in v:
            c = str(code).strip().upper()[:8]
            if c and c.isalnum():
                cleaned.append(c)
        return cleaned


@router.get("")
@router.get("/")
async def get_risk_appetite_settings(
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "AUDITOR", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Retrieves current institutional risk appetite parameters for the caller's tenant."""
    tenant_id = enforce_tenant_data_scope(current_user)
    t_key = str(tenant_id)

    try:
        row = await fetch_risk_appetite_repo(
            uuid.UUID(t_key),
            read_conn_factory=get_async_db_read_conn,
        )
        if row:
            cfg = row["config"]
            if isinstance(cfg, str):
                cfg = json.loads(cfg)
            result = dict(_DEFAULT_APPETITE)
            result.update(cfg or {})
            result["updated_by"] = row["updated_by"] or result["updated_by"]
            result["updated_at"] = row["updated_at"].isoformat() if row["updated_at"] else result["updated_at"]
            result["tenant_id"] = t_key
            if len(_tenant_appetite_cache) >= 500:
                _tenant_appetite_cache.clear()
            _tenant_appetite_cache[t_key] = result
            return build_conditional_json_response(request, result)
    except Exception as e:
        logger.warning("PostgreSQL risk_appetite read fallback to cache: %s", e)

    if t_key in _tenant_appetite_cache:
        return build_conditional_json_response(request, _tenant_appetite_cache[t_key])

    return build_conditional_json_response(request, dict(_DEFAULT_APPETITE, tenant_id=t_key))


@router.put("")
@router.put("/")
async def update_risk_appetite_settings(
    payload: RiskAppetiteConfig,
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
):
    """
    Updates institutional risk appetite thresholds in PostgreSQL atomically with
    WORM `audit_log` and mandatory `Idempotency-Key` enforcement.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    t_key = str(tenant_id)

    async def _execute_update():
        now_utc = datetime.now(timezone.utc)
        updated_by = current_user.get("username", "admin")
        updated_data = payload.model_dump(mode="json")
        # Preserve backward-compatible float view alongside exact decimal strings
        updated_data["cash_structuring_threshold_str"] = str(payload.cash_structuring_threshold)
        updated_data["crypto_travel_rule_threshold_str"] = str(payload.crypto_travel_rule_threshold)
        updated_data["cash_structuring_threshold"] = float(payload.cash_structuring_threshold)
        updated_data["crypto_travel_rule_threshold"] = float(payload.crypto_travel_rule_threshold)
        updated_data["updated_at"] = now_utc.isoformat()
        updated_data["updated_by"] = updated_by
        updated_data["tenant_id"] = t_key

        default_before = _tenant_appetite_cache.get(t_key, dict(_DEFAULT_APPETITE))
        try:
            await upsert_risk_appetite_atomic(
                tenant_uuid=uuid.UUID(t_key),
                updated_data=updated_data,
                default_before=default_before,
                actor=current_user,
                now_utc=now_utc,
                sla_hours=payload.sar_filing_sla_hours,
                edd_threshold=payload.edd_mandatory_score_threshold,
                write_conn_factory=get_async_db_conn,
            )
        except Exception as e:
            logger.warning("PostgreSQL risk_appetite write fallback to cache: %s", e)
            await record_audit_event_async(
                action="UPDATE_RISK_APPETITE",
                actor_id=str(current_user.get("sub", current_user.get("username"))),
                actor_role=current_user.get("role", "MLRO"),
                resource_type="RISK_APPETITE",
                resource_id=t_key,
                tenant_id=t_key,
                actor_username=updated_by,
                before_state=default_before,
                after_state=updated_data,
                details={"sla_hours": payload.sar_filing_sla_hours, "edd_threshold": payload.edd_mandatory_score_threshold},
            )

        _tenant_appetite_cache[t_key] = updated_data
        logger.info("Risk appetite updated for tenant %s by %s", t_key, updated_by)
        return {"status": "UPDATED", "settings": updated_data}

    return await run_idempotent_operation(
        request=request,
        tenant_id=t_key,
        scope=f"risk_appetite_put:{t_key}",
        body=payload.model_dump(mode="json"),
        handler=_execute_update,
        success_status_code=status.HTTP_200_OK,
        required=True,
    )
