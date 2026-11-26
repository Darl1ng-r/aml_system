"""
Rules Engine Configuration & Builder Router
===========================================
Thin HTTP controller for multi-tenant rule configuration management,
shadow hit inspection, historical backtesting, and rule simulation.
All PostgreSQL SQL lives in `repositories/rules_repo.py`.
"""

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from database.postgres import get_async_db_conn, get_async_db_read_conn
from database.redis_db import get_async_redis_client
from observability.logging import log_audit_event
from observability.sanitizer import sanitize_text
from repositories.rules_repo import (
    get_rule_history_repo,
    list_rule_configs_repo,
    list_rule_shadow_hits_repo,
    patch_rule_config_atomic,
    persist_global_rules_config_atomic,
)
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.http_cache import build_conditional_json_response, build_version_etag
from services.idempotency import run_idempotent_operation
from services.rate_limiter import RateLimiter
from services.rules import RulesEngine, get_rules_config

logger = logging.getLogger(__name__)


def _write_config_sync(path: str, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


router = APIRouter(prefix="/api/v1/rules", tags=["Rules Configuration & Builder"])

CONFIG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rules_config.json"))


class RulePatchPayload(BaseModel):
    enabled: Optional[bool] = None
    mode: Optional[str] = Field(None, pattern=r"^(ACTIVE|SHADOW|DISABLED)$")
    config: Optional[Dict[str, Any]] = None
    shadow_config: Optional[Dict[str, Any]] = None
    expected_version: Optional[int] = Field(None, ge=0, le=1_000_000)
    change_reason: Optional[str] = Field("Rule threshold adjustment via Rule Builder", max_length=500)

    @field_validator("change_reason", mode="before")
    @classmethod
    def sanitize_change_reason(cls, v: Optional[str]) -> Optional[str]:
        return sanitize_text(v) if v else v


class RuleBacktestPayload(BaseModel):
    candidate_config: Dict[str, Any] = Field(default_factory=dict)
    lookback_days: int = Field(default=30, ge=1, le=180)
    sample_limit: int = Field(default=2000, ge=10, le=5000)


class RuleTestPayload(BaseModel):
    sender_id: str = Field("ACC-SENDER-TEST", min_length=1, max_length=100)
    receiver_id: str = Field("ACC-RCVR-TEST", min_length=1, max_length=100)
    amount: Decimal = Field(..., gt=Decimal("0"), le=Decimal("1000000000000"))
    sender_name: Optional[str] = Field("John Doe", max_length=200)
    sender_bic: Optional[str] = Field("DEUTDEDD", max_length=20)
    receiver_name: Optional[str] = Field("Jane Smith", max_length=200)
    receiver_bic: Optional[str] = Field("CHASUS33", max_length=20)

    @field_validator("amount", mode="before")
    @classmethod
    def validate_rule_test_amount(cls, v: Any) -> Decimal:
        from domain.money import InvalidMoneyError, parse_decimal_amount

        try:
            return parse_decimal_amount(v, allow_zero=False)
        except InvalidMoneyError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("sender_id", "receiver_id", "sender_name", "sender_bic", "receiver_name", "receiver_bic", mode="before")
    @classmethod
    def sanitize_rule_test_strings(cls, v: Optional[str]) -> Optional[str]:
        return sanitize_text(v) if isinstance(v, str) else v


class LegacyRulesConfigPayload(BaseModel):
    """Strict bounded schema replacing raw untyped `dict` on PUT /api/v1/rules/config (P2-10)."""

    rules: Dict[str, Dict[str, Any]] = Field(..., min_length=1)

    @field_validator("rules")
    @classmethod
    def validate_rules_bounds(cls, v: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        if len(v) > 100:
            raise ValueError("rules map cannot exceed 100 entries.")
        serialized = json.dumps(v)
        if len(serialized) > 256 * 1024:
            raise ValueError("Serialized rules payload exceeds 256 KB limit.")
        return v


@router.get("", response_model=List[Dict[str, Any]])
async def list_rules(
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Lists all detection rules configured for the current tenant with per-rule ETags."""
    tenant_id = enforce_tenant_data_scope(current_user)

    try:
        rows = await list_rule_configs_repo(
            tenant_id=str(tenant_id),
            conn_factory=get_async_db_conn,
        )
        if rows:
            payload = [
                {
                    "id": str(r["id"]),
                    "rule_name": r["rule_name"],
                    "enabled": r["enabled"],
                    "mode": r.get("mode") if hasattr(r, "get") else (r["mode"] if "mode" in r else "ACTIVE"),
                    "config": r["config"] if isinstance(r["config"], dict) else json.loads(r["config"]),
                    "shadow_config": (
                        r["shadow_config"]
                        if isinstance(
                            r.get("shadow_config")
                            if hasattr(r, "get")
                            else (r["shadow_config"] if "shadow_config" in r else None),
                            dict,
                        )
                        else (json.loads(r["shadow_config"]) if ("shadow_config" in r and r["shadow_config"]) else None)
                    ),
                    "version": r["version"],
                    "etag": build_version_etag("rule", r["version"]),
                    "updated_by_name": r["updated_by_name"] or "SYSTEM",
                    "updated_at": r["updated_at"].isoformat() if r["updated_at"] else "",
                    "description": r["description"] or "",
                }
                for r in rows
            ]
            return build_conditional_json_response(request, payload)
    except Exception as e:
        logger.warning("Failed to query rule_configs from DB: %s. Falling back to default list.", e)

    fallback = get_rules_config().get("rules", {})
    payload = [
        {
            "id": f"local-{name}",
            "rule_name": name,
            "enabled": conf.get("enabled", True),
            "config": {k: v for k, v in conf.items() if k != "enabled"},
            "version": 1,
            "etag": build_version_etag("rule", 1),
            "updated_by_name": "LOCAL_CONFIG",
            "updated_at": "",
            "description": f"Standard {name} monitoring rule",
        }
        for name, conf in fallback.items()
    ]
    return build_conditional_json_response(request, payload)


def _parse_user_uuid(user_id: Any) -> Optional[uuid.UUID]:
    if not user_id:
        return None
    try:
        return uuid.UUID(str(user_id))
    except (ValueError, TypeError):
        return None


def _compute_rule_updates(current_row: Any, payload: RulePatchPayload) -> Tuple[bool, dict, int]:
    if payload.enabled is not None:
        new_enabled = payload.enabled
    elif current_row:
        new_enabled = current_row["enabled"]
    else:
        new_enabled = True

    existing_config = {}
    if current_row and current_row["config"]:
        raw_cfg = current_row["config"]
        existing_config = raw_cfg if isinstance(raw_cfg, dict) else json.loads(raw_cfg)

    new_config = existing_config.copy()
    if payload.config is not None:
        new_config.update(payload.config)

    new_version = (current_row["version"] + 1) if current_row else 1
    return new_enabled, new_config, new_version


async def _broadcast_rule_invalidation(rule_name: str) -> None:
    RulesEngine.reload_config()
    try:
        redis = await get_async_redis_client()
        if redis:
            await redis.publish("aml:rules:cache_invalidate", f"rule_updated:{rule_name}")
    except Exception as re:
        logger.warning("Redis cache invalidation broadcast skipped: %s", re)


@router.patch("/{rule_name}")
async def patch_rule(
    rule_name: str,
    payload: RulePatchPayload,
    request: Request = None,
    response: Response = None,
    current_user: dict = Depends(RoleChecker(["ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
):
    """Updates rule thresholds, parameters, and/or enabled state with optimistic concurrency."""
    tenant_id = enforce_tenant_data_scope(current_user)
    user_id = current_user.get("id")
    user_uuid = _parse_user_uuid(user_id)
    username = current_user.get("username", "Admin")

    async def _execute_patch():
        try:
            result = await patch_rule_config_atomic(
                tenant_id=str(tenant_id),
                rule_name=rule_name,
                payload=payload,
                request=request,
                user_id=user_id,
                user_uuid=user_uuid,
                username=username,
                actor_role=current_user.get("role", "ADMIN"),
                compute_updates_fn=_compute_rule_updates,
                conn_factory=get_async_db_conn,
            )

            await _broadcast_rule_invalidation(rule_name)

            new_version = result["new_version"]
            new_enabled = result["new_enabled"]
            new_mode = result["new_mode"]
            new_config = result["new_config"]
            new_shadow = result["new_shadow"]

            log_audit_event(
                event_type="RULE_CONFIG_UPDATED",
                actor_id=str(user_id),
                actor_role=current_user.get("role", "ADMIN"),
                action="UPDATE_RULE",
                resource_type="RULE",
                resource_id=rule_name,
                tenant_id=tenant_id,
                details={
                    "rule_name": rule_name,
                    "version": new_version,
                    "enabled": new_enabled,
                    "config": new_config,
                    "reason": payload.change_reason,
                },
            )

            new_etag = build_version_etag("rule", new_version)
            body = {
                "status": "UPDATED",
                "rule_name": rule_name,
                "version": new_version,
                "etag": new_etag,
                "enabled": new_enabled,
                "mode": new_mode,
                "config": new_config,
                "shadow_config": new_shadow if isinstance(new_shadow, dict) else (json.loads(new_shadow) if new_shadow else None),
            }
            if response is not None:
                response.headers["ETag"] = new_etag
            return JSONResponse(content=body, status_code=status.HTTP_200_OK, headers={"ETag": new_etag})
        except HTTPException:
            raise
        except Exception:
            logger.exception("Failed to update rule %s", rule_name)
            raise HTTPException(status_code=500, detail="Failed to update rule configuration.")

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope=f"rule_patch:{rule_name}",
        body=payload.model_dump(mode="json"),
        handler=_execute_patch,
        success_status_code=status.HTTP_200_OK,
        required=True,
    )


@router.post("/{rule_name}/backtest")
async def backtest_rule_endpoint(
    rule_name: str,
    payload: RuleBacktestPayload,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=15, window=60)),
):
    """Read-only Historical Rule Backtesting (P1-2)."""
    from services.rule_backtest import backtest_rule_config

    tenant_id = enforce_tenant_data_scope(current_user)
    return await backtest_rule_config(
        tenant_id=str(tenant_id),
        rule_name=rule_name,
        candidate_config=payload.candidate_config,
        lookback_days=payload.lookback_days,
        sample_limit=payload.sample_limit,
    )


@router.get("/{rule_name}/shadow-hits")
async def list_rule_shadow_hits(
    rule_name: str,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Lists silent Challenger Shadow Mode hits recorded for a rule without paging analysts."""
    tenant_id = enforce_tenant_data_scope(current_user)
    rows = await list_rule_shadow_hits_repo(
        tenant_id=str(tenant_id),
        rule_name=rule_name,
        read_conn_factory=get_async_db_read_conn,
    )
    return {
        "rule_name": rule_name.upper().strip(),
        "total_shadow_hits": len(rows or []),
        "hits": [
            {
                "id": str(r["id"]),
                "transaction_id": str(r["transaction_id"]) if r["transaction_id"] else None,
                "sender_account_id": str(r["sender_account_id"]) if r["sender_account_id"] else None,
                "amount_base_usd": float(r["amount_base_usd"] or 0.0),
                "amount_base_usd_str": str(r["amount_base_usd"] if r["amount_base_usd"] is not None else "0.0000"),
                "rule_version": int(r["rule_version"] or 1),
                "matched_reason": r["matched_reason"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in (rows or [])
        ],
    }


@router.get("/{rule_name}/history")
async def get_rule_history(
    rule_name: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Returns the immutable audit history of changes made to this rule."""
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        rows = await get_rule_history_repo(
            tenant_id=str(tenant_id),
            rule_name=rule_name,
            conn_factory=get_async_db_conn,
        )
        return [
            {
                "id": str(r["id"]),
                "version": r["version"],
                "enabled": r["enabled"],
                "config": r["config"] if isinstance(r["config"], dict) else json.loads(r["config"]),
                "changed_by_name": r["changed_by_name"] or "ANONYMOUS",
                "changed_at": r["changed_at"].isoformat() if r["changed_at"] else "",
                "change_reason": r["change_reason"] or "",
            }
            for r in rows
        ]
    except Exception as e:
        logger.warning("Failed to fetch rule history: %s", e)
        return []


@router.post("/test")
async def test_rule_simulation(
    payload: RuleTestPayload,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "ADMIN", "ANALYST", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Evaluates a synthetic transaction against current rule definitions without side effects."""
    tenant_id = enforce_tenant_data_scope(current_user)
    triggered = await RulesEngine.evaluate_transaction(
        sender_id=payload.sender_id,
        receiver_id=payload.receiver_id,
        amount=payload.amount,
        sender_name=payload.sender_name,
        sender_bic=payload.sender_bic,
        receiver_name=payload.receiver_name,
        receiver_bic=payload.receiver_bic,
        timestamp=datetime.now(timezone.utc),
        tenant_id=tenant_id,
    )

    return {
        "status": "EVALUATED",
        "input": payload.model_dump(),
        "triggered_count": len(triggered),
        "triggered_rules": triggered,
        "is_suspicious": len(triggered) > 0,
    }


# ── Backward Compatible Global Platform Endpoints (SUPER_ADMIN Only) ──────────

@router.get("/config")
async def get_legacy_rules_config(
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Legacy endpoint returning default rules config dictionary."""
    return get_rules_config()


@router.put("/config")
async def update_legacy_rules_config(
    payload_model: LegacyRulesConfigPayload,
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    """Global rules defaults update (SUPER_ADMIN only) writing to DB, local file, and Redis."""
    payload = payload_model.model_dump()
    tenant_id = str(current_user.get("tenant_id")) if current_user.get("tenant_id") else None

    async def _execute_global_update():
        try:
            try:
                await persist_global_rules_config_atomic(
                    payload=payload,
                    current_user=current_user,
                    tenant_id=tenant_id,
                    conn_factory=get_async_db_conn,
                )
            except Exception as dbe:
                logger.warning("Failed to persist rules to PostgreSQL (falling back to disk): %s", dbe)

            try:
                await asyncio.to_thread(_write_config_sync, CONFIG_PATH, payload)
            except Exception as fe:
                logger.warning("Failed to write local rules file: %s", fe)

            RulesEngine.reload_config()

            try:
                redis = await get_async_redis_client()
                if redis:
                    await redis.publish("aml:rules:cache_invalidate", "reload")
            except Exception as re:
                logger.warning("Failed to publish rules invalidation to Redis: %s", re)

            return {"status": "SUCCESS", "message": "Rules configuration updated successfully"}
        except HTTPException:
            raise
        except Exception:
            logger.exception("Failed to update global rules configuration")
            raise HTTPException(status_code=500, detail="Failed to update rules configuration.")

    return await run_idempotent_operation(
        request=request,
        tenant_id=tenant_id,
        scope="global_rules_config_put",
        body=payload,
        handler=_execute_global_update,
        success_status_code=status.HTTP_200_OK,
        required=True,
    )
