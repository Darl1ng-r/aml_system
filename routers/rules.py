"""
Rules Engine Configuration & Builder Router (Sprint 1 / Task 1.5, 1.6 Audit Remediation)
========================================================================================
Provides multi-tenant rule configuration management backed by PostgreSQL rule_configs
and rule_config_history tables, with Redis pub/sub invalidation and simulation test harness.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from observability.sanitizer import sanitize_text
from typing import Optional, Dict, Any, List, Tuple
import json
import os
import uuid
import logging
import asyncio
from datetime import datetime, timezone
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter
from database.postgres import get_async_db_conn
from database.redis_db import get_async_redis_client
from observability.logging import log_audit_event
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
    amount: float = Field(..., gt=0, le=1_000_000_000_000.0)
    sender_name: Optional[str] = Field("John Doe", max_length=200)
    sender_bic: Optional[str] = Field("DEUTDEDD", max_length=20)
    receiver_name: Optional[str] = Field("Jane Smith", max_length=200)
    receiver_bic: Optional[str] = Field("CHASUS33", max_length=20)

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
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """
    Lists all detection rules configured for the current tenant, including
    active parameters, version number, and toggle status.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    tenant_uuid = uuid.UUID(str(tenant_id))

    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            rows = await conn.fetch(
                """
                SELECT id, rule_name, enabled, mode, config, shadow_config, version,
                       updated_by_name, updated_at, description
                FROM rule_configs
                WHERE tenant_id = $1
                ORDER BY rule_name ASC;
                """,
                tenant_uuid
            )
            if rows:
                return [
                    {
                        "id": str(r["id"]),
                        "rule_name": r["rule_name"],
                        "enabled": r["enabled"],
                        "mode": r.get("mode") if hasattr(r, "get") else (r["mode"] if "mode" in r else "ACTIVE"),
                        "config": r["config"] if isinstance(r["config"], dict) else json.loads(r["config"]),
                        "shadow_config": (
                            r["shadow_config"]
                            if isinstance(r.get("shadow_config") if hasattr(r, "get") else (r["shadow_config"] if "shadow_config" in r else None), dict)
                            else (json.loads(r["shadow_config"]) if ("shadow_config" in r and r["shadow_config"]) else None)
                        ),
                        "version": r["version"],
                        "updated_by_name": r["updated_by_name"] or "SYSTEM",
                        "updated_at": r["updated_at"].isoformat() if r["updated_at"] else "",
                        "description": r["description"] or ""
                    }
                    for r in rows
                ]
    except Exception as e:
        logger.warning(f"Failed to query rule_configs from DB: {e}. Falling back to default list.")

    # Fallback to local config file
    fallback = get_rules_config().get("rules", {})
    return [
        {
            "id": f"local-{name}",
            "rule_name": name,
            "enabled": conf.get("enabled", True),
            "config": {k: v for k, v in conf.items() if k != "enabled"},
            "version": 1,
            "updated_by_name": "LOCAL_CONFIG",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "description": f"Standard {name} monitoring rule"
        }
        for name, conf in fallback.items()
    ]


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
        logger.warning(f"Redis cache invalidation broadcast skipped: {re}")


@router.patch("/{rule_name}")
async def patch_rule(
    rule_name: str,
    payload: RulePatchPayload,
    current_user: dict = Depends(RoleChecker(["ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
):
    """
    Updates rule thresholds, parameters, and/or enabled state.
    Increments version, logs historical audit record, and invalidates Redis cache.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    tenant_uuid = uuid.UUID(str(tenant_id))
    user_id = current_user.get("id")
    user_uuid = _parse_user_uuid(user_id)
    username = current_user.get("username", "Admin")

    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            # 1. Fetch existing rule
            current_row = await conn.fetchrow(
                """
                SELECT id, enabled, mode, config, shadow_config, version
                FROM rule_configs
                WHERE tenant_id = $1 AND rule_name = $2;
                """,
                tenant_uuid, rule_name
            )

            new_enabled, new_config, new_version = _compute_rule_updates(current_row, payload)
            existing_mode = (current_row["mode"] if current_row and "mode" in current_row else "ACTIVE") or "ACTIVE"
            new_mode = payload.mode or ("DISABLED" if payload.enabled is False else existing_mode)
            if payload.mode == "DISABLED":
                new_enabled = False
            elif payload.mode in ("ACTIVE", "SHADOW") and payload.enabled is None:
                new_enabled = True

            existing_shadow = current_row["shadow_config"] if (current_row and "shadow_config" in current_row) else None
            new_shadow = payload.shadow_config if payload.shadow_config is not None else existing_shadow
            new_shadow_json = json.dumps(new_shadow) if isinstance(new_shadow, dict) else new_shadow

            # 2. Upsert into rule_configs
            saved_id = await conn.fetchval(
                """
                INSERT INTO rule_configs (
                    tenant_id, rule_name, enabled, mode, config, shadow_config, version,
                    updated_by, updated_by_name, updated_at
                )
                VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8, $9, NOW())
                ON CONFLICT (tenant_id, rule_name) DO UPDATE
                SET enabled = EXCLUDED.enabled,
                    mode = EXCLUDED.mode,
                    config = EXCLUDED.config,
                    shadow_config = EXCLUDED.shadow_config,
                    version = EXCLUDED.version,
                    updated_by = EXCLUDED.updated_by,
                    updated_by_name = EXCLUDED.updated_by_name,
                    updated_at = NOW()
                RETURNING id;
                """,
                tenant_uuid, rule_name, new_enabled, new_mode, json.dumps(new_config),
                new_shadow_json, new_version, user_uuid, username
            )

            # 3. Insert audit snapshot into rule_config_history
            await conn.execute(
                """
                INSERT INTO rule_config_history (
                    rule_config_id, tenant_id, rule_name, enabled, config,
                    version, changed_by, changed_by_name, change_reason
                )
                VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9);
                """,
                saved_id, tenant_uuid, rule_name, new_enabled,
                json.dumps(new_config), new_version, user_uuid, username,
                payload.change_reason or "Rule adjusted"
            )

            # 3b. Transactional WORM audit record
            try:
                from services.audit import record_audit_event_tx
                await record_audit_event_tx(
                    conn=conn,
                    action="UPDATE_RULE",
                    actor_id=str(user_id or username),
                    actor_username=username,
                    actor_role=current_user.get("role", "ADMIN"),
                    resource_type="RULE",
                    resource_id=rule_name,
                    tenant_id=str(tenant_id),
                    details={"rule_name": rule_name, "version": new_version, "enabled": new_enabled, "mode": new_mode},
                )
            except Exception as audit_err:
                logger.warning(f"Transactional audit write skipped in patch_rule: {audit_err}")

        # 4. Invalidate memory cache and broadcast to Redis
        await _broadcast_rule_invalidation(rule_name)

        # 5. Log audit event
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
                "reason": payload.change_reason
            }
        )

        return {
            "status": "UPDATED",
            "rule_name": rule_name,
            "version": new_version,
            "enabled": new_enabled,
            "mode": new_mode,
            "config": new_config,
            "shadow_config": new_shadow if isinstance(new_shadow, dict) else (json.loads(new_shadow) if new_shadow else None),
        }
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to update rule %s", rule_name)
        raise HTTPException(status_code=500, detail="Failed to update rule configuration.")


@router.post("/{rule_name}/backtest")
async def backtest_rule_endpoint(
    rule_name: str,
    payload: RuleBacktestPayload,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=15, window=60)),
):
    """
    Read-only Historical Rule Backtesting (P1-2):
    Replays a candidate threshold configuration against historical transactions
    on the read replica to project alert volume delta & false-positive impact.
    """
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
    from database.postgres import get_async_db_read_conn

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, rule_name, transaction_id, sender_account_id,
                   amount_base_usd, rule_version, matched_reason, created_at
            FROM rule_shadow_hits
            WHERE rule_name = $1 AND tenant_id = $2::uuid
            ORDER BY created_at DESC
            LIMIT 100;
            """,
            rule_name.upper().strip(),
            str(tenant_id),
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
    """
    Returns the immutable audit history of changes made to this rule.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    tenant_uuid = uuid.UUID(str(tenant_id))

    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            rows = await conn.fetch(
                """
                SELECT id, version, enabled, config, changed_by_name, changed_at, change_reason
                FROM rule_config_history
                WHERE tenant_id = $1 AND rule_name = $2
                ORDER BY version DESC;
                """,
                tenant_uuid, rule_name
            )
            return [
                {
                    "id": str(r["id"]),
                    "version": r["version"],
                    "enabled": r["enabled"],
                    "config": r["config"] if isinstance(r["config"], dict) else json.loads(r["config"]),
                    "changed_by_name": r["changed_by_name"] or "ANONYMOUS",
                    "changed_at": r["changed_at"].isoformat() if r["changed_at"] else "",
                    "change_reason": r["change_reason"] or ""
                }
                for r in rows
            ]
    except Exception as e:
        logger.warning(f"Failed to fetch rule history: {e}")
        return []


@router.post("/test")
async def test_rule_simulation(
    payload: RuleTestPayload,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "ADMIN", "ANALYST", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """
    Rule Testing Harness: Evaluates a synthetic transaction against the current
    rule definitions without committing transactions or firing production alerts.
    """
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
        tenant_id=tenant_id
    )

    return {
        "status": "EVALUATED",
        "input": payload.model_dump(),
        "triggered_count": len(triggered),
        "triggered_rules": triggered,
        "is_suspicious": len(triggered) > 0
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
    current_user: dict = Depends(RoleChecker(["SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    """Global rules defaults update (SUPER_ADMIN only) writing to DB, local file, and Redis."""
    payload = payload_model.model_dump()
    try:
        # 1. Persist to PostgreSQL if available
        try:
            from database.postgres import get_async_db_conn as _get_db
            async with _get_db() as conn:
                await conn.execute(
                    """
                    INSERT INTO rules_configuration (rules_json, updated_by)
                    VALUES ($1, $2);
                    """,
                    json.dumps(payload),
                    current_user.get("username", "SUPER_ADMIN")
                )
                try:
                    from services.audit import record_audit_event_tx
                    await record_audit_event_tx(
                        conn=conn,
                        action="UPDATE_GLOBAL_RULES_CONFIG",
                        actor_id=str(current_user.get("id") or current_user.get("username") or "super_admin"),
                        actor_username=current_user.get("username", "SUPER_ADMIN"),
                        actor_role=current_user.get("role", "SUPER_ADMIN"),
                        resource_type="GLOBAL_RULES_CONFIG",
                        resource_id="rules_config.json",
                        tenant_id=str(current_user.get("tenant_id")) if current_user.get("tenant_id") else None,
                        details={"rule_keys": list((payload.get("rules") or {}).keys())},
                    )
                except Exception:
                    pass
        except Exception as dbe:
            logger.warning(f"Failed to persist rules to PostgreSQL (falling back to disk): {dbe}")

        # 2. Persist to local disk file for node cache / offline mode
        try:
            await asyncio.to_thread(_write_config_sync, CONFIG_PATH, payload)
        except Exception as fe:
            logger.warning(f"Failed to write local rules file: {fe}")

        # 3. Trigger reload in rules engine memory cache
        RulesEngine.reload_config()

        # 4. Broadcast Redis cache invalidation event
        try:
            from database.redis_db import get_async_redis_client as _get_redis
            redis = await _get_redis()
            if redis:
                await redis.publish("aml:rules:cache_invalidate", "reload")
        except Exception as re:
            logger.warning(f"Failed to publish rules invalidation to Redis: {re}")

        return {"status": "SUCCESS", "message": "Rules configuration updated successfully"}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to update global rules configuration")
        raise HTTPException(status_code=500, detail="Failed to update rules configuration.")
