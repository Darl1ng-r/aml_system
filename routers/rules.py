"""
Rules Engine Configuration & Builder Router (Sprint 1 / Task 1.5, 1.6 Audit Remediation)
========================================================================================
Provides multi-tenant rule configuration management backed by PostgreSQL rule_configs
and rule_config_history tables, with Redis pub/sub invalidation and simulation test harness.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import json
import os
import uuid
import logging
from datetime import datetime, timezone
from services.auth import RoleChecker, enforce_tenant_data_scope
from database.postgres import get_async_db_conn
from database.redis_db import get_async_redis_client
from observability.logging import log_audit_event
from services.rules import RulesEngine, get_rules_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/rules", tags=["Rules Configuration & Builder"])

CONFIG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rules_config.json"))


class RulePatchPayload(BaseModel):
    enabled: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None
    change_reason: Optional[str] = Field("Rule threshold adjustment via Rule Builder", max_length=500)


class RuleTestPayload(BaseModel):
    sender_id: str = "ACC-SENDER-TEST"
    receiver_id: str = "ACC-RCVR-TEST"
    amount: float = Field(..., gt=0)
    sender_name: Optional[str] = "John Doe"
    sender_bic: Optional[str] = "DEUTDEDD"
    receiver_name: Optional[str] = "Jane Smith"
    receiver_bic: Optional[str] = "CHASUS33"


@router.get("", response_model=List[Dict[str, Any]])
async def list_rules(
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"]))
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
                SELECT id, rule_name, enabled, config, version, updated_by_name,
                       updated_at, description
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
                        "config": r["config"] if isinstance(r["config"], dict) else json.loads(r["config"]),
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


@router.patch("/{rule_name}")
async def patch_rule(
    rule_name: str,
    payload: RulePatchPayload,
    current_user: dict = Depends(RoleChecker(["ADMIN"]))
):
    """
    Updates rule thresholds, parameters, and/or enabled state.
    Increments version, logs historical audit record, and invalidates Redis cache.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    tenant_uuid = uuid.UUID(str(tenant_id))
    user_id = current_user.get("id")
    user_uuid = None
    if user_id:
        try:
            user_uuid = uuid.UUID(str(user_id))
        except (ValueError, TypeError):
            user_uuid = None
    username = current_user.get("username", "Admin")

    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            # 1. Fetch existing rule
            current_row = await conn.fetchrow(
                """
                SELECT id, enabled, config, version
                FROM rule_configs
                WHERE tenant_id = $1 AND rule_name = $2;
                """,
                tenant_uuid, rule_name
            )

            new_enabled = payload.enabled if payload.enabled is not None else (current_row["enabled"] if current_row else True)
            
            existing_config = {}
            if current_row and current_row["config"]:
                existing_config = current_row["config"] if isinstance(current_row["config"], dict) else json.loads(current_row["config"])
            
            new_config = existing_config.copy()
            if payload.config is not None:
                new_config.update(payload.config)

            new_version = (current_row["version"] + 1) if current_row else 1

            # 2. Upsert into rule_configs
            saved_id = await conn.fetchval(
                """
                INSERT INTO rule_configs (
                    tenant_id, rule_name, enabled, config, version,
                    updated_by, updated_by_name, updated_at
                )
                VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, NOW())
                ON CONFLICT (tenant_id, rule_name) DO UPDATE
                SET enabled = EXCLUDED.enabled,
                    config = EXCLUDED.config,
                    version = EXCLUDED.version,
                    updated_by = EXCLUDED.updated_by,
                    updated_by_name = EXCLUDED.updated_by_name,
                    updated_at = NOW()
                RETURNING id;
                """,
                tenant_uuid, rule_name, new_enabled, json.dumps(new_config),
                new_version, user_uuid, username
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

        # 4. Invalidate memory cache and broadcast to Redis
        RulesEngine.reload_config()
        try:
            redis = await get_async_redis_client()
            if redis:
                await redis.publish("aml:rules:cache_invalidate", f"rule_updated:{rule_name}")
        except Exception as re:
            logger.warning(f"Redis cache invalidation broadcast skipped: {re}")

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
            "config": new_config
        }
    except Exception as e:
        logger.error(f"Failed to update rule {rule_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update rule {rule_name}: {e}")


@router.get("/{rule_name}/history")
async def get_rule_history(
    rule_name: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "AUDITOR"]))
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
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "MLRO"]))
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


# ── Backward Compatible Endpoints ─────────────────────────────────────────────
@router.get("/config")
async def get_legacy_rules_config(
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"]))
):
    """Legacy endpoint returning full rules config dictionary."""
    return get_rules_config()


@router.put("/config")
async def update_legacy_rules_config(
    payload: dict,
    current_user: dict = Depends(RoleChecker(["ADMIN"]))
):
    """Legacy update method writing to local file, DB table, and broadcasting to Redis."""
    if "rules" not in payload:
        raise HTTPException(status_code=400, detail="Invalid format: 'rules' required")
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
                    current_user.get("username", "ADMIN")
                )
        except Exception as dbe:
            logger.warning(f"Failed to persist rules to PostgreSQL (falling back to disk): {dbe}")

        # 2. Persist to local disk file for node cache / offline mode
        try:
            with open(CONFIG_PATH, "w") as f:
                json.dump(payload, f, indent=2)
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
