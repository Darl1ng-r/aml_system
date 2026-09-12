from fastapi import APIRouter, Depends, HTTPException
import json
import os
import logging
from services.auth import RoleChecker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/rules", tags=["Rules Configuration"])

CONFIG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rules_config.json"))

def load_rules_from_disk() -> dict:
    if not os.path.exists(CONFIG_PATH):
        raise HTTPException(status_code=404, detail="Rules configuration file not found")
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to read rules config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to load rules configuration: {e}")

async def load_active_rules() -> dict:
    """Attempts to load active rules from PostgreSQL, falling back to local JSON or defaults."""
    try:
        from database.postgres import get_async_db_conn
        async with get_async_db_conn() as conn:
            row = await conn.fetchrow(
                "SELECT rules_json FROM rules_configuration ORDER BY updated_at DESC LIMIT 1;"
            )
            if row and row["rules_json"]:
                data = row["rules_json"]
                return json.loads(data) if isinstance(data, str) else data
    except Exception as e:
        logger.debug(f"Could not load rules from PostgreSQL: {e}")
    return load_rules_from_disk()

@router.get("/config")
async def get_rules_config(
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"]))
):
    """
    Get the active AML rules configurations. Accessible by ADMIN and ANALYST.
    """
    return await load_active_rules()

@router.put("/config")
async def update_rules_config(
    payload: dict,
    current_user: dict = Depends(RoleChecker(["ADMIN"]))
):
    """
    Update the AML rules configuration with horizontal DB persistence and Redis broadcast.
    Only accessible by ADMIN.
    """
    if "rules" not in payload:
        raise HTTPException(status_code=400, detail="Invalid configuration format: 'rules' key is required")
        
    try:
        # 1. Persist to PostgreSQL if available
        try:
            from database.postgres import get_async_db_conn
            async with get_async_db_conn() as conn:
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
        from services.rules import RulesEngine
        RulesEngine.reload_config()

        # 4. Broadcast Redis cache invalidation event to all horizontally scaled pods
        try:
            from database.redis_db import get_async_redis_client
            redis = await get_async_redis_client()
            if redis:
                await redis.publish("aml:rules:cache_invalidate", "reload")
        except Exception as re:
            logger.warning(f"Failed to publish rules invalidation to Redis: {re}")
        
        return {"status": "SUCCESS", "message": "Rules configuration updated successfully"}
    except Exception as e:
        logger.error(f"Failed to write rules config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update rules configuration: {e}")
