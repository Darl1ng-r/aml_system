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

@router.get("/config")
async def get_rules_config(
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"]))
):
    """
    Get the active AML rules configurations. Accessible by ADMIN and ANALYST.
    """
    return load_rules_from_disk()

@router.put("/config")
async def update_rules_config(
    payload: dict,
    current_user: dict = Depends(RoleChecker(["ADMIN"]))
):
    """
    Update the AML rules configuration. Only accessible by ADMIN.
    """
    if "rules" not in payload:
        raise HTTPException(status_code=400, detail="Invalid configuration format: 'rules' key is required")
        
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(payload, f, indent=2)
        
        # Trigger reload in rules engine if it keeps a cache
        from services.rules import RulesEngine
        RulesEngine.reload_config()
        
        return {"status": "SUCCESS", "message": "Rules configuration updated successfully"}
    except Exception as e:
        logger.error(f"Failed to write rules config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update rules configuration: {e}")
