"""
Machine Learning Active Learning & Online Retraining Router
============================================================
Provides API endpoints for active learning feedback stats and model retraining:

  - POST /api/v1/ml/retrain:
      Executes an online retraining cycle of the Isolation Forest anomaly detector
      and scoring weights using human analyst feedback labels.

  - GET /api/v1/ml/feedback-stats:
      Queries active learning feedback statistics (total labeled samples, false
      positive reduction rate, and retrain history).
"""

import logging
from fastapi import APIRouter, Depends, HTTPException
from database.postgres import get_async_db_conn
from services.auth import RoleChecker
from services.feedback_loop import feedback_service
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ml", tags=["Machine Learning & Feedback Loop"])


@router.post("/retrain")
async def retrain_model_now(
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=5, window=60))
):
    """
    Triggers an active online retraining cycle using human-validated analyst feedback.
    """
    try:
        result = await feedback_service.retrain_model_with_feedback()

        # Broadcast real-time WebSocket update
        if result.get("status") == "RETRAINED":
            from routers.metrics import ws_manager
            await ws_manager.broadcast({
                "event": "ML_MODEL_RETRAINED",
                "samples_count": result["samples_count"],
                "false_positives_learned": result["false_positives_learned"],
                "retrained_by": current_user["username"]
            })

        return result
    except Exception as e:
        logger.error(f"Manual model retraining failed: {e}")
        raise HTTPException(status_code=500, detail=f"Retraining failed: {str(e)}")


@router.get("/feedback-stats")
async def get_feedback_stats(
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """
    Retrieves feedback loop metrics, false positive counts, and model retraining health.
    """
    try:
        async with get_async_db_conn() as conn:
            total_samples = await conn.fetchval("SELECT COUNT(*) FROM ml_feedback_samples;")
            fp_count = await conn.fetchval("SELECT COUNT(*) FROM ml_feedback_samples WHERE label = 0;")
            sar_count = await conn.fetchval("SELECT COUNT(*) FROM ml_feedback_samples WHERE label = 1;")

            fp_reduction_rate = round((fp_count / total_samples * 100), 1) if total_samples and total_samples > 0 else 0.0

            return {
                "total_labeled_samples": total_samples or 0,
                "false_positives_learned": fp_count or 0,
                "true_sars_learned": sar_count or 0,
                "false_positive_reduction_rate": f"{fp_reduction_rate}%",
                "active_learning_status": "ACTIVE_ONLINE_RETRAINING"
            }
    except Exception as e:
        logger.error(f"Failed to query feedback stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch feedback stats: {str(e)}")
