"""
Real-Time Feature Store (GAP-16)
================================
Maintains millisecond-latency rolling window aggregation metrics using Redis sorted sets.
Provides real-time velocity, volume, and count statistics for scoring engines.
"""

import time
import logging
from typing import Dict, Any
from database.redis_db import get_async_redis_client

logger = logging.getLogger(__name__)


async def record_transaction_feature_event(account_id: str, amount: float, tx_id: str, ts_epoch: float | None = None) -> None:
    """
    Appends transaction event to account's Redis sorted set.
    Member format: tx_id:amount, Score: epoch timestamp in seconds.
    """
    if ts_epoch is None:
        ts_epoch = time.time()

    redis = await get_async_redis_client()
    if not redis:
        return

    key = f"fs:tx:{account_id}"
    member = f"{tx_id}:{amount}"
    try:
        await redis.zadd(key, {member: ts_epoch})
        # Set 30-day TTL on feature store sorted set
        await redis.expire(key, 30 * 86400)
    except Exception as e:
        logger.warning(f"Feature store record bypassed: {e}")


async def get_rolling_window_features(account_id: str, current_epoch: float | None = None) -> Dict[str, Any]:
    """
    Computes rolling 1h, 24h, and 7d velocity and total amount from Redis sorted sets.
    """
    if current_epoch is None:
        current_epoch = time.time()

    redis = await get_async_redis_client()
    if not redis:
        return {
            "velocity_1h": 0, "amount_1h": 0.0,
            "velocity_24h": 0, "amount_24h": 0.0,
            "velocity_7d": 0, "amount_7d": 0.0
        }

    key = f"fs:tx:{account_id}"
    try:
        # 1 Hour Window
        one_hour_ago = current_epoch - 3600
        items_1h = await redis.zrangebyscore(key, min=one_hour_ago, max=current_epoch)
        vel_1h = len(items_1h)
        amt_1h = sum(float(x.split(":")[1]) for x in items_1h if ":" in x)

        # 24 Hour Window
        twenty_four_hours_ago = current_epoch - 86400
        items_24h = await redis.zrangebyscore(key, min=twenty_four_hours_ago, max=current_epoch)
        vel_24h = len(items_24h)
        amt_24h = sum(float(x.split(":")[1]) for x in items_24h if ":" in x)

        # 7 Day Window
        seven_days_ago = current_epoch - (7 * 86400)
        items_7d = await redis.zrangebyscore(key, min=seven_days_ago, max=current_epoch)
        vel_7d = len(items_7d)
        amt_7d = sum(float(x.split(":")[1]) for x in items_7d if ":" in x)

        return {
            "velocity_1h": vel_1h,
            "amount_1h": round(amt_1h, 2),
            "velocity_24h": vel_24h,
            "amount_24h": round(amt_24h, 2),
            "velocity_7d": vel_7d,
            "amount_7d": round(amt_7d, 2)
        }
    except Exception as e:
        logger.warning(f"Feature store retrieval bypassed: {e}")
        return {
            "velocity_1h": 0, "amount_1h": 0.0,
            "velocity_24h": 0, "amount_24h": 0.0,
            "velocity_7d": 0, "amount_7d": 0.0
        }
