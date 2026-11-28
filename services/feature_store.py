"""
Real-Time Feature Store (GAP-16)
================================
Maintains millisecond-latency rolling window aggregation metrics using Redis sorted sets.
Provides tenant-isolated, exact-Decimal, monotonic real-time 1h / 24h / 7d velocity and
volume statistics for scoring engines from a single atomic Redis range query.
"""

from __future__ import annotations

import logging
import time
from decimal import Decimal, ROUND_HALF_EVEN
from typing import Any, Dict, Optional

from database.redis_db import get_async_redis_client
from domain.money import InvalidMoneyError, to_decimal

logger = logging.getLogger(__name__)


def _feature_key(account_id: str, tenant_id: Optional[str] = None) -> str:
    tid = str(tenant_id).strip() if tenant_id else "global"
    return f"fs:tx:{tid}:{account_id}"


def _parse_member_amount(raw_member: Any) -> Optional[Decimal]:
    """Safely decodes bytes/str Redis sorted-set members formatted as `<tx_id>:<amount>` using rsplit."""
    text = raw_member.decode("utf-8", errors="ignore") if isinstance(raw_member, (bytes, bytearray)) else str(raw_member)
    if ":" not in text:
        return None
    _, amt_str = text.rsplit(":", 1)
    try:
        return to_decimal(amt_str, allow_negative=False, field_name="feature_amount")
    except InvalidMoneyError:
        return None


async def record_transaction_feature_event(
    account_id: str,
    amount: float | Decimal | str,
    tx_id: str,
    ts_epoch: float | None = None,
    *,
    tenant_id: Optional[str] = None,
) -> None:
    """
    Appends a validated transaction event to the tenant-scoped account Redis sorted set.
    Member format: `<tx_id>:<decimal_amount>`, Score: epoch timestamp in seconds.
    """
    amt_dec = to_decimal(amount, allow_negative=False, field_name="amount")
    if ts_epoch is None:
        ts_epoch = time.time()

    redis = await get_async_redis_client()
    if not redis:
        return

    key = _feature_key(account_id, tenant_id)
    member = f"{tx_id}:{amt_dec}"
    try:
        await redis.zadd(key, {member: float(ts_epoch)})
        if hasattr(redis, "zremrangebyscore"):
            prune_cutoff = min(float(ts_epoch), time.time()) - (30 * 86400)
            await redis.zremrangebyscore(key, "-inf", prune_cutoff)
        await redis.expire(key, 30 * 86400)
    except Exception as e:
        logger.warning("Feature store record bypassed: %s", e)


async def get_rolling_window_features(
    account_id: str,
    current_epoch: float | None = None,
    *,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Computes rolling 1h, 24h, and 7d velocity and exact Decimal total amounts from a
    single atomic `ZRANGEBYSCORE ... WITHSCORES` call, guaranteeing monotonic window
    counts (`velocity_1h <= velocity_24h <= velocity_7d`).
    """
    if current_epoch is None:
        current_epoch = time.time()

    empty = {
        "velocity_1h": 0, "amount_1h": 0.0,
        "velocity_24h": 0, "amount_24h": 0.0,
        "velocity_7d": 0, "amount_7d": 0.0,
    }
    redis = await get_async_redis_client()
    if not redis:
        return empty

    key = _feature_key(account_id, tenant_id)
    one_hour_ago = current_epoch - 3600.0
    twenty_four_hours_ago = current_epoch - 86400.0
    seven_days_ago = current_epoch - (7.0 * 86400.0)

    try:
        items_7d = await redis.zrangebyscore(
            key, min=seven_days_ago, max=current_epoch, withscores=True
        )
        vel_1h = vel_24h = vel_7d = 0
        amt_1h = amt_24h = amt_7d = Decimal("0")

        for entry in (items_7d or ()):
            if isinstance(entry, tuple) and len(entry) == 2:
                raw_member, raw_score = entry
                score = float(raw_score)
            else:
                raw_member = entry
                score = float(current_epoch)

            amt = _parse_member_amount(raw_member)
            if amt is None:
                continue

            if seven_days_ago <= score <= current_epoch:
                vel_7d += 1
                amt_7d += amt
                if score >= twenty_four_hours_ago:
                    vel_24h += 1
                    amt_24h += amt
                    if score >= one_hour_ago:
                        vel_1h += 1
                        amt_1h += amt

        q = Decimal("0.01")
        return {
            "velocity_1h": vel_1h,
            "amount_1h": float(amt_1h.quantize(q, rounding=ROUND_HALF_EVEN)),
            "velocity_24h": vel_24h,
            "amount_24h": float(amt_24h.quantize(q, rounding=ROUND_HALF_EVEN)),
            "velocity_7d": vel_7d,
            "amount_7d": float(amt_7d.quantize(q, rounding=ROUND_HALF_EVEN)),
        }
    except Exception as e:
        logger.warning("Feature store retrieval bypassed: %s", e)
        return empty
