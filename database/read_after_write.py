"""
Read-After-Write (RAW) Primary Stickiness Coordinator
=====================================================
Guarantees read-your-own-writes consistency when PostgreSQL asynchronous
streaming read replicas are deployed:
  - Any successful mutating request (`POST`, `PUT`, `PATCH`, `DELETE`) records
    a short-lived stickiness marker (`READ_AFTER_WRITE_WINDOW_SECONDS`, default 5s)
    keyed by authenticated session/actor fingerprint (falling back to tenant/IP)
    in State Redis AND an in-process bounded TTL fallback map.
  - Subsequent `GET`/`HEAD` requests from the same caller (or any request carrying
    `X-Read-Consistency: strong`) set `force_primary_read_var = True` so
    `get_async_db_read_conn()` routes transparently to the PostgreSQL Primary.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import time
from collections import OrderedDict

from config import settings

force_primary_read_var: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "force_primary_read", default=False
)
read_routing_reason_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "read_routing_reason", default="replica"
)

_MAX_LOCAL_STICKINESS_KEYS = 4096
_local_stickiness: OrderedDict[str, float] = OrderedDict()


def _prune_local_stickiness(now: float) -> None:
    while _local_stickiness:
        oldest_key, exp = next(iter(_local_stickiness.items()))
        if exp <= now or len(_local_stickiness) > _MAX_LOCAL_STICKINESS_KEYS:
            _local_stickiness.pop(oldest_key, None)
        else:
            break


def compute_caller_stickiness_id(
    *,
    authorization_header: str | None = None,
    cookie_header: str | None = None,
    tenant_id: str | None = None,
    user_id: str | None = None,
) -> str:
    """Builds a non-PII SHA-256 fingerprint identifying the caller's session/actor."""
    if tenant_id and user_id:
        raw = f"tu:{tenant_id}:{user_id}"
    elif authorization_header and authorization_header.startswith("Bearer "):
        raw = f"bearer:{authorization_header[7:].strip()}"
    elif cookie_header and "access_token=" in cookie_header:
        # Extract only access_token cookie segment for stable stickiness across tabs
        token_part = ""
        for seg in cookie_header.split(";"):
            seg = seg.strip()
            if seg.startswith("access_token="):
                token_part = seg
                break
        raw = f"cookie:{token_part or cookie_header}"
    else:
        return ""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _redis_key(caller_fp: str) -> str:
    return f"raw:stickiness:{caller_fp}"


async def mark_write_stickiness(caller_fp: str, ttl_seconds: int | None = None) -> None:
    """Records a short-lived Read-After-Write stickiness marker for the caller."""
    if not caller_fp:
        return
    ttl = max(1, int(ttl_seconds if ttl_seconds is not None else getattr(settings, "read_after_write_window_seconds", 5)))
    now = time.monotonic()
    _local_stickiness[caller_fp] = now + ttl
    _local_stickiness.move_to_end(caller_fp)
    _prune_local_stickiness(now)

    try:
        from database.redis_db import get_async_redis_client

        redis_client = await asyncio.wait_for(get_async_redis_client(), timeout=0.15)
        if redis_client is not None:
            await asyncio.wait_for(redis_client.set(_redis_key(caller_fp), "1", ex=ttl), timeout=0.15)
    except Exception:
        # Fail-open: local in-process TTL map still covers single-pod stickiness
        pass


async def has_active_write_stickiness(caller_fp: str) -> bool:
    """Returns True if the caller committed a write within the RAW stickiness window."""
    if not caller_fp:
        return False
    now = time.monotonic()
    exp = _local_stickiness.get(caller_fp)
    if exp is not None:
        if exp > now:
            return True
        _local_stickiness.pop(caller_fp, None)

    try:
        from database.redis_db import get_async_redis_client

        redis_client = await asyncio.wait_for(get_async_redis_client(), timeout=0.15)
        if redis_client is not None:
            val = await asyncio.wait_for(redis_client.get(_redis_key(caller_fp)), timeout=0.15)
            return bool(val)
    except Exception:
        return False
    return False


def clear_local_stickiness_cache() -> None:
    """Helper for test isolation."""
    _local_stickiness.clear()
