"""
Enterprise Cache-Aside Engine (Stampede Defense, PER/XFetch, Negative Caching & Outbox Invalidation)
====================================================================================================
Provides a reusable, fail-open L2 cache abstraction backed by the dedicated Cache
Redis pool (`get_async_cache_redis_client()`, `allkeys-lfu`, <= 200ms socket timeout):
  - Versioned, tenant-namespaced keys: `{version}:{namespace}:{tenant_id}:{key}`
  - Jittered TTL (`+0..15%`) preventing synchronized expiration avalanches
  - Dual Stampede Defense:
      1. Single-flight distributed mutex (`SET lock_key token NX PX`) with atomic
         Lua compare-and-delete release + jittered follower backoff & double-check.
      2. Probabilistic Early Expiration (PER / XFetch):
         `now - delta * beta * ln(rand(0, 1)) >= expiry` triggering a single
         non-blocking background refresh prior to TTL expiry.
  - Negative Caching (Cache Penetration defense) using `__SENTINEL_NOT_FOUND__`
    with bounded short TTL (default 25s).
  - Post-Commit Cache Invalidation + Transactional Outbox (`CACHE_INVALIDATION`)
    durability so crashes between DB `COMMIT` and Redis `DEL` self-heal.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import random
import time
import uuid
from typing import Any, Awaitable, Callable, Sequence

from database.redis_db import get_async_cache_redis_client
from observability.prometheus import record_cache_operation

logger = logging.getLogger(__name__)

NEGATIVE_SENTINEL = "__SENTINEL_NOT_FOUND__"

# Atomic Lua unlock: release lock strictly if caller still owns the unique fencing token.
_LUA_RELEASE_LOCK = """
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
"""

# Track active background PER refresh keys per process to avoid duplicate refreshes
_active_per_refreshes: set[str] = set()


def build_cache_key(
    namespace: str,
    tenant_id: str | None,
    key: str,
    *,
    version: str = "v1",
) -> str:
    """Constructs a versioned, tenant-isolated cache key."""
    safe_ns = str(namespace).strip().replace(" ", "_")
    safe_tenant = str(tenant_id or "global").strip()
    safe_key = str(key).strip()
    return f"{version}:{safe_ns}:{safe_tenant}:{safe_key}"


def compute_jittered_ttl(base_ttl: int, *, jitter_ratio: float = 0.15) -> int:
    """Applies positive random jitter (+0..jitter_ratio) to prevent cache avalanches."""
    base = max(1, int(base_ttl))
    spread = max(1, int(round(base * max(0.0, float(jitter_ratio)))))
    return base + random.randint(0, spread)


def should_probabilistically_refresh(
    *,
    now_ts: float,
    expiry_ts: float,
    compute_delta_seconds: float,
    beta: float = 1.0,
    rand_val: float | None = None,
) -> bool:
    """
    XFetch / Probabilistic Early Expiration (PER) decision function:
        now - delta * beta * ln(u) >= expiry, where u in (0, 1].
    """
    if compute_delta_seconds <= 0.0 or expiry_ts <= 0.0:
        return False
    u = rand_val if rand_val is not None else random.random()
    u = max(1e-12, min(1.0, float(u)))
    return (now_ts - (compute_delta_seconds * max(0.1, float(beta)) * math.log(u))) >= expiry_ts


def _encode_envelope(
    value: Any,
    *,
    ttl_seconds: int,
    compute_delta_seconds: float,
    is_negative: bool = False,
) -> str:
    if is_negative:
        return json.dumps({"__sentinel__": NEGATIVE_SENTINEL}, separators=(",", ":"))
    now_ts = time.time()
    return json.dumps(
        {
            "v": value,
            "exp": round(now_ts + ttl_seconds, 3),
            "delta": round(max(0.001, compute_delta_seconds), 4),
        },
        separators=(",", ":"),
        default=str,
    )


def _decode_envelope(raw: Any) -> tuple[bool, bool, Any, float, float]:
    """
    Decodes a cache envelope.
    Returns `(valid, is_negative, value, expiry_ts, delta_seconds)`.
    """
    if raw is None:
        return False, False, None, 0.0, 0.0
    text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw)
    try:
        parsed = json.loads(text)
    except Exception:
        return False, False, None, 0.0, 0.0

    if isinstance(parsed, dict) and parsed.get("__sentinel__") == NEGATIVE_SENTINEL:
        return True, True, None, 0.0, 0.0
    if isinstance(parsed, dict) and "v" in parsed and "exp" in parsed:
        return (
            True,
            False,
            parsed["v"],
            float(parsed.get("exp") or 0.0),
            float(parsed.get("delta") or 0.0),
        )
    # Backward compatibility with legacy raw JSON entries written before envelope adoption
    return True, False, parsed, 0.0, 0.0


class CacheAsideClient:
    """
    Enterprise fail-open Cache-Aside client with stampede single-flight locking,
    PER/XFetch early refresh, negative caching, and aggressive <= 250ms timeouts.
    """

    def __init__(
        self,
        *,
        redis_factory: Callable[[], Awaitable[Any]] | None = None,
        op_timeout_seconds: float = 0.25,
        lock_ttl_ms: int = 3000,
    ) -> None:
        self._redis_factory = redis_factory or get_async_cache_redis_client
        self._op_timeout = max(0.05, min(0.5, float(op_timeout_seconds)))
        self._lock_ttl_ms = max(500, int(lock_ttl_ms))

    async def _get_client(self) -> Any:
        try:
            return await asyncio.wait_for(self._redis_factory(), timeout=self._op_timeout)
        except Exception as exc:
            logger.debug("Cache client unavailable (fail-open): %s", exc)
            return None

    async def _safe_get(self, client: Any, key: str) -> tuple[bool, Any]:
        """Returns `(ok, raw_value)`. When `ok` is False (Redis error/timeout), caller fails open immediately."""
        try:
            raw = await asyncio.wait_for(client.get(key), timeout=self._op_timeout)
            return True, raw
        except Exception as exc:
            logger.debug("Cache GET failed open key=%s err=%s", key, exc)
            return False, None

    async def _safe_set(self, client: Any, key: str, value: str, *, ttl: int) -> None:
        try:
            await asyncio.wait_for(client.set(key, value, ex=max(1, int(ttl))), timeout=self._op_timeout)
        except Exception as exc:
            logger.debug("Cache SET skipped key=%s err=%s", key, exc)

    async def _safe_acquire_lock(self, client: Any, lock_key: str, token: str) -> bool | None:
        """Returns True if lock won, False if held by peer, or None if Redis errored/timed out."""
        try:
            return bool(
                await asyncio.wait_for(
                    client.set(lock_key, token, nx=True, px=self._lock_ttl_ms),
                    timeout=self._op_timeout,
                )
            )
        except Exception:
            return None

    async def _safe_release_lock(self, client: Any, lock_key: str, token: str) -> None:
        try:
            if hasattr(client, "eval"):
                await asyncio.wait_for(
                    client.eval(_LUA_RELEASE_LOCK, 1, lock_key, token),
                    timeout=self._op_timeout,
                )
            else:
                await asyncio.wait_for(client.delete(lock_key), timeout=self._op_timeout)
        except Exception:
            pass

    def _schedule_per_refresh(
        self,
        *,
        client: Any,
        cache_key: str,
        namespace: str,
        loader: Callable[[], Awaitable[Any]],
        base_ttl: int,
        jitter_ratio: float,
        cache_none: bool,
        negative_ttl: int,
    ) -> None:
        if cache_key in _active_per_refreshes:
            return
        _active_per_refreshes.add(cache_key)

        async def _refresh_task() -> None:
            lock_key = f"lock:{cache_key}"
            token = uuid.uuid4().hex
            acquired = await self._safe_acquire_lock(client, lock_key, token)
            if not acquired:
                _active_per_refreshes.discard(cache_key)
                return
            try:
                t0 = time.monotonic()
                fresh = await loader()
                delta = time.monotonic() - t0
                if fresh is None:
                    if cache_none:
                        await self._safe_set(
                            client,
                            cache_key,
                            _encode_envelope(None, ttl_seconds=negative_ttl, compute_delta_seconds=delta, is_negative=True),
                            ttl=negative_ttl,
                        )
                else:
                    ttl = compute_jittered_ttl(base_ttl, jitter_ratio=jitter_ratio)
                    await self._safe_set(
                        client,
                        cache_key,
                        _encode_envelope(fresh, ttl_seconds=ttl, compute_delta_seconds=delta),
                        ttl=ttl,
                    )
                record_cache_operation(namespace, "per_refresh")
            except Exception as exc:
                logger.debug("Background PER refresh failed for %s: %s", cache_key, exc)
            finally:
                await self._safe_release_lock(client, lock_key, token)
                _active_per_refreshes.discard(cache_key)

        try:
            asyncio.get_running_loop().create_task(_refresh_task())
        except RuntimeError:
            _active_per_refreshes.discard(cache_key)

    async def get_or_load(
        self,
        *,
        namespace: str,
        tenant_id: str | None,
        key: str,
        loader: Callable[[], Awaitable[Any]],
        base_ttl: int = 300,
        jitter_ratio: float = 0.15,
        version: str = "v1",
        enable_per: bool = False,
        per_beta: float = 1.0,
        cache_none: bool = False,
        negative_ttl: int = 25,
        stampede_wait_attempts: int = 4,
    ) -> Any:
        cache_key = build_cache_key(namespace, tenant_id, key, version=version)
        client = await self._get_client()

        if client is None:
            record_cache_operation(namespace, "error_failopen")
            return await loader()

        # 1. Fast-path GET (fail open immediately on Redis timeout/error — never retry a stalled Redis!)
        get_ok, raw = await self._safe_get(client, cache_key)
        if not get_ok:
            record_cache_operation(namespace, "error_failopen")
            return await loader()

        valid, is_neg, value, exp_ts, delta_s = _decode_envelope(raw)
        if valid:
            if is_neg:
                record_cache_operation(namespace, "negative_hit")
                return None
            record_cache_operation(namespace, "hit")
            if enable_per and should_probabilistically_refresh(
                now_ts=time.time(),
                expiry_ts=exp_ts,
                compute_delta_seconds=delta_s,
                beta=per_beta,
            ):
                self._schedule_per_refresh(
                    client=client,
                    cache_key=cache_key,
                    namespace=namespace,
                    loader=loader,
                    base_ttl=base_ttl,
                    jitter_ratio=jitter_ratio,
                    cache_none=cache_none,
                    negative_ttl=negative_ttl,
                )
            return value

        record_cache_operation(namespace, "miss")

        # 2. Single-flight distributed mutex to collapse concurrent stampedes
        lock_key = f"lock:{cache_key}"
        token = uuid.uuid4().hex
        acquired = await self._safe_acquire_lock(client, lock_key, token)
        if acquired is None:
            record_cache_operation(namespace, "error_failopen")
            return await loader()

        if not acquired:
            for attempt in range(max(1, stampede_wait_attempts)):
                await asyncio.sleep(0.02 * (attempt + 1) + random.uniform(0.0, 0.015))
                ok_w, raw_wait = await self._safe_get(client, cache_key)
                if not ok_w:
                    record_cache_operation(namespace, "error_failopen")
                    return await loader()
                valid_w, is_neg_w, val_w, _, _ = _decode_envelope(raw_wait)
                if valid_w:
                    record_cache_operation(namespace, "stampede_wait_hit")
                    return None if is_neg_w else val_w
            # Lock holder stalled/failed -> fail open gracefully to loader
            return await loader()

        try:
            # Double-check cache after winning the single-flight lock
            ok_dc, raw_dc = await self._safe_get(client, cache_key)
            if ok_dc:
                valid_dc, is_neg_dc, val_dc, _, _ = _decode_envelope(raw_dc)
                if valid_dc:
                    record_cache_operation(namespace, "stampede_wait_hit")
                    return None if is_neg_dc else val_dc

            t0 = time.monotonic()
            loaded = await loader()
            compute_delta = time.monotonic() - t0

            if loaded is None:
                if cache_none:
                    await self._safe_set(
                        client,
                        cache_key,
                        _encode_envelope(None, ttl_seconds=negative_ttl, compute_delta_seconds=compute_delta, is_negative=True),
                        ttl=negative_ttl,
                    )
            else:
                ttl = compute_jittered_ttl(base_ttl, jitter_ratio=jitter_ratio)
                await self._safe_set(
                    client,
                    cache_key,
                    _encode_envelope(loaded, ttl_seconds=ttl, compute_delta_seconds=compute_delta),
                    ttl=ttl,
                )
            return loaded
        finally:
            await self._safe_release_lock(client, lock_key, token)

    async def invalidate_keys(
        self,
        keys: Sequence[str],
        *,
        namespace: str = "global",
    ) -> int:
        """Best-effort post-commit DEL on Cache Redis (must only be called AFTER DB COMMIT)."""
        cleaned = [str(k) for k in keys if k]
        if not cleaned:
            return 0
        client = await self._get_client()
        if client is None:
            record_cache_operation(namespace, "error_failopen")
            return 0
        try:
            deleted = await asyncio.wait_for(client.delete(*cleaned), timeout=self._op_timeout)
            record_cache_operation(namespace, "invalidate")
            return int(deleted or 0)
        except Exception as exc:
            logger.warning("Post-commit cache invalidation failed for %s: %s", cleaned, exc)
            record_cache_operation(namespace, "error_failopen")
            return 0


cache_aside = CacheAsideClient()


async def record_cache_invalidation_outbox(
    conn: Any,
    *,
    keys: Sequence[str],
    tenant_id: str | None = None,
    namespace: str = "global",
) -> str | None:
    """
    Atomically enqueues a `CACHE_INVALIDATION` event inside the caller's active
    PostgreSQL transaction so that even if the app pod crashes between `COMMIT`
    and Redis `DEL`, the OutboxRelayEngine guarantees eventual cache invalidation.
    """
    cleaned = [str(k) for k in keys if k]
    if not cleaned:
        return None
    from database.outbox import record_outbox_event

    return await record_outbox_event(
        conn,
        aggregate_type="CACHE_INVALIDATION",
        aggregate_id=cleaned[0][:128],
        event_type="storage.cache.invalidate.v1",
        payload={"keys": cleaned, "namespace": namespace},
        tenant_id=str(tenant_id) if tenant_id else None,
    )


async def invalidate_cache_keys_after_commit(
    keys: Sequence[str],
    *,
    namespace: str = "global",
) -> int:
    """Triggers immediate post-commit invalidation on Cache Redis."""
    return await cache_aside.invalidate_keys(keys, namespace=namespace)


async def dispatch_cache_invalidation_outbox_event(event: dict[str, Any]) -> tuple[bool, str | None]:
    """OutboxRelayEngine handler for `aggregate_type == 'CACHE_INVALIDATION'`."""
    payload = event.get("payload") or {}
    keys = payload.get("keys") or []
    namespace = str(payload.get("namespace") or "outbox")
    if not keys:
        return True, None
    try:
        client = await get_async_cache_redis_client()
        if client is None:
            return False, "Cache Redis unavailable for outbox invalidation"
        await asyncio.wait_for(client.delete(*[str(k) for k in keys]), timeout=0.5)
        record_cache_operation(namespace, "outbox_invalidate")
        return True, None
    except Exception as exc:
        return False, str(exc)
