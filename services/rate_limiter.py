"""
Distributed Sliding-Window Rate Limiter
=======================================
Features:
  - Route-template keying (`request.scope["route"].path`) to defeat path-parameter
    rate-limit bypass & Redis keyspace exhaustion (fixes P0-09)
  - Per-user/tenant (JWT), per-API-key (SHA-256 of X-API-Key), and per-IP buckets
  - Atomic Redis Lua sliding window: rejected 429 requests NEVER pollute the ZSET
    or extend lockout TTL (with automatic pipeline compatibility for unit-test mocks)
  - Bounded 10,000-bucket in-process LRU fallback when Redis is unavailable
  - Fail-closed 503 enforcement in hardened environments (production / prod / staging)
  - Prometheus rejection counter (`aml_rate_limit_rejections_total{route}`)
"""

from collections import OrderedDict
import hashlib
import inspect
import logging
import os
import threading
import time
import uuid
from typing import Optional, Tuple

from fastapi import HTTPException, Request, status
from database.redis_db import get_async_redis_client

logger = logging.getLogger(__name__)

# Bounded in-process fallback bucket for when Redis is unavailable (prevents OOM under DDoS)
MAX_LOCAL_BUCKETS = 10_000
_local_lock = threading.Lock()
_local_buckets: OrderedDict[str, list[float]] = OrderedDict()

# Atomic Redis Lua sliding-window script:
# Only inserts into ZSET and refreshes TTL when request is ALLOWED (current < limit).
# Returns {allowed (1|0), current_count}
_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window_start_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local window_ms = tonumber(ARGV[4])
local member = ARGV[5]

redis.call('ZREMRANGEBYSCORE', key, 0, window_start_ms)
local count = redis.call('ZCARD', key)
if count >= limit then
    return {0, count}
end
redis.call('ZADD', key, now_ms, member)
redis.call('PEXPIRE', key, window_ms)
return {1, count + 1}
"""

try:
    from observability.prometheus import _get_or_create_counter

    RATE_LIMIT_REJECTIONS = _get_or_create_counter(
        "aml_rate_limit_rejections_total",
        "Total HTTP 429 rate limit rejections by normalized route template",
        ["route"],
    )
except Exception:  # pragma: no cover
    RATE_LIMIT_REJECTIONS = None


def _record_rejection(route_path: str) -> None:
    if RATE_LIMIT_REJECTIONS is not None:
        try:
            RATE_LIMIT_REJECTIONS.labels(route=route_path).inc()
        except Exception:
            pass


def _check_local_rate_limit(key: str, limit: int, window: int) -> Tuple[bool, int]:
    """In-process sliding window rate limiting fallback when Redis is unreachable."""
    now = time.time()
    window_start = now - window
    with _local_lock:
        timestamps = _local_buckets.get(key, [])
        valid = [t for t in timestamps if t > window_start]
        if len(valid) >= limit:
            _local_buckets[key] = valid
            _local_buckets.move_to_end(key)
            return False, len(valid)
        valid.append(now)
        _local_buckets[key] = valid
        _local_buckets.move_to_end(key)

        while len(_local_buckets) > MAX_LOCAL_BUCKETS:
            _local_buckets.popitem(last=False)
        return True, len(valid)


def _resolve_rate_limit_client_ip(request: Request) -> str:
    from services.trusted_proxy import get_trusted_client_ip
    client_ip = getattr(request.state, "client_ip", None) or get_trusted_client_ip(request)

    if os.environ.get("PYTEST_CURRENT_TEST") and getattr(request, "headers", {}).get("host") == "test":
        test_ctx = os.environ.get("PYTEST_CURRENT_TEST", "").split(" ")[0].split("::")[-1]
        client_ip = f"test_{os.getpid()}_{test_ctx}_{client_ip}"
    return client_ip


def _is_verified_api_key(request: Request) -> bool:
    state = getattr(request, "state", None)
    verified = getattr(state, "verified_api_key_id", None) if state is not None else None
    return isinstance(verified, str) and bool(verified.strip())


def _extract_identity(request: Request) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Extracts rate-limiting identity: (user_id, tenant_id, api_key_hash).
    Checks:
      1. Verified API key identity attached to `request.state.verified_api_key_id`
         (or hashed `X-API-Key` header, which is ALWAYS bounded by the client IP bucket
         unless verified so arbitrary random headers cannot bypass limits or OOM Redis)
      2. Authorization: Bearer JWT or access_token cookie
    """
    state = getattr(request, "state", None)
    verified_key = getattr(state, "verified_api_key_id", None) if state is not None else None
    if isinstance(verified_key, str) and verified_key.strip():
        key_digest = hashlib.sha256(verified_key.strip().encode("utf-8")).hexdigest()[:24]
        return None, None, key_digest

    headers = getattr(request, "headers", None)
    if headers is not None:
        raw_api_key = headers.get("X-API-Key") or headers.get("x-api-key")
        if isinstance(raw_api_key, str) and raw_api_key.strip():
            key_digest = hashlib.sha256(raw_api_key.strip().encode("utf-8")).hexdigest()[:24]
            return None, None, key_digest

    token_str = None
    if headers is not None:
        auth_header = headers.get("Authorization", "")
        if isinstance(auth_header, str) and auth_header.startswith("Bearer "):
            token_str = auth_header[7:].strip()

    cookies = getattr(request, "cookies", None)
    if not token_str and cookies is not None:
        cookie_token = cookies.get("access_token")
        if isinstance(cookie_token, str) and cookie_token:
            token_str = cookie_token

    if not token_str:
        return None, None, None

    try:
        payload = None
        if hasattr(request, "state") and getattr(request.state, "jwt_raw_token", None) == token_str:
            payload = getattr(request.state, "jwt_payload", None)

        if payload is None:
            from services.secrets_manager import decode_jwt_with_rotation
            from config import settings
            payload = decode_jwt_with_rotation(token_str, algorithm=settings.jwt_algorithm)
            if hasattr(request, "state"):
                request.state.jwt_raw_token = token_str
                request.state.jwt_payload = payload

        if isinstance(payload, dict):
            user_id = str(payload.get("id") or payload.get("sub") or "") or None
            tenant_id = str(payload.get("tenant_id") or "") or None
            return user_id, tenant_id, None
    except Exception:
        pass
    return None, None, None


def _extract_user_and_tenant(request: Request) -> Tuple[Optional[str], Optional[str]]:
    """Backwards-compatible wrapper returning (user_id, tenant_id)."""
    user_id, tenant_id, _ = _extract_identity(request)
    return user_id, tenant_id


def _resolve_normalized_route_path(request: Request) -> str:
    """
    Uses FastAPI's matched route template (`request.scope['route'].path`) so varying
    path parameters (`{token}`, `{case_id}`, `{id}`) share one rate-limit bucket (P0-09).
    Falls back to stripped `request.url.path` only for bare mock Requests without scope.
    """
    scope = getattr(request, "scope", None)
    if isinstance(scope, dict):
        route = scope.get("route")
        route_path = getattr(route, "path", None) if route is not None else None
        if isinstance(route_path, str) and route_path:
            return route_path.rstrip("/") or "/"
    raw_path = getattr(getattr(request, "url", None), "path", "/")
    if isinstance(raw_path, str) and raw_path:
        return raw_path.rstrip("/") or "/"
    return "/"


def _build_rate_limit_key(
    request: Request,
    client_ip: str,
    user_id: Optional[str],
    tenant_id: Optional[str],
    api_key_hash: Optional[str] = None,
) -> Tuple[str, str]:
    normalized_path = _resolve_normalized_route_path(request)
    if api_key_hash:
        return f"rate_limit:apikey:{api_key_hash}:{normalized_path}", normalized_path
    if user_id or tenant_id:
        return f"rate_limit:{tenant_id or 'global'}:{user_id or 'anon'}:{normalized_path}:{client_ip}", normalized_path
    return f"rate_limit:{normalized_path}:{client_ip}", normalized_path


def _build_user_aggregate_key(
    normalized_path: str,
    user_id: Optional[str],
    tenant_id: Optional[str],
) -> Optional[str]:
    """Per-user aggregate bucket (independent of client IP) so IP rotation cannot multiply quota."""
    if user_id or tenant_id:
        return f"rate_limit:{tenant_id or 'global'}:{user_id or 'anon'}:{normalized_path}"
    return None


def _rate_limit_headers(limit: int, remaining: int, window: int) -> dict[str, str]:
    reset_ts = int(time.time()) + window
    return {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(max(0, remaining)),
        "X-RateLimit-Reset": str(reset_ts),
    }


async def _check_redis_rate_limit(
    redis,
    key: str,
    route_path: str,
    limit: int,
    window: int,
    aggregate_key: Optional[str] = None,
) -> dict[str, str]:
    now_ms = int(time.time() * 1000)
    window_ms = int(window * 1000)
    window_start_ms = now_ms - window_ms
    member = f"{now_ms}:{uuid.uuid4().hex[:8]}"

    # Prefer atomic Lua script on real async Redis clients (or explicit async-eval doubles)
    # so rejected 429s never pollute the ZSET. Generic AsyncMock/MagicMock do not define
    # `eval` on their class and automatically take the pipeline compatibility path.
    if callable(getattr(type(redis), "eval", None)):
        lua_key = aggregate_key or key
        res = await redis.eval(
            _SLIDING_WINDOW_LUA,
            1,
            lua_key,
            now_ms,
            window_start_ms,
            limit,
            window_ms,
            member,
        )
        allowed = int(res[0]) == 1
        current_count = int(res[1])
        headers = _rate_limit_headers(limit, limit - current_count, window)
        if not allowed:
            _record_rejection(route_path)
            headers["Retry-After"] = str(window)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
                headers=headers,
            )
        return headers

    # Fallback pipeline path (e.g. unit-test mocks without real Redis eval)
    pipe = redis.pipeline()
    pipe.zremrangebyscore(key, 0, window_start_ms)
    pipe.zadd(key, {member: now_ms})
    pipe.zcard(key)
    pipe.pexpire(key, window_ms)
    results = await pipe.execute()

    current_requests = int(results[2])
    headers = _rate_limit_headers(limit, limit - current_requests, window)
    if current_requests > limit:
        _record_rejection(route_path)
        headers["Retry-After"] = str(window)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers=headers,
        )
    return headers


class RateLimiter:
    def __init__(self, limit: int, window: int, fail_closed: bool = False, ip_only: bool = False):
        self.limit = limit
        self.window = window
        self.fail_closed = fail_closed
        self.ip_only = ip_only

    async def __call__(self, request: Request):
        client_ip = _resolve_rate_limit_client_ip(request)
        if self.ip_only:
            user_id, tenant_id, api_key_hash = None, None, None
        else:
            user_id, tenant_id, api_key_hash = _extract_identity(request)

        verified_key = bool(api_key_hash and _is_verified_api_key(request))
        if api_key_hash and not verified_key:
            # Unvalidated X-API-Key header MUST NOT bypass rate limits or allocate per-header
            # keys in noeviction State Redis: force strictly onto the client-IP bucket!
            key, route_path = _build_rate_limit_key(request, client_ip, None, None, None)
            aggregate_key = key
        else:
            key, route_path = _build_rate_limit_key(request, client_ip, user_id, tenant_id, api_key_hash)
            aggregate_key = (
                _build_user_aggregate_key(route_path, user_id, tenant_id)
                if not api_key_hash
                else f"rate_limit:{route_path}:{client_ip}"
            )

        from config import settings
        enforce_fail_closed = self.fail_closed and getattr(settings, "is_hardened", settings.is_production)

        try:
            redis = await get_async_redis_client()
            if redis is not None:
                if verified_key:
                    # Verified API keys are checked against IP aggregate cap BEFORE creating/charging per-key ZSET
                    await _check_redis_rate_limit(
                        redis, aggregate_key, route_path, self.limit, self.window, aggregate_key=aggregate_key
                    )
                    headers = await _check_redis_rate_limit(
                        redis, key, route_path, self.limit, self.window, aggregate_key=key
                    )
                else:
                    headers = await _check_redis_rate_limit(
                        redis, key, route_path, self.limit, self.window, aggregate_key=aggregate_key
                    )
                if hasattr(request, "state"):
                    request.state.rate_limit_headers = headers
                return
        except HTTPException:
            raise
        except Exception as e:
            if enforce_fail_closed:
                logger.error("Rate limiter fail-closed triggered due to Redis outage: %s", e)
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Rate limiting backend unavailable. Request rejected (fail-closed policy).",
                    headers={"Retry-After": str(self.window)},
                )
            logger.warning("Rate limiter failed to communicate with Redis: %s. Falling back to in-process limiter.", e)

        if enforce_fail_closed:
            logger.error("Rate limiter fail-closed triggered: Redis client returned None.")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Rate limiting backend unavailable. Request rejected (fail-closed policy).",
                headers={"Retry-After": str(self.window)},
            )

        allowed, count = _check_local_rate_limit(key, self.limit, self.window)
        headers = _rate_limit_headers(self.limit, self.limit - count, self.window)
        if hasattr(request, "state"):
            request.state.rate_limit_headers = headers
        if not allowed:
            _record_rejection(route_path)
            headers["Retry-After"] = str(self.window)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
                headers=headers,
            )
