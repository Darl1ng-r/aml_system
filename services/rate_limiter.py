from fastapi import Request, HTTPException, status
import logging
import time
import uuid
import threading
from database.redis_db import get_async_redis_client

logger = logging.getLogger(__name__)

# Local in-process fallback bucket for when Redis is unavailable (Finding #14)
_local_lock = threading.Lock()
_local_buckets: dict[str, list[float]] = {}


def _check_local_rate_limit(key: str, limit: int, window: int) -> bool:
    """In-process sliding window rate limiting fallback when Redis is unreachable."""
    now = time.time()
    window_start = now - window
    with _local_lock:
        timestamps = _local_buckets.get(key, [])
        valid = [t for t in timestamps if t > window_start]
        if len(valid) >= limit:
            _local_buckets[key] = valid
            return False
        valid.append(now)
        _local_buckets[key] = valid
        return True


def _resolve_rate_limit_client_ip(request: Request) -> str:
    from services.trusted_proxy import get_trusted_client_ip
    client_ip = getattr(request.state, "client_ip", None) or get_trusted_client_ip(request)

    # In pytest test suite executions, isolate test client calls using test execution context
    # to prevent cross-test bucket saturation while executing full Redis pipeline
    import os
    if os.environ.get("PYTEST_CURRENT_TEST") and getattr(request, "headers", {}).get("host") == "test":
        test_ctx = os.environ.get("PYTEST_CURRENT_TEST", "").split(" ")[0].split("::")[-1]
        client_ip = f"test_{os.getpid()}_{test_ctx}_{client_ip}"
    return client_ip


def _extract_user_and_tenant(request: Request) -> tuple[str | None, str | None]:
    if not hasattr(request, "headers") or request.headers is None:
        return None, None
    auth_header = request.headers.get("Authorization", "")
    if not isinstance(auth_header, str) or not auth_header.startswith("Bearer "):
        return None, None
    try:
        from services.secrets_manager import decode_jwt_with_rotation
        from config import settings
        token_str = auth_header.split(" ")[1]
        payload = decode_jwt_with_rotation(token_str, algorithm=settings.jwt_algorithm)
        if isinstance(payload, dict):
            user_id = str(payload.get("id") or payload.get("sub") or "") or None
            tenant_id = str(payload.get("tenant_id") or "") or None
            return user_id, tenant_id
    except Exception:
        pass
    return None, None


def _build_rate_limit_key(request: Request, client_ip: str, user_id: str | None, tenant_id: str | None) -> str:
    normalized_path = request.url.path.rstrip("/") or "/"
    if user_id or tenant_id:
        return f"rate_limit:{tenant_id or 'global'}:{user_id or 'anon'}:{normalized_path}:{client_ip}"
    return f"rate_limit:{normalized_path}:{client_ip}"


async def _check_redis_rate_limit(redis, key: str, limit: int, window: int) -> None:
    now_ms = time.time() * 1000
    window_start_ms = now_ms - (window * 1000)
    member = f"{now_ms}:{uuid.uuid4().hex[:8]}"

    # Redis pipeline for atomic sliding window using Sorted Set (ZSET)
    pipe = redis.pipeline()
    pipe.zremrangebyscore(key, 0, window_start_ms)
    pipe.zadd(key, {member: now_ms})
    pipe.zcard(key)
    pipe.pexpire(key, window * 1000)
    results = await pipe.execute()

    current_requests = results[2]
    if current_requests > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(window)}
        )


class RateLimiter:
    def __init__(self, limit: int, window: int, fail_closed: bool = False):
        self.limit = limit
        self.window = window
        self.fail_closed = fail_closed

    async def __call__(self, request: Request):
        client_ip = _resolve_rate_limit_client_ip(request)
        user_id, tenant_id = _extract_user_and_tenant(request)
        key = _build_rate_limit_key(request, client_ip, user_id, tenant_id)

        try:
            redis = await get_async_redis_client()
            if redis is not None:
                await _check_redis_rate_limit(redis, key, self.limit, self.window)
                return
        except HTTPException:
            raise
        except Exception as e:
            # When Redis fails, log and proceed to local in-process fallback
            logger.warning(f"Rate limiter failed to communicate with Redis: {e}. Falling back to in-process limiter.")

        # Local in-process fallback: enforce sliding window even without Redis
        if not _check_local_rate_limit(key, self.limit, self.window):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
                headers={"Retry-After": str(self.window)}
            )
