"""
Dual-Layer Financial Ingestion Idempotency Service (GAP-IDEMP + Logic Pillar L2)
================================================================================
Enforces RFC 7231 / FinTech standard idempotency semantics across TWO coordinated layers:
  - L1 (Redis): Sub-millisecond `SET NX EX` reservation + Lua compare-and-delete.
  - L2 (PostgreSQL `idempotency_records`, FORCE RLS): Durable authority that
    guarantees zero duplicate financial mutations or regulatory filings even across
    Redis restarts, key evictions, or network failovers.
"""

import asyncio
import hashlib
import json
import logging
import re
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from fastapi import HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from database.redis_db import get_async_redis_client
from observability.prometheus import record_idempotency_event
from repositories.idempotency_repo import (
    complete_db_idempotency,
    release_in_flight_db_idempotency,
    try_reserve_db_idempotency,
)

logger = logging.getLogger(__name__)

DEFAULT_IDEMPOTENCY_TTL_SECONDS = 86400  # 24 Hours retention per financial compliance requirements


def _split_scope_and_key(raw_scoped_key: str) -> Tuple[str, str]:
    if ":" in raw_scoped_key:
        scope, key = raw_scoped_key.split(":", 1)
        return scope[:64], key[:128]
    return "default", raw_scoped_key[:128]


async def check_idempotency(
    key: str,
    tenant_id: Optional[str] = None,
    request_hash: Optional[str] = None,
    ttl_seconds: int = DEFAULT_IDEMPOTENCY_TTL_SECONDS,
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Checks if an idempotency key is already registered across L1 (Redis) and L2 (PostgreSQL).
    Returns:
        (is_cached, cached_payload_or_none)
    Raises:
        HTTPException(409) if a request with this key is currently in-flight.
        HTTPException(422) if the key was already completed with a different payload.
    """
    if not key:
        return False, None

    redis_key = f"idemp:{tenant_id}:{key}" if tenant_id else f"idemp:{key}"
    scope, pure_key = _split_scope_and_key(key)
    redis_client = None
    l1_acquired = False

    # ── L1: Redis Fast Path ───────────────────────────────────────────────────
    try:
        redis_client = await get_async_redis_client()
        if redis_client:
            in_flight_payload: Dict[str, Any] = {"status": "IN_FLIGHT"}
            if request_hash:
                in_flight_payload["request_hash"] = request_hash

            acquired = await redis_client.set(
                redis_key,
                json.dumps(in_flight_payload),
                nx=True,
                ex=ttl_seconds,
            )

            if acquired:
                l1_acquired = True
            else:
                val = await redis_client.get(redis_key)
                if val:
                    data = json.loads(val)
                    if data.get("status") == "IN_FLIGHT":
                        record_idempotency_event("redis", "in_flight_409")
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="Concurrent request with identical Idempotency-Key is currently being processed.",
                        )

                    if data.get("status") == "COMPLETED":
                        if request_hash and data.get("request_hash") and data["request_hash"] != request_hash:
                            record_idempotency_event("redis", "hash_mismatch_422")
                            raise HTTPException(
                                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail="Idempotency-Key mismatch: payload differs from previous request with identical key.",
                            )
                        record_idempotency_event("redis", "hit")
                        return True, data
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("Idempotency L1 Redis error (%s); delegating to L2 PostgreSQL.", e)
        record_idempotency_event("postgres", "l2_fallback")

    # ── L2: Durable PostgreSQL Authority (guards against Redis eviction/failover) ─
    outcome, db_record = await try_reserve_db_idempotency(
        tenant_id=tenant_id,
        scope=scope,
        idempotency_key=pure_key,
        request_hash=request_hash or "",
        ttl_seconds=ttl_seconds,
    )

    if outcome == "IN_FLIGHT":
        if l1_acquired:
            await _clear_redis_only(redis_key, redis_client)
        record_idempotency_event("postgres", "in_flight_409")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Concurrent request with identical Idempotency-Key is currently being processed.",
        )

    if outcome == "HASH_MISMATCH":
        if l1_acquired:
            await _clear_redis_only(redis_key, redis_client)
        record_idempotency_event("postgres", "hash_mismatch_422")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Idempotency-Key mismatch: payload differs from previous request with identical key.",
        )

    if outcome == "COMPLETED" and db_record is not None:
        record_idempotency_event("postgres", "hit")
        # Re-warm L1 Redis so subsequent retries hit cache in <1ms
        if redis_client:
            try:
                await redis_client.set(redis_key, json.dumps(db_record), ex=ttl_seconds)
            except Exception:
                pass
        return True, db_record

    return False, None


async def save_idempotency_result(
    key: str,
    status_code: int,
    body: Dict[str, Any],
    tenant_id: Optional[str] = None,
    request_hash: Optional[str] = None,
    ttl_seconds: int = DEFAULT_IDEMPOTENCY_TTL_SECONDS,
) -> None:
    """Stores the final response payload and status code in both L2 PostgreSQL and L1 Redis."""
    if not key:
        return

    redis_key = f"idemp:{tenant_id}:{key}" if tenant_id else f"idemp:{key}"
    scope, pure_key = _split_scope_and_key(key)

    # Persist durably in PostgreSQL first so evictions never lose completed state
    await complete_db_idempotency(
        tenant_id=tenant_id,
        scope=scope,
        idempotency_key=pure_key,
        status_code=status_code,
        body=body,
        request_hash=request_hash or "",
        ttl_seconds=ttl_seconds,
    )

    try:
        r = await get_async_redis_client()
        if not r:
            return

        payload: Dict[str, Any] = {
            "status": "COMPLETED",
            "status_code": status_code,
            "body": body,
        }
        if request_hash:
            payload["request_hash"] = request_hash

        await r.set(redis_key, json.dumps(payload), ex=ttl_seconds)
    except Exception as e:
        logger.warning("Failed to cache L1 idempotency result for key %s: %s", key, e)


store_idempotency_result = save_idempotency_result


_LUA_DELETE_IF_IN_FLIGHT = """
local current = redis.call('GET', KEYS[1])
if not current then
    return 0
end
if string.find(current, '"status": "IN_FLIGHT"', 1, true) or string.find(current, '"status":"IN_FLIGHT"', 1, true) then
    return redis.call('DEL', KEYS[1])
end
return 0
"""


async def _clear_redis_only(redis_key: str, redis_client: Any = None) -> None:
    try:
        r = redis_client or await get_async_redis_client()
        if not r:
            return
        if hasattr(r, "eval"):
            try:
                await r.eval(_LUA_DELETE_IF_IN_FLIGHT, 1, redis_key)
                return
            except Exception:
                pass
        val = await r.get(redis_key)
        if val:
            data = json.loads(val)
            if data.get("status") == "IN_FLIGHT":
                await r.delete(redis_key)
    except Exception:
        pass


async def clear_idempotency_key(
    key: str,
    tenant_id: Optional[str] = None,
) -> None:
    """
    Atomically clears an in-flight idempotency key from both L1 Redis and L2 PostgreSQL
    so failed requests can be safely retried without ever deleting a COMPLETED entry.
    """
    if not key:
        return

    redis_key = f"idemp:{tenant_id}:{key}" if tenant_id else f"idemp:{key}"
    scope, pure_key = _split_scope_and_key(key)

    await release_in_flight_db_idempotency(
        tenant_id=tenant_id,
        scope=scope,
        idempotency_key=pure_key,
    )
    await _clear_redis_only(redis_key)


_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")


async def extract_idempotency_key(request: Optional[Request] = None, body_key: Optional[str] = None) -> Optional[str]:
    """Extracts idempotency key from headers (Idempotency-Key or X-Idempotency-Key) or body."""
    await asyncio.sleep(0)
    header_key = None
    if request is not None and hasattr(request, "headers"):
        header_key = request.headers.get("Idempotency-Key") or request.headers.get("X-Idempotency-Key")
    if header_key and header_key.strip():
        return header_key.strip()
    if body_key and body_key.strip():
        return body_key.strip()
    return None


def _hash_idempotent_body(body: Any) -> str:
    encoded = jsonable_encoder(body) if body is not None else {}
    canonical = json.dumps(encoded, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


async def run_idempotent_operation(
    *,
    request: Optional[Request],
    tenant_id: Optional[str],
    scope: str,
    body: Any,
    handler: Callable[[], Awaitable[Any]],
    success_status_code: int = status.HTTP_200_OK,
    required: bool = True,
    ttl_seconds: int = DEFAULT_IDEMPOTENCY_TTL_SECONDS,
) -> Any:
    """
    Executes a state-mutating compliance operation under dual-layer (Redis + PostgreSQL)
    idempotency protection.
      - When `request` is present and `required=True`, enforces a valid `Idempotency-Key` header
        (HTTP 400 Bad Request if missing or malformed).
      - Replays cached/persisted completed responses with `Idempotency-Replayed: true`.
      - Returns HTTP 409 Conflict for concurrent duplicate in-flight keys and HTTP 422 on payload mismatch.
      - Atomically clears in-flight locks on error so callers can safely retry.
    """
    if request is None:
        return await handler()

    raw_key = await extract_idempotency_key(request)
    if not raw_key:
        if required:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing required 'Idempotency-Key' header for regulatory mutation.",
            )
        return await handler()

    if not _IDEMPOTENCY_KEY_RE.match(raw_key):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 'Idempotency-Key' header format (expected 8-128 URL-safe characters or UUIDv4).",
        )

    tenant_str = str(tenant_id) if tenant_id else None
    scoped_key = f"{scope}:{raw_key}"
    request_hash = _hash_idempotent_body(body)

    is_cached, cached = await check_idempotency(
        scoped_key,
        tenant_id=tenant_str,
        request_hash=request_hash,
        ttl_seconds=ttl_seconds,
    )
    if is_cached and cached is not None:
        return JSONResponse(
            content=cached.get("body"),
            status_code=int(cached.get("status_code", success_status_code)),
            headers={
                "Idempotency-Key": raw_key,
                "Idempotency-Replayed": "true",
            },
        )

    try:
        result = await handler()
    except Exception:
        await clear_idempotency_key(scoped_key, tenant_id=tenant_str)
        raise

    if isinstance(result, JSONResponse):
        try:
            parsed_body = json.loads(result.body.decode("utf-8"))
        except Exception:
            parsed_body = {}
        final_status = result.status_code
        await save_idempotency_result(
            scoped_key,
            final_status,
            parsed_body,
            tenant_id=tenant_str,
            request_hash=request_hash,
            ttl_seconds=ttl_seconds,
        )
        result.headers["Idempotency-Key"] = raw_key
        return result

    encoded_body = jsonable_encoder(result)
    await save_idempotency_result(
        scoped_key,
        success_status_code,
        encoded_body,
        tenant_id=tenant_str,
        request_hash=request_hash,
        ttl_seconds=ttl_seconds,
    )
    return JSONResponse(
        content=encoded_body,
        status_code=success_status_code,
        headers={"Idempotency-Key": raw_key},
    )
