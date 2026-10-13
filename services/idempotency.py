"""
Financial Ingestion Idempotency Service (GAP-IDEMP)
===================================================
Enforces RFC 7231 / FinTech standard idempotency semantics for financial
transaction ingestion and state-mutating compliance operations.

Uses Redis atomic key reservation (`SET NX EX`) to:
1. Prevent duplicate balance deductions and duplicate AML alert creation.
2. Fast-return the exact previously cached HTTP response on retried requests.
3. Detect and reject concurrent duplicate in-flight requests (HTTP 409 Conflict).
"""

import json
import logging
from typing import Optional, Tuple, Any, Dict
from fastapi import Request, HTTPException, status
from database.redis_db import get_async_redis_client

logger = logging.getLogger(__name__)

DEFAULT_IDEMPOTENCY_TTL_SECONDS = 86400  # 24 Hours retention per financial compliance requirements


async def check_idempotency(
    key: str,
    tenant_id: Optional[str] = None,
    request_hash: Optional[str] = None,
    ttl_seconds: int = DEFAULT_IDEMPOTENCY_TTL_SECONDS
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Checks if an idempotency key is already registered.
    Returns:
        (is_cached, cached_payload_or_none)
    Raises:
        HTTPException(409) if a request with this key is currently in-flight.
        HTTPException(422) if the key was already completed with a different payload.
    """
    if not key:
        return False, None

    redis_key = f"idemp:{tenant_id}:{key}" if tenant_id else f"idemp:{key}"

    try:
        r = await get_async_redis_client()
        if not r:
            return False, None

        # Attempt to atomically set the key in 'IN_FLIGHT' state if not present
        in_flight_payload = {"status": "IN_FLIGHT"}
        if request_hash:
            in_flight_payload["request_hash"] = request_hash

        acquired = await r.set(
            redis_key,
            json.dumps(in_flight_payload),
            nx=True,
            ex=ttl_seconds
        )

        if acquired:
            # First time seeing this key; processing proceeds
            return False, None

        # Key already existed; fetch cached value
        val = await r.get(redis_key)
        if not val:
            return False, None

        data = json.loads(val)
        if data.get("status") == "IN_FLIGHT":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Concurrent request with identical Idempotency-Key is currently being processed."
            )

        if data.get("status") == "COMPLETED":
            # Guard against idempotency key reuse with mismatched body (RFC 7231 / FinTech standard)
            if request_hash and data.get("request_hash") and data["request_hash"] != request_hash:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Idempotency-Key mismatch: payload differs from previous request with identical key."
                )
            return True, data

        return False, None

    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Idempotency check bypassed due to Redis error: {e}")
        return False, None


async def save_idempotency_result(
    key: str,
    status_code: int,
    body: Dict[str, Any],
    tenant_id: Optional[str] = None,
    request_hash: Optional[str] = None,
    ttl_seconds: int = DEFAULT_IDEMPOTENCY_TTL_SECONDS
) -> None:
    """Stores the final response payload and status code for the idempotency key."""
    if not key:
        return

    redis_key = f"idemp:{tenant_id}:{key}" if tenant_id else f"idemp:{key}"

    try:
        r = await get_async_redis_client()
        if not r:
            return

        payload = {
            "status": "COMPLETED",
            "status_code": status_code,
            "body": body
        }
        if request_hash:
            payload["request_hash"] = request_hash

        await r.set(redis_key, json.dumps(payload), ex=ttl_seconds)
    except Exception as e:
        logger.warning(f"Failed to cache idempotency result for key {key}: {e}")


store_idempotency_result = save_idempotency_result


async def clear_idempotency_key(
    key: str,
    tenant_id: Optional[str] = None
) -> None:
    """
    Clears an in-flight idempotency key so failed requests can be safely retried
    without being locked out for 24 hours.
    """
    if not key:
        return

    redis_key = f"idemp:{tenant_id}:{key}" if tenant_id else f"idemp:{key}"

    try:
        r = await get_async_redis_client()
        if not r:
            return

        val = await r.get(redis_key)
        if val:
            data = json.loads(val)
            # Only remove if still IN_FLIGHT (preserve COMPLETED idempotency cache)
            if data.get("status") == "IN_FLIGHT":
                await r.delete(redis_key)
                logger.debug(f"Cleared in-flight idempotency key: {key}")
    except Exception as e:
        logger.warning(f"Failed to clear idempotency key {key}: {e}")


async def extract_idempotency_key(request: Optional[Request] = None, body_key: Optional[str] = None) -> Optional[str]:
    """Extracts idempotency key from headers (Idempotency-Key or X-Idempotency-Key) or body."""
    header_key = None
    if request is not None and hasattr(request, "headers"):
        header_key = request.headers.get("Idempotency-Key") or request.headers.get("X-Idempotency-Key")
    if header_key and header_key.strip():
        return header_key.strip()
    if body_key and body_key.strip():
        return body_key.strip()
    return None
