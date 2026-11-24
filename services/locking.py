"""
Pessimistic Resource Locking Service (Section 4.1 Audit Remediation)
===================================================================
Provides distributed lease locking across horizontally scaled worker pods to prevent
analyst/investigator collisions on alerts and cases.

Architecture:
  - Tier 1: Redis atomic lease (SET NX EX) with TTL for sub-millisecond acquisition
  - Tier 2: PostgreSQL resource_locks table for durable state, auditability, and fallback
"""

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, Dict, Any
from database.redis_db import get_async_redis_client
from database.postgres import get_async_db_conn
from observability.logging import log_audit_event

logger = logging.getLogger(__name__)

DEFAULT_LOCK_TTL_SECONDS = 300  # 5 minutes

# Atomic Lua compare-and-set / compare-and-delete scripts (strict JSON field match; prevents TOCTOU & substring bypass)
_LUA_COMPARE_AND_SET = """
local current = redis.call('GET', KEYS[1])
if not current then
    return 0
end
local ok, parsed = pcall(cjson.decode, current)
if not ok or type(parsed) ~= 'table' then
    return -1
end
if tostring(parsed['locked_by']) == ARGV[1] then
    redis.call('SET', KEYS[1], ARGV[2], 'EX', tonumber(ARGV[3]))
    return 1
end
return -1
"""

_LUA_COMPARE_AND_DEL = """
local current = redis.call('GET', KEYS[1])
if not current then
    return 1
end
local ok, parsed = pcall(cjson.decode, current)
if not ok or type(parsed) ~= 'table' then
    return -1
end
if tostring(parsed['locked_by']) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return -1
"""


def _redis_key(resource_type: str, resource_id: str, tenant_id: Optional[str] = None) -> str:
    scope = str(tenant_id).strip() if tenant_id else "global"
    return f"aml:lock:{scope}:{resource_type.upper()}:{resource_id}"


def _sanitize_public_lock_info(data: Dict[str, Any]) -> Dict[str, Any]:
    """Strips secret lock_token before returning lock metadata to non-holders."""
    return {k: v for k, v in data.items() if k != "lock_token"}


async def _try_acquire_redis_lease(
    redis: Any,
    key: str,
    lock_payload: Dict[str, Any],
    user_id: str,
    ttl_seconds: int,
    res_type: str,
    resource_id: str,
    username: str,
    tenant_id: str,
    expires_at: datetime,
    lock_token: str
) -> Tuple[bool, Optional[Tuple[bool, Dict[str, Any]]]]:
    try:
        payload_json = json.dumps(lock_payload)
        acquired = await redis.set(
            key,
            payload_json,
            nx=True,
            ex=ttl_seconds
        )
        if acquired:
            await _persist_lock_to_db(res_type, resource_id, user_id, username, tenant_id, expires_at, lock_token)
            return True, (True, lock_payload)

        existing_raw = await redis.get(key)
        if existing_raw:
            existing_data = json.loads(existing_raw)
            if existing_data.get("locked_by") == str(user_id):
                # Atomic compare-and-set renewal via Lua when supported
                if hasattr(redis, "eval"):
                    try:
                        res = await redis.eval(_LUA_COMPARE_AND_SET, 1, key, str(user_id), payload_json, str(ttl_seconds))
                        if res == -1:
                            refreshed = await redis.get(key)
                            conflict = json.loads(refreshed) if refreshed else existing_data
                            return True, (False, _sanitize_public_lock_info(conflict))
                    except Exception:
                        await redis.set(key, payload_json, ex=ttl_seconds)
                else:
                    await redis.set(key, payload_json, ex=ttl_seconds)
                await _persist_lock_to_db(res_type, resource_id, user_id, username, tenant_id, expires_at, lock_token)
                return True, (True, lock_payload)
            return True, (False, _sanitize_public_lock_info(existing_data))
    except Exception as e:
        logger.warning(f"Redis lock check failed, falling back to PostgreSQL: {e}")
    return False, None


async def _persist_and_validate_db_lock(
    res_type: str,
    resource_id: str,
    user_id: str,
    username: str,
    tenant_id: str,
    now: datetime,
    expires_at: datetime,
    lock_token: str
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        existing_row = await conn.fetchrow(
            """
            SELECT resource_type, resource_id, locked_by, locked_by_name,
                   locked_at, expires_at
            FROM resource_locks
            WHERE resource_type = $1 AND resource_id = $2
              AND tenant_id = $3
              AND expires_at > NOW() AND released_at IS NULL;
            """,
            res_type, uuid.UUID(str(resource_id)), uuid.UUID(str(tenant_id))
        )
        if existing_row:
            existing_user = str(existing_row["locked_by"])
            if existing_user != str(user_id):
                return False, {
                    "resource_type": existing_row["resource_type"],
                    "resource_id": str(existing_row["resource_id"]),
                    "locked_by": existing_user,
                    "locked_by_name": existing_row["locked_by_name"],
                    "expires_at": existing_row["expires_at"].isoformat() if existing_row["expires_at"] else None,
                }

        acquired_owner = await conn.fetchval(
            """
            INSERT INTO resource_locks (
                resource_type, resource_id, locked_by, locked_by_name,
                tenant_id, locked_at, expires_at, lock_token, released_at, force_broken_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL)
            ON CONFLICT (resource_type, resource_id) DO UPDATE
            SET locked_by = EXCLUDED.locked_by,
                locked_by_name = EXCLUDED.locked_by_name,
                locked_at = EXCLUDED.locked_at,
                expires_at = EXCLUDED.expires_at,
                lock_token = EXCLUDED.lock_token,
                released_at = NULL,
                force_broken_by = NULL
            WHERE resource_locks.tenant_id = EXCLUDED.tenant_id
              AND (
                  resource_locks.expires_at <= NOW()
                  OR resource_locks.released_at IS NOT NULL
                  OR resource_locks.locked_by = EXCLUDED.locked_by
              )
            RETURNING locked_by;
            """,
            res_type, uuid.UUID(str(resource_id)), uuid.UUID(str(user_id)), username,
            uuid.UUID(str(tenant_id)), now, expires_at, uuid.UUID(lock_token)
        )
        if acquired_owner is None:
            # Atomic conditional UPSERT lost a concurrent race to another active holder
            holder_row = await conn.fetchrow(
                """
                SELECT resource_type, resource_id, locked_by, locked_by_name,
                       locked_at, expires_at
                FROM resource_locks
                WHERE resource_type = $1 AND resource_id = $2 AND tenant_id = $3;
                """,
                res_type, uuid.UUID(str(resource_id)), uuid.UUID(str(tenant_id))
            )
            if holder_row and str(holder_row["locked_by"]) != str(user_id):
                return False, {
                    "resource_type": holder_row["resource_type"],
                    "resource_id": str(holder_row["resource_id"]),
                    "locked_by": str(holder_row["locked_by"]),
                    "locked_by_name": holder_row["locked_by_name"],
                    "expires_at": holder_row["expires_at"].isoformat() if holder_row["expires_at"] else None,
                }
    return True, None


async def acquire_resource_lock(
    resource_type: str,
    resource_id: str,
    user_id: str,
    username: str,
    tenant_id: str,
    ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS
) -> Tuple[bool, Dict[str, Any]]:
    """
    Attempts to acquire an exclusive pessimistic lease lock on a resource (ALERT or CASE).
    Returns (True, lock_payload) on success.
    Returns (False, existing_lock_payload) if already held by another user.
    """
    res_type = resource_type.upper()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl_seconds)
    lock_token = str(uuid.uuid4())

    lock_payload = {
        "resource_type": res_type,
        "resource_id": str(resource_id),
        "locked_by": str(user_id),
        "locked_by_name": username,
        "tenant_id": str(tenant_id),
        "locked_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "lock_token": lock_token,
        "ttl_seconds": ttl_seconds
    }

    # 1. Try acquiring in Redis first (tenant-namespaced key)
    redis = await get_async_redis_client()
    key = _redis_key(res_type, resource_id, tenant_id=tenant_id)

    if redis:
        handled, result = await _try_acquire_redis_lease(
            redis, key, lock_payload, user_id, ttl_seconds,
            res_type, resource_id, username, tenant_id, expires_at, lock_token
        )
        if handled and result is not None:
            return result

    # 2. Database validation & persistence
    try:
        ok, conflict_data = await _persist_and_validate_db_lock(
            res_type, resource_id, user_id, username, tenant_id, now, expires_at, lock_token
        )
        if not ok and conflict_data is not None:
            return False, conflict_data
    except Exception as dbe:
        logger.exception(f"Failed to persist lock to database: {dbe}")
        if not redis:
            raise

    return True, lock_payload


async def _persist_lock_to_db(
    resource_type: str,
    resource_id: str,
    user_id: str,
    username: str,
    tenant_id: str,
    expires_at: datetime,
    lock_token: str
):
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            await conn.execute(
                """
                INSERT INTO resource_locks (
                    resource_type, resource_id, locked_by, locked_by_name,
                    tenant_id, locked_at, expires_at, lock_token, released_at, force_broken_by
                )
                VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7, NULL, NULL)
                ON CONFLICT (resource_type, resource_id) DO UPDATE
                SET locked_by = EXCLUDED.locked_by,
                    locked_by_name = EXCLUDED.locked_by_name,
                    locked_at = NOW(),
                    expires_at = EXCLUDED.expires_at,
                    lock_token = EXCLUDED.lock_token,
                    released_at = NULL,
                    force_broken_by = NULL
                WHERE resource_locks.tenant_id = EXCLUDED.tenant_id;
                """,
                resource_type, uuid.UUID(str(resource_id)), uuid.UUID(str(user_id)), username,
                uuid.UUID(str(tenant_id)), expires_at, uuid.UUID(lock_token)
            )
    except Exception as e:
        logger.warning(f"Could not persist lock to DB: {e}")


async def _refresh_redis_lease(
    redis: Any,
    key: str,
    user_id: str,
    lock_token: Optional[str],
    new_expires_at: datetime,
    ttl_seconds: int,
    res_type: str,
    resource_id: str,
    tenant_id: Optional[str] = None,
) -> Tuple[bool, Optional[Tuple[bool, Dict[str, Any]]]]:
    try:
        raw = await redis.get(key)
        if raw:
            data = json.loads(raw)
            if data.get("locked_by") == str(user_id):
                if lock_token and data.get("lock_token") and str(data.get("lock_token")) != str(lock_token):
                    return True, (False, {"detail": "Invalid lock token"})
                data["expires_at"] = new_expires_at.isoformat()
                data["ttl_seconds"] = ttl_seconds
                await redis.set(key, json.dumps(data), ex=ttl_seconds)
                await _update_db_expiry(res_type, resource_id, new_expires_at, tenant_id=tenant_id)
                return True, (True, data)
            return True, (False, {"detail": "Lock held by different user", "current_holder": data.get("locked_by_name")})
    except Exception as e:
        logger.warning(f"Redis refresh failed: {e}")
    return False, None


async def _refresh_db_lease(
    res_type: str,
    resource_id: str,
    user_id: str,
    lock_token: Optional[str],
    new_expires_at: datetime,
    ttl_seconds: int,
    tenant_id: Optional[str] = None,
) -> Tuple[bool, Optional[Tuple[bool, Dict[str, Any]]]]:
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            if tenant_id:
                row = await conn.fetchrow(
                    """
                    UPDATE resource_locks
                    SET expires_at = $1
                    WHERE resource_type = $2 AND resource_id = $3
                      AND locked_by = $4 AND tenant_id = $5
                      AND (released_at IS NULL OR expires_at > NOW())
                    RETURNING resource_type, resource_id, locked_by, locked_by_name, expires_at, lock_token;
                    """,
                    new_expires_at, res_type, uuid.UUID(str(resource_id)),
                    uuid.UUID(str(user_id)), uuid.UUID(str(tenant_id))
                )
            else:
                row = await conn.fetchrow(
                    """
                    UPDATE resource_locks
                    SET expires_at = $1
                    WHERE resource_type = $2 AND resource_id = $3
                      AND locked_by = $4 AND (released_at IS NULL OR expires_at > NOW())
                    RETURNING resource_type, resource_id, locked_by, locked_by_name, expires_at, lock_token;
                    """,
                    new_expires_at, res_type, uuid.UUID(str(resource_id)), uuid.UUID(str(user_id))
                )
            if row:
                if lock_token and row["lock_token"] and str(row["lock_token"]) != str(lock_token):
                    return True, (False, {"detail": "Invalid lock token"})
                return True, (True, {
                    "resource_type": row["resource_type"],
                    "resource_id": str(row["resource_id"]),
                    "locked_by": str(row["locked_by"]),
                    "locked_by_name": row["locked_by_name"],
                    "expires_at": row["expires_at"].isoformat(),
                    "ttl_seconds": ttl_seconds
                })
    except Exception as e:
        logger.exception(f"DB refresh failed: {e}")
    return False, None


async def refresh_resource_lock(
    resource_type: str,
    resource_id: str,
    user_id: str,
    lock_token: Optional[str] = None,
    ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS,
    tenant_id: Optional[str] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Heartbeat / refresh lock lease TTL (tenant-scoped).
    """
    res_type = resource_type.upper()
    now = datetime.now(timezone.utc)
    new_expires_at = now + timedelta(seconds=ttl_seconds)

    redis = await get_async_redis_client()
    key = _redis_key(res_type, resource_id, tenant_id=tenant_id)

    if redis:
        handled, result = await _refresh_redis_lease(
            redis, key, user_id, lock_token, new_expires_at, ttl_seconds, res_type, resource_id, tenant_id=tenant_id
        )
        if handled and result is not None:
            return result

    handled_db, db_result = await _refresh_db_lease(
        res_type, resource_id, user_id, lock_token, new_expires_at, ttl_seconds, tenant_id=tenant_id
    )
    if handled_db and db_result is not None:
        return db_result

    return False, {"detail": "Lock not found or expired"}


async def _update_db_expiry(
    resource_type: str,
    resource_id: str,
    new_expires_at: datetime,
    tenant_id: Optional[str] = None,
):
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            if tenant_id:
                await conn.execute(
                    """
                    UPDATE resource_locks
                    SET expires_at = $1
                    WHERE resource_type = $2 AND resource_id = $3 AND tenant_id = $4;
                    """,
                    new_expires_at, resource_type, uuid.UUID(str(resource_id)), uuid.UUID(str(tenant_id))
                )
            else:
                await conn.execute(
                    """
                    UPDATE resource_locks
                    SET expires_at = $1
                    WHERE resource_type = $2 AND resource_id = $3;
                    """,
                    new_expires_at, resource_type, uuid.UUID(str(resource_id))
                )
    except Exception:
        pass


async def release_resource_lock(
    resource_type: str,
    resource_id: str,
    user_id: str,
    user_role: str = "ANALYST",
    force: bool = False,
    tenant_id: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Releases an active lock lease atomically (Lua compare-and-delete in Redis + tenant-scoped PG update).
    If force=True, allows MLRO / ADMIN to break another analyst's lock within their tenant.
    """
    res_type = resource_type.upper()
    redis = await get_async_redis_client()
    key = _redis_key(res_type, resource_id, tenant_id=tenant_id)

    if redis:
        try:
            if force:
                await redis.delete(key)
            elif hasattr(redis, "eval"):
                res = await redis.eval(_LUA_COMPARE_AND_DEL, 1, key, str(user_id))
                if res == -1:
                    raw = await redis.get(key)
                    holder = json.loads(raw).get("locked_by_name") if raw else "another user"
                    return False, f"Cannot release lock owned by {holder}"
            else:
                raw = await redis.get(key)
                if raw:
                    data = json.loads(raw)
                    if data.get("locked_by") == str(user_id):
                        await redis.delete(key)
                    else:
                        return False, f"Cannot release lock owned by {data.get('locked_by_name')}"
        except Exception as e:
            logger.warning(f"Redis release error: {e}")

    # Mark released in DB (explicitly tenant-scoped)
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            if force:
                if tenant_id:
                    await conn.execute(
                        """
                        UPDATE resource_locks
                        SET released_at = NOW(), force_broken_by = $1
                        WHERE resource_type = $2 AND resource_id = $3 AND tenant_id = $4;
                        """,
                        uuid.UUID(str(user_id)), res_type, uuid.UUID(str(resource_id)), uuid.UUID(str(tenant_id))
                    )
                else:
                    await conn.execute(
                        """
                        UPDATE resource_locks
                        SET released_at = NOW(), force_broken_by = $1
                        WHERE resource_type = $2 AND resource_id = $3;
                        """,
                        uuid.UUID(str(user_id)), res_type, uuid.UUID(str(resource_id))
                    )
                log_audit_event(
                    event_type="LOCK_FORCE_BROKEN",
                    actor_id=str(user_id),
                    actor_role=user_role,
                    action="FORCE_UNLOCK",
                    resource_type=res_type,
                    resource_id=str(resource_id),
                    details={"message": f"Lock forcibly cleared by {user_role}", "tenant_id": str(tenant_id) if tenant_id else None}
                )
            else:
                if tenant_id:
                    await conn.execute(
                        """
                        UPDATE resource_locks
                        SET released_at = NOW()
                        WHERE resource_type = $1 AND resource_id = $2
                          AND locked_by = $3 AND tenant_id = $4;
                        """,
                        res_type, uuid.UUID(str(resource_id)), uuid.UUID(str(user_id)), uuid.UUID(str(tenant_id))
                    )
                else:
                    await conn.execute(
                        """
                        UPDATE resource_locks
                        SET released_at = NOW()
                        WHERE resource_type = $1 AND resource_id = $2 AND locked_by = $3;
                        """,
                        res_type, uuid.UUID(str(resource_id)), uuid.UUID(str(user_id))
                    )
    except Exception as e:
        logger.exception(f"DB release lock error: {e}")

    return True, "Lock released successfully"


async def get_resource_lock_status(
    resource_type: str,
    resource_id: str,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Checks who currently holds the lock on a resource within the caller's tenant.
    Never exposes secret lock_token to callers.
    """
    res_type = resource_type.upper()
    redis = await get_async_redis_client()
    key = _redis_key(res_type, resource_id, tenant_id=tenant_id)

    if redis:
        try:
            raw = await redis.get(key)
            ttl = await redis.ttl(key)
            if raw and ttl > 0:
                data = _sanitize_public_lock_info(json.loads(raw))
                data["seconds_remaining"] = ttl
                data["is_locked"] = True
                return data
        except Exception as e:
            logger.warning(f"Redis status check error: {e}")

    # Check database
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            if tenant_id:
                row = await conn.fetchrow(
                    """
                    SELECT resource_type, resource_id, locked_by, locked_by_name,
                           locked_at, expires_at
                    FROM resource_locks
                    WHERE resource_type = $1 AND resource_id = $2
                      AND tenant_id = $3
                      AND expires_at > NOW() AND released_at IS NULL;
                    """,
                    res_type, uuid.UUID(str(resource_id)), uuid.UUID(str(tenant_id))
                )
            else:
                row = await conn.fetchrow(
                    """
                    SELECT resource_type, resource_id, locked_by, locked_by_name,
                           locked_at, expires_at
                    FROM resource_locks
                    WHERE resource_type = $1 AND resource_id = $2
                      AND expires_at > NOW() AND released_at IS NULL;
                    """,
                    res_type, uuid.UUID(str(resource_id))
                )
            if row:
                now = datetime.now(timezone.utc)
                remaining = max(0, int((row["expires_at"] - now).total_seconds()))
                return {
                    "is_locked": True,
                    "resource_type": row["resource_type"],
                    "resource_id": str(row["resource_id"]),
                    "locked_by": str(row["locked_by"]),
                    "locked_by_name": row["locked_by_name"],
                    "expires_at": row["expires_at"].isoformat(),
                    "seconds_remaining": remaining
                }
    except Exception as e:
        logger.warning(f"DB status check error: {e}")

    return {"is_locked": False, "resource_type": res_type, "resource_id": str(resource_id)}
