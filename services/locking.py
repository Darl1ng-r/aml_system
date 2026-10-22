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


def _redis_key(resource_type: str, resource_id: str) -> str:
    return f"aml:lock:{resource_type.upper()}:{resource_id}"


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
        acquired = await redis.set(
            key,
            json.dumps(lock_payload),
            nx=True,
            ex=ttl_seconds
        )
        if not acquired:
            existing_raw = await redis.get(key)
            if existing_raw:
                existing_data = json.loads(existing_raw)
                if existing_data.get("locked_by") == str(user_id):
                    await redis.set(key, json.dumps(lock_payload), ex=ttl_seconds)
                    await _persist_lock_to_db(res_type, resource_id, user_id, username, tenant_id, expires_at, lock_token)
                    return True, (True, lock_payload)
                return True, (False, existing_data)
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
                   locked_at, expires_at, lock_token
            FROM resource_locks
            WHERE resource_type = $1 AND resource_id = $2
              AND expires_at > NOW() AND released_at IS NULL;
            """,
            res_type, uuid.UUID(str(resource_id))
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
                    "lock_token": str(existing_row["lock_token"]) if existing_row["lock_token"] else None
                }

        await conn.execute(
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
                force_broken_by = NULL;
            """,
            res_type, uuid.UUID(str(resource_id)), uuid.UUID(str(user_id)), username,
            uuid.UUID(str(tenant_id)), now, expires_at, uuid.UUID(lock_token)
        )
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

    # 1. Try acquiring in Redis first
    redis = await get_async_redis_client()
    key = _redis_key(res_type, resource_id)

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
                    force_broken_by = NULL;
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
    resource_id: str
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
                await _update_db_expiry(res_type, resource_id, new_expires_at)
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
    ttl_seconds: int
) -> Tuple[bool, Optional[Tuple[bool, Dict[str, Any]]]]:
    try:
        async with get_async_db_conn() as conn:
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
    ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS
) -> Tuple[bool, Dict[str, Any]]:
    """
    Heartbeat / refresh lock lease TTL.
    """
    res_type = resource_type.upper()
    now = datetime.now(timezone.utc)
    new_expires_at = now + timedelta(seconds=ttl_seconds)

    redis = await get_async_redis_client()
    key = _redis_key(res_type, resource_id)

    if redis:
        handled, result = await _refresh_redis_lease(
            redis, key, user_id, lock_token, new_expires_at, ttl_seconds, res_type, resource_id
        )
        if handled and result is not None:
            return result

    handled_db, db_result = await _refresh_db_lease(
        res_type, resource_id, user_id, lock_token, new_expires_at, ttl_seconds
    )
    if handled_db and db_result is not None:
        return db_result

    return False, {"detail": "Lock not found or expired"}


async def _update_db_expiry(resource_type: str, resource_id: str, new_expires_at: datetime):
    try:
        async with get_async_db_conn() as conn:
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
    force: bool = False
) -> Tuple[bool, str]:
    """
    Releases an active lock lease.
    If force=True, allows MLRO / ADMIN to break another analyst's lock.
    """
    res_type = resource_type.upper()
    redis = await get_async_redis_client()
    key = _redis_key(res_type, resource_id)

    existing_holder = None
    if redis:
        try:
            raw = await redis.get(key)
            if raw:
                data = json.loads(raw)
                existing_holder = data.get("locked_by")
                if existing_holder == str(user_id) or force:
                    await redis.delete(key)
                elif not force:
                    return False, f"Cannot release lock owned by {data.get('locked_by_name')}"
        except Exception as e:
            logger.warning(f"Redis release error: {e}")

    # Mark released in DB
    try:
        async with get_async_db_conn() as conn:
            if force:
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
                    details={"message": f"Lock forcibly cleared by {user_role}"}
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
    resource_id: str
) -> Dict[str, Any]:
    """
    Checks who currently holds the lock on a resource and seconds remaining.
    """
    res_type = resource_type.upper()
    redis = await get_async_redis_client()
    key = _redis_key(res_type, resource_id)

    if redis:
        try:
            raw = await redis.get(key)
            ttl = await redis.ttl(key)
            if raw and ttl > 0:
                data = json.loads(raw)
                data["seconds_remaining"] = ttl
                data["is_locked"] = True
                return data
        except Exception as e:
            logger.warning(f"Redis status check error: {e}")

    # Check database
    try:
        async with get_async_db_conn() as conn:
            row = await conn.fetchrow(
                """
                SELECT resource_type, resource_id, locked_by, locked_by_name,
                       locked_at, expires_at, lock_token
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
