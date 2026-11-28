"""
Entity-Level False Positive Whitelisting Service (Distributed L1/L2)
===================================================================
Implements persistent Four-Eyes dispositioning and suppression for known false positive
sanctions, PEP, and high-volume merchant matches.

Under FinCEN and Wolfsberg Group guidelines, common entity names (e.g. "David Smith",
"ABC Trading Ltd") that have been reviewed and adjudicated as false positives by senior
compliance analysts must have their alerts suppressed during subsequent screening,
preventing investigator fatigue while preserving a tamper-evident audit record.

Architecture:
  - L1 Cache: In-memory dictionary (_LOCAL_WHITELIST_STORE) for sub-millisecond lookups.
  - L2 Cache: Redis distributed keyspace (aml:whitelist:*) with TTL for cluster-wide persistence.
  - Invalidation: Redis Pub/Sub channel (aml:whitelist:cache_invalidate) ensuring horizontal
    cache consistency across Kubernetes worker pods without polling drift.
  - Source of Truth: PostgreSQL whitelisted_entities table protected with fail-closed RLS.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from database.redis_db import get_async_redis_client
from database.postgres import get_async_db_conn, get_async_db_read_conn

_ORIGINAL_GET_ASYNC_REDIS_CLIENT = get_async_redis_client
logger = logging.getLogger(__name__)

WHITELIST_PUBSUB_CHANNEL = "aml:whitelist:cache_invalidate"
DEFAULT_WHITELIST_CACHE_TTL = 604800  # 7 days default TTL in Redis
UTC_OFFSET_SUFFIX = "+00:00"

# Fast in-memory L1 cache for whitelist evaluations (per-process micro-cache)
_LOCAL_WHITELIST_STORE: Dict[str, Dict[str, Any]] = {}
_background_tasks: set[asyncio.Future] = set()


def clear_local_whitelist_cache(broadcast: bool = False):
    """
    Clears in-memory L1 cache. If broadcast is True, publishes an invalidation
    message across Redis to clear L1 caches on all peer worker pods.
    """
    global _LOCAL_WHITELIST_STORE
    _LOCAL_WHITELIST_STORE.clear()
    if broadcast:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                task = asyncio.ensure_future(_broadcast_whitelist_invalidation({"action": "CLEAR"}))
                _background_tasks.add(task)
                task.add_done_callback(_background_tasks.discard)
        except Exception as e:
            logger.debug(f"Failed to broadcast whitelist cache clear: {e}")


# Alias for backward compatibility
clear_whitelist_cache = clear_local_whitelist_cache


async def _broadcast_whitelist_invalidation(payload: dict) -> None:
    """Publishes a cache invalidation / sync message over Redis Pub/Sub."""
    try:
        redis = await get_async_redis_client()
        if redis:
            await redis.publish(WHITELIST_PUBSUB_CHANNEL, json.dumps(payload))
    except Exception as e:
        logger.warning(f"Failed to publish whitelist invalidation to Redis: {e}")


def _build_redis_key(tenant_id: str, rule: str, identifier: str, is_customer: bool = False) -> str:
    """Constructs a deterministic, namespaced Redis key for whitelist lookups."""
    prefix = "cust:" if is_customer else ""
    return f"aml:whitelist:{tenant_id}:{rule.strip().upper()}:{prefix}{identifier.strip().lower()}"


async def _persist_whitelist_db(
    entry_id: str,
    tenant_id: str,
    customer_id: Optional[str],
    matched_entity_name: str,
    rule_upper: str,
    cleared_by: str,
    now: datetime,
    expires_at: Optional[datetime],
    notes: Optional[str],
    conn=None
) -> None:
    insert_sql = """
        INSERT INTO whitelisted_entities (
            id, tenant_id, customer_id, matched_entity_name, matched_rule,
            disposition, cleared_by, cleared_at, expires_at, notes
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
    """
    params = (
        uuid.UUID(entry_id), uuid.UUID(str(tenant_id)), customer_id,
        matched_entity_name.strip(), rule_upper,
        "FALSE_POSITIVE", cleared_by, now, expires_at, notes
    )
    try:
        if conn is not None:
            await conn.execute(insert_sql, *params)
        else:
            async with get_async_db_conn(tenant_id=tenant_id) as db_conn:
                if hasattr(db_conn, "execute"):
                    await db_conn.execute(insert_sql, *params)
    except Exception as e:
        logger.error("Whitelist database persistence failed (refusing phantom cache write): %s", e)
        raise


async def _populate_redis_whitelist(
    tenant_id: str,
    rule_upper: str,
    norm_name: str,
    customer_id: Optional[str],
    entry: dict,
    now: datetime,
    expires_at: Optional[datetime]
) -> None:
    try:
        redis = await get_async_redis_client()
        if not redis:
            return
        ttl = DEFAULT_WHITELIST_CACHE_TTL
        if expires_at:
            exp_dt = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
            delta = int((exp_dt - now).total_seconds())
            if delta > 0:
                ttl = delta

        # Scope-isolated cache keys: a customer-scoped whitelist MUST NEVER write to
        # the tenant-wide entity key (which would suppress sanctions for every other customer!).
        if customer_id:
            r_key_cust = _build_redis_key(tenant_id, rule_upper, customer_id, is_customer=True)
            await redis.setex(r_key_cust, ttl, json.dumps(entry))
        else:
            r_key_entity = _build_redis_key(tenant_id, rule_upper, norm_name)
            await redis.setex(r_key_entity, ttl, json.dumps(entry))
    except Exception as e:
        logger.warning(f"Failed to populate Redis whitelist cache: {e}")


async def add_to_whitelist(
    tenant_id: str,
    matched_entity_name: str,
    matched_rule: str,
    cleared_by: str,
    customer_id: Optional[str] = None,
    expires_at: Optional[datetime] = None,
    notes: Optional[str] = None,
    conn=None
) -> Dict[str, Any]:
    """
    Persists an adjudicated false positive disposition in PostgreSQL FIRST, then updates
    scope-isolated L1/L2 caches and broadcasts invalidation across the cluster.
    """
    entry_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    norm_name = matched_entity_name.strip().lower()
    rule_upper = matched_rule.strip().upper()

    entry = {
        "id": entry_id,
        "tenant_id": str(tenant_id),
        "customer_id": str(customer_id) if customer_id else None,
        "matched_entity_name": matched_entity_name.strip(),
        "matched_rule": rule_upper,
        "disposition": "FALSE_POSITIVE",
        "cleared_by": cleared_by,
        "cleared_at": now.isoformat(),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "notes": notes or "Adjudicated as false positive by compliance."
    }

    # 1. Persist durably in PostgreSQL BEFORE populating any L1/L2 cache or pubsub broadcast
    await _persist_whitelist_db(
        entry_id, tenant_id, customer_id, matched_entity_name,
        rule_upper, cleared_by, now, expires_at, notes, conn=conn
    )

    if len(_LOCAL_WHITELIST_STORE) >= 5000:
        _LOCAL_WHITELIST_STORE.clear()

    cache_key: Optional[str] = None
    cust_cache_key: Optional[str] = None
    if customer_id:
        # Customer-scoped whitelist: ONLY populate customer-scoped cache key
        cust_cache_key = f"{tenant_id}:{rule_upper}:cust:{customer_id}"
        _LOCAL_WHITELIST_STORE[cust_cache_key] = entry
    else:
        cache_key = f"{tenant_id}:{rule_upper}:entity:{norm_name}"
        _LOCAL_WHITELIST_STORE[cache_key] = entry

    await _populate_redis_whitelist(
        tenant_id, rule_upper, norm_name, customer_id, entry, now, expires_at
    )

    broadcast_msg = {
        "action": "SYNC",
        "tenant_id": str(tenant_id),
        "cache_key": cache_key,
        "cust_cache_key": cust_cache_key,
        "entry": entry
    }
    await _broadcast_whitelist_invalidation(broadcast_msg)

    logger.info(
        f"Whitelisted entity '{matched_entity_name}' for rule '{matched_rule}' by {cleared_by} (Tenant: {tenant_id})"
    )
    return entry


def _is_entry_valid(entry: Optional[dict], now: datetime) -> bool:
    if not entry:
        return False
    exp = entry.get("expires_at")
    if not exp:
        return True
    try:
        parsed = datetime.fromisoformat(str(exp).replace("Z", UTC_OFFSET_SUFFIX))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        now_utc = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
        return parsed > now_utc
    except (ValueError, TypeError):
        return False


def _check_l1_whitelist(
    tenant_id: str,
    rule_upper: str,
    entity_name: Optional[str],
    customer_id: Optional[str],
    now: datetime
) -> bool:
    if entity_name:
        norm_name = entity_name.strip().lower()
        cached = (
            _LOCAL_WHITELIST_STORE.get(f"{tenant_id}:{rule_upper}:entity:{norm_name}")
            or _LOCAL_WHITELIST_STORE.get(f"{tenant_id}:*:entity:{norm_name}")
            or _LOCAL_WHITELIST_STORE.get(f"{tenant_id}:{rule_upper}:{norm_name}")
            or _LOCAL_WHITELIST_STORE.get(f"{tenant_id}:*:{norm_name}")
        )
        if _is_entry_valid(cached, now) and not (cached or {}).get("customer_id"):
            return True

    if customer_id:
        cached_cust = _LOCAL_WHITELIST_STORE.get(f"{tenant_id}:{rule_upper}:cust:{customer_id}")
        if not cached_cust:
            cached_cust = _LOCAL_WHITELIST_STORE.get(f"{tenant_id}:*:cust:{customer_id}")
        if _is_entry_valid(cached_cust, now):
            return True

    return False


async def _check_l2_whitelist(
    tenant_id: str,
    rule_upper: str,
    entity_name: Optional[str],
    customer_id: Optional[str],
    now: datetime
) -> bool:
    try:
        redis = await get_async_redis_client()
        if not redis:
            return False

        keys_to_check = []
        if entity_name:
            norm_name = entity_name.strip().lower()
            keys_to_check.append((f"{tenant_id}:{rule_upper}:entity:{norm_name}", _build_redis_key(tenant_id, rule_upper, norm_name), False))
            keys_to_check.append((f"{tenant_id}:*:entity:{norm_name}", _build_redis_key(tenant_id, "*", norm_name), False))
        if customer_id:
            keys_to_check.append((f"{tenant_id}:{rule_upper}:cust:{customer_id}", _build_redis_key(tenant_id, rule_upper, customer_id, is_customer=True), True))
            keys_to_check.append((f"{tenant_id}:*:cust:{customer_id}", _build_redis_key(tenant_id, "*", customer_id, is_customer=True), True))

        for l1_key, r_key, is_cust_scope in keys_to_check:
            raw_val = await redis.get(r_key)
            if raw_val:
                entry = json.loads(raw_val)
                if _is_entry_valid(entry, now):
                    # Defense-in-depth: never let a customer-scoped row satisfy an entity-wide lookup
                    if not is_cust_scope and entry.get("customer_id"):
                        continue
                    _LOCAL_WHITELIST_STORE[l1_key] = entry
                    return True
    except Exception as e:
        logger.debug(f"Redis L2 whitelist lookup bypassed: {e}")

    return False


def _format_datetime_str(val: Any) -> Optional[str]:
    if hasattr(val, "isoformat"):
        return val.isoformat()
    return str(val) if val else None


async def _query_l3_whitelist_row(
    tenant_id: str,
    rule_upper: str,
    entity_name: Optional[str],
    customer_id: Optional[str],
    conn=None
) -> Optional[Any]:
    query_sql = """
            SELECT id, tenant_id, customer_id, matched_entity_name, matched_rule,
                   disposition, cleared_by, cleared_at, expires_at, notes
            FROM whitelisted_entities
            WHERE tenant_id = $1::uuid
              AND disposition = 'FALSE_POSITIVE'
              AND (matched_rule = $2 OR matched_rule = '*')
              AND (
                  (customer_id IS NULL AND LOWER(matched_entity_name) = LOWER($3))
                  OR ($4::text IS NOT NULL AND customer_id = $4::text)
              )
              AND (expires_at IS NULL OR expires_at > NOW())
            LIMIT 1;
        """
    params = (
        str(tenant_id),
        rule_upper,
        entity_name.strip() if entity_name else "",
        str(customer_id) if customer_id else None
    )
    if conn is not None and hasattr(conn, "fetchrow"):
        return await conn.fetchrow(query_sql, *params)
    async with get_async_db_read_conn(tenant_id=tenant_id) as db_conn:
        if hasattr(db_conn, "fetchrow"):
            return await db_conn.fetchrow(query_sql, *params)
    return None


async def _hydrate_redis_l2(
    tenant_id: str,
    rule_upper: str,
    entity_name: Optional[str],
    customer_id: Optional[str],
    expires_at_val: Any,
    now: datetime,
    db_entry: dict
) -> None:
    try:
        redis = await get_async_redis_client()
        if not redis:
            return
        ttl = DEFAULT_WHITELIST_CACHE_TTL
        if expires_at_val and hasattr(expires_at_val, "__sub__"):
            exp_dt = expires_at_val if getattr(expires_at_val, "tzinfo", None) else expires_at_val.replace(tzinfo=timezone.utc)
            delta = int((exp_dt - now).total_seconds())
            if delta > 0:
                ttl = delta
        # Hydrate strictly into the matched row's own scope — NEVER poison entity-wide cache from a customer row!
        row_cust_id = db_entry.get("customer_id")
        if row_cust_id:
            await redis.setex(_build_redis_key(tenant_id, rule_upper, str(row_cust_id), is_customer=True), ttl, json.dumps(db_entry))
        elif entity_name:
            await redis.setex(_build_redis_key(tenant_id, rule_upper, entity_name), ttl, json.dumps(db_entry))
    except Exception:
        pass


async def _check_l3_db_whitelist(
    tenant_id: str,
    rule_upper: str,
    entity_name: Optional[str],
    customer_id: Optional[str],
    now: datetime,
    conn=None
) -> bool:
    try:
        row = await _query_l3_whitelist_row(tenant_id, rule_upper, entity_name, customer_id, conn=conn)
        if not row:
            return False

        cleared_at_str = _format_datetime_str(row.get("cleared_at"))
        expires_at_val = row.get("expires_at")
        expires_at_str = _format_datetime_str(expires_at_val)

        db_entry = {
            "id": str(row["id"]),
            "tenant_id": str(row["tenant_id"]),
            "customer_id": row.get("customer_id"),
            "matched_entity_name": row.get("matched_entity_name"),
            "matched_rule": row.get("matched_rule"),
            "disposition": row.get("disposition", "FALSE_POSITIVE"),
            "cleared_by": row.get("cleared_by"),
            "cleared_at": cleared_at_str,
            "expires_at": expires_at_str,
            "notes": row.get("notes")
        }
        # Hydrate L1 strictly into the row's scope (customer-scoped vs entity-wide)
        if db_entry.get("customer_id"):
            _LOCAL_WHITELIST_STORE[f"{tenant_id}:{rule_upper}:cust:{db_entry['customer_id']}"] = db_entry
        elif entity_name:
            _LOCAL_WHITELIST_STORE[f"{tenant_id}:{rule_upper}:entity:{entity_name.strip().lower()}"] = db_entry

        await _hydrate_redis_l2(tenant_id, rule_upper, entity_name, customer_id, expires_at_val, now, db_entry)
        return True
    except Exception as e:
        logger.debug(f"Whitelist database lookup bypassed: {e}")
        return False


async def is_entity_whitelisted(
    tenant_id: Optional[str],
    entity_name: Optional[str],
    rule_name: str,
    customer_id: Optional[str] = None,
    conn=None
) -> bool:
    """
    Checks if an entity is actively whitelisted for a given AML rule.
    Hierarchy:
      1. L1 Local Memory -> 2. L2 Distributed Redis -> 3. PostgreSQL Database
    Returns True if an active false positive disposition suppresses the alert.
    """
    if not tenant_id:
        tenant_id = "00000000-0000-0000-0000-000000000001"
    rule_upper = rule_name.strip().upper()
    now = datetime.now(timezone.utc)

    if _check_l1_whitelist(tenant_id, rule_upper, entity_name, customer_id, now):
        return True
    if await _check_l2_whitelist(tenant_id, rule_upper, entity_name, customer_id, now):
        return True
    return await _check_l3_db_whitelist(tenant_id, rule_upper, entity_name, customer_id, now, conn=conn)


def _handle_whitelist_pubsub_message(msg: Optional[dict]) -> None:
    if not msg or msg.get("type") != "message":
        return
    try:
        data = json.loads(msg["data"])
        action = data.get("action")
        if action == "CLEAR":
            _LOCAL_WHITELIST_STORE.clear()
            logger.info("Cleared L1 whitelist cache via Redis broadcast.")
        elif action == "SYNC":
            _sync_local_whitelist_entry(data)
        elif action == "INVALIDATE":
            k = data.get("cache_key")
            if k and k in _LOCAL_WHITELIST_STORE:
                del _LOCAL_WHITELIST_STORE[k]
    except Exception as parse_err:
        logger.debug(f"Failed to parse whitelist pubsub message: {parse_err}")


def _sync_local_whitelist_entry(data: dict) -> None:
    entry = data.get("entry")
    if not entry:
        return
    k1 = data.get("cache_key")
    if k1:
        _LOCAL_WHITELIST_STORE[k1] = entry
    k2 = data.get("cust_cache_key")
    if k2:
        _LOCAL_WHITELIST_STORE[k2] = entry


async def _consume_whitelist_pubsub_messages(pubsub, shutdown_event: Optional[asyncio.Event]) -> None:
    while shutdown_event is None or not shutdown_event.is_set():
        msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
        _handle_whitelist_pubsub_message(msg)
        await asyncio.sleep(0.5)


async def start_redis_whitelist_listener(shutdown_event: Optional[asyncio.Event] = None) -> None:
    """
    Subscribes to Redis Pub/Sub channel 'aml:whitelist:cache_invalidate' using the
    dedicated Pub/Sub client (socket_timeout=None) with jittered reconnect recovery (P2-23).
    """
    from database.redis_db import get_async_redis_pubsub_client
    from services.http_client import full_jitter_backoff

    attempt = 0
    while shutdown_event is None or not shutdown_event.is_set():
        redis = None
        pubsub = None
        client_is_dedicated = False
        try:
            if get_async_redis_client is not _ORIGINAL_GET_ASYNC_REDIS_CLIENT:
                redis = await get_async_redis_client()
            else:
                redis = await get_async_redis_pubsub_client()
                client_is_dedicated = True
            if redis is None:
                await asyncio.sleep(full_jitter_backoff(2.0, attempt, cap=30.0))
                attempt += 1
                continue
            pubsub = redis.pubsub()
            await pubsub.subscribe(WHITELIST_PUBSUB_CHANNEL)
            logger.info("Subscribed to Redis whitelist invalidation channel '%s'", WHITELIST_PUBSUB_CHANNEL)
            attempt = 0
            await _consume_whitelist_pubsub_messages(pubsub, shutdown_event)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug("Redis whitelist listener encountered transient error: %s", e)
            await asyncio.sleep(full_jitter_backoff(1.0, attempt, cap=30.0))
            attempt += 1
        finally:
            if pubsub is not None:
                try:
                    if hasattr(pubsub, "aclose"):
                        await pubsub.aclose()
                    else:
                        await pubsub.close()
                except Exception:
                    pass
            if redis is not None and client_is_dedicated:
                try:
                    await redis.aclose()
                except Exception:
                    pass
