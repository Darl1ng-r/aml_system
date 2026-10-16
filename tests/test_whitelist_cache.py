"""
Test Suite: Whitelist Distributed Caching & Pub/Sub Invalidation
================================================================
Verifies L1 (in-memory) + L2 (Redis) distributed caching and Pub/Sub cache invalidation
to eliminate cache drift across multi-replica deployments.
"""

import asyncio
import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from services.whitelisting import (
    is_entity_whitelisted,
    add_to_whitelist,
    clear_local_whitelist_cache,
    start_redis_whitelist_listener,
    _LOCAL_WHITELIST_STORE,
    WHITELIST_PUBSUB_CHANNEL,
)


@pytest.fixture(autouse=True)
def clean_local_cache():
    """Ensure local in-memory L1 cache is clean before each test."""
    _LOCAL_WHITELIST_STORE.clear()
    yield
    _LOCAL_WHITELIST_STORE.clear()


@pytest.mark.asyncio
async def test_whitelist_l1_cache_hit():
    """Verifies that an L1 in-memory hit returns immediately without querying Redis or DB."""
    tenant_id = str(uuid.uuid4())
    cache_key = f"{tenant_id}:OFAC_SANCTIONS:acme corp"
    _LOCAL_WHITELIST_STORE[cache_key] = {
        "matched_entity_name": "Acme Corp",
        "matched_rule": "OFAC_SANCTIONS",
        "disposition": "FALSE_POSITIVE",
        "expires_at": None,
    }

    with patch("services.whitelisting.get_async_redis_client") as mock_redis, \
         patch("database.postgres.get_async_db_conn") as mock_db:

        result = await is_entity_whitelisted(
            tenant_id=tenant_id,
            entity_name="Acme Corp",
            rule_name="OFAC_SANCTIONS",
        )

        assert result is True
        assert not mock_redis.called
        assert not mock_db.called


@pytest.mark.asyncio
async def test_whitelist_l2_redis_hit_populates_l1():
    """Verifies that an L2 Redis hit populates L1 and avoids database queries."""
    tenant_id = str(uuid.uuid4())
    norm_key = f"{tenant_id}:OFAC_SANCTIONS:acme corp"
    cached_entry = {
        "matched_entity_name": "Acme Corp",
        "matched_rule": "OFAC_SANCTIONS",
        "disposition": "FALSE_POSITIVE",
        "expires_at": None,
    }

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=json.dumps(cached_entry))

    with patch("services.whitelisting.get_async_redis_client", return_value=mock_redis), \
         patch("database.postgres.get_async_db_conn") as mock_db:

        result = await is_entity_whitelisted(
            tenant_id=tenant_id,
            entity_name="Acme Corp",
            rule_name="OFAC_SANCTIONS",
        )

        assert result is True
        assert mock_redis.get.called
        assert not mock_db.called
        # Check that L1 was populated
        assert norm_key in _LOCAL_WHITELIST_STORE


@pytest.mark.asyncio
async def test_whitelist_db_fallback_populates_l1_and_l2():
    """Verifies DB query on L1/L2 miss, which populates both L1 and Redis L2."""
    tenant_id = str(uuid.uuid4())
    norm_key = f"{tenant_id}:OFAC_SANCTIONS:acme corp"

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.setex = AsyncMock()

    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value={
        "id": uuid.uuid4(),
        "tenant_id": uuid.UUID(tenant_id),
        "customer_id": None,
        "matched_entity_name": "Acme Corp",
        "matched_rule": "OFAC_SANCTIONS",
        "disposition": "FALSE_POSITIVE",
        "expires_at": None,
    })

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)

    with patch("services.whitelisting.get_async_redis_client", return_value=mock_redis), \
         patch("services.whitelisting.get_async_db_read_conn", return_value=mock_ctx):

        result = await is_entity_whitelisted(
            tenant_id=tenant_id,
            entity_name="Acme Corp",
            rule_name="OFAC_SANCTIONS",
        )

        assert result is True
        assert mock_conn.fetchrow.called
        assert mock_redis.setex.called
        assert norm_key in _LOCAL_WHITELIST_STORE


@pytest.mark.asyncio
async def test_add_to_whitelist_publishes_pubsub_invalidation():
    """Verifies that add_to_whitelist writes to DB, caches locally/Redis, and broadcasts Pub/Sub invalidation."""
    tenant_id = str(uuid.uuid4())
    customer_id = "CUST-999"
    entity_name = "Global Trading Ltd"
    matched_rule = "GEOGRAPHIC_SANCTIONS"

    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)

    mock_redis = AsyncMock()
    mock_redis.setex = AsyncMock()
    mock_redis.publish = AsyncMock()

    with patch("services.whitelisting.get_async_db_conn", return_value=mock_ctx), \
         patch("services.whitelisting.get_async_redis_client", return_value=mock_redis):

        entry = await add_to_whitelist(
            tenant_id=tenant_id,
            matched_entity_name=entity_name,
            matched_rule=matched_rule,
            cleared_by="compliance_officer",
            customer_id=customer_id,
        )

        assert entry["customer_id"] == customer_id
        assert mock_redis.setex.called
        assert mock_redis.publish.called

        pub_args = mock_redis.publish.call_args[0]
        assert pub_args[0] == WHITELIST_PUBSUB_CHANNEL
        pub_payload = json.loads(pub_args[1])
        assert pub_payload["action"] == "SYNC"
        assert pub_payload["tenant_id"] == tenant_id
        assert pub_payload["entry"]["matched_rule"] == matched_rule


@pytest.mark.asyncio
async def test_whitelist_pubsub_listener_eviction():
    """Verifies that the Redis Pub/Sub listener evicts L1 cache upon receiving invalidation."""
    tenant_id = str(uuid.uuid4())
    key1 = f"{tenant_id}:OFAC_SANCTIONS:acme corp"
    key2 = f"{tenant_id}:OFAC_SANCTIONS:cust:cust-123"
    _LOCAL_WHITELIST_STORE[key1] = {"matched_entity_name": "acme corp"}
    _LOCAL_WHITELIST_STORE[key2] = {"customer_id": "cust-123"}

    shutdown_event = asyncio.Event()

    msg = {
        "type": "message",
        "data": json.dumps({
            "action": "INVALIDATE",
            "cache_key": key1,
        })
    }

    mock_pubsub = AsyncMock()
    get_message_call_count = 0

    async def mock_get_message(ignore_subscribe_messages=True, timeout=1.0):
        nonlocal get_message_call_count
        get_message_call_count += 1
        if get_message_call_count == 1:
            return msg
        shutdown_event.set()
        return None

    mock_pubsub.get_message = mock_get_message
    mock_pubsub.subscribe = AsyncMock()

    mock_redis = AsyncMock()
    mock_redis.pubsub = MagicMock(return_value=mock_pubsub)

    with patch("services.whitelisting.get_async_redis_client", return_value=mock_redis):
        listener_task = asyncio.create_task(start_redis_whitelist_listener(shutdown_event))
        await asyncio.wait_for(shutdown_event.wait(), timeout=2.0)
        await listener_task

        # key1 should be evicted from L1 store
        assert key1 not in _LOCAL_WHITELIST_STORE
        # key2 is untouched
        assert key2 in _LOCAL_WHITELIST_STORE
