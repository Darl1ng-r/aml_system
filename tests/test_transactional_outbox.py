"""
Test Suite: Transactional Outbox Engine
=======================================
Verifies outbox record creation, traceparent injection, and status transitions.
"""

import asyncio
import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from database.outbox import (
    record_outbox_event,
    fetch_pending_outbox_events,
    mark_outbox_event_published,
    mark_outbox_event_failed,
    OutboxRelayEngine,
)


@pytest.mark.asyncio
async def test_record_outbox_event_captures_context():
    """Verifies that record_outbox_event executes SQL insert with JSON serialized payload."""
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()

    payload = {
        "transaction_id": "tx-12345",
        "amount": 50000.0,
        "currency": "USD",
        "sender": "ACC-01",
        "receiver": "ACC-02",
    }

    event_id = await record_outbox_event(
        conn=mock_conn,
        aggregate_type="TRANSACTION",
        aggregate_id="tx-12345",
        event_type="aml.core.transaction.ingested.v1",
        payload=payload,
        tenant_id="00000000-0000-0000-0000-000000000001",
        headers={"custom_header": "test_val"},
    )

    assert event_id is not None
    assert mock_conn.execute.called
    args = mock_conn.execute.call_args[0]
    sql = args[0]
    assert "INSERT INTO transactional_outbox" in sql
    assert args[3] == "TRANSACTION"
    assert args[4] == "tx-12345"
    assert args[5] == "aml.core.transaction.ingested.v1"
    assert json.loads(args[6])["transaction_id"] == "tx-12345"
    assert json.loads(args[7])["custom_header"] == "test_val"


@pytest.mark.asyncio
async def test_fetch_pending_outbox_events_format():
    """Verifies fetching pending events deserializes JSON correctly."""
    mock_conn = AsyncMock()
    event_uuid = uuid.uuid4()
    mock_rows = [
        {
            "id": event_uuid,
            "tenant_id": uuid.uuid4(),
            "aggregate_type": "TRANSACTION",
            "aggregate_id": "tx-999",
            "event_type": "aml.core.transaction.ingested.v1",
            "payload": '{"amount": 1000.0}',
            "headers": '{"traceparent": "00-test-01"}',
            "retry_count": 0,
        }
    ]
    mock_conn.fetch = AsyncMock(return_value=mock_rows)

    events = await fetch_pending_outbox_events(mock_conn, limit=10)
    assert len(events) == 1
    assert events[0]["id"] == str(event_uuid)
    assert events[0]["payload"]["amount"] == 1000.0
    assert events[0]["headers"]["traceparent"] == "00-test-01"


@pytest.mark.asyncio
async def test_outbox_relay_engine_lifecycle():
    """Verifies that the relay engine starts and cleanly terminates via shutdown event."""
    engine = OutboxRelayEngine(poll_interval_seconds=0.01, batch_size=5)
    shutdown = asyncio.Event()

    with patch("database.postgres.get_db_pool", new_callable=AsyncMock) as mock_pool_fn:
        mock_pool = MagicMock()
        mock_pool_fn.return_value = mock_pool

        # Start relay in background task
        task = asyncio.create_task(engine.run(shutdown_event=shutdown))

        # Allow loop to execute
        await asyncio.sleep(0.05)
        assert engine._running is True

        # Signal shutdown
        shutdown.set()
        await task
        assert engine._running is False


@pytest.mark.asyncio
async def test_mark_outbox_event_failed_triggers_dlq():
    """Verifies that reaching max retries transitions outbox event to FAILED and triggers DLQ alert."""
    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = {
        "retry_count": 5,
        "status": "FAILED"
    }

    event_id = str(uuid.uuid4())
    with patch("database.outbox.logger.critical") as mock_logger_crit:
        await mark_outbox_event_failed(mock_conn, event_id, "Broker connection timeout", max_retries=5)
        assert mock_logger_crit.called
        log_msg = mock_logger_crit.call_args[0][0]
        assert "[OUTBOX-DLQ]" in log_msg
        assert event_id in log_msg

