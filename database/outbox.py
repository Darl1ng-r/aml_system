"""
Transactional Outbox Engine
============================
Guarantees atomic, zero-loss publishing of domain events from PostgreSQL to Kafka/Redpanda
without requiring 2-Phase Commit (2PC).

Domain services record events inside the same database transaction as the primary state change.
A background relay engine processes unpublished records using `SELECT FOR UPDATE SKIP LOCKED`
and marks them as PUBLISHED once confirmed by the broker.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


async def record_outbox_event(
    conn,
    aggregate_type: str,
    aggregate_id: str,
    event_type: str,
    payload: Dict[str, Any],
    tenant_id: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
) -> str:
    """
    Atomically records an event into the transactional outbox.
    Must be called with an active transaction connection `conn`.
    """
    event_id = str(uuid.uuid4())
    headers_dict = headers or {}

    # Automatically capture OpenTelemetry traceparent if not explicitly supplied
    if "traceparent" not in headers_dict:
        try:
            from opentelemetry import trace
            span = trace.get_current_span()
            ctx = span.get_span_context()
            if ctx.is_valid:
                traceparent = f"00-{ctx.trace_id:032x}-{ctx.span_id:016x}-{ctx.trace_flags:02x}"
                headers_dict["traceparent"] = traceparent
        except Exception:
            pass

    # Normalize tenant_id if provided
    tid_param = tenant_id if tenant_id else None

    query = """
        INSERT INTO transactional_outbox (
            id, tenant_id, aggregate_type, aggregate_id, 
            event_type, payload, headers, status, created_at
        ) VALUES (
            $1::uuid, $2::uuid, $3, $4, $5, $6::jsonb, $7::jsonb, 'PENDING', NOW()
        )
        RETURNING id;
    """

    await conn.execute(
        query,
        event_id,
        tid_param,
        aggregate_type,
        aggregate_id,
        event_type,
        json.dumps(payload),
        json.dumps(headers_dict),
    )

    logger.debug(
        f"Recorded outbox event {event_id} ({event_type}) for {aggregate_type}:{aggregate_id}"
    )
    return event_id


async def fetch_pending_outbox_events(conn, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Fetches up to `limit` pending outbox events using SKIP LOCKED concurrency protection.
    """
    query = """
        SELECT id, tenant_id, aggregate_type, aggregate_id, 
               event_type, payload, headers, retry_count
        FROM transactional_outbox
        WHERE status = 'PENDING'
        ORDER BY created_at ASC
        LIMIT $1
        FOR UPDATE SKIP LOCKED;
    """
    rows = await conn.fetch(query, limit)
    results = []
    for r in rows:
        results.append({
            "id": str(r["id"]),
            "tenant_id": str(r["tenant_id"]) if r["tenant_id"] else None,
            "aggregate_type": r["aggregate_type"],
            "aggregate_id": r["aggregate_id"],
            "event_type": r["event_type"],
            "payload": json.loads(r["payload"]) if isinstance(r["payload"], str) else r["payload"],
            "headers": json.loads(r["headers"]) if isinstance(r["headers"], str) else r["headers"],
            "retry_count": r["retry_count"],
        })
    return results


async def mark_outbox_event_published(conn, event_id: str) -> None:
    """Marks an outbox event as successfully published."""
    query = """
        UPDATE transactional_outbox
        SET status = 'PUBLISHED', published_at = NOW()
        WHERE id = $1::uuid;
    """
    await conn.execute(query, event_id)


async def mark_outbox_event_failed(
    conn, event_id: str, error_msg: str, max_retries: int = 5
) -> None:
    """Records an outbox publishing failure with retry counting and DLQ routing."""
    query = """
        UPDATE transactional_outbox
        SET retry_count = retry_count + 1,
            last_error = $2,
            status = CASE WHEN retry_count + 1 >= $3 THEN 'FAILED' ELSE 'PENDING' END
        WHERE id = $1::uuid
        RETURNING retry_count, status;
    """
    row = await conn.fetchrow(query, event_id, error_msg, max_retries)
    if row and row["status"] == "FAILED":
        logger.critical(
            f"[OUTBOX-DLQ] Outbox event {event_id} marked as FAILED after {row['retry_count']} retries. "
            f"Dead-letter condition triggered: {error_msg}"
        )


class OutboxRelayEngine:
    """
    Background worker that continuously processes unpublished events from
    PostgreSQL outbox and streams them to Kafka / Redpanda.
    Decouples database locks from network I/O to prevent connection pool starvation.
    """

    def __init__(self, poll_interval_seconds: float = 1.0, batch_size: int = 50):
        self.poll_interval = poll_interval_seconds
        self.batch_size = batch_size
        self._running = False

    async def run(self, shutdown_event: Optional[asyncio.Event] = None):
        self._running = True
        logger.info("Starting Transactional Outbox Relay Engine...")

        from database.postgres import get_db_pool

        while self._running:
            if shutdown_event and shutdown_event.is_set():
                logger.info("Outbox Relay Engine received shutdown signal.")
                break

            processed_count = 0
            try:
                pool = await get_db_pool()
                if not pool:
                    await asyncio.sleep(self.poll_interval)
                    continue

                # 1. Fetch pending batch inside a brief, isolated read transaction
                events = []
                async with pool.acquire() as conn:
                    async with conn.transaction():
                        events = await fetch_pending_outbox_events(conn, limit=self.batch_size)

                # 2. Publish to Kafka outside of any database transaction (Zero DB Lock Contention)
                if events:
                    from services.redpanda import publish_transaction_async
                    published_ids = []
                    failed_records = []

                    for event in events:
                        try:
                            success = await publish_transaction_async(event["payload"])
                            if success:
                                published_ids.append(event["id"])
                                processed_count += 1
                            else:
                                failed_records.append((event["id"], "Broker publish returned False"))
                        except Exception as pub_exc:
                            logger.error(f"Error publishing outbox event {event['id']}: {pub_exc}")
                            failed_records.append((event["id"], str(pub_exc)))

                    # 3. Batch update statuses in a single swift transaction
                    async with pool.acquire() as conn:
                        async with conn.transaction():
                            if published_ids:
                                await conn.execute(
                                    """
                                    UPDATE transactional_outbox
                                    SET status = 'PUBLISHED', published_at = NOW()
                                    WHERE id = ANY($1::uuid[]);
                                    """,
                                    published_ids,
                                )
                            for eid, err in failed_records:
                                await mark_outbox_event_failed(conn, eid, err)

            except Exception as loop_exc:
                logger.error(f"Outbox relay loop encounter error: {loop_exc}")

            # If we processed a full batch, check immediately again; otherwise sleep
            if processed_count < self.batch_size:
                try:
                    await asyncio.sleep(self.poll_interval)
                except asyncio.CancelledError:
                    break

        self._running = False
        logger.info("Transactional Outbox Relay Engine stopped.")

    def stop(self):
        self._running = False
