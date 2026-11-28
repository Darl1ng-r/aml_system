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
    headers_dict = dict(headers) if headers else {}

    # Propagate request Correlation-ID across async worker boundaries (T-06)
    if "correlation_id" not in headers_dict:
        try:
            from observability.middleware import correlation_id_var
            cid = correlation_id_var.get()
            if cid:
                headers_dict["correlation_id"] = cid
        except Exception:
            pass

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


async def fetch_pending_outbox_events(
    conn, limit: int = 50, lease_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Fetches up to `limit` pending outbox events using SKIP LOCKED concurrency protection
    and atomically transitions them to 'PROCESSING' with a lease_id and timestamp inside
    the transaction. This prevents multi-pod relays from picking up the same batch.
    Recovers expired processing leases (> 300 seconds).
    """
    worker_lease = lease_id or str(uuid.uuid4())
    query = """
        WITH selected AS (
            SELECT id
            FROM transactional_outbox
            WHERE (
                status = 'PENDING'
                AND (
                    headers->>'next_retry_at' IS NULL
                    OR (headers->>'next_retry_at')::timestamptz <= NOW()
                )
            )
               OR (status = 'PROCESSING' AND (
                   headers->>'leased_at' IS NULL 
                   OR (headers->>'leased_at')::timestamptz < NOW() - INTERVAL '300 seconds'
               ))
            ORDER BY created_at ASC, id ASC
            LIMIT $1
            FOR UPDATE SKIP LOCKED
        )
        UPDATE transactional_outbox
        SET status = 'PROCESSING',
            headers = jsonb_set(
                jsonb_set(COALESCE(headers, '{}'::jsonb), '{lease_id}', to_jsonb($2::text)),
                '{leased_at}', to_jsonb(NOW()::text)
            )
        WHERE id IN (SELECT id FROM selected)
        RETURNING id, tenant_id, aggregate_type, aggregate_id, 
                  event_type, payload, headers, retry_count;
    """
    rows = await conn.fetch(query, limit, worker_lease)
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
    conn,
    event_id: str,
    error_msg: str,
    max_retries: int = 5,
    base_backoff_seconds: float = 5.0,
) -> None:
    """
    Records an outbox publishing failure with retry counting, full-jitter exponential
    backoff (`next_retry_at` in headers; fixes P2-04), and DLQ routing.
    """
    import random
    jitter_factor = random.uniform(0.25, 1.0)
    query = """
        UPDATE transactional_outbox
        SET retry_count = retry_count + 1,
            last_error = $2,
            status = CASE WHEN retry_count + 1 >= $3 THEN 'FAILED' ELSE 'PENDING' END,
            headers = CASE
                WHEN retry_count + 1 >= $3 THEN COALESCE(headers, '{}'::jsonb)
                ELSE jsonb_set(
                    COALESCE(headers, '{}'::jsonb),
                    '{next_retry_at}',
                    to_jsonb(
                        (NOW() + make_interval(secs => ($4::double precision * POWER(2, LEAST(retry_count, 8)) * $5::double precision)))::text
                    )
                )
            END
        WHERE id = $1::uuid
        RETURNING retry_count, status;
    """
    row = await conn.fetchrow(
        query,
        event_id,
        error_msg,
        max_retries,
        float(base_backoff_seconds),
        float(jitter_factor),
    )
    if row and row["status"] == "FAILED":
        logger.critical(
            f"[OUTBOX-DLQ] Outbox event {event_id} marked as FAILED after {row['retry_count']} retries. "
            f"Dead-letter condition triggered: {error_msg}"
        )


async def prune_published_outbox_events(
    conn, retention_hours: int = 24, batch_size: int = 1000
) -> int:
    """
    Safely prunes historical outbox records that have already been confirmed PUBLISHED
    older than `retention_hours`. Uses chunked deletion to avoid table-level locks.
    """
    query = """
        WITH deleted_batch AS (
            SELECT id FROM transactional_outbox
            WHERE status = 'PUBLISHED'
              AND published_at < NOW() - ($1 || ' hours')::interval
            LIMIT $2
        )
        DELETE FROM transactional_outbox
        WHERE id IN (SELECT id FROM deleted_batch)
        RETURNING id;
    """
    rows = await conn.fetch(query, str(retention_hours), batch_size)
    pruned_count = len(rows)
    if pruned_count > 0:
        logger.info(
            f"[OUTBOX-PRUNER] Purged {pruned_count} published events older than {retention_hours}h."
        )
    return pruned_count


class OutboxRelayEngine:
    """
    Background worker that continuously processes unpublished events from
    PostgreSQL outbox and streams them to Kafka / Redpanda.
    Decouples database locks from network I/O to prevent connection pool starvation.
    """

    def __init__(
        self,
        poll_interval_seconds: float = 1.0,
        batch_size: int = 50,
        retention_hours: int = 24,
        prune_interval_seconds: float = 300.0,
    ):
        self.poll_interval = poll_interval_seconds
        self.batch_size = batch_size
        self.retention_hours = retention_hours
        self.prune_interval = prune_interval_seconds
        self.worker_id = f"relay_{uuid.uuid4().hex[:8]}"
        self._running = False
        self._last_prune_time = 0.0

    async def _wait_for_next_poll(self, shutdown_event: Optional[asyncio.Event]) -> bool:
        if not shutdown_event:
            await asyncio.sleep(self.poll_interval)
            return False
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=self.poll_interval)
            return True
        except asyncio.TimeoutError:
            return False

    async def _fetch_pending_batch(self, pool: Any) -> list[dict]:
        async with pool.acquire(timeout=5.0) as conn, conn.transaction():
            return await fetch_pending_outbox_events(
                conn, limit=self.batch_size, lease_id=self.worker_id
            )

    @staticmethod
    async def _publish_single_event(event: dict) -> tuple[str, bool, str | None]:
        from services.redpanda import publish_transaction_async
        event_id = event["id"]
        try:
            # P0-2: Route core-banking outbound webhook outbox rows to signed HTTP dispatcher
            if event.get("aggregate_type") == "WEBHOOK_DISPATCH":
                from services.webhooks import dispatch_webhook_outbox_event
                ok, err = await dispatch_webhook_outbox_event(event)
                return event_id, ok, err

            # P3 / V-03: Route durable SIEM compliance outbox rows to signed HTTPS forwarder
            if event.get("aggregate_type") == "SIEM_DISPATCH":
                from services.siem_forwarder import dispatch_siem_outbox_event
                ok, err = await dispatch_siem_outbox_event(event)
                return event_id, ok, err

            # Storage Pillar: Crash-safe post-commit Cache Redis invalidation
            if event.get("aggregate_type") == "CACHE_INVALIDATION":
                from services.cache_aside import dispatch_cache_invalidation_outbox_event
                ok, err = await dispatch_cache_invalidation_outbox_event(event)
                return event_id, ok, err

            payload = event["payload"]
            # Partition by sender account when present (eliminates single-tenant hot partitions),
            # falling back to tenant_id then aggregate_id for non-account domain events
            partition_key = (
                payload.get("sender_account_id")
                or payload.get("sender_id")
                or payload.get("sender_account")
                or event.get("tenant_id")
                or payload.get("tenant_id")
                or event.get("aggregate_id")
            )
            headers = event.get("headers") or {}
            topic = headers.get("topic")
            if not topic and event.get("aggregate_type") == "ASYNC_JOB_DISPATCH":
                from services.async_jobs import resolve_topic_for_job_type

                topic = resolve_topic_for_job_type(payload.get("job_type", ""))
            if not topic and event.get("event_type") == "aml.core.transaction.buffered.v1":
                topic = "aml.transactions.raw"

            # Propagate W3C traceparent and Correlation-ID into payload envelope if present in outbox headers
            if isinstance(payload, dict):
                enriched = None
                if headers.get("traceparent") and "_traceparent" not in payload:
                    enriched = {**(enriched or payload), "_traceparent": headers["traceparent"]}
                if headers.get("correlation_id") and "_correlation_id" not in payload:
                    enriched = {**(enriched or payload), "_correlation_id": headers["correlation_id"]}
                if enriched is not None:
                    payload = enriched

            pub_kwargs: dict[str, Any] = {
                "key": str(partition_key) if partition_key else None,
                "topic": topic,
            }
            if headers.get("correlation_id"):
                pub_kwargs["correlation_id"] = headers["correlation_id"]

            success = await publish_transaction_async(payload, **pub_kwargs)
            if success:
                return event_id, True, None
            return event_id, False, "Broker publish returned False"
        except Exception as pub_exc:
            logger.exception("Error publishing outbox event %s", event_id)
            return event_id, False, str(pub_exc)

    async def _persist_event_statuses(
        self,
        pool: Any,
        published_ids: list[str],
        failed_records: list[tuple[str, str]],
    ) -> None:
        async with pool.acquire(timeout=5.0) as conn, conn.transaction():
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

    async def _dispatch_events_batch(self, pool: Any, events: list[dict]) -> int:
        """
        P1-16: Bounded concurrent dispatch (Semaphore(10)) with 15s per-event timeout
        so a 100-event batch completes in <= 150s (strictly below the 300s lease expiry),
        preventing Head-of-Line blocking and sibling-pod duplicate delivery.
        """
        sem = asyncio.Semaphore(10)

        async def _guarded_dispatch(ev: dict) -> tuple[str, bool, str | None]:
            eid = ev["id"]
            async with sem:
                try:
                    return await asyncio.wait_for(self._publish_single_event(ev), timeout=15.0)
                except asyncio.TimeoutError:
                    logger.warning("Outbox event %s dispatch timed out after 15s", eid)
                    return eid, False, "Event dispatch timed out after 15s"

        results = await asyncio.gather(*(_guarded_dispatch(ev) for ev in events))
        published_ids: list[str] = []
        failed_records: list[tuple[str, str]] = []
        for eid, ok, err in results:
            if ok:
                published_ids.append(eid)
            else:
                failed_records.append((eid, err or "Unknown publish failure"))

        await self._persist_event_statuses(pool, published_ids, failed_records)
        return len(published_ids)

    async def _maybe_prune_retention(self, pool: Any) -> None:
        loop_time = asyncio.get_running_loop().time()
        if loop_time - self._last_prune_time >= self.prune_interval:
            self._last_prune_time = loop_time
            try:
                async with pool.acquire(timeout=5.0) as conn:
                    await prune_published_outbox_events(
                        conn, retention_hours=self.retention_hours
                    )
            except Exception as prune_exc:
                logger.warning("Error during periodic outbox pruning: %s", prune_exc)

    async def _execute_relay_cycle(self, pool: Any) -> int:
        try:
            events = await self._fetch_pending_batch(pool)
            try:
                from observability.prometheus import set_outbox_pending_events
                set_outbox_pending_events(len(events))
            except Exception:
                pass
            if events:
                processed_count = await self._dispatch_events_batch(pool, events)
            else:
                processed_count = 0
            await self._maybe_prune_retention(pool)
            return processed_count
        except Exception:
            logger.exception("Outbox relay loop encountered error")
            return 0

    async def run(self, shutdown_event: Optional[asyncio.Event] = None):
        self._running = True
        logger.info(f"Starting Transactional Outbox Relay Engine ({self.worker_id})...")
        from database.postgres import get_db_pool

        try:
            while self._running:
                if shutdown_event and shutdown_event.is_set():
                    logger.info("Outbox Relay Engine received shutdown signal.")
                    break

                pool = await get_db_pool()
                if not pool:
                    if await self._wait_for_next_poll(shutdown_event):
                        break
                    continue

                processed_count = await self._execute_relay_cycle(pool)

                if processed_count < self.batch_size:
                    if await self._wait_for_next_poll(shutdown_event):
                        break
        except asyncio.CancelledError:
            self._running = False
            logger.info("Transactional Outbox Relay Engine task cancelled.")
            raise
        finally:
            self._running = False
            logger.info("Transactional Outbox Relay Engine stopped.")

    def stop(self):
        self._running = False
