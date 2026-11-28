"""
Dedicated Async Export, Analytics & Notification Worker (Scale Stage 2)
=======================================================================
Consumes partitioned Redpanda queues (`aml.jobs.exports`, `aml.jobs.notifications`),
executes jobs idempotently via `services.async_jobs.execute_async_job`, retries with
full-jitter backoff, routes poison messages to companion `.dlq` topics, and refuses to
commit offsets when both execution and DLQ publishing fail (zero-loss guarantee).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import KAFKA_BOOTSTRAP_SERVERS, settings
from database.postgres import close_db_pool, init_db_pool
from observability.logging import setup_json_logging
from repositories.jobs_repo import fail_async_job_repo
from services.async_jobs import (
    JOBS_EXPORTS_TOPIC,
    JOBS_NOTIFICATIONS_TOPIC,
    execute_async_job,
    resolve_dlq_topic_for_source_topic,
)

logger = logging.getLogger("aml.job_worker")

CONSUMER_GROUP_ID = "aml-job-worker-group"
MAX_RETRY_ATTEMPTS = 3


async def send_job_to_dlq(producer, source_topic: str, payload: dict, error: str) -> bool:
    """Publishes an unrecoverable async job message to its companion `.dlq` topic."""
    dlq_topic = resolve_dlq_topic_for_source_topic(source_topic)
    dlq_payload = {
        "original_payload": payload,
        "error": str(error),
        "failed_at": datetime.now(timezone.utc).isoformat(),
        "source_topic": source_topic,
    }
    try:
        await producer.send_and_wait(
            topic=dlq_topic,
            key=str(payload.get("job_id", "unknown")),
            value=dlq_payload,
        )
        logger.warning(
            "[JOB-DLQ] Sent job %s to %s. Error: %s",
            payload.get("job_id"),
            dlq_topic,
            error,
        )
        return True
    except Exception:
        logger.exception("[JOB-DLQ] Failed to write job %s to DLQ %s", payload.get("job_id"), dlq_topic)
        return False


class MessageOutcome(StrEnum):
    COMMITTED = "COMMITTED"
    DLQ_COMMITTED = "DLQ_COMMITTED"
    BLOCKED = "BLOCKED"


def _decode_job_payload(raw_value: Any) -> tuple[dict | None, str | None]:
    if isinstance(raw_value, dict):
        return raw_value, None
    try:
        text = raw_value.decode("utf-8") if isinstance(raw_value, (bytes, bytearray)) else str(raw_value)
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            return None, f"Expected JSON object payload, got {type(parsed).__name__}"
        return parsed, None
    except Exception as exc:
        return None, f"Malformed JSON poison-pill payload: {type(exc).__name__}: {exc}"


async def process_job_message_with_outcome(msg, tp, dlq_producer, consumer) -> MessageOutcome:
    """
    Executes one Kafka job message with safe per-message JSON decode, bounded retries,
    DLQ fallback, and manual offset commit. Returns 3-state `MessageOutcome` so the
    partition loop seeks and breaks on `BLOCKED` (true zero-loss guarantee).
    """
    source_topic = getattr(tp, "topic", JOBS_EXPORTS_TOPIC)
    payload, decode_err = _decode_job_payload(msg.value)
    if decode_err or payload is None:
        raw_repr = (
            msg.value.decode("utf-8", errors="replace")[:1000]
            if isinstance(msg.value, (bytes, bytearray))
            else str(msg.value)[:1000]
        )
        logger.error("[JOB POISON PILL] offset=%s on %s: %s; routing to DLQ.", msg.offset, tp, decode_err)
        dlq_ok = await send_job_to_dlq(
            dlq_producer, source_topic, {"job_id": "poison_pill", "raw_payload": raw_repr}, decode_err or "Malformed payload"
        )
        if not dlq_ok:
            return MessageOutcome.BLOCKED
        await consumer.commit({tp: msg.offset + 1})
        return MessageOutcome.DLQ_COMMITTED

    job_id = payload.get("job_id", "unknown")
    tenant_id = payload.get("tenant_id")
    last_error = "Unknown async job error"

    for attempt in range(1, MAX_RETRY_ATTEMPTS + 1):
        try:
            await execute_async_job(payload)
            await consumer.commit({tp: msg.offset + 1})
            return MessageOutcome.COMMITTED
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "[JOB RETRY %d/%d] job=%s failed: %s",
                attempt,
                MAX_RETRY_ATTEMPTS,
                job_id,
                last_error,
            )
            if attempt < MAX_RETRY_ATTEMPTS:
                from services.http_client import full_jitter_backoff

                await asyncio.sleep(full_jitter_backoff(0.5, attempt - 1, cap=10.0))

    logger.error("[JOB PERMANENT FAILURE] job=%s after %d attempts; routing to DLQ.", job_id, MAX_RETRY_ATTEMPTS)
    dlq_ok = await send_job_to_dlq(dlq_producer, source_topic, payload, last_error)
    if not dlq_ok:
        logger.critical(
            "[ZERO-LOSS GUARD] Refusing to commit offset %s on %s for job=%s: both execution and DLQ failed.",
            msg.offset,
            tp,
            job_id,
        )
        return MessageOutcome.BLOCKED

    if tenant_id and job_id != "unknown":
        try:
            await fail_async_job_repo(
                tenant_id=str(tenant_id),
                job_id=uuid.UUID(str(job_id)),
                error_message=last_error,
                dead_lettered=True,
            )
        except Exception:
            logger.warning("Could not update DEAD_LETTERED status for job=%s", job_id)

    await consumer.commit({tp: msg.offset + 1})
    return MessageOutcome.DLQ_COMMITTED


async def process_job_message(msg, tp, dlq_producer, consumer) -> bool:
    """Backward-compatible boolean wrapper returning True iff job executed & committed."""
    outcome = await process_job_message_with_outcome(msg, tp, dlq_producer, consumer)
    return outcome == MessageOutcome.COMMITTED


async def process_job_partition_batch(batch: dict, dlq_producer, consumer) -> dict[str, int]:
    counts = {"committed": 0, "dlq": 0, "blocked": 0}
    for tp, messages in (batch or {}).items():
        for msg in messages:
            outcome = await process_job_message_with_outcome(msg, tp, dlq_producer, consumer)
            if outcome == MessageOutcome.COMMITTED:
                counts["committed"] += 1
            elif outcome == MessageOutcome.DLQ_COMMITTED:
                counts["dlq"] += 1
            else:
                counts["blocked"] += 1
                if hasattr(consumer, "seek"):
                    consumer.seek(tp, msg.offset)
                break
    return counts


async def main() -> None:
    import time as _time

    setup_json_logging(level=logging.INFO)
    logger.info("Starting AML Async Export & Notification Job Worker...")
    from services.compute_executor import shutdown_compute_executors
    from services.http_client import close_http_client
    from services.redpanda import build_kafka_security_kwargs
    from services.vault_loader import VaultSecretsLoader

    await VaultSecretsLoader.bootstrap()
    await init_db_pool()

    heartbeat_path = os.getenv("WORKER_HEARTBEAT_FILE", "/tmp/job_worker.hb")
    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown_event.set)
        except NotImplementedError:
            pass

    consumer = None
    dlq_producer = None
    kafka_sec = build_kafka_security_kwargs()
    try:
        from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

        consumer = AIOKafkaConsumer(
            JOBS_EXPORTS_TOPIC,
            JOBS_NOTIFICATIONS_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            group_id=CONSUMER_GROUP_ID,
            auto_offset_reset="earliest",
            enable_auto_commit=False,
            value_deserializer=None,
            max_poll_interval_ms=300_000,
            request_timeout_ms=10_000,
            **kafka_sec,
        )
        dlq_producer = AIOKafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            acks="all",
            request_timeout_ms=10_000,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if isinstance(k, str) else k,
            **kafka_sec,
        )
        await asyncio.wait_for(consumer.start(), timeout=15.0)
        await asyncio.wait_for(dlq_producer.start(), timeout=15.0)
        logger.info(
            "Connected job worker to topics [%s, %s] at %s",
            JOBS_EXPORTS_TOPIC,
            JOBS_NOTIFICATIONS_TOPIC,
            KAFKA_BOOTSTRAP_SERVERS,
        )

        while not shutdown_event.is_set():
            try:
                with open(heartbeat_path, "w", encoding="utf-8") as hb:
                    hb.write(str(int(_time.time())))
            except Exception:
                pass
            try:
                batch = await asyncio.wait_for(
                    consumer.getmany(timeout_ms=500, max_records=20),
                    timeout=2.0,
                )
            except asyncio.TimeoutError:
                continue
            await process_job_partition_batch(batch or {}, dlq_producer, consumer)
    except Exception as e:
        if getattr(settings, "is_hardened", settings.is_production):
            logger.critical("CRITICAL: Async job worker failed in hardened environment: %s", e)
            raise
        logger.warning("Async job worker Kafka init failed (offline dev mode): %s", e)
    finally:
        if consumer is not None:
            try:
                await consumer.stop()
            except Exception:
                pass
        if dlq_producer is not None:
            try:
                await dlq_producer.stop()
            except Exception:
                pass
        shutdown_compute_executors(wait=False)
        for closer in (close_http_client, close_db_pool, VaultSecretsLoader.shutdown):
            try:
                await closer()
            except Exception:
                pass
        logger.info("AML Async Job Worker stopped cleanly.")


if __name__ == "__main__":
    asyncio.run(main())
