"""
Redpanda / Kafka Async Producer
================================
Publishes scored transaction events to the aml.transactions.scored topic
using aiokafka — a pure-Python async Kafka client that speaks the native
Kafka binary protocol. This replaces the REST Proxy approach which required
Redpanda's HTTP proxy to be running separately.

Fallback:  If Redpanda is unreachable, the payload is logged at WARNING
           level so it is at minimum captured in the log stream and can
           be replayed later.
"""

import asyncio
import json
import logging
from typing import Optional

from config import KAFKA_BOOTSTRAP_SERVERS, TRANSACTIONS_TOPIC

logger = logging.getLogger(__name__)


# ── OpenTelemetry trace-context helpers ────────────────────────────────────────
def _inject_trace_headers() -> list[tuple[str, bytes]]:
    """Returns Kafka headers carrying the current W3C traceparent."""
    try:
        from opentelemetry import context as otel_context
        from opentelemetry.propagators import textmap
        from opentelemetry.propagate import inject

        carrier: dict[str, str] = {}
        inject(carrier)
        return [(k, v.encode("utf-8")) for k, v in carrier.items()]
    except Exception:
        return []

# ── Singleton async producer ───────────────────────────────────────────────────
_producer = None
_producer_lock = asyncio.Lock()


async def _get_producer():
    """
    Returns a started AIOKafkaProducer singleton.
    Thread-safe via asyncio.Lock — only one producer is ever created.
    """
    global _producer
    if _producer is not None:
        return _producer

    async with _producer_lock:
        if _producer is not None:  # double-check after acquiring lock
            return _producer
        try:
            from aiokafka import AIOKafkaProducer
            p = AIOKafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if isinstance(k, str) else k,
                # Reliability settings
                acks="all",            # wait for all in-sync replicas to confirm
                retries=3,
                retry_backoff_ms=500,
                request_timeout_ms=10_000,
                compression_type="snappy",   # reduce wire size for high-volume topics
            )
            await p.start()
            _producer = p
            logger.info(f"AIOKafka producer connected to {KAFKA_BOOTSTRAP_SERVERS}")
        except Exception as e:
            logger.error(f"Failed to start Kafka producer: {e}")
            _producer = None
    return _producer


async def publish_transaction_async(transaction_payload: dict) -> bool:
    """
    Async version: publishes a scored transaction to Redpanda.
    Returns True on success, False on failure.
    """
    producer = await _get_producer()
    if producer is None:
        logger.warning(
            f"[REDPANDA OFFLINE] Falling back to log-only for tx "
            f"{transaction_payload.get('transaction_id')}: {json.dumps(transaction_payload)}"
        )
        return False

    try:
        headers = _inject_trace_headers()
        await producer.send_and_wait(
            topic=TRANSACTIONS_TOPIC,
            key=transaction_payload.get("transaction_id", ""),
            value=transaction_payload,
            headers=headers,
        )
        logger.info(
            f"Published tx {transaction_payload.get('transaction_id')} "
            f"→ {TRANSACTIONS_TOPIC}"
        )
        return True
    except Exception as e:
        logger.error(
            f"Failed to publish tx {transaction_payload.get('transaction_id')}: {e}. "
            f"Payload: {json.dumps(transaction_payload)}"
        )
        return False


def publish_transaction(transaction_payload: dict):
    """
    Sync wrapper — called by FastAPI BackgroundTasks (which run in the event loop).
    Creates a coroutine and schedules it onto the running loop.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(publish_transaction_async(transaction_payload))
        else:
            loop.run_until_complete(publish_transaction_async(transaction_payload))
    except Exception as e:
        logger.error(f"publish_transaction wrapper error: {e}")
        logger.warning(
            f"[LOG ONLY - REDPANDA OFFLINE] Message: {json.dumps(transaction_payload)}"
        )


async def close_producer():
    """Called on app shutdown to flush in-flight messages."""
    global _producer
    if _producer is not None:
        try:
            await _producer.stop()
            logger.info("Kafka producer stopped cleanly.")
        except Exception as e:
            logger.warning(f"Error stopping Kafka producer: {e}")
        finally:
            _producer = None


def flush_producer():
    """Sync flush — kept for backward compatibility."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(close_producer())
        else:
            loop.run_until_complete(close_producer())
    except Exception:
        pass
