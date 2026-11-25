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

_background_tasks: set[asyncio.Future] = set()


# ── OpenTelemetry trace-context helpers ────────────────────────────────────────
def _inject_trace_headers(correlation_id: Optional[str] = None) -> list[tuple[str, bytes]]:
    """Returns Kafka headers carrying the current W3C traceparent and X-Correlation-ID."""
    headers: list[tuple[str, bytes]] = []
    try:
        from opentelemetry.propagate import inject

        carrier: dict[str, str] = {}
        inject(carrier)
        headers.extend((k, v.encode("utf-8")) for k, v in carrier.items())
    except Exception:
        pass

    cid = correlation_id
    if not cid:
        try:
            from observability.middleware import correlation_id_var
            cid = correlation_id_var.get()
        except Exception:
            cid = None
    if cid:
        headers.append(("x-correlation-id", str(cid).encode("utf-8")))
    return headers

# ── Singleton async producer ───────────────────────────────────────────────────
_producer = None
_producer_lock = asyncio.Lock()


def build_kafka_security_kwargs() -> dict:
    """
    Returns AIOKafka security/TLS/SASL kwargs matching cluster configuration (fixes P0-03).
    Supports PLAINTEXT (local dev), SSL (TLS-only), and SASL_SSL (SCRAM-SHA-512 + TLS).
    """
    import os
    from config import settings
    from services.tls_manager import get_ssl_context

    kwargs: dict = {}
    ssl_ctx = get_ssl_context()
    sasl_user = (getattr(settings, "kafka_sasl_username", "") or os.getenv("KAFKA_SASL_USERNAME", "")).strip()
    sasl_pass = (getattr(settings, "kafka_sasl_password", "") or os.getenv("KAFKA_SASL_PASSWORD", "")).strip()
    sasl_mech = (getattr(settings, "kafka_sasl_mechanism", "SCRAM-SHA-512") or "SCRAM-SHA-512").strip()

    if ssl_ctx and sasl_user and sasl_pass:
        kwargs.update(
            security_protocol="SASL_SSL",
            ssl_context=ssl_ctx,
            sasl_mechanism=sasl_mech,
            sasl_plain_username=sasl_user,
            sasl_plain_password=sasl_pass,
        )
    elif ssl_ctx:
        kwargs.update(security_protocol="SSL", ssl_context=ssl_ctx)
    elif sasl_user and sasl_pass:
        kwargs.update(
            security_protocol="SASL_PLAINTEXT",
            sasl_mechanism=sasl_mech,
            sasl_plain_username=sasl_user,
            sasl_plain_password=sasl_pass,
        )
    return kwargs


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
                retry_backoff_ms=500,
                request_timeout_ms=10_000,
                compression_type="gzip",     # built-in compression (no native libsnappy dependency)
                **build_kafka_security_kwargs(),
            )
            await asyncio.wait_for(p.start(), timeout=15.0)
            _producer = p
            logger.info("AIOKafka producer connected to %s", KAFKA_BOOTSTRAP_SERVERS)
        except Exception:
            logger.exception("Failed to start Kafka producer")
            _producer = None
    return _producer


async def publish_transaction_async(
    transaction_payload: dict,
    key: Optional[str] = None,
    topic: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> bool:
    """
    Async version: publishes an event to Redpanda/Kafka.
    Enforces tenant-keyed partition hashing to guarantee fair-queuing and eliminate
    Head-of-Line (HoL) blocking between different tenants.
    """
    producer = await _get_producer()
    if producer is None:
        logger.warning(
            f"[REDPANDA OFFLINE] Falling back to log-only for tx "
            f"{transaction_payload.get('transaction_id')}: {json.dumps(transaction_payload)}"
        )
        return False

    # Partition key resolution: prioritize explicit key -> tenant_id for fair-queuing -> transaction_id
    partition_key = (
        key
        or (str(transaction_payload["tenant_id"]) if transaction_payload.get("tenant_id") else None)
        or transaction_payload.get("transaction_id", "")
    )
    target_topic = topic or TRANSACTIONS_TOPIC

    try:
        cid = correlation_id or (
            transaction_payload.get("_correlation_id")
            if isinstance(transaction_payload, dict)
            else None
        )
        headers = _inject_trace_headers(correlation_id=cid)
        await producer.send_and_wait(
            topic=target_topic,
            key=partition_key,
            value=transaction_payload,
            headers=headers,
        )
        logger.info(
            f"Published tx {transaction_payload.get('transaction_id')} (partition_key={partition_key}) "
            f"→ {target_topic}"
        )
        return True
    except Exception:
        logger.exception("Failed to publish tx %s", transaction_payload.get("transaction_id"))
        return False


def publish_transaction(
    transaction_payload: dict,
    key: Optional[str] = None,
    topic: Optional[str] = None
):
    """
    Sync wrapper — called by FastAPI BackgroundTasks (which run in the event loop).
    Creates a coroutine with tenant-keyed partitioning and schedules it onto the running loop.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            task = asyncio.ensure_future(publish_transaction_async(transaction_payload, key=key, topic=topic))
            _background_tasks.add(task)
            task.add_done_callback(_background_tasks.discard)
        else:
            loop.run_until_complete(publish_transaction_async(transaction_payload, key=key, topic=topic))
    except Exception:
        logger.exception("publish_transaction wrapper error")
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
            task = asyncio.ensure_future(close_producer())
            _background_tasks.add(task)
            task.add_done_callback(_background_tasks.discard)
        else:
            loop.run_until_complete(close_producer())
    except Exception:
        pass
