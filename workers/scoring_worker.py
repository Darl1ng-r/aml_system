"""
Asynchronous AML Transaction Compliance Scoring Worker
======================================================
Pure messaging/transport worker consuming buffered transaction events from
Redpanda/Kafka (`aml.transactions.raw`). Delegates ALL compliance evaluation,
exact Decimal FX normalization, AML rules, offloaded ML/dynamic RBA scoring,
BSA CTR & cash structuring detection, shadow rules, graph taint, row-locked
ACID persistence, WORM audit logging, and canonical outbox publishing to the
single authoritative `services.transaction_ingestion.TransactionIngestionService`
— guaranteeing 100% parity between synchronous HTTP and asynchronous Kafka paths.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

# Ensure repository root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import KAFKA_BOOTSTRAP_SERVERS, TRANSACTIONS_TOPIC, settings
from database.postgres import close_db_pool, get_async_db_conn, init_db_pool
from domain.money import to_decimal
from observability.logging import setup_json_logging
from repositories.transaction_repo import ConcurrentAccountBlockError, DuplicateTransactionIdempotencyError
from services.behavioral import calculate_customer_baseline, get_customer_baseline
from services.dynamic_scorer import compute_dynamic_risk
from services.fx_rates import convert_to_base_currency_exact
from services.isolation_forest import get_iforest_score
from services.ml_model import anomaly_model
from services.rules import RulesEngine
from services.transaction_ingestion import (
    AccountNotFoundError,
    AccountStatusBlockedError,
    IngestionDependencies,
    TransactionIngestionService,
    _ensure_utc,
)

logger = logging.getLogger("aml.scoring_worker")

RAW_TRANSACTIONS_TOPIC = "aml.transactions.raw"
RAW_DLQ_TOPIC = "aml.transactions.raw.dlq"
CONSUMER_GROUP_ID = "aml-scoring-worker-group"
MAX_RETRY_ATTEMPTS = 3

# Prevent premature garbage collection of background tasks
_background_tasks: set[asyncio.Task] = set()


async def score_transaction(event: dict) -> dict[str, Any]:
    """
    Processes a single raw transaction event through the unified `TransactionIngestionService`
    with full sync/async compliance parity (including CTR/structuring, shadow rules, taint,
    deterministic FOR UPDATE row locking, and SR 11-7 provenance).
    """
    tx_id = event["transaction_id"]
    tenant_id = event["tenant_id"]
    sender_ref = (
        event.get("sender_account_id")
        or event.get("sender_id")
        or event.get("sender_account")
    )
    receiver_ref = (
        event.get("receiver_account_id")
        or event.get("receiver_id")
        or event.get("receiver_account")
    )
    if not sender_ref or not receiver_ref:
        raise ValueError(f"Scoring event {tx_id} missing sender/receiver account identifiers.")

    evaluated_at = datetime.now(timezone.utc)
    amount_orig = to_decimal(event["amount"], allow_negative=False, field_name="amount")
    currency = str(event.get("currency") or "USD").upper()
    tx_dt = _ensure_utc(event.get("timestamp"), evaluated_at)

    logger.info("Processing async transaction scoring for tx=%s tenant=%s", tx_id, tenant_id)

    deps = IngestionDependencies(
        read_conn_factory=get_async_db_conn,
        write_conn_factory=get_async_db_conn,
        rules_evaluate_fn=RulesEngine.evaluate_transaction,
        ml_predict_dict_fn=anomaly_model.predict,
        baseline_loader=get_customer_baseline,
        iforest_scorer=get_iforest_score,
        dynamic_scorer=compute_dynamic_risk,
    )

    try:
        acct = await TransactionIngestionService.resolve_and_validate_accounts(
            sender_ref=str(sender_ref),
            receiver_ref=str(receiver_ref),
            tenant_id=str(tenant_id),
            evaluated_at=evaluated_at,
            deps=deps,
            allow_fallback_event_ctx=event,
        )
    except (AccountNotFoundError, AccountStatusBlockedError) as exc:
        raise ValueError(str(exc)) from exc

    is_geo_override = int(event["is_geo_risk"]) if event.get("is_geo_risk") is not None else None

    scoring = await TransactionIngestionService.compute_risk_and_decision(
        amount_original=amount_orig,
        currency=currency,
        tx_timestamp=tx_dt,
        evaluated_at=evaluated_at,
        country=event.get("country"),
        merchant=event.get("merchant"),
        channel=event.get("channel"),
        acct=acct,
        tenant_id=str(tenant_id),
        deps=deps,
        is_geo_override=is_geo_override,
    )

    outbox_headers: dict[str, str] = {"topic": TRANSACTIONS_TOPIC}
    if event.get("_correlation_id"):
        outbox_headers["correlation_id"] = str(event["_correlation_id"])
    if event.get("_traceparent"):
        outbox_headers["traceparent"] = str(event["_traceparent"])

    actor = {
        "id": str(event.get("ingested_by") or "scoring_worker"),
        "username": str(event.get("ingested_by") or "scoring_worker"),
        "role": "SYSTEM",
    }

    try:
        _, ctr_decision = await TransactionIngestionService.persist_decision(
            tenant_id=str(tenant_id),
            tx_id=tx_id,
            acct=acct,
            amount_original=amount_orig,
            currency=currency,
            tx_timestamp=tx_dt,
            country=event.get("country"),
            merchant=event.get("merchant"),
            device=event.get("device"),
            channel=event.get("channel"),
            scoring=scoring,
            actor=actor,
            deps=deps,
            idempotency_key=event.get("idempotency_key"),
            upsert_on_id=True,
            outbox_headers=outbox_headers,
            ingestion_mode="ASYNC_BUFFERED",
        )
    except ConcurrentAccountBlockError as exc:
        raise ValueError(str(exc)) from exc
    except DuplicateTransactionIdempotencyError:
        logger.info("Idempotent duplicate skipped during async scoring for tx=%s", tx_id)
        ctr_decision = None

    task = asyncio.create_task(
        calculate_customer_baseline(str(acct["sender_id"]), tenant_id=str(tenant_id))
    )
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    logger.info(
        "Transaction tx=%s evaluated: decision=%s risk=%.3f amount_usd=%.2f ctr=%s",
        tx_id,
        scoring["decision"],
        scoring["dynamic_score"],
        scoring["amount_base_usd"],
        bool(ctr_decision and ctr_decision.requires_ctr_filing),
    )

    return {
        "transaction_id": tx_id,
        "decision": scoring["decision"],
        "status": scoring["tx_status"],
        "dynamic_score": scoring["dynamic_score"],
        "alert_triggered": scoring["alert_triggered"],
        "amount_base_usd": scoring["amount_base_usd"],
        "fx_rate_applied": scoring["fx_rate_applied"],
        "ctr_filing_created": bool(ctr_decision and ctr_decision.requires_ctr_filing),
        "ruleset_hash": scoring["ruleset_hash"],
        "model_version": scoring["model_version"],
        "evaluated_at": scoring["evaluated_at"].isoformat(),
    }


async def send_raw_to_dlq(producer, payload: dict, error: str) -> bool:
    """Publishes an unrecoverable raw transaction message to `aml.transactions.raw.dlq`."""
    dlq_payload = {
        "original_payload": payload,
        "error": str(error),
        "failed_at": datetime.now(timezone.utc).isoformat(),
        "source_topic": RAW_TRANSACTIONS_TOPIC,
    }
    try:
        await producer.send_and_wait(
            topic=RAW_DLQ_TOPIC,
            key=str(payload.get("transaction_id", "unknown")),
            value=dlq_payload,
        )
        logger.warning(
            "[SCORING-DLQ] Sent tx %s to %s. Error: %s",
            payload.get("transaction_id"),
            RAW_DLQ_TOPIC,
            error,
        )
        return True
    except Exception:
        logger.exception("[SCORING-DLQ] Failed to write tx %s to DLQ", payload.get("transaction_id"))
        return False


class MessageOutcome(StrEnum):
    COMMITTED = "COMMITTED"
    DLQ_COMMITTED = "DLQ_COMMITTED"
    BLOCKED = "BLOCKED"


def _decode_kafka_payload(raw_value: Any) -> tuple[dict | None, str | None]:
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


async def process_raw_message_with_outcome(msg, tp, dlq_producer, consumer) -> MessageOutcome:
    """
    Scores one Kafka message with per-message poison-pill decoding, bounded retries,
    DLQ fallback, and manual offset commit. Returns 3-state `MessageOutcome` so the
    partition loop can `seek(tp, msg.offset)` and `break` on `BLOCKED` (true zero-loss).
    """
    payload, decode_err = _decode_kafka_payload(msg.value)
    if decode_err or payload is None:
        raw_repr = (
            msg.value.decode("utf-8", errors="replace")[:1000]
            if isinstance(msg.value, (bytes, bytearray))
            else str(msg.value)[:1000]
        )
        logger.error("[SCORING POISON PILL] offset=%s on %s: %s; routing to DLQ.", msg.offset, tp, decode_err)
        dlq_ok = await send_raw_to_dlq(
            dlq_producer,
            {"transaction_id": "poison_pill", "raw_payload": raw_repr},
            decode_err or "Malformed payload",
        )
        if not dlq_ok:
            logger.critical("[ZERO-LOSS GUARD] Refusing to commit poison-pill offset %s on %s: DLQ failed.", msg.offset, tp)
            return MessageOutcome.BLOCKED
        await consumer.commit({tp: msg.offset + 1})
        return MessageOutcome.DLQ_COMMITTED

    tx_id = payload.get("transaction_id", "unknown")
    last_error = "Unknown scoring error"

    for attempt in range(1, MAX_RETRY_ATTEMPTS + 1):
        try:
            await score_transaction(payload)
            await consumer.commit({tp: msg.offset + 1})
            return MessageOutcome.COMMITTED
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "[SCORING RETRY %d/%d] tx=%s failed: %s",
                attempt,
                MAX_RETRY_ATTEMPTS,
                tx_id,
                last_error,
            )
            if attempt < MAX_RETRY_ATTEMPTS:
                from services.http_client import full_jitter_backoff

                await asyncio.sleep(full_jitter_backoff(0.5, attempt - 1, cap=10.0))

    logger.error("[SCORING PERMANENT FAILURE] tx=%s after %d attempts; routing to DLQ.", tx_id, MAX_RETRY_ATTEMPTS)
    dlq_ok = await send_raw_to_dlq(dlq_producer, payload, last_error)
    if not dlq_ok:
        logger.critical(
            "[ZERO-LOSS GUARD] Refusing to commit offset %s on %s for tx=%s: both scoring and DLQ failed.",
            msg.offset,
            tp,
            tx_id,
        )
        return MessageOutcome.BLOCKED

    await consumer.commit({tp: msg.offset + 1})
    return MessageOutcome.DLQ_COMMITTED


async def process_raw_message(msg, tp, dlq_producer, consumer) -> bool:
    """Backward-compatible boolean wrapper returning True iff message scored & committed."""
    outcome = await process_raw_message_with_outcome(msg, tp, dlq_producer, consumer)
    return outcome == MessageOutcome.COMMITTED


async def process_partition_batch(batch: dict, dlq_producer, consumer) -> dict[str, int]:
    """
    Processes a Kafka `getmany` batch per partition with strict zero-loss ordering:
    if a message returns `MessageOutcome.BLOCKED` (processing AND DLQ both failed),
    seeks the consumer back to `msg.offset` and breaks out of that partition immediately
    so later messages on the same partition can NEVER commit past the failed offset.
    """
    counts = {"committed": 0, "dlq": 0, "blocked": 0}
    for tp, messages in (batch or {}).items():
        for msg in messages:
            outcome = await process_raw_message_with_outcome(msg, tp, dlq_producer, consumer)
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


async def main():
    import time as _time

    setup_json_logging(level=logging.INFO)
    logger.info("Starting AML Async Transaction Scoring Worker...")
    from services.compute_executor import shutdown_compute_executors
    from services.http_client import close_http_client
    from services.redpanda import build_kafka_security_kwargs
    from services.vault_loader import VaultSecretsLoader

    await VaultSecretsLoader.bootstrap()
    await init_db_pool()

    heartbeat_path = os.getenv("WORKER_HEARTBEAT_FILE", "/tmp/scoring_worker.hb")
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
            RAW_TRANSACTIONS_TOPIC,
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
        logger.info("Connected to Kafka topic %s at %s", RAW_TRANSACTIONS_TOPIC, KAFKA_BOOTSTRAP_SERVERS)

        while not shutdown_event.is_set():
            try:
                with open(heartbeat_path, "w", encoding="utf-8") as hb:
                    hb.write(str(int(_time.time())))
            except Exception:
                pass
            try:
                batch = await asyncio.wait_for(
                    consumer.getmany(timeout_ms=500, max_records=50),
                    timeout=2.0,
                )
            except asyncio.TimeoutError:
                continue
            await process_partition_batch(batch or {}, dlq_producer, consumer)
    except Exception as e:
        if getattr(settings, "is_hardened", settings.is_production):
            logger.critical("CRITICAL: Kafka scoring worker failed in hardened environment: %s", e)
            raise
        logger.warning("Kafka consumer initialization failed (offline dev mode active): %s", e)
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
        logger.info("AML Async Transaction Scoring Worker stopped cleanly.")


if __name__ == "__main__":
    asyncio.run(main())
