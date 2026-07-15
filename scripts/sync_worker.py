"""
AML Graph Sync Worker — Redpanda (Kafka) Consumer
===================================================
Consumes scored transaction events from the aml.transactions.scored topic
and writes Account nodes + TRANSFERS_TO edges into Neo4j in real-time.

Architecture:
  FastAPI (producer) ──► Redpanda topic ──► This worker (consumer) ──► Neo4j

Reliability guarantees:
  - Consumer group: aml-graph-sync-group (auto-rebalances on replica scale-out)
  - Manual offset commit AFTER Neo4j write succeeds (at-least-once delivery)
  - Failed messages retried up to MAX_RETRY_ATTEMPTS with exponential backoff
  - After MAX_RETRY_ATTEMPTS, payload written to a Dead Letter Queue (DLQ)
    topic: aml.transactions.dlq — for manual inspection and replay
  - Graceful shutdown via asyncio.Event

Fallback:
  If Redpanda is unreachable at startup, automatically falls back to the
  PostgreSQL polling fallback (run_postgres_poll_fallback) until Kafka
  becomes available on the next worker restart.
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone

# Add parent directory to sys.path so we can import project modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import KAFKA_BOOTSTRAP_SERVERS, TRANSACTIONS_TOPIC
from database.neo4j_db import get_async_neo4j_driver

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("sync_worker")

# ── Constants ──────────────────────────────────────────────────────────────────
CONSUMER_GROUP_ID = "aml-graph-sync-group"
DLQ_TOPIC = "aml.transactions.dlq"
MAX_RETRY_ATTEMPTS = 3
POLL_INTERVAL_MS = 100          # consumer poll timeout
POSTGRES_POLL_INTERVAL_S = 5    # fallback PostgreSQL polling interval
POSTGRES_POLL_LIMIT = 200       # max rows per poll cycle


# ── Neo4j graph write ──────────────────────────────────────────────────────────
async def sync_transaction_to_neo4j(tx_payload: dict, neo4j_driver) -> bool:
    """
    Upserts Account nodes and a TRANSFERS_TO relationship edge into Neo4j.

    Uses MERGE so the operation is idempotent — re-processing the same
    transaction_id (e.g. on consumer restart) is safe and produces no duplicates.
    """
    tx_id = tx_payload.get("transaction_id")
    sender_id = tx_payload.get("sender_id")
    sender_acc = tx_payload.get("sender_account")
    receiver_id = tx_payload.get("receiver_id")
    receiver_acc = tx_payload.get("receiver_account")
    amount = float(tx_payload.get("amount", 0.0))
    status = tx_payload.get("status", "UNKNOWN")
    currency = tx_payload.get("currency", "USD")
    timestamp_str = tx_payload.get("timestamp", "")

    # Parse timestamp → epoch int for Neo4j (stores as integer property)
    try:
        ts = timestamp_str.rstrip("Z")
        dt = datetime.fromisoformat(ts)
        epoch = int(dt.timestamp())
    except Exception:
        epoch = int(datetime.now(timezone.utc).timestamp())

    # MERGE on transaction_id guarantees idempotency
    query = """
    MERGE (s:Account {id: $sender_id})
      ON CREATE SET s.account_number = $sender_acc,
                    s.created_at     = timestamp()
      ON MATCH  SET s.account_number = $sender_acc

    MERGE (r:Account {id: $receiver_id})
      ON CREATE SET r.account_number = $receiver_acc,
                    r.created_at     = timestamp()
      ON MATCH  SET r.account_number = $receiver_acc

    MERGE (s)-[t:TRANSFERS_TO {transaction_id: $tx_id}]->(r)
      ON CREATE SET t.amount    = $amount,
                    t.currency  = $currency,
                    t.status    = $status,
                    t.timestamp = $epoch
      ON MATCH  SET t.status    = $status
    """

    try:
        async with neo4j_driver.session() as session:
            await session.run(
                query,
                sender_id=sender_id,
                sender_acc=sender_acc,
                receiver_id=receiver_id,
                receiver_acc=receiver_acc,
                tx_id=tx_id,
                amount=amount,
                currency=currency,
                status=status,
                epoch=epoch,
            )
        logger.info(
            f"[Neo4j] Wrote edge: {sender_acc} --[${amount:.2f}]--> {receiver_acc} "
            f"(tx={tx_id}, status={status})"
        )
        return True
    except Exception as e:
        logger.error(f"[Neo4j] Write failed for tx {tx_id}: {e}")
        return False


# ── Dead Letter Queue ──────────────────────────────────────────────────────────
async def send_to_dlq(producer, payload: dict, error: str):
    """Publishes a failed message to the DLQ topic for manual replay."""
    dlq_payload = {
        "original_payload": payload,
        "error": str(error),
        "failed_at": datetime.now(timezone.utc).isoformat(),
        "source_topic": TRANSACTIONS_TOPIC,
    }
    try:
        await producer.send_and_wait(
            topic=DLQ_TOPIC,
            key=payload.get("transaction_id", "unknown"),
            value=dlq_payload,
        )
        logger.warning(
            f"[DLQ] Sent tx {payload.get('transaction_id')} to {DLQ_TOPIC}. Error: {error}"
        )
    except Exception as e:
        logger.error(f"[DLQ] Failed to write to DLQ: {e}. Original error: {error}")


# ── Main Redpanda consumer loop ────────────────────────────────────────────────
async def run_kafka_consumer(neo4j_driver, shutdown_event: asyncio.Event):
    """
    Runs the AIOKafkaConsumer event loop.

    - Subscribes to TRANSACTIONS_TOPIC
    - Manually commits offsets AFTER confirmed Neo4j write
    - Retries up to MAX_RETRY_ATTEMPTS on Neo4j failure
    - Routes unrecoverable messages to the DLQ
    - Exits cleanly when shutdown_event is set
    """
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

    logger.info(
        f"Starting Redpanda consumer | topic={TRANSACTIONS_TOPIC} | "
        f"group={CONSUMER_GROUP_ID} | brokers={KAFKA_BOOTSTRAP_SERVERS}"
    )

    consumer = AIOKafkaConsumer(
        TRANSACTIONS_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        group_id=CONSUMER_GROUP_ID,
        auto_offset_reset="earliest",
        enable_auto_commit=False,       # manual commit for at-least-once delivery
        value_deserializer=lambda b: json.loads(b.decode("utf-8")),
        key_deserializer=lambda b: b.decode("utf-8") if b else None,
        session_timeout_ms=30_000,
        heartbeat_interval_ms=10_000,
        max_poll_interval_ms=300_000,   # allow slow Neo4j writes without rebalance
        fetch_max_bytes=10 * 1024 * 1024,
    )

    # DLQ producer (separate instance to avoid circular dependency)
    dlq_producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if isinstance(k, str) else k,
    )

    try:
        await consumer.start()
        await dlq_producer.start()
        logger.info("Redpanda consumer started successfully.")

        processed = 0
        failed = 0

        while not shutdown_event.is_set():
            try:
                # Batch fetch — getmany returns a dict of {TopicPartition: [msgs]}
                batch = await asyncio.wait_for(
                    consumer.getmany(timeout_ms=POLL_INTERVAL_MS, max_records=50),
                    timeout=2.0,
                )
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Consumer poll error: {e}. Sleeping 2s...")
                await asyncio.sleep(2)
                continue

            for tp, messages in batch.items():
                for msg in messages:
                    tx_payload = msg.value
                    tx_id = tx_payload.get("transaction_id", "unknown")

                    # Retry loop with exponential backoff
                    success = False
                    last_error = None
                    for attempt in range(1, MAX_RETRY_ATTEMPTS + 1):
                        success = await sync_transaction_to_neo4j(tx_payload, neo4j_driver)
                        if success:
                            break
                        last_error = f"Neo4j write failed on attempt {attempt}"
                        if attempt < MAX_RETRY_ATTEMPTS:
                            backoff = 0.5 * (2 ** (attempt - 1))  # 0.5s, 1s, 2s
                            logger.warning(
                                f"[Retry {attempt}/{MAX_RETRY_ATTEMPTS}] "
                                f"tx={tx_id} — retrying in {backoff:.1f}s"
                            )
                            await asyncio.sleep(backoff)

                    if success:
                        processed += 1
                    else:
                        failed += 1
                        logger.error(
                            f"[PERMANENT FAILURE] tx={tx_id} after "
                            f"{MAX_RETRY_ATTEMPTS} attempts. Routing to DLQ."
                        )
                        await send_to_dlq(dlq_producer, tx_payload, last_error)

                    # Commit offset after processing (success or DLQ) so we
                    # never reprocess a message that already hit the DLQ.
                    await consumer.commit({tp: msg.offset + 1})

            if processed % 100 == 0 and processed > 0:
                logger.info(
                    f"[Stats] Processed: {processed} | DLQ'd: {failed}"
                )

    except asyncio.CancelledError:
        logger.info("Consumer task cancelled — shutting down.")
    except Exception as e:
        logger.error(f"Consumer loop fatal error: {e}")
        raise
    finally:
        logger.info("Stopping consumer and DLQ producer...")
        try:
            await consumer.stop()
        except Exception:
            pass
        try:
            await dlq_producer.stop()
        except Exception:
            pass
        logger.info("Redpanda consumer stopped cleanly.")


# ── PostgreSQL polling fallback ────────────────────────────────────────────────
async def run_postgres_poll_fallback(neo4j_driver, shutdown_event: asyncio.Event):
    """
    Fallback: polls PostgreSQL for recently completed transactions that have
    not yet been synced to Neo4j.

    Uses a `neo4j_synced` boolean column on the transactions table (added by
    the migration below) to track sync state without an in-memory set.
    This survives worker restarts — any unsynced transactions are picked up
    automatically on next start.
    """
    logger.info("Starting PostgreSQL polling fallback worker (Redpanda unavailable).")

    import asyncpg
    from config import POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD

    # Add neo4j_synced column if it doesn't exist
    try:
        conn = await asyncpg.connect(
            host=POSTGRES_HOST, port=POSTGRES_PORT, database=POSTGRES_DB,
            user=POSTGRES_USER, password=POSTGRES_PASSWORD,
        )
        await conn.execute(
            "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS neo4j_synced BOOLEAN DEFAULT FALSE;"
        )
        await conn.close()
        logger.info("PostgreSQL migration: neo4j_synced column ready.")
    except Exception as e:
        logger.warning(f"Could not apply neo4j_synced migration: {e}")

    while not shutdown_event.is_set():
        try:
            conn = await asyncpg.connect(
                host=POSTGRES_HOST, port=POSTGRES_PORT, database=POSTGRES_DB,
                user=POSTGRES_USER, password=POSTGRES_PASSWORD,
            )
            try:
                rows = await conn.fetch(
                    """
                    SELECT t.id, t.sender_account_id, s.account_number AS sender_acc,
                           t.receiver_account_id, r.account_number AS receiver_acc,
                           t.amount, t.currency, t.status, t.timestamp
                    FROM transactions t
                    JOIN accounts s ON t.sender_account_id = s.id
                    JOIN accounts r ON t.receiver_account_id = r.id
                    WHERE t.neo4j_synced = FALSE
                    ORDER BY t.timestamp ASC
                    LIMIT $1;
                    """,
                    POSTGRES_POLL_LIMIT,
                )

                synced_ids = []
                for row in rows:
                    tx_id = str(row["id"])
                    payload = {
                        "transaction_id": tx_id,
                        "sender_id": str(row["sender_account_id"]),
                        "sender_account": row["sender_acc"],
                        "receiver_id": str(row["receiver_account_id"]),
                        "receiver_account": row["receiver_acc"],
                        "amount": float(row["amount"]),
                        "currency": row["currency"] or "USD",
                        "status": row["status"],
                        "timestamp": row["timestamp"].isoformat(),
                    }
                    success = await sync_transaction_to_neo4j(payload, neo4j_driver)
                    if success:
                        synced_ids.append(tx_id)

                # Bulk-mark as synced in one UPDATE
                if synced_ids:
                    await conn.execute(
                        "UPDATE transactions SET neo4j_synced = TRUE WHERE id = ANY($1::uuid[]);",
                        synced_ids,
                    )
                    logger.info(f"[Postgres Fallback] Synced {len(synced_ids)} transactions to Neo4j.")

            finally:
                await conn.close()

        except Exception as e:
            logger.error(f"PostgreSQL polling error: {e}")

        await asyncio.sleep(POSTGRES_POLL_INTERVAL_S)


# ── Entry point ────────────────────────────────────────────────────────────────
async def main(shutdown_event: asyncio.Event | None = None):
    """
    Main entry point for the sync worker.

    1. Waits for Neo4j to be ready.
    2. Attempts to connect to Redpanda and run the Kafka consumer.
    3. If Redpanda is unavailable, falls back to PostgreSQL polling.
    """
    if shutdown_event is None:
        shutdown_event = asyncio.Event()

    logger.info("Initializing AML Graph Sync Worker...")
    await asyncio.sleep(3)  # give databases time to be ready on startup

    # Connect to Neo4j
    try:
        neo4j_driver = await get_async_neo4j_driver()
        logger.info("Neo4j connection established.")
    except Exception as e:
        logger.error(f"Cannot connect to Neo4j — worker cannot start: {e}")
        return

    # Probe Redpanda availability before committing to the consumer
    use_kafka = False
    try:
        from aiokafka import AIOKafkaConsumer
        probe = AIOKafkaConsumer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            group_id="aml-probe",
        )
        await asyncio.wait_for(probe.start(), timeout=5.0)
        await probe.stop()
        use_kafka = True
        logger.info("Redpanda is reachable — using Kafka consumer.")
    except Exception as e:
        logger.warning(
            f"Redpanda unreachable ({e}). "
            f"Falling back to PostgreSQL polling sync."
        )

    if use_kafka:
        await run_kafka_consumer(neo4j_driver, shutdown_event)
    else:
        await run_postgres_poll_fallback(neo4j_driver, shutdown_event)


if __name__ == "__main__":
    asyncio.run(main())
