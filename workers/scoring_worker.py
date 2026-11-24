"""
Asynchronous AML Transaction Compliance Scoring Worker
======================================================
Consumes buffered transaction events from Redpanda/Kafka (`aml.transactions.raw`),
resolves accounts & enforces FROZEN/CIP_PENDING guards, performs USD FX normalization,
executes the complete AI/ML risk evaluation pipeline (Rules Engine, Isolation Forest,
XGBoost + SHAP, Dynamic RBA Scorer), atomically upserts transactions + alerts + CTR +
webhooks + WORM audit_log + `aml.core.transaction.ingested.v1` outbox into PostgreSQL,
and commits Kafka offsets manually ONLY after durable persistence or confirmed DLQ write.

Decouples compute-heavy scoring (50-200ms) from synchronous HTTP ingestion (Finding #8 / V-01).
"""

import asyncio
import json
import logging
import os
import signal
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

# Ensure repository root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import KAFKA_BOOTSTRAP_SERVERS, TRANSACTIONS_TOPIC, settings
from database.postgres import init_db_pool, close_db_pool, get_async_db_conn
from services.rules import RulesEngine, get_rules_config
from services.ml_model import anomaly_model
from services.behavioral import get_customer_baseline, calculate_customer_baseline
from services.isolation_forest import get_iforest_score
from services.dynamic_scorer import compute_dynamic_risk
from services.fx_rates import convert_to_base_currency
from observability.logging import setup_json_logging

logger = logging.getLogger("aml.scoring_worker")

RAW_TRANSACTIONS_TOPIC = "aml.transactions.raw"
RAW_DLQ_TOPIC = "aml.transactions.raw.dlq"
CONSUMER_GROUP_ID = "aml-scoring-worker-group"
MAX_RETRY_ATTEMPTS = 3

# Prevent premature garbage collection of background tasks
_background_tasks: set[asyncio.Task] = set()


def _parse_utc_timestamp(ts_val: Any) -> datetime:
    """Normalizes any ISO-8601 string or datetime into a UTC-aware datetime."""
    if isinstance(ts_val, datetime):
        return ts_val.replace(tzinfo=timezone.utc) if ts_val.tzinfo is None else ts_val.astimezone(timezone.utc)
    if isinstance(ts_val, str) and ts_val.strip():
        try:
            dt = datetime.fromisoformat(ts_val.strip().replace("Z", "+00:00"))
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _extract_hour_of_day(event: dict) -> int:
    """Extracts UTC transaction hour from event payload with graceful fallback."""
    ts_val = event.get("timestamp")
    if not ts_val:
        return 12
    try:
        return _parse_utc_timestamp(ts_val).hour
    except Exception:
        return 12


def _determine_threat_level(dynamic_score: float) -> str:
    """Categorizes threat severity based on calibrated dynamic risk threshold."""
    if dynamic_score >= 0.90:
        return "CRITICAL"
    if dynamic_score >= 0.75:
        return "HIGH"
    return "MEDIUM"


def _is_valid_uuid(val: Any) -> bool:
    if not val:
        return False
    try:
        uuid.UUID(str(val))
        return True
    except (ValueError, TypeError):
        return False


def _is_high_risk_geo(sender_bic: str | None, receiver_bic: str | None) -> int:
    rules_cfg = get_rules_config()
    geo_config = rules_cfg.get("rules", {}).get("GEOGRAPHIC_SANCTIONS", {})
    high_risk_countries = geo_config.get("high_risk_countries", ["RU", "IR", "KP", "SY"])
    for bic in (sender_bic, receiver_bic):
        if bic and len(bic) >= 6 and bic[4:6].upper() in high_risk_countries:
            return 1
    return 0


async def _fetch_account_row_from_db(
    tenant_id: str,
    sender_ref: str,
    receiver_ref: str,
):
    """
    Resolves sender & receiver accounts by UUID or account_number within tenant RLS scope,
    returning UUIDs, risk scores, owner names, SWIFT BICs, statuses, and 24h velocity.
    """
    sender_is_uuid = _is_valid_uuid(sender_ref)
    receiver_is_uuid = _is_valid_uuid(receiver_ref)
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            sender_clause = "id = $1::uuid" if sender_is_uuid else "account_number = $1"
            receiver_clause = "id = $2::uuid" if receiver_is_uuid else "account_number = $2"
            return await conn.fetchrow(
                f"""
                WITH sender_info AS (
                    SELECT id, account_number, risk_score, owner_name, swift_bic, status
                    FROM accounts
                    WHERE {sender_clause}
                ),
                receiver_info AS (
                    SELECT id, account_number, risk_score, owner_name, swift_bic, status
                    FROM accounts
                    WHERE {receiver_clause}
                ),
                velocity_info AS (
                    SELECT COUNT(*) AS velocity_24h
                    FROM transactions
                    WHERE sender_account_id = (SELECT id FROM sender_info)
                      AND timestamp >= NOW() - INTERVAL '24 hours'
                )
                SELECT
                    s.id AS sender_id,
                    s.account_number AS sender_account_number,
                    s.risk_score AS sender_risk,
                    s.owner_name AS sender_name,
                    s.swift_bic AS sender_bic,
                    s.status AS sender_status,
                    r.id AS receiver_id,
                    r.account_number AS receiver_account_number,
                    r.risk_score AS receiver_risk,
                    r.owner_name AS receiver_name,
                    r.swift_bic AS receiver_bic,
                    r.status AS receiver_status,
                    COALESCE(v.velocity_24h, 0) AS velocity_24h
                FROM (SELECT 1) dummy
                LEFT JOIN sender_info s ON TRUE
                LEFT JOIN receiver_info r ON TRUE
                LEFT JOIN velocity_info v ON TRUE;
                """,
                str(sender_ref),
                str(receiver_ref),
            )
    except Exception as e:
        logger.warning(f"Could not load account attributes from DB: {e}")
        return None


def _safe_float(val, fallback: float) -> float:
    try:
        return float(val) if val is not None else fallback
    except (ValueError, TypeError):
        return fallback


def _safe_int(val, fallback: int) -> int:
    try:
        return int(val) if val is not None else fallback
    except (ValueError, TypeError):
        return fallback


def _row_get(row: Any, key: str, default: Any = None) -> Any:
    if row is None:
        return default
    if hasattr(row, "get"):
        val = row.get(key)
        return val if val is not None else default
    try:
        val = row[key]
        return val if val is not None else default
    except Exception:
        return default


async def _resolve_account_context(
    event: dict, tenant_id: str, sender_ref: str, receiver_ref: str
) -> dict[str, Any]:
    """Resolves canonical account UUIDs, KYC/sanctions metadata, statuses, and 24h velocity."""
    s_val = event.get("sender_risk")
    r_val = event.get("receiver_risk")
    v_val = event.get("velocity_count")

    needs_db_lookup = (
        not _is_valid_uuid(sender_ref)
        or not _is_valid_uuid(receiver_ref)
        or s_val is None
        or r_val is None
        or v_val is None
    )
    db_row = None
    if needs_db_lookup:
        db_row = await _fetch_account_row_from_db(tenant_id, sender_ref, receiver_ref)

    resolved_sender_id = str(_row_get(db_row, "sender_id") or sender_ref)
    resolved_receiver_id = str(_row_get(db_row, "receiver_id") or receiver_ref)

    if needs_db_lookup and db_row is not None:
        if not _is_valid_uuid(resolved_sender_id):
            raise ValueError(f"Sender account '{sender_ref}' not found in tenant {tenant_id}")
        if not _is_valid_uuid(resolved_receiver_id):
            raise ValueError(f"Receiver account '{receiver_ref}' not found in tenant {tenant_id}")

    sender_status = str(_row_get(db_row, "sender_status", "ACTIVE"))
    receiver_status = str(_row_get(db_row, "receiver_status", "ACTIVE"))
    if sender_status in ("FROZEN", "CIP_PENDING"):
        raise ValueError(f"Transaction rejected: sender account {sender_ref} status is {sender_status}")
    if receiver_status in ("FROZEN", "CIP_PENDING"):
        raise ValueError(f"Transaction rejected: receiver account {receiver_ref} status is {receiver_status}")

    if s_val is None:
        s_val = _row_get(db_row, "sender_risk")
    if r_val is None:
        r_val = _row_get(db_row, "receiver_risk")
    if v_val is None:
        v_val = _row_get(db_row, "velocity_24h")

    return {
        "sender_id": resolved_sender_id,
        "receiver_id": resolved_receiver_id,
        "sender_account": event.get("sender_account") or _row_get(db_row, "sender_account_number") or "",
        "receiver_account": event.get("receiver_account") or _row_get(db_row, "receiver_account_number") or "",
        "sender_name": event.get("sender_name") or _row_get(db_row, "sender_name"),
        "receiver_name": event.get("receiver_name") or _row_get(db_row, "receiver_name"),
        "sender_bic": event.get("sender_bic") or _row_get(db_row, "sender_bic"),
        "receiver_bic": event.get("receiver_bic") or _row_get(db_row, "receiver_bic"),
        "sender_risk": _safe_float(s_val, 0.2),
        "receiver_risk": _safe_float(r_val, 0.2),
        "velocity_24h": _safe_int(v_val, 1),
    }


async def _persist_scoring_decision(
    tx_id: str,
    tenant_id: str,
    acct_ctx: dict[str, Any],
    event: dict[str, Any],
    tx_dt: datetime,
    amount_orig: float,
    currency: str,
    amount_base_usd: float,
    fx_rate_applied: float,
    new_status: str,
    decision: str,
    alert_triggered: bool,
    dynamic_score: float,
    triggered_rules: list[str],
    attributions: dict,
    explainability: dict,
    is_geo: int,
) -> None:
    """
    Atomically persists transaction upsert, alert creation, CTR/structuring detection,
    outbound HELD webhook, WORM audit_log (for alerted/held tx), and canonical
    `aml.core.transaction.ingested.v1` outbox event inside one PostgreSQL ACID transaction.
    """
    from database.outbox import record_outbox_event

    threat_level = _determine_threat_level(dynamic_score) if alert_triggered else "NONE"
    correlation_id = event.get("_correlation_id")

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        # 1. Idempotent upsert into `transactions` (handles both async-buffered inserts & re-scoring updates)
        await conn.execute(
            """
            INSERT INTO transactions (
                id, tenant_id, sender_account_id, receiver_account_id, amount, currency,
                amount_base_usd, fx_rate_applied, status, timestamp, country, merchant, device, channel
            )
            VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ON CONFLICT (id) DO UPDATE SET
                status = EXCLUDED.status,
                amount_base_usd = EXCLUDED.amount_base_usd,
                fx_rate_applied = EXCLUDED.fx_rate_applied;
            """,
            tx_id,
            tenant_id,
            acct_ctx["sender_id"],
            acct_ctx["receiver_id"],
            amount_orig,
            currency,
            amount_base_usd,
            fx_rate_applied,
            new_status,
            tx_dt,
            event.get("country"),
            event.get("merchant"),
            event.get("device"),
            event.get("channel"),
        )

        # 2. Enqueue signed core-banking interdiction webhook on HELD transactions
        if decision == "HELD" and tenant_id:
            from services.webhooks import enqueue_webhook_event_tx
            await enqueue_webhook_event_tx(
                conn=conn,
                tenant_id=str(tenant_id),
                event_type="TRANSACTION_HELD",
                aggregate_id=tx_id,
                payload={
                    "transaction_id": tx_id,
                    "sender_account": acct_ctx["sender_account"],
                    "receiver_account": acct_ctx["receiver_account"],
                    "amount": amount_orig,
                    "currency": currency,
                    "amount_base_usd": amount_base_usd,
                    "triggered_rules": triggered_rules,
                    "threat_level": threat_level,
                },
            )

        # 3. Insert regulatory alert when triggered
        if alert_triggered:
            rule_name = triggered_rules[0] if triggered_rules else "BEHAVIORAL_ANOMALY"
            explainability_payload = {
                "ml_attributions": attributions,
                "dynamic_risk": explainability,
            }
            await conn.execute(
                """
                INSERT INTO alerts (tenant_id, transaction_id, rule_name, threat_level, ai_risk_score, explainability_payload)
                VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
                ON CONFLICT DO NOTHING;
                """,
                tenant_id,
                tx_id,
                rule_name,
                threat_level,
                dynamic_score,
                json.dumps(explainability_payload),
            )

        # 4. Record cryptographic WORM audit_log for alerted / held transactions
        if (alert_triggered or decision == "HELD") and tenant_id:
            from services.audit import record_audit_event_tx
            await record_audit_event_tx(
                conn=conn,
                action="TRANSACTION_HELD" if decision == "HELD" else "TRANSACTION_ALERTED",
                actor_id=str(event.get("ingested_by") or "scoring_worker"),
                actor_username=str(event.get("ingested_by") or "scoring_worker"),
                actor_role="SYSTEM",
                resource_type="TRANSACTION",
                resource_id=tx_id,
                tenant_id=str(tenant_id),
                details={
                    "ingestion_mode": "ASYNC_BUFFERED",
                    "decision": decision,
                    "threat_level": threat_level,
                    "risk_score": dynamic_score,
                    "amount": amount_orig,
                    "currency": currency,
                    "amount_base_usd": amount_base_usd,
                    "fx_rate_applied": fx_rate_applied,
                    "triggered_rules": triggered_rules,
                    "correlation_id": correlation_id,
                },
            )

        # 5. Record canonical scored event in transactional_outbox for downstream Neo4j graph sync
        outbox_headers: dict[str, str] = {"topic": TRANSACTIONS_TOPIC}
        if correlation_id:
            outbox_headers["correlation_id"] = str(correlation_id)
        if event.get("_traceparent"):
            outbox_headers["traceparent"] = str(event["_traceparent"])

        outbox_payload = {
            "transaction_id": tx_id,
            "tenant_id": str(tenant_id),
            "sender_id": str(acct_ctx["sender_id"]),
            "sender_account": acct_ctx["sender_account"],
            "receiver_id": str(acct_ctx["receiver_id"]),
            "receiver_account": acct_ctx["receiver_account"],
            "amount": amount_orig,
            "currency": currency,
            "amount_base_usd": amount_base_usd,
            "fx_rate_applied": fx_rate_applied,
            "status": new_status,
            "timestamp": tx_dt.isoformat(),
            "country": event.get("country"),
            "merchant": event.get("merchant"),
            "device": event.get("device"),
            "channel": event.get("channel"),
            "sender_risk": acct_ctx["sender_risk"],
            "receiver_risk": acct_ctx["receiver_risk"],
            "velocity_count": acct_ctx["velocity_24h"],
            "is_geo_risk": is_geo,
            "dynamic_score": dynamic_score,
            "alert_triggered": alert_triggered,
            "triggered_rules": triggered_rules,
        }
        await record_outbox_event(
            conn=conn,
            aggregate_type="TRANSACTION",
            aggregate_id=tx_id,
            event_type="aml.core.transaction.ingested.v1",
            payload=outbox_payload,
            tenant_id=str(tenant_id) if tenant_id else None,
            headers=outbox_headers,
        )


async def score_transaction(event: dict) -> dict[str, Any]:
    """Processes a single raw transaction event through the multi-model AML pipeline."""
    tx_id = event["transaction_id"]
    tenant_id = event["tenant_id"]
    # Support both normalized account-ID contract and buffered account-number keys
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

    amount_orig = float(event["amount"])
    currency = str(event.get("currency") or "USD").upper()
    tx_dt = _parse_utc_timestamp(event.get("timestamp"))

    logger.info(f"Processing async transaction scoring for tx={tx_id} tenant={tenant_id}")

    acct_ctx = await _resolve_account_context(event, tenant_id, str(sender_ref), str(receiver_ref))
    sender_id = acct_ctx["sender_id"]
    receiver_id = acct_ctx["receiver_id"]
    sender_risk = acct_ctx["sender_risk"]
    receiver_risk = acct_ctx["receiver_risk"]
    velocity_24h = acct_ctx["velocity_24h"]

    # FX Normalization to base currency (USD) prior to Rules / ML / Dynamic Risk (V-01 / V-06)
    amount_base_usd, fx_rate_applied = await convert_to_base_currency(amount_orig, currency)

    hour_of_day = _extract_hour_of_day(event)
    is_geo = int(event["is_geo_risk"]) if event.get("is_geo_risk") is not None else _is_high_risk_geo(
        acct_ctx["sender_bic"], acct_ctx["receiver_bic"]
    )

    # 1. Rules evaluation (in base USD with full account metadata)
    triggered_rules = await RulesEngine.evaluate_transaction(
        sender_id=sender_id,
        receiver_id=receiver_id,
        amount=amount_base_usd,
        sender_name=acct_ctx["sender_name"],
        sender_bic=acct_ctx["sender_bic"],
        receiver_name=acct_ctx["receiver_name"],
        receiver_bic=acct_ctx["receiver_bic"],
        timestamp=tx_dt,
        sender_account_number=acct_ctx["sender_account"],
        receiver_account_number=acct_ctx["receiver_account"],
        tenant_id=tenant_id,
        metadata={
            "channel": event.get("channel"),
            "merchant": event.get("merchant"),
            "country": event.get("country"),
            "original_amount": amount_orig,
            "original_currency": currency,
            "fx_rate_applied": fx_rate_applied,
        },
    )

    # 2. ML scoring with normalized USD features (offloaded from event loop)
    features = {
        "amount": amount_base_usd,
        "sender_risk": sender_risk,
        "receiver_risk": receiver_risk,
        "velocity_24h": velocity_24h,
        "hour_of_day": hour_of_day,
        "is_geographic_risk": is_geo,
        "currency": currency,
        "channel": event.get("channel", "Wire"),
    }
    ai_score, attributions = await asyncio.to_thread(anomaly_model.predict, features)

    # 3. Tenant-scoped Behavioral Baseline & Isolation Forest
    baseline = await get_customer_baseline(str(sender_id), tenant_id=str(tenant_id))
    iforest_score = await get_iforest_score(
        amount=amount_base_usd,
        sender_risk=sender_risk,
        receiver_risk=receiver_risk,
        hour=hour_of_day,
        is_geo=is_geo,
    )

    jurisdiction_risk = float((baseline or {}).get("jurisdiction_risk_score", 0.1))
    if is_geo == 1:
        jurisdiction_risk = max(jurisdiction_risk, 0.85)

    dynamic_res = compute_dynamic_risk(
        rules_triggered=triggered_rules,
        ml_score=ai_score,
        amount=amount_base_usd,
        baseline=baseline or {},
        iforest_score=iforest_score,
        sender_risk=sender_risk,
        receiver_risk=receiver_risk,
        jurisdiction_risk=jurisdiction_risk,
    )
    dynamic_score = dynamic_res["dynamic_risk_score"]
    explainability = dynamic_res["explainability"]

    # 4. Compliance determination (UCC 4A / Reg CC decoupled hold logic)
    hard_hold_triggers = {"SANCTIONS_HIT", "ACCOUNT_FROZEN", "OFAC_SANCTIONS_MATCH"}
    is_hard_hold = any(r in hard_hold_triggers for r in triggered_rules)
    alert_triggered = dynamic_score >= 0.75 or len(triggered_rules) > 0
    decision = "HELD" if is_hard_hold else "APPROVED"
    new_status = "HELD" if is_hard_hold else "COMPLETED"

    # 5. Atomically persist transaction, alerts, webhooks, WORM audit & scored outbox event
    await _persist_scoring_decision(
        tx_id=tx_id,
        tenant_id=str(tenant_id),
        acct_ctx=acct_ctx,
        event=event,
        tx_dt=tx_dt,
        amount_orig=amount_orig,
        currency=currency,
        amount_base_usd=amount_base_usd,
        fx_rate_applied=fx_rate_applied,
        new_status=new_status,
        decision=decision,
        alert_triggered=alert_triggered,
        dynamic_score=dynamic_score,
        triggered_rules=triggered_rules,
        attributions=attributions,
        explainability=explainability,
        is_geo=is_geo,
    )

    # 6. Recalculate tenant-scoped baseline in background without premature GC
    task = asyncio.create_task(
        calculate_customer_baseline(str(sender_id), tenant_id=str(tenant_id))
    )
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    logger.info(
        f"Transaction tx={tx_id} evaluated: decision={decision} risk={dynamic_score:.3f} "
        f"amount_usd={amount_base_usd:.2f}"
    )
    return {
        "transaction_id": tx_id,
        "decision": decision,
        "status": new_status,
        "dynamic_score": dynamic_score,
        "alert_triggered": alert_triggered,
        "amount_base_usd": amount_base_usd,
        "fx_rate_applied": fx_rate_applied,
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
            f"[SCORING-DLQ] Sent tx {payload.get('transaction_id')} to {RAW_DLQ_TOPIC}. Error: {error}"
        )
        return True
    except Exception:
        logger.exception(f"[SCORING-DLQ] Failed to write tx {payload.get('transaction_id')} to DLQ")
        return False


async def process_raw_message(msg, tp, dlq_producer, consumer) -> bool:
    """
    Scores one Kafka message with bounded retries, DLQ fallback, and manual offset commit.
    Never commits the offset if BOTH scoring and DLQ publishing fail (zero-loss guarantee).
    """
    payload = msg.value
    tx_id = payload.get("transaction_id", "unknown") if isinstance(payload, dict) else "unknown"
    last_error = "Unknown scoring error"

    for attempt in range(1, MAX_RETRY_ATTEMPTS + 1):
        try:
            await score_transaction(payload)
            await consumer.commit({tp: msg.offset + 1})
            return True
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            logger.warning(
                f"[SCORING RETRY {attempt}/{MAX_RETRY_ATTEMPTS}] tx={tx_id} failed: {last_error}"
            )
            if attempt < MAX_RETRY_ATTEMPTS:
                await asyncio.sleep(0.5 * (2 ** (attempt - 1)))

    logger.error(f"[SCORING PERMANENT FAILURE] tx={tx_id} after {MAX_RETRY_ATTEMPTS} attempts; routing to DLQ.")
    dlq_ok = await send_raw_to_dlq(dlq_producer, payload, last_error)
    if not dlq_ok:
        logger.critical(
            f"[ZERO-LOSS GUARD] Refusing to commit offset {msg.offset} on {tp} for tx={tx_id}: "
            f"both scoring and DLQ failed."
        )
        return False

    await consumer.commit({tp: msg.offset + 1})
    return False


async def main():
    setup_json_logging(level=logging.INFO)
    logger.info("Starting AML Async Transaction Scoring Worker...")
    await init_db_pool()

    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown_event.set)
        except NotImplementedError:
            pass

    consumer = None
    dlq_producer = None
    try:
        from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
        consumer = AIOKafkaConsumer(
            RAW_TRANSACTIONS_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            group_id=CONSUMER_GROUP_ID,
            auto_offset_reset="earliest",
            enable_auto_commit=False,  # Manual offset commit after verified PG commit or DLQ
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            max_poll_interval_ms=300_000,
        )
        dlq_producer = AIOKafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            acks="all",
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if isinstance(k, str) else k,
        )
        await consumer.start()
        await dlq_producer.start()
        logger.info(f"Connected to Kafka topic {RAW_TRANSACTIONS_TOPIC} at {KAFKA_BOOTSTRAP_SERVERS}")

        while not shutdown_event.is_set():
            try:
                batch = await asyncio.wait_for(
                    consumer.getmany(timeout_ms=500, max_records=50),
                    timeout=2.0,
                )
            except asyncio.TimeoutError:
                continue
            for tp, messages in (batch or {}).items():
                for msg in messages:
                    await process_raw_message(msg, tp, dlq_producer, consumer)
    except Exception as e:
        logger.warning(f"Kafka consumer initialization failed (offline dev mode active): {e}")
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
        await close_db_pool()
        logger.info("AML Async Transaction Scoring Worker stopped cleanly.")


if __name__ == "__main__":
    asyncio.run(main())
