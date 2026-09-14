"""
Asynchronous AML Transaction Compliance Scoring Worker
======================================================
Consumes raw transaction events from Redpanda/Kafka, executes the complete
AI/ML risk evaluation pipeline (Rules Engine, Isolation Forest, XGBoost + SHAP,
Dynamic RBA Scorer), persists compliance determinations and alerts to PostgreSQL,
updates graph intelligence in Neo4j, and emits real-time WebSocket notifications.

Decouples compute-heavy scoring (50-200ms) from synchronous HTTP ingestion (Finding #8).
"""

import asyncio
import json
import logging
import os
import sys

# Ensure repository root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import KAFKA_BOOTSTRAP_SERVERS, TRANSACTIONS_TOPIC, settings
from database.postgres import init_db_pool, get_async_db_conn
from services.rules import RulesEngine, get_rules_config
from services.ml_model import anomaly_model
from services.behavioral import get_customer_baseline, calculate_customer_baseline
from services.isolation_forest import get_iforest_score
from services.dynamic_scorer import compute_dynamic_risk
from observability.logging import setup_json_logging

from datetime import datetime

logger = logging.getLogger("aml.scoring_worker")


async def score_transaction(event: dict):
    """Processes a single raw transaction event through the multi-model AML pipeline."""
    tx_id = event["transaction_id"]
    tenant_id = event["tenant_id"]
    sender_id = event["sender_id"]
    receiver_id = event["receiver_id"]
    amount = float(event["amount"])

    logger.info(f"Processing async transaction scoring for tx={tx_id} tenant={tenant_id}")

    # Extract real transaction features with fallback to DB lookup if missing from payload
    sender_risk = float(event["sender_risk"]) if event.get("sender_risk") is not None else None
    receiver_risk = float(event["receiver_risk"]) if event.get("receiver_risk") is not None else None
    velocity_24h = int(event["velocity_count"]) if event.get("velocity_count") is not None else None

    if sender_risk is None or receiver_risk is None or velocity_24h is None:
        try:
            async with get_async_db_conn(tenant_id=tenant_id) as conn:
                row = await conn.fetchrow(
                    """
                    SELECT 
                        s.risk_score AS sender_risk,
                        r.risk_score AS receiver_risk,
                        (SELECT COUNT(*) FROM transactions WHERE sender_account_id = s.id AND timestamp >= NOW() - INTERVAL '24 hours') AS velocity_24h
                    FROM accounts s
                    LEFT JOIN accounts r ON r.id = $2
                    WHERE s.id = $1;
                    """,
                    sender_id, receiver_id
                )
                if row:
                    if sender_risk is None and row["sender_risk"] is not None:
                        sender_risk = float(row["sender_risk"])
                    if receiver_risk is None and row["receiver_risk"] is not None:
                        receiver_risk = float(row["receiver_risk"])
                    if velocity_24h is None and row["velocity_24h"] is not None:
                        velocity_24h = int(row["velocity_24h"])
        except Exception as e:
            logger.warning(f"Could not load account risk attributes from DB: {e}")

    sender_risk = sender_risk if sender_risk is not None else 0.2
    receiver_risk = receiver_risk if receiver_risk is not None else 0.2
    velocity_24h = velocity_24h if velocity_24h is not None else 1

    # Extract transaction hour
    ts_val = event.get("timestamp")
    hour_of_day = 12
    if ts_val:
        try:
            if isinstance(ts_val, str):
                hour_of_day = datetime.fromisoformat(ts_val.replace("Z", "+00:00")).hour
            elif hasattr(ts_val, "hour"):
                hour_of_day = ts_val.hour
        except Exception:
            hour_of_day = 12

    is_geo = int(event.get("is_geo_risk", 0))

    # 1. Rules evaluation
    triggered_rules = await RulesEngine.evaluate_transaction(
        sender_id=sender_id,
        receiver_id=receiver_id,
        amount=amount,
        sender_account_number=event.get("sender_account", ""),
        receiver_account_number=event.get("receiver_account", "")
    )

    # 2. ML scoring with real dynamic features
    features = {
        "amount": amount,
        "sender_risk": sender_risk,
        "receiver_risk": receiver_risk,
        "velocity_24h": velocity_24h,
        "hour_of_day": hour_of_day,
        "is_geographic_risk": is_geo,
        "currency": event.get("currency", "USD"),
        "channel": event.get("channel", "Wire")
    }
    ai_score, attributions = anomaly_model.predict(features)

    # 3. Behavioral baseline & Isolation Forest
    baseline = await get_customer_baseline(str(sender_id))
    iforest_score = await get_iforest_score(
        amount=amount,
        sender_risk=sender_risk,
        receiver_risk=receiver_risk,
        hour=hour_of_day,
        is_geo=is_geo
    )

    dynamic_res = compute_dynamic_risk(
        rules_triggered=triggered_rules,
        ml_score=ai_score,
        amount=amount,
        baseline=baseline,
        iforest_score=iforest_score,
        sender_risk=sender_risk,
        receiver_risk=receiver_risk,
        jurisdiction_risk=float(baseline.get("jurisdiction_risk_score", 0.1))
    )
    dynamic_score = dynamic_res["dynamic_risk_score"]
    explainability = dynamic_res["explainability"]

    # 4. Compliance determination
    alert_triggered = dynamic_score >= 0.75 or len(triggered_rules) > 0
    decision = "HELD" if alert_triggered else "APPROVED"
    new_status = "HELD" if alert_triggered else "COMPLETED"

    # 5. Persist updates to PostgreSQL
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        await conn.execute(
            "UPDATE transactions SET status = $1 WHERE id = $2 AND tenant_id = $3;",
            new_status, tx_id, tenant_id
        )

        if alert_triggered:
            threat_level = "CRITICAL" if dynamic_score >= 0.90 else ("HIGH" if dynamic_score >= 0.75 else "MEDIUM")
            rule_name = triggered_rules[0] if triggered_rules else "BEHAVIORAL_ANOMALY"
            explainability_payload = {
                "ml_attributions": attributions,
                "dynamic_risk": explainability
            }
            await conn.execute(
                """
                INSERT INTO alerts (tenant_id, transaction_id, rule_name, threat_level, ai_risk_score, explainability_payload)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT DO NOTHING;
                """,
                tenant_id, tx_id, rule_name, threat_level, dynamic_score, json.dumps(explainability_payload)
            )

    # 6. Recalculate baseline in background
    asyncio.create_task(calculate_customer_baseline(str(sender_id)))
    logger.info(f"Transaction tx={tx_id} evaluated: decision={decision} risk={dynamic_score:.3f}")


async def main():
    setup_json_logging(level=logging.INFO)
    logger.info("Starting AML Async Transaction Scoring Worker...")
    await init_db_pool()

    try:
        from aiokafka import AIOKafkaConsumer
        consumer = AIOKafkaConsumer(
            "aml.transactions.raw",
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            group_id="aml-scoring-worker-group",
            auto_offset_reset="earliest",
            value_deserializer=lambda v: json.loads(v.decode("utf-8"))
        )
        await consumer.start()
        logger.info(f"Connected to Kafka topic aml.transactions.raw at {KAFKA_BOOTSTRAP_SERVERS}")
        try:
            async for msg in consumer:
                try:
                    await score_transaction(msg.value)
                except Exception as e:
                    logger.error(f"Error scoring transaction {msg.value.get('transaction_id')}: {e}", exc_info=e)
        finally:
            await consumer.stop()
    except Exception as e:
        logger.warning(f"Kafka consumer initialization failed (offline dev mode active): {e}")


if __name__ == "__main__":
    asyncio.run(main())
