from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from datetime import datetime
import uuid
import logging
from database.postgres import get_db_cursor
from services.rules import RulesEngine
from services.ml_model import AMLAnomalyModel
from services.redpanda import publish_transaction

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/transactions", tags=["Transactions"])

class TransactionRequest(BaseModel):
    sender_account: str
    receiver_account: str
    amount: float
    currency: str
    timestamp: str

@router.post("")
def ingest_transaction(payload: TransactionRequest):
    # Step 1: Look up sender and receiver in PostgreSQL to verify they exist
    try:
        with get_db_cursor() as cur:
            cur.execute(
                "SELECT id, tenant_id, risk_score FROM accounts WHERE account_number = %s;",
                (payload.sender_account,)
            )
            sender = cur.fetchone()
            if not sender:
                raise HTTPException(status_code=404, detail=f"Sender account {payload.sender_account} not found")
            sender_id, tenant_id, sender_risk = sender[0], sender[1], float(sender[2])

            cur.execute(
                "SELECT id, risk_score FROM accounts WHERE account_number = %s;",
                (payload.receiver_account,)
            )
            receiver = cur.fetchone()
            if not receiver:
                raise HTTPException(status_code=404, detail=f"Receiver account {payload.receiver_account} not found")
            receiver_id, receiver_risk = receiver[0], float(receiver[1])

            # Get sender transaction velocity (number of txs in last 24 hours) from Postgres
            cur.execute(
                """
                SELECT COUNT(*) FROM transactions 
                WHERE sender_account_id = %s 
                  AND timestamp >= NOW() - INTERVAL '24 hours';
                """,
                (sender_id,)
            )
            velocity_count = cur.fetchone()[0]

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database lookup failed: {str(e)}")

    # Step 2: Synchronously run Rules Engine
    triggered_rules = RulesEngine.evaluate_transaction(sender_id, receiver_id, payload.amount)

    # Step 3: Synchronously run AI Anomaly Model
    model = AMLAnomalyModel()
    ml_result = model.predict_risk(payload.amount, sender_risk, receiver_risk, velocity_count)
    ai_score = ml_result["risk_score"]
    attributions = ml_result["attributions"]

    # Determine Compliance Decision
    # If AI risk score is >= 0.75, or critical rules are triggered: HELD
    alert_triggered = ai_score >= 0.75 or len(triggered_rules) > 0
    decision = "HELD" if alert_triggered else "APPROVED"
    status = "HELD" if alert_triggered else "COMPLETED"

    # Step 4: Write transaction to PostgreSQL
    tx_id = str(uuid.uuid4())
    try:
        with get_db_cursor() as cur:
            cur.execute(
                """
                INSERT INTO transactions (id, tenant_id, sender_account_id, receiver_account_id, amount, currency, status, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                """,
                (tx_id, tenant_id, sender_id, receiver_id, payload.amount, payload.currency, status, payload.timestamp)
            )

            # Create Alert if compliance triggered
            if alert_triggered:
                # Deduce threat level
                threat_level = "CRITICAL" if ai_score >= 0.90 else ("HIGH" if ai_score >= 0.75 else "MEDIUM")
                rule_name = triggered_rules[0] if triggered_rules else "BEHAVIORAL_ANOMALY"
                
                import json
                cur.execute(
                    """
                    INSERT INTO alerts (tenant_id, transaction_id, rule_name, threat_level, ai_risk_score, explainability_payload)
                    VALUES (%s, %s, %s, %s, %s, %s);
                    """,
                    (tenant_id, tx_id, rule_name, threat_level, ai_score, json.dumps(attributions))
                )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to record transaction: {str(e)}")

    # Step 5: Publish Scored Transaction to Redpanda for Async Graph Updates
    redpanda_payload = {
        "transaction_id": tx_id,
        "tenant_id": str(tenant_id),
        "sender_id": str(sender_id),
        "sender_account": payload.sender_account,
        "receiver_id": str(receiver_id),
        "receiver_account": payload.receiver_account,
        "amount": payload.amount,
        "currency": payload.currency,
        "status": status,
        "timestamp": payload.timestamp
    }
    publish_transaction(redpanda_payload)

    return {
        "transaction_id": tx_id,
        "decision": decision,
        "alert_triggered": alert_triggered,
        "risk_score": ai_score,
        "triggered_rules": triggered_rules,
        "explainability": {
            "attributions": attributions
        }
    }
