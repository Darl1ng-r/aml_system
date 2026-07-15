from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from datetime import datetime
import uuid
import logging
import json
from database.postgres import get_async_db_conn
from services.rules import RulesEngine
from services.ml_model import anomaly_model
from services.redpanda import publish_transaction
from services.auth import get_current_user, RoleChecker
from services.rate_limiter import RateLimiter


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/transactions", tags=["Transactions"])

class TransactionRequest(BaseModel):
    sender_account: str
    receiver_account: str
    amount: float
    currency: str
    timestamp: str

@router.post("")
async def ingest_transaction(
    payload: TransactionRequest, 
    background_tasks: BackgroundTasks, 
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=100, window=60))
):
    # Step 1: Look up sender, receiver, and velocity count in a single PostgreSQL query (1 round trip)
    try:
        async with get_async_db_conn() as conn:
            row = await conn.fetchrow(
                """
                WITH sender_info AS (
                    SELECT id, tenant_id, risk_score 
                    FROM accounts 
                    WHERE account_number = $1
                ),
                receiver_info AS (
                    SELECT id, risk_score 
                    FROM accounts 
                    WHERE account_number = $2
                ),
                velocity_info AS (
                    SELECT COUNT(*) AS velocity_count 
                    FROM transactions 
                    WHERE sender_account_id = (SELECT id FROM sender_info)
                      AND timestamp >= NOW() - INTERVAL '24 hours'
                )
                SELECT 
                    s.id AS sender_id, 
                    s.tenant_id AS sender_tenant, 
                    s.risk_score AS sender_risk,
                    r.id AS receiver_id, 
                    r.risk_score AS receiver_risk,
                    COALESCE(v.velocity_count, 0) AS velocity_count
                FROM (SELECT 1) dummy
                LEFT JOIN sender_info s ON TRUE
                LEFT JOIN receiver_info r ON TRUE
                LEFT JOIN velocity_info v ON TRUE;
                """,
                payload.sender_account,
                payload.receiver_account
            )
            
            if not row or row["sender_id"] is None:
                raise HTTPException(status_code=404, detail=f"Sender account {payload.sender_account} not found")
            if row["receiver_id"] is None:
                raise HTTPException(status_code=404, detail=f"Receiver account {payload.receiver_account} not found")
                
            sender_id = row["sender_id"]
            tenant_id = row["sender_tenant"]
            sender_risk = float(row["sender_risk"])
            receiver_id = row["receiver_id"]
            receiver_risk = float(row["receiver_risk"])
            velocity_count = int(row["velocity_count"])

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database lookup failed: {str(e)}")

    # Step 2: Run Rules Engine (asynchronously)
    triggered_rules = await RulesEngine.evaluate_transaction(str(sender_id), str(receiver_id), payload.amount)

    # Step 3: Run AI Anomaly Model (using pre-initialized singleton instance)
    ml_result = anomaly_model.predict_risk(payload.amount, sender_risk, receiver_risk, velocity_count)
    ai_score = ml_result["risk_score"]
    attributions = ml_result["attributions"]

    # Determine Compliance Decision
    alert_triggered = ai_score >= 0.75 or len(triggered_rules) > 0
    decision = "HELD" if alert_triggered else "APPROVED"
    status = "HELD" if alert_triggered else "COMPLETED"

    # Step 4: Write transaction to PostgreSQL
    tx_id = str(uuid.uuid4())
    try:
        async with get_async_db_conn() as conn:
            # Parse iso format string to datetime
            dt = datetime.fromisoformat(payload.timestamp.replace('Z', '+00:00'))
            
            await conn.execute(
                """
                INSERT INTO transactions (id, tenant_id, sender_account_id, receiver_account_id, amount, currency, status, timestamp)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
                """,
                tx_id, tenant_id, sender_id, receiver_id, payload.amount, payload.currency, status, dt
            )

            # Create Alert if compliance triggered
            if alert_triggered:
                # Deduce threat level
                threat_level = "CRITICAL" if ai_score >= 0.90 else ("HIGH" if ai_score >= 0.75 else "MEDIUM")
                rule_name = triggered_rules[0] if triggered_rules else "BEHAVIORAL_ANOMALY"
                
                await conn.execute(
                    """
                    INSERT INTO alerts (tenant_id, transaction_id, rule_name, threat_level, ai_risk_score, explainability_payload)
                    VALUES ($1, $2, $3, $4, $5, $6);
                    """,
                    tenant_id, tx_id, rule_name, threat_level, ai_score, json.dumps(attributions)
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
    background_tasks.add_task(publish_transaction, redpanda_payload)

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
