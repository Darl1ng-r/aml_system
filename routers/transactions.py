from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from datetime import datetime
import uuid
import logging
import json
from database.postgres import get_async_db_conn
from services.rules import RulesEngine, get_rules_config
from services.ml_model import anomaly_model
from services.redpanda import publish_transaction
from services.auth import get_current_user, RoleChecker
from services.rate_limiter import RateLimiter
from services.behavioral import get_customer_baseline, calculate_customer_baseline
from services.isolation_forest import get_iforest_score
from services.dynamic_scorer import compute_dynamic_risk

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/transactions", tags=["Transactions"])

from pydantic import BaseModel, Field, field_validator
from observability.sanitizer import sanitize_text

class TransactionRequest(BaseModel):
    sender_account: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_-]+$")
    receiver_account: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_-]+$")
    amount: float = Field(..., gt=0.0, le=1_000_000_000.0)
    currency: str = Field("USD", min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")
    timestamp: datetime
    country: str | None = Field(None, min_length=2, max_length=3, pattern=r"^[A-Za-z]{2,3}$")
    merchant: str | None = Field(None, max_length=100)
    device: str | None = Field(None, max_length=100)
    channel: str | None = Field(None, max_length=50)

    @field_validator("sender_account", "receiver_account", "merchant", "device", "channel", mode="before")
    @classmethod
    def sanitize_input_strings(cls, v: str | None) -> str | None:
        return sanitize_text(v) if v is not None else None

@router.post("")
async def ingest_transaction(
    payload: TransactionRequest, 
    background_tasks: BackgroundTasks, 
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=100, window=60))
):
    # Step 1: Look up sender, receiver, and velocity count in a single PostgreSQL query (1 round trip)
    try:
        user_tenant_id = current_user.get("tenant_id")
        async with get_async_db_conn(tenant_id=user_tenant_id) as conn:
            row = await conn.fetchrow(
                """
                WITH sender_info AS (
                    SELECT id, tenant_id, risk_score, owner_name, swift_bic
                    FROM accounts 
                    WHERE account_number = $1
                ),
                receiver_info AS (
                    SELECT id, risk_score, owner_name, swift_bic
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
                    s.owner_name AS sender_name,
                    s.swift_bic AS sender_bic,
                    r.id AS receiver_id, 
                    r.risk_score AS receiver_risk,
                    r.owner_name AS receiver_name,
                    r.swift_bic AS receiver_bic,
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
            sender_name = row["sender_name"]
            sender_bic = row["sender_bic"]
            receiver_id = row["receiver_id"]
            receiver_risk = float(row["receiver_risk"])
            receiver_name = row["receiver_name"]
            receiver_bic = row["receiver_bic"]
            velocity_count = int(row["velocity_count"])

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database lookup failed: {str(e)}")

    # Step 2: Run Rules Engine (asynchronously)
    triggered_rules = await RulesEngine.evaluate_transaction(
        sender_id=str(sender_id),
        receiver_id=str(receiver_id),
        amount=payload.amount,
        sender_name=sender_name,
        sender_bic=sender_bic,
        receiver_name=receiver_name,
        receiver_bic=receiver_bic,
        timestamp=payload.timestamp
    )

    # Step 3: Run AI Anomaly Model (using pre-initialized singleton instance)
    ml_result = anomaly_model.predict_risk(payload.amount, sender_risk, receiver_risk, velocity_count)
    ai_score = ml_result["risk_score"]
    attributions = ml_result["attributions"]

    # Step 3.5: Run Dynamic Behavioral Risk Scoring
    try:
        baseline = await get_customer_baseline(str(sender_id))
        
        # Determine if geographic risk is present
        is_geo = 0
        rules_cfg = get_rules_config()
        geo_config = rules_cfg.get("rules", {}).get("GEOGRAPHIC_SANCTIONS", {})
        high_risk_countries = geo_config.get("high_risk_countries", ["RU", "IR", "KP", "SY"])
        for bic in [sender_bic, receiver_bic]:
            if bic and len(bic) >= 6:
                if bic[4:6].upper() in high_risk_countries:
                    is_geo = 1
                    break
                    
        # Get Isolation Forest Anomaly Score
        iforest_score = await get_iforest_score(
            amount=payload.amount,
            sender_risk=sender_risk,
            receiver_risk=receiver_risk,
            hour=payload.timestamp.hour,
            is_geo=is_geo
        )
        
        # Calculate dynamic risk score
        dynamic_res = compute_dynamic_risk(
            rules_triggered=triggered_rules,
            ml_score=ai_score,
            amount=payload.amount,
            baseline=baseline,
            iforest_score=iforest_score
        )
        dynamic_score = dynamic_res["dynamic_risk_score"]
        explainability = dynamic_res["explainability"]
    except Exception as e:
        logger.error(f"Failed to calculate dynamic risk scoring: {e}")
        # Fallback to standard ML model risk score
        dynamic_score = ai_score
        explainability = {
            "ml_model_contribution": ai_score,
            "isolation_forest_contribution": 0.5,
            "baseline_zscore_contribution": 0.0,
            "amount_zscore": 0.0,
            "rule_escalated": len(triggered_rules) > 0
        }

    # Determine Compliance Decision based on Dynamic Score
    alert_triggered = dynamic_score >= 0.75 or len(triggered_rules) > 0
    decision = "HELD" if alert_triggered else "APPROVED"
    status = "HELD" if alert_triggered else "COMPLETED"

    # Step 4: Write transaction to PostgreSQL
    tx_id = str(uuid.uuid4())
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            # Pydantic validates payload.timestamp is a valid datetime object
            dt = payload.timestamp
            
            await conn.execute(
                """
                INSERT INTO transactions (id, tenant_id, sender_account_id, receiver_account_id, amount, currency, status, timestamp, country, merchant, device, channel)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);
                """,
                tx_id, tenant_id, sender_id, receiver_id, payload.amount, payload.currency, status, dt,
                payload.country, payload.merchant, payload.device, payload.channel
            )

            # Create Alert if compliance triggered
            if alert_triggered:
                # Deduce threat level
                threat_level = "CRITICAL" if dynamic_score >= 0.90 else ("HIGH" if dynamic_score >= 0.75 else "MEDIUM")
                rule_name = triggered_rules[0] if triggered_rules else "BEHAVIORAL_ANOMALY"
                
                # Blend standard attributions with dynamic scorer explainability
                explainability_payload = {
                    "ml_attributions": attributions,
                    "dynamic_risk": explainability
                }
                
                await conn.execute(
                    """
                    INSERT INTO alerts (tenant_id, transaction_id, rule_name, threat_level, ai_risk_score, explainability_payload)
                    VALUES ($1, $2, $3, $4, $5, $6);
                    """,
                    tenant_id, tx_id, rule_name, threat_level, dynamic_score, json.dumps(explainability_payload)
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
        "timestamp": payload.timestamp.isoformat(),
        "country": payload.country,
        "merchant": payload.merchant,
        "device": payload.device,
        "channel": payload.channel
    }
    background_tasks.add_task(publish_transaction, redpanda_payload)
    
    # Recalculate customer behavior baseline in background
    background_tasks.add_task(calculate_customer_baseline, str(sender_id))

    return {
        "transaction_id": tx_id,
        "decision": decision,
        "alert_triggered": alert_triggered,
        "risk_score": dynamic_score,
        "triggered_rules": triggered_rules,
        "explainability": {
            "attributions": attributions,
            "dynamic_risk": explainability
        }
    }
