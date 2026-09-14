from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Response, status, Query
from pydantic import BaseModel
from datetime import datetime
import uuid
import logging
import json
from database.postgres import get_async_db_conn, get_async_db_read_conn
from services.rules import RulesEngine, get_rules_config
from services.ml_model import anomaly_model
from services.redpanda import publish_transaction
from services.auth import get_current_user, RoleChecker, enforce_tenant_data_scope
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

@router.post("", status_code=status.HTTP_201_CREATED)
async def ingest_transaction(
    payload: TransactionRequest, 
    background_tasks: BackgroundTasks, 
    response: Response = None,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=100, window=60))
):
    # Enforce Data-Level RBAC tenant scoping
    user_tenant_id = enforce_tenant_data_scope(current_user)

    # Step 1: Look up sender, receiver, and velocity count using read replica pool
    try:
        async with get_async_db_read_conn(tenant_id=user_tenant_id) as conn:
            row = await conn.fetchrow(
                """
                WITH sender_info AS (
                    SELECT id, tenant_id, risk_score, owner_name, swift_bic, status
                    FROM accounts 
                    WHERE account_number = $1
                ),
                receiver_info AS (
                    SELECT id, risk_score, owner_name, swift_bic, status
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
                    s.status AS sender_status,
                    r.id AS receiver_id, 
                    r.risk_score AS receiver_risk,
                    r.owner_name AS receiver_name,
                    r.swift_bic AS receiver_bic,
                    r.status AS receiver_status,
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
            
            # Cross-tenant boundary check: enforce caller is authorized for sender account tenant
            if tenant_id:
                enforce_tenant_data_scope(current_user, target_tenant_id=str(tenant_id))

            sender_status = (row.get("sender_status") if hasattr(row, "get") else (row["sender_status"] if "sender_status" in row else None)) or "ACTIVE"
            receiver_status = (row.get("receiver_status") if hasattr(row, "get") else (row["receiver_status"] if "receiver_status" in row else None)) or "ACTIVE"

            if sender_status == "FROZEN":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Transaction rejected: Sender account {payload.sender_account} is FROZEN under regulatory/court order."
                )
            if receiver_status == "FROZEN":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Transaction rejected: Receiver account {payload.receiver_account} is FROZEN under regulatory/court order."
                )
            if sender_status == "CIP_PENDING":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Transaction rejected: Sender account {payload.sender_account} has pending Customer Identification (CIP) verification."
                )

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
        timestamp=payload.timestamp,
        tenant_id=str(tenant_id) if tenant_id else None
    )

    # Step 3: Run AI Anomaly Model (using pre-initialized singleton instance)
    ml_result = anomaly_model.predict_risk(payload.amount, sender_risk, receiver_risk, velocity_count)
    ai_score = ml_result["risk_score"]
    attributions = ml_result["attributions"]

    # Step 3.5: Run Dynamic Behavioral Risk Scoring
    try:
        baseline = await get_customer_baseline(str(sender_id), tenant_id=str(tenant_id) if tenant_id else None)
        
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
        
        # Calculate dynamic risk score with RBA weights
        jurisdiction_risk = float(baseline.get("jurisdiction_risk_score", 0.1))
        if is_geo == 1:
            jurisdiction_risk = max(jurisdiction_risk, 0.85)

        dynamic_res = compute_dynamic_risk(
            rules_triggered=triggered_rules,
            ml_score=ai_score,
            amount=payload.amount,
            baseline=baseline,
            iforest_score=iforest_score,
            sender_risk=sender_risk,
            receiver_risk=receiver_risk,
            jurisdiction_risk=jurisdiction_risk
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

            # Automatic Currency Transaction Report (CTR) trigger for cash transactions >= $10,000 (BSA 31 CFR 1010.311)
            is_cash_channel = (payload.channel and payload.channel.upper() == "CASH") or (payload.merchant and payload.merchant.upper() == "CASH")
            if is_cash_channel and payload.amount >= 10000.0:
                await conn.execute(
                    """
                    INSERT INTO ctr_filings (tenant_id, transaction_id, account_id, amount, currency, cash_in_out, status)
                    VALUES ($1, $2, $3, $4, $5, 'DEPOSIT', 'PENDING');
                    """,
                    tenant_id, uuid.UUID(tx_id), sender_id, payload.amount, payload.currency
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
        "channel": payload.channel,
        "sender_risk": sender_risk,
        "receiver_risk": receiver_risk,
        "velocity_count": velocity_count,
        "is_geo_risk": is_geo
    }
    background_tasks.add_task(publish_transaction, redpanda_payload)
    
    # Recalculate customer behavior baseline in background
    background_tasks.add_task(calculate_customer_baseline, str(sender_id))

    # Broadcast real-time WebSocket event to active dashboard clients
    from routers.metrics import ws_manager
    event_payload = {
        "event": "NEW_ALERT" if alert_triggered else "NEW_TRANSACTION",
        "transaction_id": tx_id,
        "amount": payload.amount,
        "currency": payload.currency,
        "risk_score": dynamic_score,
        "alert_triggered": alert_triggered,
        "threat_level": threat_level if alert_triggered else "NONE",
        "rule_name": triggered_rules[0] if triggered_rules else "NORMAL",
        "timestamp": payload.timestamp.isoformat()
    }
    background_tasks.add_task(ws_manager.broadcast, event_payload)

    if response is not None:
        response.headers["Location"] = f"/api/v1/transactions/{tx_id}"

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


@router.get("/{id}")
async def get_transaction_by_id(
    id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    """
    Retrieves a single transaction by its UUID with sender/receiver details and tenant isolation.
    """
    try:
        tx_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid transaction ID format")

    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
            row = await conn.fetchrow(
                """
                SELECT t.id, t.amount, t.currency, t.status, t.timestamp,
                       t.country, t.merchant, t.device, t.channel,
                       s.account_number as sender_account, s.owner_name as sender_name,
                       r.account_number as receiver_account, r.owner_name as receiver_name
                FROM transactions t
                JOIN accounts s ON t.sender_account_id = s.id
                JOIN accounts r ON t.receiver_account_id = r.id
                WHERE t.id = $1;
                """,
                tx_uuid
            )
            if not row:
                raise HTTPException(status_code=404, detail="Transaction not found")

            return {
                "id": str(row["id"]),
                "transaction_id": str(row["id"]),
                "amount": float(row["amount"]),
                "currency": row["currency"],
                "status": row["status"],
                "timestamp": row["timestamp"].isoformat() if hasattr(row["timestamp"], "isoformat") else str(row["timestamp"]),
                "country": row["country"] or "DOMESTIC",
                "channel": row["channel"] or "Wire Transfer",
                "merchant": row["merchant"],
                "device": row["device"],
                "sender": {
                    "account_number": row["sender_account"],
                    "owner_name": row["sender_name"]
                },
                "receiver": {
                    "account_number": row["receiver_account"],
                    "owner_name": row["receiver_name"]
                }
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch transaction {id}: {e}")
        raise HTTPException(status_code=500, detail=f"Database query failed: {str(e)}")


@router.get("")
async def list_transactions(
    response: Response,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=100),
    cursor_timestamp: datetime | None = Query(default=None),
    cursor_id: uuid.UUID | None = Query(default=None),
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    """
    Retrieves a paginated list of transactions within the caller's tenant boundary.
    Supports both traditional offset pagination (page/limit) and high-throughput keyset cursor pagination.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    offset = (page - 1) * limit
    try:
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
            if cursor_timestamp:
                cid = cursor_id or uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
                rows = await conn.fetch(
                    """
                    SELECT t.id, t.amount, t.currency, t.status, t.timestamp,
                           t.country, t.channel,
                           s.account_number as sender_account, s.owner_name as sender_name,
                           r.account_number as receiver_account, r.owner_name as receiver_name
                    FROM transactions t
                    JOIN accounts s ON t.sender_account_id = s.id
                    JOIN accounts r ON t.receiver_account_id = r.id
                    WHERE t.tenant_id = $1 AND (t.timestamp < $2 OR (t.timestamp = $2 AND t.id < $3))
                    ORDER BY t.timestamp DESC, t.id DESC
                    LIMIT $4;
                    """,
                    tenant_id, cursor_timestamp, cid, limit
                )
                total_count = None
            else:
                total_count = await conn.fetchval(
                    "SELECT COUNT(*) FROM transactions WHERE tenant_id = $1;",
                    tenant_id
                )
                rows = await conn.fetch(
                    """
                    SELECT t.id, t.amount, t.currency, t.status, t.timestamp,
                           t.country, t.channel,
                           s.account_number as sender_account, s.owner_name as sender_name,
                           r.account_number as receiver_account, r.owner_name as receiver_name
                    FROM transactions t
                    JOIN accounts s ON t.sender_account_id = s.id
                    JOIN accounts r ON t.receiver_account_id = r.id
                    WHERE t.tenant_id = $1
                    ORDER BY t.timestamp DESC, t.id DESC
                    LIMIT $2 OFFSET $3;
                    """,
                    tenant_id, limit, offset
                )

            transactions = []
            for r in rows:
                transactions.append({
                    "id": str(r["id"]),
                    "transaction_id": str(r["id"]),
                    "amount": float(r["amount"]),
                    "currency": r["currency"],
                    "status": r["status"],
                    "timestamp": r["timestamp"].isoformat() if hasattr(r["timestamp"], "isoformat") else str(r["timestamp"]),
                    "country": r["country"] or "DOMESTIC",
                    "channel": r["channel"] or "Wire",
                    "sender_account": r["sender_account"],
                    "sender_name": r["sender_name"],
                    "receiver_account": r["receiver_account"],
                    "receiver_name": r["receiver_name"]
                })

            if rows:
                last_r = rows[-1]
                ts_val = last_r["timestamp"]
                response.headers["X-Next-Cursor-Timestamp"] = ts_val.isoformat() if hasattr(ts_val, "isoformat") else str(ts_val)
                response.headers["X-Next-Cursor-ID"] = str(last_r["id"])

            if total_count is not None:
                response.headers["X-Total-Count"] = str(total_count)
            response.headers["Access-Control-Expose-Headers"] = "X-Total-Count, X-Next-Cursor-Timestamp, X-Next-Cursor-ID"
            return transactions
    except Exception as e:
        logger.error(f"Failed to list transactions: {e}")
        raise HTTPException(status_code=500, detail=f"Database query failed: {str(e)}")
