import time
import json
import os
import logging
from datetime import datetime, timezone
from database.redis_db import get_async_redis_client
from database.postgres import get_async_db_conn
from database.elasticsearch_db import get_async_elasticsearch_client

logger = logging.getLogger(__name__)

CONFIG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rules_config.json"))

_config_cache = None

def get_rules_config() -> dict:
    global _config_cache
    if _config_cache is None:
        try:
            with open(CONFIG_PATH, "r") as f:
                _config_cache = json.load(f)
            logger.info("Rules configuration loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to read rules config from {CONFIG_PATH}: {e}. Falling back to defaults.")
            _config_cache = {
                "rules": {
                    "LARGE_TRANSACTION": {
                        "enabled": True,
                        "threshold": 10000.0
                    },
                    "STRUCTURING_SMURFING": {
                        "enabled": True,
                        "threshold": 10000.0,
                        "window_hours": 24
                    },
                    "VELOCITY_MONITORING": {
                        "enabled": True,
                        "history_days": 30,
                        "deviation_threshold": 3.0
                    },
                    "RAPID_MOVEMENT_FUNDS": {
                        "enabled": True,
                        "window_minutes": 10,
                        "amount_ratio_threshold": 0.90
                    },
                    "DORMANT_ACCOUNT": {
                        "enabled": True,
                        "dormant_period_days": 90,
                        "activation_threshold": 50000.0
                    },
                    "GEOGRAPHIC_SANCTIONS": {
                        "enabled": True,
                        "high_risk_countries": ["RU", "IR", "KP", "SY"],
                        "sanctions_similarity_threshold": 0.80
                    }
                }
            }
    return _config_cache

class RulesEngine:
    @classmethod
    def reload_config(cls):
        global _config_cache
        _config_cache = None
        logger.info("Rules configuration cache invalidated.")

    @staticmethod
    async def evaluate_transaction(
        sender_id: str,
        receiver_id: str,
        amount: float,
        sender_name: str = None,
        sender_bic: str = None,
        receiver_name: str = None,
        receiver_bic: str = None,
        timestamp: datetime = None,
        tenant_id: str = None
    ) -> list[str]:
        triggered_rules = []
        config = get_rules_config()
        
        # 1. LARGE_TRANSACTION Rule
        large_config = config.get("rules", {}).get("LARGE_TRANSACTION", {})
        if large_config.get("enabled", True):
            threshold = large_config.get("threshold", 10000.0)
            if amount > threshold:
                triggered_rules.append("LARGE_TRANSACTION_THRESHOLD")
                
        # 2. STRUCTURING_SMURFING Rule (Redis-based 24h sliding window)
        structuring_config = config.get("rules", {}).get("STRUCTURING_SMURFING", {})
        if structuring_config.get("enabled", True):
            threshold = structuring_config.get("threshold", 10000.0)
            window_hours = structuring_config.get("window_hours", 24)
            try:
                r = await get_async_redis_client()
                now = time.time()
                window_ago = now - (window_hours * 3600)
                redis_key = f"acc:velocity:{tenant_id}:{sender_id}" if tenant_id else f"acc:velocity:{sender_id}"
                
                async with r.pipeline(transaction=True) as pipe:
                    pipe.zremrangebyscore(redis_key, "-inf", window_ago)
                    pipe.zrange(redis_key, 0, -1, withscores=True)
                    pipe.zadd(redis_key, {f"{amount}:{now}": now})
                    pipe.expire(redis_key, 90000)
                    results = await pipe.execute()
                
                recent_txs = results[1]
                
                tx_amounts = [amount]
                for tx_val, _ in recent_txs:
                    try:
                        val_amt = float(tx_val.split(":")[0])
                        tx_amounts.append(val_amt)
                    except (ValueError, IndexError):
                        pass
                
                below_threshold_txs = [amt for amt in tx_amounts if amt < threshold]
                total_amount = sum(below_threshold_txs)
                if total_amount > threshold and len(below_threshold_txs) >= 2:
                    triggered_rules.append("STRUCTURING_VELOCITY_24H")
            except Exception as e:
                logger.error(f"Structuring check Redis error: {e}")
 
        # 3. VELOCITY_MONITORING Rule (Z-score deviation in daily volume/count)
        velocity_config = config.get("rules", {}).get("VELOCITY_MONITORING", {})
        if velocity_config.get("enabled", True):
            history_days = velocity_config.get("history_days", 30)
            dev_threshold = velocity_config.get("deviation_threshold", 3.0)
            try:
                tx_time = timestamp or datetime.now(timezone.utc)
                async with get_async_db_conn(tenant_id=tenant_id) as conn:
                    # Fetch past average & standard deviation
                    hist_row = await conn.fetchrow(
                        """
                        SELECT 
                            COALESCE(AVG(daily_count), 0) as avg_daily_count,
                            COALESCE(STDDEV(daily_count), 0) as stddev_daily_count,
                            COALESCE(AVG(daily_amount), 0) as avg_daily_amount,
                            COALESCE(STDDEV(daily_amount), 0) as stddev_daily_amount
                        FROM (
                            SELECT 
                                DATE_TRUNC('day', timestamp) as tx_day,
                                COUNT(*) as daily_count,
                                SUM(amount) as daily_amount
                            FROM transactions
                            WHERE sender_account_id = $1::uuid
                              AND timestamp >= $3::timestamptz - $2 * INTERVAL '1 day'
                              AND timestamp < DATE_TRUNC('day', $3::timestamptz)
                            GROUP BY DATE_TRUNC('day', timestamp)
                        ) daily_stats;
                        """,
                        sender_id, history_days, tx_time
                    )
                    
                    # Fetch today's count & amount from DB
                    today_row = await conn.fetchrow(
                        """
                        SELECT 
                            COUNT(*) as today_count,
                            COALESCE(SUM(amount), 0) as today_amount
                        FROM transactions
                        WHERE sender_account_id = $1::uuid
                          AND timestamp >= DATE_TRUNC('day', $2::timestamptz)
                          AND timestamp <= $2::timestamptz;
                        """,
                        sender_id, tx_time
                    )
                    
                    avg_count = float(hist_row["avg_daily_count"])
                    stddev_count = float(hist_row["stddev_daily_count"])
                    avg_amount = float(hist_row["avg_daily_amount"])
                    stddev_amount = float(hist_row["stddev_daily_amount"])
                    
                    if avg_count > 0.0:
                        today_count = int(today_row["today_count"]) + 1
                        today_amount = float(today_row["today_amount"]) + amount
                        
                        stddev_count = stddev_count if stddev_count > 0 else 1.0
                        stddev_amount = stddev_amount if stddev_amount > 0 else (avg_amount if avg_amount > 0 else 1.0)
                        
                        count_z = (today_count - avg_count) / stddev_count
                        amount_z = (today_amount - avg_amount) / stddev_amount
                        
                        if count_z > dev_threshold or amount_z > dev_threshold:
                            triggered_rules.append("VELOCITY_MONITORING_SPIKE")
                            logger.warning(f"Velocity spike deviation triggered for {sender_id}. Count Z: {count_z:.2f}, Amount Z: {amount_z:.2f}")
            except Exception as e:
                logger.error(f"Velocity rule Postgres error: {e}")

        # 4. RAPID_MOVEMENT_FUNDS Rule
        rapid_config = config.get("rules", {}).get("RAPID_MOVEMENT_FUNDS", {})
        if rapid_config.get("enabled", True):
            window_minutes = rapid_config.get("window_minutes", 10)
            amount_ratio_threshold = rapid_config.get("amount_ratio_threshold", 0.90)
            try:
                async with get_async_db_conn(tenant_id=tenant_id) as conn:
                    # Find most recent incoming transaction received in window
                    incoming_row = await conn.fetchrow(
                        """
                        SELECT amount, timestamp 
                        FROM transactions 
                        WHERE receiver_account_id = $1::uuid
                          AND status = 'COMPLETED'
                          AND timestamp >= NOW() - $2 * INTERVAL '1 minute'
                        ORDER BY timestamp DESC 
                        LIMIT 1;
                        """,
                        sender_id, window_minutes
                    )
                    
                    if incoming_row:
                        incoming_amount = float(incoming_row["amount"])
                        incoming_time = incoming_row["timestamp"]
                        
                        current_time = timestamp or datetime.now(timezone.utc)
                        if incoming_time.tzinfo is None:
                            incoming_time = incoming_time.replace(tzinfo=timezone.utc)
                        if current_time.tzinfo is None:
                            current_time = current_time.replace(tzinfo=timezone.utc)
                            
                        time_diff = (current_time - incoming_time).total_seconds()
                        if time_diff <= window_minutes * 60 and amount >= incoming_amount * amount_ratio_threshold:
                            triggered_rules.append("RAPID_MOVEMENT_FUNDS")
            except Exception as e:
                logger.error(f"Rapid movement check error: {e}")

        # 5. DORMANT_ACCOUNT Activation Rule
        dormant_config = config.get("rules", {}).get("DORMANT_ACCOUNT", {})
        if dormant_config.get("enabled", True):
            dormant_period_days = dormant_config.get("dormant_period_days", 90)
            activation_threshold = dormant_config.get("activation_threshold", 50000.0)
            try:
                async with get_async_db_conn(tenant_id=tenant_id) as conn:
                    # Get last transaction or fallback to account creation
                    active_row = await conn.fetchrow(
                        """
                        WITH last_tx AS (
                            SELECT timestamp 
                            FROM transactions 
                            WHERE (sender_account_id = $1::uuid OR receiver_account_id = $1::uuid)
                              AND status = 'COMPLETED'
                            ORDER BY timestamp DESC 
                            LIMIT 1
                        ),
                        acc_info AS (
                            SELECT created_at 
                            FROM accounts 
                            WHERE id = $1::uuid
                        )
                        SELECT 
                            COALESCE(
                                (SELECT timestamp FROM last_tx),
                                (SELECT created_at FROM acc_info)
                            ) AS last_activity;
                        """,
                        sender_id
                    )
                    
                    if active_row and active_row["last_activity"]:
                        last_activity = active_row["last_activity"]
                        current_time = timestamp or datetime.now(timezone.utc)
                        if last_activity.tzinfo is None:
                            last_activity = last_activity.replace(tzinfo=timezone.utc)
                        if current_time.tzinfo is None:
                            current_time = current_time.replace(tzinfo=timezone.utc)
                            
                        inactivity_days = (current_time - last_activity).days
                        if inactivity_days >= dormant_period_days and amount > activation_threshold:
                            triggered_rules.append("DORMANT_ACCOUNT_ACTIVATION")
            except Exception as e:
                logger.error(f"Dormant account check error: {e}")

        # 6. GEOGRAPHIC_SANCTIONS Rule
        geo_sanctions_config = config.get("rules", {}).get("GEOGRAPHIC_SANCTIONS", {})
        if geo_sanctions_config.get("enabled", True):
            high_risk_countries = geo_sanctions_config.get("high_risk_countries", ["RU", "IR", "KP", "SY"])
            sanctions_threshold = geo_sanctions_config.get("sanctions_similarity_threshold", 0.80)
            
            # Geographic Risk: indices 4-5 of SWIFT BIC represents country code
            for bic in [sender_bic, receiver_bic]:
                if bic and len(bic) >= 6:
                    country = bic[4:6].upper()
                    if country in high_risk_countries:
                        triggered_rules.append("GEOGRAPHIC_RISK")
                        break
                        
            # Sanctions Risk fuzzy search
            try:
                from routers.screening import perform_sanctions_search
                es = await get_async_elasticsearch_client()
                
                if sender_name:
                    sender_screen = await perform_sanctions_search(sender_name, sanctions_threshold, es)
                    if sender_screen.get("match_found", False):
                        triggered_rules.append("SANCTIONS_HIT")
                        
                if receiver_name and receiver_name != sender_name and "SANCTIONS_HIT" not in triggered_rules:
                    receiver_screen = await perform_sanctions_search(receiver_name, sanctions_threshold, es)
                    if receiver_screen.get("match_found", False):
                        triggered_rules.append("SANCTIONS_HIT")
            except Exception as e:
                logger.error(f"Sanctions check within rules engine error: {e}")

        return triggered_rules


async def start_redis_rules_listener(shutdown_event=None):
    """Listens for distributed rules cache invalidation events across horizontal pods."""
    from database.redis_db import get_async_redis_client
    import asyncio
    while shutdown_event is None or not shutdown_event.is_set():
        try:
            redis = await get_async_redis_client()
            if redis is None:
                await asyncio.sleep(5)
                continue
            pubsub = redis.pubsub()
            await pubsub.subscribe("aml:rules:cache_invalidate")
            logger.info("Subscribed to Redis channel 'aml:rules:cache_invalidate'")
            while shutdown_event is None or not shutdown_event.is_set():
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg.get("type") == "message":
                    RulesEngine.reload_config()
                await asyncio.sleep(0.5)
        except Exception as e:
            logger.debug(f"Redis rules invalidation listener error: {e}")
            await asyncio.sleep(5)
