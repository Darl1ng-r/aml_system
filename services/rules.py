import time
from database.redis_db import get_redis_client

class RulesEngine:
    @staticmethod
    def evaluate_transaction(sender_id: str, receiver_id: str, amount: float) -> list[str]:
        triggered_rules = []
        
        # Rule 1: Large Transaction Threshold
        if amount >= 10000.0:
            triggered_rules.append("LARGE_TRANSACTION_THRESHOLD")
            
        # Rule 2: 24h Velocity & Potential Structuring Check (using Redis)
        try:
            r = get_redis_client()
            now = time.time()
            day_ago = now - 86400

            # Redis key for tracking transaction times and amounts for this sender
            redis_key = f"acc:velocity:{sender_id}"
            
            # Clean up elements older than 24h
            r.zremrangebyscore(redis_key, "-inf", day_ago)
            
            # Retrieve all transactions in the last 24 hours
            recent_txs = r.zrange(redis_key, 0, -1, withscores=True)
            
            # Calculate sum of recent transactions
            total_recent_amount = amount
            for tx_val, tx_time in recent_txs:
                try:
                    # tx_val is stored as "amount:timestamp_uuid" to ensure uniqueness in sorted set
                    val_amt = float(tx_val.split(":")[0])
                    total_recent_amount += val_amt
                except (ValueError, IndexError):
                    pass
            
            # Structuring threshold is usually just under $10,000 (e.g. $9,000 to $9,999) 
            # or cumulative amount > $10,000 across multiple small transactions.
            if total_recent_amount >= 10000.0 and len(recent_txs) >= 2:
                triggered_rules.append("STRUCTURING_VELOCITY_24H")
                
            # Log current transaction in Redis
            # Member is "amount:timestamp" to ensure uniqueness in sorted set
            r.zadd(redis_key, {f"{amount}:{now}": now})
            # Set key expiry to 25h to automatically clean up inactive accounts
            r.expire(redis_key, 90000)

        except Exception as e:
            # Fallback if Redis is unavailable
            print(f"Rules engine Redis velocity lookup error: {e}")
            
        return triggered_rules
