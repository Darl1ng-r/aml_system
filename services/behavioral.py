import logging
from datetime import datetime, timezone, timedelta
import numpy as np
from database.postgres import get_async_db_conn

logger = logging.getLogger(__name__)

def get_mode_list(items: list, limit: int = 3) -> list[str]:
    """Helper to find top items ordered by frequency."""
    valid_items = [str(x) for x in items if x is not None and str(x).strip() != ""]
    if not valid_items:
        return []
    from collections import Counter
    counts = Counter(valid_items)
    return [item for item, _ in counts.most_common(limit)]

async def calculate_customer_baseline(account_id: str) -> dict:
    """
    Computes a customer's transaction baseline behavior using historical data
    and updates/inserts the baseline cache in the database.
    """
    logger.info(f"Recalculating baseline for customer account: {account_id}")
    
    # 1. Fetch completed outgoing transactions for this account in the last 90 days
    query = """
        SELECT amount, receiver_account_id, country, merchant, device, channel, timestamp
        FROM transactions
        WHERE sender_account_id = $1::uuid
          AND status = 'COMPLETED'
          AND timestamp >= NOW() - INTERVAL '90 days'
        ORDER BY timestamp DESC;
    """
    
    try:
        async with get_async_db_conn() as conn:
            rows = await conn.fetch(query, account_id)
            
            if not rows:
                # Default baseline profile if no transaction history exists
                baseline = {
                    "account_id": account_id,
                    "avg_amount": 0.0,
                    "median_amount": 0.0,
                    "variance_amount": 0.0,
                    "daily_frequency": 0.0,
                    "weekly_frequency": 0.0,
                    "monthly_frequency": 0,
                    "unique_receivers_count": 0,
                    "unique_receiver_countries_count": 0,
                    "avg_hour": 0.0,
                    "variance_hour": 0.0,
                    "top_countries": [],
                    "top_merchants": [],
                    "top_devices": [],
                    "top_channels": []
                }
            else:
                amounts = [float(row["amount"]) for row in rows]
                hours = [row["timestamp"].hour for row in rows]
                receivers = [str(row["receiver_account_id"]) for row in rows]
                countries = [row["country"] for row in rows if row["country"]]
                merchants = [row["merchant"] for row in rows if row["merchant"]]
                devices = [row["device"] for row in rows if row["device"]]
                channels = [row["channel"] for row in rows if row["channel"]]
                
                # Frequencies in last 30 days
                now = datetime.now(timezone.utc)
                limit_30_days = now - timedelta(days=30)
                rows_30 = [r for r in rows if r["timestamp"].replace(tzinfo=timezone.utc) >= limit_30_days]
                count_30 = len(rows_30)
                
                # Dynamic time range for daily/weekly division (min 1 day, max 30 days)
                timestamps = [r["timestamp"] for r in rows_30]
                if timestamps:
                    min_time = min(timestamps).replace(tzinfo=timezone.utc)
                    max_time = max(timestamps).replace(tzinfo=timezone.utc)
                    span_days = max((max_time - min_time).days, 1.0)
                else:
                    span_days = 30.0
                
                daily_freq = count_30 / span_days
                weekly_freq = daily_freq * 7.0
                
                baseline = {
                    "account_id": account_id,
                    "avg_amount": float(np.mean(amounts)),
                    "median_amount": float(np.median(amounts)),
                    "variance_amount": float(np.var(amounts)) if len(amounts) > 1 else 0.0,
                    "daily_frequency": float(daily_freq),
                    "weekly_frequency": float(weekly_freq),
                    "monthly_frequency": int(count_30),
                    "unique_receivers_count": int(len(set(receivers))),
                    "unique_receiver_countries_count": int(len(set(countries))),
                    "avg_hour": float(np.mean(hours)),
                    "variance_hour": float(np.var(hours)) if len(hours) > 1 else 0.0,
                    "top_countries": get_mode_list(countries),
                    "top_merchants": get_mode_list(merchants),
                    "top_devices": get_mode_list(devices),
                    "top_channels": get_mode_list(channels)
                }

            # 2. Upsert baseline in PostgreSQL
            upsert_query = """
                INSERT INTO customer_profiles (
                    account_id, avg_amount, median_amount, variance_amount,
                    daily_frequency, weekly_frequency, monthly_frequency,
                    unique_receivers_count, unique_receiver_countries_count,
                    avg_hour, variance_hour, top_countries, top_merchants, top_devices, top_channels, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW())
                ON CONFLICT (account_id) DO UPDATE SET
                    avg_amount = EXCLUDED.avg_amount,
                    median_amount = EXCLUDED.median_amount,
                    variance_amount = EXCLUDED.variance_amount,
                    daily_frequency = EXCLUDED.daily_frequency,
                    weekly_frequency = EXCLUDED.weekly_frequency,
                    monthly_frequency = EXCLUDED.monthly_frequency,
                    unique_receivers_count = EXCLUDED.unique_receivers_count,
                    unique_receiver_countries_count = EXCLUDED.unique_receiver_countries_count,
                    avg_hour = EXCLUDED.avg_hour,
                    variance_hour = EXCLUDED.variance_hour,
                    top_countries = EXCLUDED.top_countries,
                    top_merchants = EXCLUDED.top_merchants,
                    top_devices = EXCLUDED.top_devices,
                    top_channels = EXCLUDED.top_channels,
                    updated_at = NOW();
            """
            
            await conn.execute(
                upsert_query,
                baseline["account_id"],
                baseline["avg_amount"],
                baseline["median_amount"],
                baseline["variance_amount"],
                baseline["daily_frequency"],
                baseline["weekly_frequency"],
                baseline["monthly_frequency"],
                baseline["unique_receivers_count"],
                baseline["unique_receiver_countries_count"],
                baseline["avg_hour"],
                baseline["variance_hour"],
                baseline["top_countries"],
                baseline["top_merchants"],
                baseline["top_devices"],
                baseline["top_channels"]
            )
            
            return baseline

    except Exception as e:
        logger.error(f"Failed to calculate or cache customer baseline for {account_id}: {e}")
        # Return fallback on error
        return {
            "account_id": account_id,
            "avg_amount": 0.0,
            "median_amount": 0.0,
            "variance_amount": 0.0,
            "daily_frequency": 0.0,
            "weekly_frequency": 0.0,
            "monthly_frequency": 0,
            "unique_receivers_count": 0,
            "unique_receiver_countries_count": 0,
            "avg_hour": 0.0,
            "variance_hour": 0.0,
            "top_countries": [],
            "top_merchants": [],
            "top_devices": [],
            "top_channels": []
        }

async def get_customer_baseline(account_id: str) -> dict:
    """Retrieves baseline cache from database, or generates it if missing."""
    query = "SELECT * FROM customer_profiles WHERE account_id = $1::uuid;"
    try:
        async with get_async_db_conn() as conn:
            row = await conn.fetchrow(query, account_id)
            if row:
                return dict(row)
    except Exception as e:
        logger.warning(f"Baseline query failed: {e}. Calculating dynamically...")
        
    return await calculate_customer_baseline(account_id)
