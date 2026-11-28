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

def _build_default_baseline(account_id: str) -> dict:
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
        "top_channels": [],
        "jurisdiction_risk_score": 0.1,
        "kyc_risk_tier": "STANDARD",
    }


def _compute_circular_hour_stats(hours: list[int]) -> tuple[float, float]:
    if not hours:
        return 0.0, 0.0
    import math
    angles = [2.0 * math.pi * (float(h) % 24.0) / 24.0 for h in hours]
    sin_mean = float(np.mean([math.sin(a) for a in angles]))
    cos_mean = float(np.mean([math.cos(a) for a in angles]))
    R = min(math.sqrt(sin_mean**2 + cos_mean**2), 1.0)
    circ_dispersion = 2.0 * (1.0 - R) * ((24.0 / (2.0 * math.pi)) ** 2)
    # Antipodal / uniform distribution has undefined circular mean (R ~= 0):
    # avoid IEEE-754 sin(pi)=1.22e-16 atan2 noise by returning 0.0 with maximum dispersion.
    if R < 1e-6:
        return 0.0, round(float(circ_dispersion), 2)
    circ_hour = (math.atan2(sin_mean, cos_mean) * 24.0 / (2.0 * math.pi)) % 24.0
    avg_hour_val = round(circ_hour, 2) % 24.0
    return avg_hour_val, round(float(circ_dispersion), 2)


def _to_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _calculate_frequencies(rows: list) -> tuple[float, float, int]:
    now = datetime.now(timezone.utc)
    limit_30_days = now - timedelta(days=30)
    utc_times = [_to_utc(r["timestamp"]) for r in rows]
    times_30 = [t for t in utc_times if t >= limit_30_days]
    count_30 = len(times_30)
    if times_30:
        # Smooth denominator clamped to [7, 30] days eliminates discontinuous 60x burst spikes
        raw_span = (now - min(times_30)).total_seconds() / 86400.0
        span_days = min(max(raw_span, 7.0), 30.0)
    else:
        span_days = 30.0
    daily_freq = count_30 / span_days
    weekly_freq = daily_freq * 7.0
    return float(daily_freq), float(weekly_freq), int(count_30)


def _evaluate_jurisdiction_risk(countries: list) -> float:
    high_risk_set = {"RU", "IR", "KP", "SY", "AF", "MM"}
    for c in countries:
        if c and c.upper() in high_risk_set:
            return 0.85
    return 0.1


def _compute_baseline_stats_sync(account_id: str, rows: list) -> dict:
    if not rows:
        return _build_default_baseline(account_id)

    import math

    amounts: list[float] = []
    for row in rows:
        raw_amt = row["amount"]
        if raw_amt is None:
            continue
        try:
            f_amt = float(raw_amt)
            if math.isfinite(f_amt):
                amounts.append(f_amt)
        except (ValueError, TypeError):
            continue
    if not amounts:
        return _build_default_baseline(account_id)

    hours = [_to_utc(row["timestamp"]).hour for row in rows if row.get("timestamp") is not None]
    receivers = [str(row["receiver_account_id"]) for row in rows]
    countries = [str(row["country"]).strip().upper() for row in rows if row["country"] and str(row["country"]).strip()]
    merchants = [row["merchant"] for row in rows if row["merchant"]]
    devices = [row["device"] for row in rows if row["device"]]
    channels = [row["channel"] for row in rows if row["channel"]]

    daily_freq, weekly_freq, count_30 = _calculate_frequencies(rows)
    avg_hour_val, var_hour_val = _compute_circular_hour_stats(hours)

    # Unbiased sample variance with Bessel's correction (ddof=1) capped for numeric(15,2) safety
    raw_variance = float(np.var(amounts, ddof=1)) if len(amounts) > 1 else 0.0
    safe_variance = min(raw_variance, 999_999_999_999.0)
    j_risk = _evaluate_jurisdiction_risk(countries)

    return {
        "account_id": account_id,
        "avg_amount": float(np.mean(amounts)),
        "median_amount": float(np.median(amounts)),
        "variance_amount": safe_variance,
        "daily_frequency": daily_freq,
        "weekly_frequency": weekly_freq,
        "monthly_frequency": count_30,
        "unique_receivers_count": int(len(set(receivers))),
        "unique_receiver_countries_count": int(len(set(countries))),
        "avg_hour": avg_hour_val,
        "variance_hour": var_hour_val,
        "top_countries": get_mode_list(countries),
        "top_merchants": get_mode_list(merchants),
        "top_devices": get_mode_list(devices),
        "top_channels": get_mode_list(channels),
        "jurisdiction_risk_score": float(j_risk),
        "kyc_risk_tier": "HIGH" if j_risk > 0.5 else "STANDARD",
    }


async def calculate_customer_baseline(account_id: str, tenant_id: str | None = None) -> dict:
    """
    Computes a customer's transaction baseline behavior using historical data
    and updates/inserts the baseline cache in the database without holding a DB
    transaction open during NumPy CPU aggregation.
    """
    from services.compute_executor import run_analytics_compute

    logger.info(f"Recalculating baseline for customer account: {account_id}")

    # 1. Fetch completed outgoing transactions for this account in the last 90 days (bounded to 10,000)
    # Normalize amounts to base reporting currency (USD) so multi-currency baselines are consistent (V-06)
    query = """
        SELECT COALESCE(amount_base_usd, amount) AS amount,
               receiver_account_id, country, merchant, device, channel, timestamp
        FROM transactions
        WHERE sender_account_id = $1::uuid
          AND status = 'COMPLETED'
          AND timestamp >= NOW() - INTERVAL '90 days'
        ORDER BY timestamp DESC
        LIMIT 10000;
    """

    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            rows = await conn.fetch(query, account_id)

        # Offload CPU-bound NumPy aggregation outside the DB transaction onto the analytics bulkhead
        baseline = await run_analytics_compute(_compute_baseline_stats_sync, account_id, list(rows or []), timeout=10.0)

        # 2. Upsert baseline in PostgreSQL with tenant_id from accounts
        upsert_query = """
            INSERT INTO customer_profiles (
                account_id, tenant_id, avg_amount, median_amount, variance_amount,
                daily_frequency, weekly_frequency, monthly_frequency,
                unique_receivers_count, unique_receiver_countries_count,
                avg_hour, variance_hour, top_countries, top_merchants, top_devices, top_channels,
                jurisdiction_risk_score, kyc_risk_tier, updated_at
            )
            SELECT $1, a.tenant_id, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, NOW()
            FROM accounts a WHERE a.id = $1::uuid
            ON CONFLICT (account_id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
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
                jurisdiction_risk_score = EXCLUDED.jurisdiction_risk_score,
                kyc_risk_tier = EXCLUDED.kyc_risk_tier,
                updated_at = NOW();
        """

        async with get_async_db_conn(tenant_id=tenant_id) as conn:
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
                baseline["top_channels"],
                float(baseline.get("jurisdiction_risk_score", 0.1)),
                str(baseline.get("kyc_risk_tier", "STANDARD")),
            )

        return baseline

    except Exception as e:
        logger.exception(f"Failed to calculate or cache customer baseline for {account_id}: {e}")
        return _build_default_baseline(account_id)

async def get_customer_baseline(account_id: str, tenant_id: str | None = None) -> dict:
    """Retrieves baseline cache from database, or generates it if missing."""
    query = "SELECT * FROM customer_profiles WHERE account_id = $1::uuid;"
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            row = await conn.fetchrow(query, account_id)
            if row:
                return dict(row)
    except Exception as e:
        logger.warning(f"Baseline query failed: {e}. Calculating dynamically...")
        
    return await calculate_customer_baseline(account_id, tenant_id=tenant_id)
