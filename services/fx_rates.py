"""
Multi-Currency FX Normalization Engine (P0-1)
=============================================
Normalizes all incoming ISO-4217 transaction amounts into a tenant's base
reporting currency (USD default) prior to AML threshold, CTR, Travel Rule,
and ML scoring evaluations.

Resolution Chain:
  1. Fast-path 1.0 when source == base currency
  2. Redis hot cache (`fx:rates:{base}`, 6h TTL)
  3. Live ECB/Frankfurter JSON feed (`settings.fx_rates_url`, 2s timeout)
  4. Deterministic built-in ISO-4217 fallback rates for offline/sandbox resilience
"""

import json
import logging
import math
import os
from decimal import Decimal, ROUND_HALF_UP
from typing import Dict, Tuple

import httpx
from config import settings
from database.redis_db import get_async_redis_client

logger = logging.getLogger(__name__)

FX_CACHE_TTL_SECONDS = 6 * 3600  # 6 hours

# Reference mid-market fallback rates expressed as: 1 <CURRENCY> = <VALUE> USD
# Used strictly when Redis + external FX feed are unavailable or during deterministic test runs.
FALLBACK_RATES_TO_USD: Dict[str, float] = {
    "USD": 1.0000,
    "EUR": 1.0800,
    "GBP": 1.2700,
    "CHF": 1.1300,
    "CAD": 0.7200,
    "AUD": 0.6500,
    "NZD": 0.6000,
    "JPY": 0.0066,
    "CNY": 0.1380,
    "HKD": 0.1285,
    "SGD": 0.7450,
    "AED": 0.2723,
    "SAR": 0.2666,
    "QAR": 0.2747,
    "KWD": 3.2500,
    "BHD": 2.6525,
    "OMR": 2.5974,
    "JOD": 1.4104,
    "INR": 0.0119,
    "MXN": 0.0500,
    "BRL": 0.1750,
    "TRY": 0.0290,
    "ZAR": 0.0550,
    "SEK": 0.0940,
    "NOK": 0.0910,
    "DKK": 0.1450,
    "PLN": 0.2500,
    "CZK": 0.0425,
    "HUF": 0.0027,
    "KRW": 0.00072,
    "TWD": 0.0310,
    "THB": 0.0290,
    "MYR": 0.2250,
    "IDR": 0.000063,
    "PHP": 0.0172,
    "RUB": 0.0105,
    "NGN": 0.00062,
    "EGP": 0.0205,
    "ILS": 0.2700,
}


def get_fallback_fx_rate(currency: str, base_currency: str = "USD") -> float:
    """Synchronous deterministic fallback FX rate (1 unit of `currency` in `base_currency`)."""
    src = (currency or base_currency).upper().strip()
    dst = (base_currency or "USD").upper().strip()
    if src == dst:
        return 1.0
    src_to_usd = FALLBACK_RATES_TO_USD.get(src)
    dst_to_usd = FALLBACK_RATES_TO_USD.get(dst)
    if src_to_usd is not None and dst_to_usd:
        return round(src_to_usd / dst_to_usd, 8)
    logger.warning(f"Unknown ISO-4217 currency '{src}' or '{dst}'; defaulting FX rate to 1.0")
    return 1.0


async def _fetch_live_rates_map(base_currency: str = "USD") -> Dict[str, float] | None:
    """Fetches latest FX table from configured ECB/Frankfurter endpoint."""
    # Never make live external HTTP calls during automated pytest runs
    if os.getenv("PYTEST_CURRENT_TEST"):
        return None
    url = getattr(settings, "fx_rates_url", "")
    if not url:
        return None
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(url, params={"from": base_currency})
            if resp.status_code == 200:
                data = resp.json()
                raw_rates = data.get("rates") or {}
                # Frankfurter returns 1 base = X target -> invert to 1 target = (1/X) base
                converted = {base_currency: 1.0}
                for code, val in raw_rates.items():
                    if val is None:
                        continue
                    fval = float(val)
                    if math.isfinite(fval) and fval > 0.0:
                        converted[code.upper()] = round(1.0 / fval, 8)
                return converted
    except Exception as e:
        logger.debug(f"Live FX rate fetch skipped/failed ({e}); using fallback table.")
    return None


async def get_fx_rate(currency: str | None, base_currency: str = "USD") -> float:
    """Resolves 1 unit of `currency` expressed in `base_currency` via Redis -> Live Feed -> Fallback."""
    src = (currency or base_currency).upper().strip()
    dst = (base_currency or getattr(settings, "base_currency", "USD")).upper().strip()
    if src == dst:
        return 1.0

    cache_key = f"fx:rates:{dst}"
    redis = None
    try:
        redis = await get_async_redis_client()
        if redis:
            cached_raw = await redis.get(cache_key)
            if cached_raw:
                rates_map = json.loads(cached_raw)
                if src in rates_map:
                    return float(rates_map[src])
    except Exception:
        redis = None

    live_map = await _fetch_live_rates_map(dst)
    if live_map:
        if redis:
            try:
                await redis.set(cache_key, json.dumps(live_map), ex=FX_CACHE_TTL_SECONDS)
            except Exception:
                pass
        if src in live_map:
            return float(live_map[src])

    return get_fallback_fx_rate(src, dst)


def _quantize_currency(amount: float, rate: float) -> float:
    if not (math.isfinite(float(amount)) and math.isfinite(float(rate))):
        return 0.0
    converted = (Decimal(str(amount)) * Decimal(str(rate))).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )
    return float(converted)


async def convert_to_base_currency(
    amount: float,
    currency: str | None,
    base_currency: str = "USD",
) -> Tuple[float, float]:
    """
    Converts `amount` in `currency` to `base_currency` using fixed-point Decimal arithmetic.
    Returns: (converted_amount, fx_rate_applied)
    """
    rate = await get_fx_rate(currency, base_currency=base_currency)
    return _quantize_currency(amount, rate), rate


def convert_to_base_currency_sync(
    amount: float,
    currency: str | None,
    base_currency: str = "USD",
) -> Tuple[float, float]:
    """Synchronous conversion using fallback rates for pure sync helpers (e.g., Travel Rule)."""
    rate = get_fallback_fx_rate(currency or base_currency, base_currency=base_currency)
    return _quantize_currency(amount, rate), rate
