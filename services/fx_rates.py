"""
Multi-Currency FX Normalization Engine (P0-1 + Logic Pillar Precision Upgrade)
==============================================================================
Normalizes all incoming ISO-4217 transaction amounts into a tenant's base
reporting currency (USD default) prior to AML threshold, CTR, Travel Rule,
and ML scoring evaluations using exact fixed-point Decimal math (`domain/money.py`).

Resolution Chain:
  1. Fast-path 1.0 when source == base currency (`SAME_CURRENCY`)
  2. Redis hot cache (`fx:rates:{base}`, 6h TTL, `REDIS_CACHE`)
  3. Live ECB/Frankfurter JSON feed (`settings.fx_rates_url`, 2s timeout, `ECB_LIVE`)
  4. Deterministic built-in ISO-4217 fallback rates (`ISO_FALLBACK`)
"""

from __future__ import annotations

import asyncio as _asyncio
import json
import logging
import math
import os
import time as _time
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_EVEN, ROUND_HALF_UP
from typing import Dict, Optional, Tuple

import httpx

from config import settings
from database.redis_db import get_async_redis_client
from domain.money import (
    FX_RATE_QUANTUM,
    FxConversionResult,
    InvalidMoneyError,
    convert_money,
    invert_fx_rate,
    normalize_currency,
    quantize_amount,
    to_decimal,
)

logger = logging.getLogger(__name__)

FX_CACHE_TTL_SECONDS = 6 * 3600  # 6 hours

# Reference mid-market fallback rates expressed as: 1 <CURRENCY> = <VALUE> USD
FALLBACK_RATES_TO_USD_DECIMAL: Dict[str, Decimal] = {
    "USD": Decimal("1.0000"),
    "EUR": Decimal("1.0800"),
    "GBP": Decimal("1.2700"),
    "CHF": Decimal("1.1300"),
    "CAD": Decimal("0.7200"),
    "AUD": Decimal("0.6500"),
    "NZD": Decimal("0.6000"),
    "JPY": Decimal("0.0066"),
    "CNY": Decimal("0.1380"),
    "HKD": Decimal("0.1285"),
    "SGD": Decimal("0.7450"),
    "AED": Decimal("0.2723"),
    "SAR": Decimal("0.2666"),
    "QAR": Decimal("0.2747"),
    "KWD": Decimal("3.2500"),
    "BHD": Decimal("2.6525"),
    "OMR": Decimal("2.5974"),
    "JOD": Decimal("1.4104"),
    "INR": Decimal("0.0119"),
    "MXN": Decimal("0.0500"),
    "BRL": Decimal("0.1750"),
    "TRY": Decimal("0.0290"),
    "ZAR": Decimal("0.0550"),
    "SEK": Decimal("0.0940"),
    "NOK": Decimal("0.0910"),
    "DKK": Decimal("0.1450"),
    "PLN": Decimal("0.2500"),
    "CZK": Decimal("0.0425"),
    "HUF": Decimal("0.0027"),
    "KRW": Decimal("0.00072"),
    "TWD": Decimal("0.0310"),
    "THB": Decimal("0.0290"),
    "MYR": Decimal("0.2250"),
    "IDR": Decimal("0.000063"),
    "PHP": Decimal("0.0172"),
    "RUB": Decimal("0.0105"),
    "NGN": Decimal("0.00062"),
    "EGP": Decimal("0.0205"),
    "ILS": Decimal("0.2700"),
}

# Backward-compatible float mapping for legacy callers
FALLBACK_RATES_TO_USD: Dict[str, float] = {
    k: float(v) for k, v in FALLBACK_RATES_TO_USD_DECIMAL.items()
}


def get_fallback_fx_rate_decimal(currency: str, base_currency: str = "USD") -> Decimal:
    """Exact Decimal deterministic fallback FX rate (1 unit of `currency` in `base_currency`)."""
    src = (currency or base_currency).upper().strip()
    dst = (base_currency or "USD").upper().strip()
    if src == dst:
        return Decimal("1")
    src_to_usd = FALLBACK_RATES_TO_USD_DECIMAL.get(src)
    dst_to_usd = FALLBACK_RATES_TO_USD_DECIMAL.get(dst)
    if src_to_usd is not None and dst_to_usd:
        return (src_to_usd / dst_to_usd).quantize(FX_RATE_QUANTUM, rounding=ROUND_HALF_EVEN)
    logger.warning("Unknown ISO-4217 currency '%s' or '%s'; defaulting FX rate to 1.0", src, dst)
    return Decimal("1")


def get_fallback_fx_rate(currency: str, base_currency: str = "USD") -> float:
    """Synchronous deterministic fallback FX rate (1 unit of `currency` in `base_currency`)."""
    return float(get_fallback_fx_rate_decimal(currency, base_currency))


_fx_locks: Dict[str, _asyncio.Lock] = {}
_fx_local_cache: Dict[str, tuple[float, Optional[Dict[str, str]]]] = {}
_FX_NEGATIVE_COOLDOWN_SECONDS = 60.0


def _get_fx_lock(base_currency: str) -> _asyncio.Lock:
    lock = _fx_locks.get(base_currency)
    if lock is None:
        lock = _asyncio.Lock()
        _fx_locks[base_currency] = lock
    return lock


async def _fetch_live_rates_map(base_currency: str = "USD") -> Optional[Dict[str, str]]:
    """Fetches latest FX table via pooled httpx + circuit breaker + single-flight stampede protection."""
    from services.http_client import CircuitOpenError, is_outbound_egress_allowed, request_with_resilience

    if os.getenv("PYTEST_CURRENT_TEST") or not is_outbound_egress_allowed("frankfurter_fx"):
        return None
    url = getattr(settings, "fx_rates_url", "")
    if not url:
        return None

    now = _time.monotonic()
    cached_entry = _fx_local_cache.get(base_currency)
    if cached_entry and (now - cached_entry[0]) < _FX_NEGATIVE_COOLDOWN_SECONDS:
        return cached_entry[1]

    async with _get_fx_lock(base_currency):
        now = _time.monotonic()
        cached_entry = _fx_local_cache.get(base_currency)
        if cached_entry and (now - cached_entry[0]) < _FX_NEGATIVE_COOLDOWN_SECONDS:
            return cached_entry[1]
        try:
            resp = await request_with_resilience(
                "GET",
                url,
                target="frankfurter_fx",
                timeout=httpx.Timeout(connect=1.0, read=2.0, write=1.5, pool=1.0),
                follow_redirects=False,
                retries=1,
                params={"from": base_currency},
            )
            if resp.status_code == 200:
                data = resp.json()
                raw_rates = data.get("rates") or {}
                converted: Dict[str, str] = {base_currency: "1.00000000"}
                for code, val in raw_rates.items():
                    if val is None:
                        continue
                    try:
                        inv = invert_fx_rate(val)
                        if inv > Decimal("0"):
                            converted[code.upper()] = str(inv)
                    except InvalidMoneyError:
                        continue
                _fx_local_cache[base_currency] = (_time.monotonic(), converted)
                return converted
        except (CircuitOpenError, Exception) as e:
            logger.debug("Live FX rate fetch skipped/failed (%s); using fallback table.", e)

        _fx_local_cache[base_currency] = (_time.monotonic(), None)
        return None


async def get_fx_rate_with_provenance(
    currency: str | None,
    base_currency: str = "USD",
    *,
    evaluated_at: datetime | None = None,
) -> Tuple[Decimal, str, datetime]:
    """Resolves 1 unit of `currency` in `base_currency` as exact Decimal + source + quote timestamp."""
    quoted_at = evaluated_at or datetime.now(timezone.utc)
    src = (currency or base_currency).upper().strip()
    dst = (base_currency or getattr(settings, "base_currency", "USD")).upper().strip()
    if src == dst:
        return Decimal("1"), "SAME_CURRENCY", quoted_at

    cache_key = f"fx:rates:{dst}"
    redis = None
    try:
        redis = await get_async_redis_client()
        if redis:
            cached_raw = await redis.get(cache_key)
            if cached_raw:
                rates_map = json.loads(cached_raw)
                if src in rates_map:
                    rate_dec = to_decimal(rates_map[src], allow_negative=False, allow_zero=False, field_name="fx_rate")
                    return rate_dec.quantize(FX_RATE_QUANTUM, rounding=ROUND_HALF_EVEN), "REDIS_CACHE", quoted_at
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
            rate_dec = to_decimal(live_map[src], allow_negative=False, allow_zero=False, field_name="fx_rate")
            return rate_dec.quantize(FX_RATE_QUANTUM, rounding=ROUND_HALF_EVEN), "ECB_LIVE", quoted_at

    return get_fallback_fx_rate_decimal(src, dst), "ISO_FALLBACK", quoted_at


async def get_fx_rate(currency: str | None, base_currency: str = "USD") -> float:
    """Resolves 1 unit of `currency` expressed in `base_currency` via Redis -> Live Feed -> Fallback."""
    rate_dec, _, _ = await get_fx_rate_with_provenance(currency, base_currency=base_currency)
    return float(rate_dec)


def _quantize_currency(
    amount: float | Decimal | str,
    rate: float | Decimal | str,
    *,
    base_currency: str = "USD",
    rounding: str = ROUND_HALF_UP,
) -> float:
    try:
        amt_dec = to_decimal(amount, allow_negative=False, field_name="amount")
        rate_dec = to_decimal(rate, allow_negative=False, allow_zero=False, field_name="fx_rate")
    except InvalidMoneyError:
        return 0.0
    converted = quantize_amount(amt_dec * rate_dec, base_currency, rounding=rounding)
    return float(converted)


async def convert_to_base_currency_exact(
    amount: Decimal | str | int | float,
    currency: str | None,
    base_currency: str = "USD",
    *,
    evaluated_at: datetime | None = None,
    rounding: str = ROUND_HALF_EVEN,
) -> FxConversionResult:
    """
    Enterprise fixed-point FX conversion returning exact `Decimal` amounts and full
    regulatory provenance (`source`, `quoted_at`, `fx_rate_applied`).
    """
    src_curr = normalize_currency(currency or base_currency)
    dst_curr = normalize_currency(base_currency or getattr(settings, "base_currency", "USD"))
    rate_dec, source, quoted_at = await get_fx_rate_with_provenance(
        src_curr, base_currency=dst_curr, evaluated_at=evaluated_at
    )
    return convert_money(
        amount=amount,
        currency=src_curr,
        fx_rate_to_base=rate_dec,
        base_currency=dst_curr,
        source=source,
        quoted_at=quoted_at,
        rounding=rounding,
    )


async def convert_to_base_currency(
    amount: float | Decimal | str,
    currency: str | None,
    base_currency: str = "USD",
) -> Tuple[float, float]:
    """
    Backward-compatible FX conversion returning `(converted_amount_float, fx_rate_float)`
    using conservative ROUND_HALF_UP threshold rounding.
    """
    rate_dec, _, _ = await get_fx_rate_with_provenance(currency, base_currency=base_currency)
    return _quantize_currency(amount, rate_dec, base_currency=base_currency, rounding=ROUND_HALF_UP), float(rate_dec)


def convert_to_base_currency_sync(
    amount: float | Decimal | str,
    currency: str | None,
    base_currency: str = "USD",
) -> Tuple[float, float]:
    """Synchronous conversion using fallback rates for pure sync helpers (e.g., Travel Rule)."""
    rate_dec = get_fallback_fx_rate_decimal(currency or base_currency, base_currency=base_currency)
    return _quantize_currency(amount, rate_dec, base_currency=base_currency, rounding=ROUND_HALF_UP), float(rate_dec)
