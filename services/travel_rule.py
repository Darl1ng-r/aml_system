"""
FATF Recommendation 16 / FinCEN & EU TFR Travel Rule Verification Engine (P0-1)
===============================================================================
Enforces complete originator and beneficiary information on wire transfers
exceeding $3,000 USD (FinCEN 31 CFR 1010.410) or €1,000 EUR (EU TFR 2023/1113),
using exact fixed-point Decimal arithmetic via `domain/rules_core.py`.
"""

from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, Tuple

from domain.money import FxRateUnavailableError, quantize_amount, to_decimal
from domain.rules_core import (
    TRAVEL_RULE_THRESHOLD_EUR as _DEC_EUR,
    TRAVEL_RULE_THRESHOLD_USD as _DEC_USD,
    evaluate_travel_rule_pure,
)
from services.fx_rates import get_fallback_fx_rate_decimal

# Backward-compatible float constants for legacy importers
TRAVEL_RULE_THRESHOLD_USD = float(_DEC_USD)
TRAVEL_RULE_THRESHOLD_EUR = float(_DEC_EUR)


def validate_travel_rule(
    amount: float | Decimal | str,
    currency: str,
    channel: str | None,
    originator_info: Dict[str, Any],
    beneficiary_info: Dict[str, Any],
    amount_usd: float | Decimal | str | None = None,
) -> Tuple[bool, list[str]]:
    """
    Validates FATF Travel Rule completeness across currencies using exact Decimal thresholds.
    """
    curr = (currency or "USD").upper().strip()
    resolved_usd: Decimal | float | str | None = amount_usd
    if curr not in ("EUR", "USD") and resolved_usd is None:
        try:
            amt_dec = to_decimal(amount, allow_negative=False, field_name="amount")
            rate_dec = get_fallback_fx_rate_decimal(curr, "USD")
            resolved_usd = quantize_amount(amt_dec * rate_dec, "USD", rounding=ROUND_HALF_UP)
        except FxRateUnavailableError:
            # Unknown currency -> leave resolved_usd=None so pure evaluator fails conservatively
            resolved_usd = None

    return evaluate_travel_rule_pure(
        amount=amount,
        currency=curr,
        channel=channel,
        originator_info=originator_info,
        beneficiary_info=beneficiary_info,
        amount_usd=resolved_usd,
    )
