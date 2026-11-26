"""
FATF Recommendation 16 / FinCEN & EU TFR Travel Rule Verification Engine (P0-1)
===============================================================================
Enforces complete originator and beneficiary information on wire transfers
exceeding $3,000 USD (FinCEN 31 CFR 1010.410) or €1,000 EUR (EU TFR 2023/1113),
using exact fixed-point Decimal arithmetic via `domain/rules_core.py`.
"""

from decimal import Decimal
from typing import Any, Dict, Tuple

from domain.rules_core import (
    TRAVEL_RULE_THRESHOLD_EUR as _DEC_EUR,
    TRAVEL_RULE_THRESHOLD_USD as _DEC_USD,
    evaluate_travel_rule_pure,
)
from services.fx_rates import convert_to_base_currency_sync

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
    if curr != "EUR" and resolved_usd is None:
        resolved_usd = convert_to_base_currency_sync(amount, curr, "USD")[0]

    return evaluate_travel_rule_pure(
        amount=amount,
        currency=curr,
        channel=channel,
        originator_info=originator_info,
        beneficiary_info=beneficiary_info,
        amount_usd=resolved_usd,
    )
