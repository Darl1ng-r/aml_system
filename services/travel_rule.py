"""
FATF Recommendation 16 / FinCEN & EU TFR Travel Rule Verification Engine (P0-1)
===============================================================================
Enforces complete originator and beneficiary information on wire transfers
exceeding $3,000 USD (FinCEN 31 CFR 1010.410) or €1,000 EUR (EU TFR 2023/1113),
using FX currency normalization so non-USD/EUR currencies are evaluated accurately.
"""

from typing import Dict, Any, Tuple
from services.fx_rates import convert_to_base_currency_sync


TRAVEL_RULE_THRESHOLD_USD = 3000.0
TRAVEL_RULE_THRESHOLD_EUR = 1000.0


def validate_travel_rule(
    amount: float,
    currency: str,
    channel: str | None,
    originator_info: Dict[str, Any],
    beneficiary_info: Dict[str, Any],
    amount_usd: float | None = None,
) -> Tuple[bool, list[str]]:
    """
    Validates FATF Travel Rule completeness across currencies.
    - EUR transfers are evaluated against EU TFR €1,000 threshold.
    - All other currencies are normalized to USD and evaluated against FinCEN $3,000 threshold.
    Returns:
        (is_valid: bool, missing_fields: list[str])
    """
    is_wire = channel and channel.upper() in ["WIRE", "SWIFT", "ACH", "CROSS_BORDER", "SEPA"]
    if not is_wire:
        return True, []

    curr = (currency or "USD").upper().strip()
    if curr == "EUR":
        if float(amount) < TRAVEL_RULE_THRESHOLD_EUR:
            return True, []
    else:
        normalized_usd = (
            float(amount_usd)
            if amount_usd is not None
            else convert_to_base_currency_sync(float(amount), curr, "USD")[0]
        )
        if normalized_usd < TRAVEL_RULE_THRESHOLD_USD:
            return True, []

    missing = []

    # 1. Originator checks
    if not originator_info.get("name") or len(str(originator_info["name"]).strip()) < 2:
        missing.append("originator_name")
    if not originator_info.get("account_number"):
        missing.append("originator_account_number")
    if not (originator_info.get("address") or originator_info.get("date_of_birth") or originator_info.get("tax_id")):
        missing.append("originator_address_or_identifier")

    # 2. Beneficiary checks
    if not beneficiary_info.get("name") or len(str(beneficiary_info["name"]).strip()) < 2:
        missing.append("beneficiary_name")
    if not beneficiary_info.get("account_number"):
        missing.append("beneficiary_account_number")

    return len(missing) == 0, missing
