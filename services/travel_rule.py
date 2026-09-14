"""
FATF Recommendation 16 / FinCEN Travel Rule Verification Engine (GAP-8)
========================================================================
Enforces complete originator and beneficiary information on wire transfers
exceeding $3,000 USD (FinCEN 31 CFR 1010.410) and €1,000 EUR (EU TFR).
"""

from typing import Dict, Any, Tuple


TRAVEL_RULE_THRESHOLD_USD = 3000.0


def validate_travel_rule(
    amount: float,
    currency: str,
    channel: str | None,
    originator_info: Dict[str, Any],
    beneficiary_info: Dict[str, Any]
) -> Tuple[bool, list[str]]:
    """
    Validates travel rule completeness.
    Returns:
        (is_valid: bool, missing_fields: list[str])
    """
    is_wire = channel and channel.upper() in ["WIRE", "SWIFT", "ACH", "CROSS_BORDER"]
    if not is_wire:
        return True, []

    if amount < TRAVEL_RULE_THRESHOLD_USD and currency.upper() == "USD":
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
