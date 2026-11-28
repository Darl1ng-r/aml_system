"""
Pure Financial Precision & ISO 4217 Money Value Objects
=======================================================
Zero-I/O, deterministic fixed-point Decimal arithmetic for monetary amounts,
FX normalization, and statutory regulatory threshold evaluation.

Policy (Enterprise Hybrid):
  - Accounting / ledger / FX operations default to ROUND_HALF_EVEN (Banker's Rounding)
    to prevent systematic directional drift across high-volume settlements.
  - Regulatory threshold quantization (BSA CTR $10,000 / Travel Rule $3,000 / €1,000)
    uses explicit ROUND_HALF_UP so reporting obligations are never understated.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN, ROUND_HALF_UP, localcontext
from typing import Any, Mapping

# ISO 4217 currency minor-unit decimal exponents (default = 2)
CURRENCY_EXPONENTS: Mapping[str, int] = {
    # 0-decimal currencies
    "BIF": 0,
    "CLP": 0,
    "DJF": 0,
    "GNF": 0,
    "ISK": 0,
    "JPY": 0,
    "KMF": 0,
    "KRW": 0,
    "PYG": 0,
    "RWF": 0,
    "UGX": 0,
    "VND": 0,
    "VUV": 0,
    "XAF": 0,
    "XOF": 0,
    "XPF": 0,
    # 3-decimal currencies
    "BHD": 3,
    "IQD": 3,
    "JOD": 3,
    "KWD": 3,
    "LYD": 3,
    "OMR": 3,
    "TND": 3,
    # 2-decimal major currencies (explicitly listed for clarity)
    "AED": 2,
    "AUD": 2,
    "BRL": 2,
    "CAD": 2,
    "CHF": 2,
    "CNY": 2,
    "CZK": 2,
    "DKK": 2,
    "EGP": 2,
    "EUR": 2,
    "GBP": 2,
    "HKD": 2,
    "HUF": 2,
    "IDR": 2,
    "ILS": 2,
    "INR": 2,
    "MXN": 2,
    "MYR": 2,
    "NGN": 2,
    "NOK": 2,
    "NZD": 2,
    "PHP": 2,
    "PLN": 2,
    "QAR": 2,
    "RUB": 2,
    "SAR": 2,
    "SEK": 2,
    "SGD": 2,
    "THB": 2,
    "TRY": 2,
    "TWD": 2,
    "USD": 2,
    "ZAR": 2,
}

MAX_LEDGER_SCALE = 4
MAX_MONEY_MAGNITUDE = Decimal("9999999999999999.99")  # NUMERIC(18, 2) ledger ceiling
FX_RATE_QUANTUM = Decimal("0.00000001")  # 8 decimal places (matches NUMERIC(18, 8))
LEDGER_QUANTUM = Decimal("0.0001")       # 4 decimal places (matches NUMERIC(19, 4))


class DomainError(Exception):
    """Base class for pure domain invariant violations."""


class InvalidMoneyError(DomainError, ValueError):
    """Raised when a monetary amount, currency code, or FX rate is invalid or non-finite."""


class FxRateUnavailableError(InvalidMoneyError):
    """Raised when no authoritative or static FX conversion rate exists for a currency pair."""


def normalize_currency(currency: str | None, default: str = "USD") -> str:
    """Normalizes an ISO-4217 3-letter currency code."""
    code = (currency or default).strip().upper()
    if len(code) != 3 or not code.isalpha():
        raise InvalidMoneyError(f"Invalid ISO-4217 currency code: {currency!r}")
    return code


def get_currency_exponent(currency: str) -> int:
    """Returns the ISO-4217 minor-unit exponent (0, 2, or 3) for a currency."""
    return CURRENCY_EXPONENTS.get(currency.strip().upper(), 2)


def get_currency_quantum(currency: str) -> Decimal:
    """Returns the quantization unit Decimal (e.g. 1, 0.01, 0.001) for a currency."""
    exp = get_currency_exponent(currency)
    return Decimal(10) ** (-exp)


def to_decimal(
    value: Any,
    *,
    allow_negative: bool = True,
    allow_zero: bool = True,
    field_name: str = "amount",
) -> Decimal:
    """
    Strictly parses an exact Decimal from str, int, Decimal, or finite float.
    Rejects booleans, NaN, ±Infinity, and non-numeric strings.
    """
    if isinstance(value, bool) or value is None:
        raise InvalidMoneyError(f"{field_name} must be a finite numeric value, got {value!r}")

    try:
        if isinstance(value, Decimal):
            dec = value
        elif isinstance(value, int):
            dec = Decimal(value)
        elif isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                raise InvalidMoneyError(f"{field_name} cannot be empty")
            dec = Decimal(stripped)
        elif isinstance(value, float):
            # Convert via str() so Python's shortest round-trip repr avoids binary dust
            dec = Decimal(str(value))
        else:
            dec = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise InvalidMoneyError(f"Invalid decimal value for {field_name}: {value!r}") from exc

    if not dec.is_finite():
        raise InvalidMoneyError(f"{field_name} must be finite (got {dec})")
    if not allow_negative and dec < Decimal("0"):
        raise InvalidMoneyError(f"{field_name} cannot be negative (got {dec})")
    if not allow_zero and dec == Decimal("0"):
        raise InvalidMoneyError(f"{field_name} must be strictly positive (got {dec})")

    return dec


def parse_decimal_amount(
    value: Any,
    *,
    currency: str | None = None,
    max_scale: int = MAX_LEDGER_SCALE,
    allow_zero: bool = False,
) -> Decimal:
    """
    Parses and validates an inbound monetary amount for API/DTO boundaries.
    Ensures finiteness, sign constraints, and bounded fractional precision.
    """
    dec = to_decimal(value, allow_negative=False, allow_zero=allow_zero, field_name="amount")
    normalized = dec.normalize()
    exponent = normalized.as_tuple().exponent
    scale = -exponent if isinstance(exponent, int) and exponent < 0 else 0

    limit_scale = max_scale
    if currency:
        curr_exp = get_currency_exponent(normalize_currency(currency))
        # Allow up to max(curr_exp, max_scale) so 3-decimal currencies & 4-dp FX remain valid
        limit_scale = max(curr_exp, max_scale)

    if scale > limit_scale:
        raise InvalidMoneyError(
            f"amount precision ({scale} decimal places) exceeds maximum allowed scale ({limit_scale})"
        )
    return dec


def quantize_amount(
    amount: Decimal | str | int | float,
    currency: str = "USD",
    *,
    rounding: str = ROUND_HALF_EVEN,
) -> Decimal:
    """Quantizes a monetary amount to its ISO-4217 currency precision using explicit rounding."""
    dec = to_decimal(amount, field_name="amount")
    if abs(dec) > MAX_MONEY_MAGNITUDE:
        raise InvalidMoneyError(
            f"amount magnitude {dec} exceeds maximum ledger capacity ({MAX_MONEY_MAGNITUDE})"
        )
    quantum = get_currency_quantum(normalize_currency(currency))
    try:
        with localcontext() as ctx:
            ctx.prec = 60
            return dec.quantize(quantum, rounding=rounding)
    except InvalidOperation as exc:
        raise InvalidMoneyError(f"cannot quantize amount {dec} to quantum {quantum}") from exc


def invert_fx_rate(base_to_quote_rate: Any) -> Decimal:
    """
    Computes exact reciprocal FX rate (1 unit of quote currency expressed in base currency)
    rounded to 8 decimal places with ROUND_HALF_EVEN.
    """
    rate_dec = to_decimal(base_to_quote_rate, allow_negative=False, allow_zero=False, field_name="fx_rate")
    try:
        with localcontext() as ctx:
            ctx.prec = 60
            inverted = (Decimal("1") / rate_dec).quantize(FX_RATE_QUANTUM, rounding=ROUND_HALF_EVEN)
    except InvalidOperation as exc:
        raise InvalidMoneyError(f"cannot invert extreme FX rate: {rate_dec}") from exc
    if inverted <= Decimal("0"):
        raise InvalidMoneyError(f"inverted FX rate underflowed to zero for rate {rate_dec}")
    return inverted


@dataclass(frozen=True, slots=True)
class Money:
    """Immutable value object representing an exact monetary quantity in an ISO-4217 currency."""

    amount: Decimal
    currency: str

    def __post_init__(self) -> None:
        curr = normalize_currency(self.currency)
        dec = to_decimal(self.amount, field_name="amount")
        object.__setattr__(self, "currency", curr)
        object.__setattr__(self, "amount", dec)

    @classmethod
    def of(cls, amount: Decimal | str | int | float, currency: str = "USD") -> "Money":
        return cls(amount=to_decimal(amount, field_name="amount"), currency=currency)

    @classmethod
    def from_minor_units(cls, minor_units: int, currency: str = "USD") -> "Money":
        if isinstance(minor_units, bool) or not isinstance(minor_units, int):
            raise InvalidMoneyError(f"minor_units must be an integer, got {minor_units!r}")
        curr = normalize_currency(currency)
        exp = get_currency_exponent(curr)
        return cls(amount=Decimal(minor_units) / (Decimal(10) ** exp), currency=curr)

    def to_minor_units(self, *, rounding: str = ROUND_HALF_EVEN) -> int:
        exp = get_currency_exponent(self.currency)
        quantized = self.quantize(rounding=rounding)
        return int((quantized.amount * (Decimal(10) ** exp)).to_integral_exact())

    def quantize(self, *, rounding: str = ROUND_HALF_EVEN) -> "Money":
        return Money(quantize_amount(self.amount, self.currency, rounding=rounding), self.currency)

    def _assert_same_currency(self, other: "Money") -> None:
        if self.currency != other.currency:
            raise InvalidMoneyError(
                f"Cannot combine different currencies without explicit FX conversion: "
                f"{self.currency} vs {other.currency}"
            )

    def __add__(self, other: "Money") -> "Money":
        self._assert_same_currency(other)
        return Money(self.amount + other.amount, self.currency)

    def __sub__(self, other: "Money") -> "Money":
        self._assert_same_currency(other)
        return Money(self.amount - other.amount, self.currency)


@dataclass(frozen=True, slots=True)
class FxConversionResult:
    """Immutable FX normalization outcome carrying full regulatory provenance."""

    original_amount: Decimal
    original_currency: str
    amount_base: Decimal
    base_currency: str
    fx_rate_applied: Decimal
    source: str  # SAME_CURRENCY | REDIS_CACHE | ECB_LIVE | ISO_FALLBACK
    quoted_at: datetime
    rounding_mode: str = ROUND_HALF_EVEN


def convert_money(
    amount: Decimal | str | int | float,
    currency: str,
    fx_rate_to_base: Decimal | str | int | float,
    *,
    base_currency: str = "USD",
    source: str = "ISO_FALLBACK",
    quoted_at: datetime,
    rounding: str = ROUND_HALF_EVEN,
) -> FxConversionResult:
    """
    Pure FX normalization using exact fixed-point Decimal arithmetic.
    Multiplies strictly by the recorded 8-dp `quantized_rate` so persisted audit
    provenance satisfies `quantize(original_amount * fx_rate_applied) == amount_base`.
    """
    src_curr = normalize_currency(currency)
    dst_curr = normalize_currency(base_currency)
    orig_dec = to_decimal(amount, allow_negative=False, field_name="amount")
    rate_dec = to_decimal(fx_rate_to_base, allow_negative=False, allow_zero=False, field_name="fx_rate")
    try:
        with localcontext() as ctx:
            ctx.prec = 60
            quantized_rate = rate_dec.quantize(FX_RATE_QUANTUM, rounding=ROUND_HALF_EVEN)
    except InvalidOperation as exc:
        raise InvalidMoneyError(f"cannot quantize FX rate {rate_dec}") from exc
    if quantized_rate <= Decimal("0"):
        raise InvalidMoneyError(f"FX rate {rate_dec} quantized to non-positive value ({quantized_rate})")

    if src_curr == dst_curr and quantized_rate == Decimal("1.00000000"):
        converted = quantize_amount(orig_dec, dst_curr, rounding=rounding)
        return FxConversionResult(
            original_amount=orig_dec,
            original_currency=src_curr,
            amount_base=converted,
            base_currency=dst_curr,
            fx_rate_applied=Decimal("1"),
            source="SAME_CURRENCY",
            quoted_at=quoted_at,
            rounding_mode=rounding,
        )

    with localcontext() as ctx:
        ctx.prec = 60
        raw_converted = orig_dec * quantized_rate
    converted = quantize_amount(raw_converted, dst_curr, rounding=rounding)
    return FxConversionResult(
        original_amount=orig_dec,
        original_currency=src_curr,
        amount_base=converted,
        base_currency=dst_curr,
        fx_rate_applied=quantized_rate,
        source=source,
        quoted_at=quoted_at,
        rounding_mode=rounding,
    )
