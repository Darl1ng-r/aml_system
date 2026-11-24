"""
ISO 20022 Wire Message Parser (GAP-17)
======================================
Parses SWIFT / ISO 20022 pacs.008.001.08 credit transfer messages into normalized
internal AML transaction events with enriched originator and beneficiary metadata.
Hardened against XXE / Billion-Laughs entity expansion (V-08), preserves original
UTC wire timestamps, and parses monetary amounts with Decimal precision.
"""

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Dict, Any

try:
    from defusedxml import ElementTree as _SafeET  # type: ignore
except ImportError:
    _SafeET = None

MAX_ISO20022_XML_BYTES = 1 * 1024 * 1024  # 1 MiB cap
_FORBIDDEN_XML_DECL_RE = re.compile(r"<!\s*(DOCTYPE|ENTITY|ELEMENT|ATTLIST)\b", re.IGNORECASE)


def _safe_fromstring(xml_content: str) -> ET.Element:
    if not isinstance(xml_content, str) or not xml_content.strip():
        raise ValueError("ISO 20022 XML payload must be a non-empty string.")
    if len(xml_content.encode("utf-8")) > MAX_ISO20022_XML_BYTES:
        raise ValueError("ISO 20022 XML payload exceeds 1 MiB safety limit.")
    if _FORBIDDEN_XML_DECL_RE.search(xml_content):
        raise ValueError("Unsafe XML rejected: DOCTYPE and ENTITY declarations are forbidden (XXE protection).")
    if _SafeET is not None:
        return _SafeET.fromstring(xml_content)
    return ET.fromstring(xml_content)


def _parse_iso_wire_timestamp(raw_ts: str) -> str:
    if not raw_ts:
        return datetime.now(timezone.utc).isoformat()
    cleaned = raw_ts.strip()
    try:
        # Handle full ISO-8601 datetime (CreDtTm) or date-only (IntrBkSttlmDt)
        if len(cleaned) == 10 and cleaned[4] == "-" and cleaned[7] == "-":
            dt = datetime.fromisoformat(f"{cleaned}T00:00:00+00:00")
        else:
            dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()


def parse_pacs008_message(xml_content: str) -> Dict[str, Any]:
    """
    Parses pacs.008 Financial Institutional Customer Credit Transfer message.
    """
    root = _safe_fromstring(xml_content)

    def _find(elem, tag):
        found = elem.find(f".//{{*}}{tag}")
        return found.text.strip() if found is not None and found.text else ""

    # Transaction identification & amounts (Decimal precision)
    msg_id = _find(root, "MsgId") or "MSG-UNKNOWN"
    amount_str = _find(root, "IntrBkSttlmAmt") or _find(root, "InstdAmt") or "0.00"
    try:
        amount_dec = Decimal(amount_str).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        if not amount_dec.is_finite() or amount_dec < Decimal("0.00"):
            raise ValueError(f"Invalid ISO 20022 amount: {amount_str}")
    except InvalidOperation as exc:
        raise ValueError(f"Malformed ISO 20022 monetary amount '{amount_str}': {exc}") from exc

    currency = "USD"
    amt_elem = root.find(".//{*}IntrBkSttlmAmt")
    if amt_elem is None:
        amt_elem = root.find(".//{*}InstdAmt")
    if amt_elem is not None and "Ccy" in amt_elem.attrib:
        currency = amt_elem.attrib["Ccy"].strip().upper()

    # Preserve original wire timestamp (CreDtTm -> IntrBkSttlmDt -> UTC now fallback)
    wire_ts_raw = _find(root, "CreDtTm") or _find(root, "IntrBkSttlmDt")
    wire_ts_iso = _parse_iso_wire_timestamp(wire_ts_raw)

    # Debtor (Originator)
    debtor_name = _find(root, "Dbtr/{*}Nm") or _find(root, "Nm")
    debtor_acct = _find(root, "DbtrAcct/{*}Id/{*}Othr/{*}Id") or _find(root, "DbtrAcct/{*}Id/{*}IBAN")

    # Creditor (Beneficiary)
    creditor_name = _find(root, "Cdtr/{*}Nm")
    creditor_acct = _find(root, "CdtrAcct/{*}Id/{*}Othr/{*}Id") or _find(root, "CdtrAcct/{*}Id/{*}IBAN")

    return {
        "message_type": "pacs.008.001.08",
        "message_id": msg_id,
        "amount": float(amount_dec),
        "amount_decimal": str(amount_dec),
        "currency": currency,
        "sender_name": debtor_name,
        "sender_account": debtor_acct,
        "receiver_name": creditor_name,
        "receiver_account": creditor_acct,
        "timestamp": wire_ts_iso,
        "channel": "WIRE"
    }
