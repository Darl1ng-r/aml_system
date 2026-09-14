"""
ISO 20022 Wire Message Parser (GAP-17)
======================================
Parses SWIFT / ISO 20022 pacs.008.001.08 credit transfer messages into normalized
internal AML transaction events with enriched originator and beneficiary metadata.
"""

import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional
from datetime import datetime, timezone


def parse_pacs008_message(xml_content: str) -> Dict[str, Any]:
    """
    Parses pacs.008 Financial Institutional Customer Credit Transfer message.
    """
    root = ET.fromstring(xml_content)

    def _find(elem, tag):
        found = elem.find(f".//{{*}}{tag}")
        return found.text.strip() if found is not None and found.text else ""

    # Transaction identification & amounts
    msg_id = _find(root, "MsgId") or "MSG-UNKNOWN"
    amount_str = _find(root, "IntrBkSttlmAmt") or _find(root, "InstdAmt") or "0.0"
    currency = "USD"
    amt_elem = root.find(".//{*}IntrBkSttlmAmt")
    if amt_elem is None:
        amt_elem = root.find(".//{*}InstdAmt")
    if amt_elem is not None and "Ccy" in amt_elem.attrib:
        currency = amt_elem.attrib["Ccy"]

    # Debtor (Originator)
    debtor_name = _find(root, "Dbtr/{*}Nm") or _find(root, "Nm")
    debtor_acct = _find(root, "DbtrAcct/{*}Id/{*}Othr/{*}Id") or _find(root, "DbtrAcct/{*}Id/{*}IBAN")

    # Creditor (Beneficiary)
    creditor_name = _find(root, "Cdtr/{*}Nm")
    creditor_acct = _find(root, "CdtrAcct/{*}Id/{*}Othr/{*}Id") or _find(root, "CdtrAcct/{*}Id/{*}IBAN")

    return {
        "message_type": "pacs.008.001.08",
        "message_id": msg_id,
        "amount": float(amount_str) if amount_str else 0.0,
        "currency": currency,
        "sender_name": debtor_name,
        "sender_account": debtor_acct,
        "receiver_name": creditor_name,
        "receiver_account": creditor_acct,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "channel": "WIRE"
    }
