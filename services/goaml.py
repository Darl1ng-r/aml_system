"""
EU goAML (UNODC) XML Export Generator
=====================================
Generates regulatory XML filings conforming to the United Nations Office on Drugs and Crime
(UNODC) goAML Schema 4.0/5.0 used by European Financial Intelligence Units (FIUs) and global
regulators for Suspicious Transaction Reports (STRs) and Suspicious Activity Reports (SARs).
"""

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, Tuple, Union, List


def generate_goaml_xml(
    data: Union[Tuple, List, Dict[str, Any]],
    narrative: str,
    reporting_entity: str = "AML-SENTINEL-FIU",
    report_code: str = "STR",
    submission_code: str = "E"
) -> str:
    """
    Constructs a UNODC goAML XML payload.

    Args:
        data: Tuple/List format (alert_id, rule_name, threat, score, amt, curr, ts, s_acc, s_owner, r_acc, r_owner)
              or dictionary containing equivalent fields.
        narrative: Analyst/MLRO reasoning narrative.
        reporting_entity: Registered FIU reporting institution code.
        report_code: goAML report type ('STR', 'SAR', 'AIF', 'CTR').
        submission_code: 'E' (Electronic), 'M' (Manual).

    Returns:
        Formatted XML string matching UNODC goAML specifications.
    """
    if isinstance(data, (list, tuple)):
        alert_id, rule_name, threat, score, amt, curr, ts, s_acc, s_owner, r_acc, r_owner = data
        txn_id = f"TX-{alert_id}"
    else:
        alert_id = data.get("alert_id") or data.get("id") or "UNKNOWN"
        rule_name = data.get("rule_name") or data.get("reason") or "SUSPICIOUS_TRANSACTION"
        threat = data.get("threat_level") or data.get("threat") or "HIGH"
        score = data.get("risk_score") or data.get("score") or 0.85
        amt = data.get("amount") or data.get("amt") or 0.0
        curr = data.get("currency") or data.get("curr") or "EUR"
        ts = data.get("timestamp") or data.get("ts") or datetime.now(timezone.utc)
        s_acc = data.get("sender_account") or data.get("sender_account_id") or data.get("s_acc") or ""
        s_owner = data.get("sender_name") or data.get("s_owner") or ""
        r_acc = data.get("receiver_account") or data.get("receiver_account_id") or data.get("r_acc") or ""
        r_owner = data.get("receiver_name") or data.get("r_owner") or ""
        txn_id = data.get("transaction_id") or f"TX-{alert_id}"

    if hasattr(ts, "isoformat"):
        ts_str = ts.isoformat()
    else:
        ts_str = str(ts)

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    root = ET.Element("report", {
        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
        "schemaVersion": "5.0.0"
    })

    # Header / Reporting Entity Metadata
    ET.SubElement(root, "rentity_id").text = str(reporting_entity)
    ET.SubElement(root, "rentity_branch").text = "HEADQUARTERS"
    ET.SubElement(root, "submission_code").text = str(submission_code)
    ET.SubElement(root, "report_code").text = str(report_code)
    ET.SubElement(root, "entity_reference").text = str(alert_id)
    ET.SubElement(root, "submission_date").text = now_iso
    ET.SubElement(root, "currency_code_local").text = str(curr)

    # Narrative & Reason
    ET.SubElement(root, "reason").text = f"[{rule_name} | {threat} | Score: {score}] {narrative}"
    ET.SubElement(root, "action").text = "TRANSACTION_BLOCKED_AND_REFERRED"

    # Transaction node
    txn_elem = ET.SubElement(root, "transaction")
    ET.SubElement(txn_elem, "transactionnumber").text = str(txn_id)
    ET.SubElement(txn_elem, "internal_ref_number").text = str(alert_id)
    ET.SubElement(txn_elem, "transaction_location").text = "CORE_BANKING_SWIFT"
    ET.SubElement(txn_elem, "transaction_description").text = f"Triggered AML rule: {rule_name}"
    ET.SubElement(txn_elem, "date_transaction").text = ts_str
    ET.SubElement(txn_elem, "amount_local").text = f"{float(amt):.2f}"

    # Originator / From Client
    from_client = ET.SubElement(txn_elem, "t_from_my_client")
    from_account = ET.SubElement(from_client, "from_account")
    ET.SubElement(from_account, "institution_name").text = "AML Sentinel Partner Bank"
    ET.SubElement(from_account, "account_number").text = str(s_acc)
    ET.SubElement(from_account, "account_name").text = str(s_owner)
    ET.SubElement(from_account, "currency_code").text = str(curr)

    # Beneficiary / To Counterparty
    to_client = ET.SubElement(txn_elem, "t_to")
    to_account = ET.SubElement(to_client, "to_account")
    ET.SubElement(to_account, "institution_name").text = "External Beneficiary Institution"
    ET.SubElement(to_account, "account_number").text = str(r_acc)
    ET.SubElement(to_account, "account_name").text = str(r_owner)
    ET.SubElement(to_account, "currency_code").text = str(curr)

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8").decode("utf-8")
