import pytest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import uuid
from routers.alerts import generate_sar_xml


def test_generate_sar_xml_valid_structure():
    """Verify generate_sar_xml outputs valid FinCEN SAR XML structure."""
    alert_id = uuid.uuid4()
    alert_data = (
        alert_id,
        "STRUCTURING_VELOCITY_24H",
        "CRITICAL",
        0.95,
        9900.00,
        "USD",
        datetime.now(timezone.utc),
        "DE89370400440532013000",
        "Alice Schmidt",
        "US91280039201938210392",
        "Bob Jones"
    )
    justification = "Confirmed rapid structuring transfers below mandatory CTR reporting limit."

    xml_str = generate_sar_xml(alert_data, justification)

    assert isinstance(xml_str, str)
    assert xml_str.startswith("<SuspiciousActivityReport>")

    root = ET.fromstring(xml_str)
    assert root.tag == "SuspiciousActivityReport"

    header = root.find("Header")
    assert header is not None
    assert header.find("ReportID").text == str(alert_id)
    assert header.find("FilingDate") is not None

    summary = root.find("ActivitySummary")
    assert summary is not None
    assert summary.find("Reason").text == "STRUCTURING_VELOCITY_24H"
    assert summary.find("ThreatLevel").text == "CRITICAL"
    assert summary.find("RiskScore").text == "0.95"
    assert summary.find("Description").text == justification

    transaction = root.find("Transaction")
    assert transaction is not None
    assert transaction.find("Amount").text == "9900.0"
    assert transaction.find("Currency").text == "USD"

    sender = transaction.find("Sender")
    assert sender is not None
    assert sender.find("AccountNumber").text == "DE89370400440532013000"
    assert sender.find("OwnerName").text == "Alice Schmidt"

    receiver = transaction.find("Receiver")
    assert receiver is not None
    assert receiver.find("AccountNumber").text == "US91280039201938210392"
    assert receiver.find("OwnerName").text == "Bob Jones"
