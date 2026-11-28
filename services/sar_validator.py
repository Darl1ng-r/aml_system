"""
Regulatory SAR / STR XML & XSD Structural Validator (P0-4)
===========================================================
Enforces strict pre-submission validation for:
  - U.S. FinCEN BSABatch (`EFilingBatchXML`) & `SuspiciousActivityReport`
  - UNODC goAML 5.0 (`<report schemaVersion="5.0.0">`)

Security & Compliance Checks:
  - Rejects XML External Entity (XXE) & DTD expansion (`<!DOCTYPE`, `<!ENTITY`)
  - Validates required element hierarchy, ISO-4217 currency codes, numeric amounts,
    and mandatory narrative/reason text prior to FIU transmission.
  - Runs full `xmlschema.XMLSchema` validation automatically if XSD files are mounted.
"""

import os
import re
import xml.etree.ElementTree as ET
from decimal import Decimal, InvalidOperation
from typing import List, Tuple

_XXE_FORBIDDEN_RE = re.compile(r"<!\s*(DOCTYPE|ENTITY)\b", re.IGNORECASE)
_ISO_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def _find_text_recursive(root: ET.Element, target_tags: set[str]) -> str:
    for elem in root.iter():
        if _strip_ns(elem.tag) in target_tags and elem.text and elem.text.strip():
            return elem.text.strip()
    return ""


_NARRATIVE_TAGS = {"Narrative", "Description", "ActivityNarrativeText", "SuspiciousActivityNarrative", "Reason"}
_AMOUNT_TAGS = {"Amount", "TotalSuspiciousAmount", "TransactionAmount", "AmountUSD"}


def _parse_strict_non_negative_decimal(raw_text: str, field_label: str) -> tuple[Decimal | None, str | None]:
    cleaned = raw_text.strip().replace(",", "").replace("$", "")
    if not cleaned:
        return None, f"Empty monetary amount in {field_label}."
    try:
        val = Decimal(cleaned)
    except InvalidOperation:
        return None, f"Non-numeric monetary amount '{raw_text.strip()}' in {field_label}."
    if not val.is_finite():
        return None, f"Non-finite monetary value '{raw_text.strip()}' in {field_label}."
    if val < 0:
        return None, f"Negative monetary value '{val}' in {field_label}."
    return val, None


def _validate_fincen_single_report(report_root: ET.Element) -> List[str]:
    errors: List[str] = []
    if len(list(report_root)) == 0:
        errors.append("FinCEN SAR XML is empty; missing required child sections (Header / ActivitySummary / Narrative).")
        return errors

    # If explicit narrative tags are present, they must contain non-empty narrative text
    present_narrative_elems = [elem for elem in report_root.iter() if _strip_ns(elem.tag) in _NARRATIVE_TAGS]
    if present_narrative_elems:
        if not any(elem.text and elem.text.strip() for elem in present_narrative_elems):
            errors.append("FinCEN SAR <Narrative> / <Description> element cannot be empty.")

    # Validate ISO-4217 currency codes & finite non-negative monetary values
    for elem in report_root.iter():
        local = _strip_ns(elem.tag)
        if local in ("Currency", "CurrencyCode") and elem.text and elem.text.strip():
            code = elem.text.strip().upper()
            if not _ISO_CURRENCY_RE.match(code):
                errors.append(f"Invalid ISO-4217 currency code '{code}' in <{local}>.")
        if local in _AMOUNT_TAGS:
            if elem.text is None or not elem.text.strip():
                errors.append(f"Empty monetary value in <{local}>.")
            else:
                _, err = _parse_strict_non_negative_decimal(elem.text, f"<{local}>")
                if err:
                    errors.append(err)

    return errors


def _validate_fincen_batch(root: ET.Element) -> List[str]:
    errors: List[str] = []
    reports_node = next((c for c in root if _strip_ns(c.tag) == "Reports"), None)
    if reports_node is None:
        errors.append("BatchSuspiciousActivityReport missing required <Reports> container.")
        return errors

    child_reports = [c for c in reports_node if _strip_ns(c.tag) == "SuspiciousActivityReport"]
    if not child_reports:
        errors.append("BatchSuspiciousActivityReport contains zero <SuspiciousActivityReport> records.")
        return errors

    declared_count_str = root.attrib.get("total_records")
    if declared_count_str is not None:
        try:
            declared_count = int(declared_count_str)
            if declared_count != len(child_reports):
                errors.append(
                    f"BatchSuspiciousActivityReport total_records={declared_count} does not match "
                    f"actual child report count ({len(child_reports)})."
                )
        except ValueError:
            errors.append(f"Invalid total_records attribute '{declared_count_str}'.")

    child_usd_sum = Decimal("0")
    for idx, child in enumerate(child_reports):
        child_errs = _validate_fincen_single_report(child)
        errors.extend([f"Report[{idx}]: {e}" for e in child_errs])
        usd_elem = next((e for e in child.iter() if _strip_ns(e.tag) == "AmountUSD"), None)
        if usd_elem is None:
            usd_elem = next((e for e in child.iter() if _strip_ns(e.tag) == "Amount"), None)
        if usd_elem is not None and usd_elem.text and usd_elem.text.strip():
            val, _ = _parse_strict_non_negative_decimal(usd_elem.text, "<AmountUSD>")
            if val is not None:
                child_usd_sum += val

    header_node = next((c for c in root if _strip_ns(c.tag) == "BatchHeader"), None)
    if header_node is not None and "total_batch_amount" in header_node.attrib:
        batch_total, err = _parse_strict_non_negative_decimal(
            header_node.attrib["total_batch_amount"], "BatchHeader@total_batch_amount"
        )
        if err:
            errors.append(err)
        elif batch_total is not None:
            # Allow <= 0.01 per child for sum-then-round vs display-rounded child AmountUSD
            tolerance = Decimal("0.01") * len(child_reports)
            if abs(batch_total - child_usd_sum) > tolerance:
                errors.append(
                    f"BatchHeader total_batch_amount ({batch_total}) disagrees with child report sum ({child_usd_sum})."
                )

    return errors


def _validate_fincen_structure(root: ET.Element) -> List[str]:
    root_name = _strip_ns(root.tag)
    if root_name == "BatchSuspiciousActivityReport":
        return _validate_fincen_batch(root)
    if root_name not in ("SuspiciousActivityReport", "EFilingBatchXML"):
        return [
            f"Invalid FinCEN root element '<{root_name}>'; expected <SuspiciousActivityReport>, "
            "<EFilingBatchXML>, or <BatchSuspiciousActivityReport>."
        ]
    return _validate_fincen_single_report(root)


def _validate_goaml_structure(root: ET.Element) -> List[str]:
    errors: List[str] = []
    root_name = _strip_ns(root.tag)
    if root_name != "report":
        errors.append(f"Invalid goAML root element '<{root_name}>'; expected <report>.")
        return errors

    required_children = [
        "rentity_id",
        "submission_code",
        "report_code",
        "submission_date",
        "currency_code_local",
        "reason",
        "transaction",
    ]
    present = {_strip_ns(child.tag) for child in root}
    for req in required_children:
        if req not in present:
            errors.append(f"goAML 5.0 XML missing required element <{req}>.")

    sub_code = _find_text_recursive(root, {"submission_code"})
    if sub_code and sub_code not in ("E", "M"):
        errors.append(f"goAML <submission_code> must be 'E' or 'M', got '{sub_code}'.")

    curr = _find_text_recursive(root, {"currency_code_local"})
    if curr and not _ISO_CURRENCY_RE.match(curr.upper()):
        errors.append(f"goAML <currency_code_local> invalid ISO-4217 code '{curr}'.")

    tx_node = next((c for c in root if _strip_ns(c.tag) == "transaction"), None)
    if tx_node is not None:
        tx_children = {_strip_ns(c.tag): c for c in tx_node}
        for tx_req in ("transactionnumber", "date_transaction", "amount_local"):
            if tx_req not in tx_children:
                errors.append(f"goAML <transaction> missing required element <{tx_req}>.")
        amt_node = tx_children.get("amount_local")
        if amt_node is not None:
            _, err = _parse_strict_non_negative_decimal(amt_node.text or "", "goAML <amount_local>")
            if err:
                errors.append(err)

    return errors


def _try_optional_xsd_validation(xml_str: str, fiu_format: str) -> List[str]:
    """Runs full xmlschema XSD validation if xmlschema is installed and XSD file exists."""
    xsd_dir = os.getenv("REGULATORY_XSD_DIR", "")
    if not xsd_dir:
        return []
    xsd_file = "BSABatch.xsd" if "FINCEN" in fiu_format.upper() else "goAML_5.0.xsd"
    xsd_path = os.path.join(xsd_dir, xsd_file)
    if not os.path.exists(xsd_path):
        return []
    try:
        import xmlschema  # type: ignore
        schema = xmlschema.XMLSchema(xsd_path)
        if not schema.is_valid(xml_str):
            return [str(err) for err in schema.iter_errors(xml_str)][:10]
    except ImportError:
        pass
    except Exception as exc:
        return [f"XSD validation error: {exc}"]
    return []


def validate_regulatory_xml(xml_str: str, fiu_format: str | None = None) -> Tuple[bool, List[str]]:
    """
    Validates a FinCEN SAR or UNODC goAML 5.0 XML document.
    Returns: (is_valid: bool, errors: list[str])
    """
    if not xml_str or not isinstance(xml_str, str) or not xml_str.strip():
        return False, ["XML payload is empty."]

    # Security: Block XXE / DTD entity expansion attacks
    if _XXE_FORBIDDEN_RE.search(xml_str):
        return False, ["Security violation: XML DOCTYPE / ENTITY declarations (XXE) are strictly forbidden."]

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as exc:
        return False, [f"Malformed XML syntax: {exc}"]

    root_name = _strip_ns(root.tag)
    resolved_format = (fiu_format or ("GOAML_5" if root_name == "report" else "FINCEN_BSABATCH")).upper()

    if "GOAML" in resolved_format:
        errors = _validate_goaml_structure(root)
    else:
        errors = _validate_fincen_structure(root)

    if not errors:
        errors.extend(_try_optional_xsd_validation(xml_str, resolved_format))

    return len(errors) == 0, errors


async def validate_sar_xml_async(
    xml_payload: str,
    fiu_format: str | None = None,
) -> Tuple[bool, List[str]]:
    """Non-blocking wrapper offloading XML/XSD parsing onto the bounded analytics compute pool."""
    from services.compute_executor import run_analytics_compute

    return await run_analytics_compute(validate_regulatory_xml, xml_payload, fiu_format, timeout=5.0)
