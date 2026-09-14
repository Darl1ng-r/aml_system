"""
Integration test for Phase 4: Travel Rule, Feature Store, PII Encryption, Reporting & Privacy
=============================================================================================
"""

import pytest
import uuid
from datetime import datetime, timezone
from services.travel_rule import validate_travel_rule
from services.feature_store import record_transaction_feature_event, get_rolling_window_features
from services.encryption import encrypt_pii, decrypt_pii
from services.adverse_media import evaluate_adverse_media_text
from services.iso20022 import parse_pacs008_message
from routers.compliance_reporting import get_sar_summary, get_ctr_summary, get_conversion_rates, get_kyc_status
from routers.privacy import create_legal_hold, release_legal_hold, export_data_subject_dossier, LegalHoldCreate
from database.postgres import get_async_db_conn

TENANT_ID = "00000000-0000-0000-0000-000000000001"


def test_fatf_travel_rule_validation():
    # Compliant $10,000 wire transfer
    originator_valid = {
        "name": "Global Corp Ltd",
        "account_number": "ACC-1001",
        "address": "10 Wall St, New York, NY"
    }
    beneficiary_valid = {
        "name": "Pacific Imports S.A.",
        "account_number": "ACC-2002"
    }
    is_valid, missing = validate_travel_rule(
        amount=10000.0,
        currency="USD",
        channel="WIRE",
        originator_info=originator_valid,
        beneficiary_info=beneficiary_valid
    )
    assert is_valid is True
    assert len(missing) == 0

    # Non-compliant wire transfer (missing originator address/identifier)
    originator_incomplete = {
        "name": "Global Corp Ltd",
        "account_number": "ACC-1001"
    }
    is_valid, missing = validate_travel_rule(
        amount=10000.0,
        currency="USD",
        channel="WIRE",
        originator_info=originator_incomplete,
        beneficiary_info=beneficiary_valid
    )
    assert is_valid is False
    assert "originator_address_or_identifier" in missing


def test_field_level_pii_encryption_aes_gcm():
    sensitive_tin = "987-65-4321"
    ciphertext = encrypt_pii(sensitive_tin)

    assert ciphertext != sensitive_tin
    assert len(ciphertext) > 20

    decrypted = decrypt_pii(ciphertext)
    assert decrypted == sensitive_tin


def test_adverse_media_evaluation():
    article = (
        "Authorities in Frankfurt today announced charges against suspect Viktor Vance "
        "for orchestrating an elaborate money laundering and fraud network involving shell companies."
    )
    res = evaluate_adverse_media_text(subject_name="Viktor Vance", article_text=article)
    assert res["match_found"] is True
    assert "FINANCIAL_CRIME" in res["matched_categories"]
    assert res["risk_score"] > 0.30
    assert res["edd_recommended"] is False or res["edd_recommended"] is True

    # Clean article
    clean_article = "Viktor Vance attended the European Chess Championship awards ceremony in Berlin."
    clean_res = evaluate_adverse_media_text(subject_name="Viktor Vance", article_text=clean_article)
    assert clean_res["match_found"] is False


def test_iso20022_pacs008_parser():
    pacs008_sample = """<?xml version="1.0" encoding="UTF-8"?>
    <Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">
      <FIToFICstmrCdtTrf>
        <GrpHdr>
          <MsgId>SWIFT-MSG-20260914-001</MsgId>
        </GrpHdr>
        <CdtTrfTxInf>
          <IntrBkSttlmAmt Ccy="USD">150000.00</IntrBkSttlmAmt>
          <Dbtr>
            <Nm>Acme Global Trade</Nm>
          </Dbtr>
          <DbtrAcct>
            <Id>
              <IBAN>US1234567890123456</IBAN>
            </Id>
          </DbtrAcct>
          <Cdtr>
            <Nm>Zurich Financial AG</Nm>
          </Cdtr>
          <CdtrAcct>
            <Id>
              <IBAN>CH9876543210987654</IBAN>
            </Id>
          </CdtrAcct>
        </CdtTrfTxInf>
      </FIToFICstmrCdtTrf>
    </Document>
    """
    parsed = parse_pacs008_message(pacs008_sample)
    assert parsed["message_id"] == "SWIFT-MSG-20260914-001"
    assert parsed["amount"] == 150000.00
    assert parsed["currency"] == "USD"
    assert parsed["sender_name"] == "Acme Global Trade"
    assert parsed["receiver_name"] == "Zurich Financial AG"
    assert parsed["sender_account"] == "US1234567890123456"
    assert parsed["receiver_account"] == "CH9876543210987654"


@pytest.mark.asyncio
async def test_real_time_feature_store():
    test_acc_id = f"acc_{uuid.uuid4().hex[:8]}"
    tx_id = f"tx_{uuid.uuid4().hex[:8]}"

    # Record feature event
    await record_transaction_feature_event(account_id=test_acc_id, amount=12500.0, tx_id=tx_id)

    # Query rolling window aggregates
    metrics = await get_rolling_window_features(account_id=test_acc_id)
    assert metrics["velocity_1h"] >= 1
    assert metrics["amount_1h"] >= 12500.0


@pytest.mark.asyncio
async def test_compliance_reporting_and_privacy():
    auditor = {"id": str(uuid.uuid4()), "username": "auditor_claire", "role": "AUDITOR", "tenant_id": TENANT_ID}
    mlro = {"id": str(uuid.uuid4()), "username": "mlro_david", "role": "MLRO", "tenant_id": TENANT_ID}

    # 1. Reports API
    sar_sum = await get_sar_summary(current_user=auditor)
    assert "total_sar_drafts" in sar_sum

    ctr_sum = await get_ctr_summary(current_user=auditor)
    assert "total_ctrs" in ctr_sum

    rates = await get_conversion_rates(current_user=auditor)
    assert "alert_to_case_conversion_pct" in rates

    kyc_stat = await get_kyc_status(current_user=auditor)
    assert "total_scheduled_kyc" in kyc_stat

    # 2. Privacy Legal Hold & DSAR
    acc_number = f"ACCT-DSAR-{uuid.uuid4().hex[:6]}"
    acc_id = str(uuid.uuid4())

    async with get_async_db_conn(tenant_id=TENANT_ID) as conn:
        await conn.execute(
            "INSERT INTO accounts (id, tenant_id, account_number, owner_name, status) VALUES ($1, $2, $3, 'Robert Test', 'ACTIVE');",
            uuid.UUID(acc_id), uuid.UUID(TENANT_ID), acc_number
        )

    hold_req = LegalHoldCreate(
        account_id=acc_id,
        reference_number="SUBPOENA-2026-0042",
        reason="DOJ subpoena regarding related party wire activities."
    )
    hold_res = await create_legal_hold(payload=hold_req, current_user=mlro)
    assert hold_res["status"] == "ACTIVE"
    hold_id = hold_res["hold_id"]

    # Export DSAR Dossier
    dsar_dossier = await export_data_subject_dossier(account_number=acc_number, current_user=auditor)
    assert dsar_dossier["account"]["account_number"] == acc_number
    assert len(dsar_dossier["legal_holds_active"]) >= 1

    # Release Legal Hold
    rel_res = await release_legal_hold(id=hold_id, current_user=mlro)
    assert rel_res["status"] == "RELEASED"
