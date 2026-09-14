"""
Integration test for Phase 3: Case Management, CIP, Account Freeze, EDD & CTR
=============================================================================
"""

import pytest
import uuid
from datetime import datetime, timezone
from database.postgres import get_async_db_conn
from routers.cases import create_case, add_case_note, close_case, CaseCreateRequest, CaseNoteRequest, CaseCloseRequest
from routers.accounts import (
    verify_account_cip, freeze_account, unfreeze_account,
    create_edd_request, decide_edd_request,
    CIPVerifyRequest, AccountFreezeRequest, EDDCreateRequest, EDDDecisionRequest
)
from routers.ctr import submit_ctr_filing
from fastapi import HTTPException

TENANT_ID = "00000000-0000-0000-0000-000000000001"


@pytest.mark.asyncio
async def test_case_management_lifecycle():
    investigator = {"id": str(uuid.uuid4()), "username": "inv_sarah", "role": "L2_INVESTIGATOR", "tenant_id": TENANT_ID}
    alert_id = str(uuid.uuid4())

    async with get_async_db_conn(tenant_id=TENANT_ID) as conn:
        await conn.execute(
            "INSERT INTO alerts (id, tenant_id, rule_name, threat_level, ai_risk_score, status) VALUES ($1, $2, 'RAPID_MOVEMENT', 'HIGH', 0.88, 'OPEN');",
            uuid.UUID(alert_id), uuid.UUID(TENANT_ID)
        )

    # 1. Create Case
    case_req = CaseCreateRequest(
        title="Rapid Movement of Funds Investigation",
        priority="HIGH",
        alert_ids=[alert_id],
        narrative="Multiple rapid transactions detected shortly after account opening."
    )
    case_res = await create_case(payload=case_req, current_user=investigator)
    assert case_res["status"] == "OPEN"
    assert case_res["alert_count"] == 1
    case_id = case_res["case_id"]

    # 2. Add Note
    note_req = CaseNoteRequest(note="Contacted originating institution for source of funds confirmation.")
    note_res = await add_case_note(id=case_id, payload=note_req, current_user=investigator)
    assert "note_id" in note_res

    # 3. Close Case
    close_req = CaseCloseRequest(
        closure_reason="CLOSED_CLEARED",
        closing_notes="Originating bank confirmed legitimate corporate dividend distribution."
    )
    close_res = await close_case(id=case_id, payload=close_req, current_user=investigator)
    assert close_res["status"] == "CLOSED"
    assert close_res["closure_reason"] == "CLOSED_CLEARED"


@pytest.mark.asyncio
async def test_account_cip_and_freeze_enforcement():
    analyst = {"id": str(uuid.uuid4()), "username": "analyst_amy", "role": "L1_ANALYST", "tenant_id": TENANT_ID}
    mlro = {"id": str(uuid.uuid4()), "username": "officer_bob", "role": "MLRO", "tenant_id": TENANT_ID}
    account_id = str(uuid.uuid4())

    async with get_async_db_conn(tenant_id=TENANT_ID) as conn:
        await conn.execute(
            """
            INSERT INTO accounts (id, tenant_id, account_number, owner_name, status, risk_score)
            VALUES ($1, $2, $3, 'John Doe Test', 'CIP_PENDING', 0.20);
            """,
            uuid.UUID(account_id), uuid.UUID(TENANT_ID), f"ACCT-{uuid.uuid4().hex[:8]}"
        )

    # 1. CIP Verification Gate
    cip_req = CIPVerifyRequest(
        document_type="PASSPORT",
        document_number="P98765432",
        verification_notes="Passport authenticated successfully via secure scanner."
    )
    cip_res = await verify_account_cip(id=account_id, payload=cip_req, current_user=analyst)
    assert cip_res["status"] == "ACTIVE"

    # 2. Freeze Account under Sanctions Order
    freeze_req = AccountFreezeRequest(
        reason="OFAC SDN hit confirmation on beneficial owner",
        freezing_order_ref="OFAC-ORDER-2026-891"
    )
    freeze_res = await freeze_account(id=account_id, payload=freeze_req, current_user=mlro)
    assert freeze_res["status"] == "FROZEN"
    assert freeze_res["freezing_order_ref"] == "OFAC-ORDER-2026-891"

    # 3. Unfreeze Account
    unfreeze_res = await unfreeze_account(id=account_id, current_user=mlro)
    assert unfreeze_res["status"] == "ACTIVE"


@pytest.mark.asyncio
async def test_edd_request_workflow():
    analyst = {"id": str(uuid.uuid4()), "username": "analyst_amy", "role": "L1_ANALYST", "tenant_id": TENANT_ID}
    mlro = {"id": str(uuid.uuid4()), "username": "officer_bob", "role": "MLRO", "tenant_id": TENANT_ID}
    account_id = str(uuid.uuid4())

    async with get_async_db_conn(tenant_id=TENANT_ID) as conn:
        await conn.execute(
            """
            INSERT INTO accounts (id, tenant_id, account_number, owner_name, status, risk_score)
            VALUES ($1, $2, $3, 'Foreign Senior Official', 'ACTIVE', 0.85);
            """,
            uuid.UUID(account_id), uuid.UUID(TENANT_ID), f"ACCT-{uuid.uuid4().hex[:8]}"
        )

    # 1. Create EDD Request
    edd_req = EDDCreateRequest(
        account_id=account_id,
        trigger_reason="PEP_HIT",
        source_of_wealth="Inherited family mining assets and government service salary.",
        source_of_funds="Official ministry payroll wire transfer."
    )
    edd_res = await create_edd_request(payload=edd_req, current_user=analyst)
    assert edd_res["status"] == "PENDING"
    edd_id = edd_res["edd_id"]

    # Verify account status shifted to EDD_REQUIRED
    async with get_async_db_conn(tenant_id=TENANT_ID) as conn:
        acc_status = await conn.fetchval("SELECT status FROM accounts WHERE id = $1;", uuid.UUID(account_id))
        assert acc_status == "EDD_REQUIRED"

    # 2. MLRO Decision
    dec_req = EDDDecisionRequest(
        decision="APPROVED",
        notes="Source of wealth substantiated by independent tax declarations and audit statements."
    )
    dec_res = await decide_edd_request(id=edd_id, payload=dec_req, current_user=mlro)
    assert dec_res["status"] == "RESOLVED"
    assert dec_res["account_status"] == "ACTIVE"


@pytest.mark.asyncio
async def test_ctr_electronic_filing():
    mlro = {"id": str(uuid.uuid4()), "username": "officer_bob", "role": "MLRO", "tenant_id": TENANT_ID}
    account_id = str(uuid.uuid4())
    ctr_id = str(uuid.uuid4())

    async with get_async_db_conn(tenant_id=TENANT_ID) as conn:
        await conn.execute(
            """
            INSERT INTO accounts (id, tenant_id, account_number, owner_name, status)
            VALUES ($1, $2, $3, 'Large Cash Merchant LLC', 'ACTIVE');
            """,
            uuid.UUID(account_id), uuid.UUID(TENANT_ID), f"ACCT-{uuid.uuid4().hex[:8]}"
        )
        await conn.execute(
            """
            INSERT INTO ctr_filings (id, tenant_id, account_id, amount, currency, cash_in_out, status)
            VALUES ($1, $2, $3, 25000.00, 'USD', 'DEPOSIT', 'PENDING');
            """,
            uuid.UUID(ctr_id), uuid.UUID(TENANT_ID), uuid.UUID(account_id)
        )

    # MLRO submits CTR filing
    submit_res = await submit_ctr_filing(id=ctr_id, current_user=mlro)
    assert submit_res["status"] == "FILED"
    assert submit_res["fincen_tracking_id"].startswith("CTR-")
