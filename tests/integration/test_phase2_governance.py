"""
Integration test for Phase 2: Governance, RBAC, Dual-Control & Machine Auth
===========================================================================
"""

import pytest
import uuid
from services.auth import RoleChecker, PermissionChecker, ROLE_HIERARCHY
from services.api_keys import generate_api_key, verify_api_key
from services.masking import mask_pii_data
from database.postgres import get_async_db_conn
from fastapi import HTTPException

@pytest.mark.asyncio
async def test_role_hierarchy_and_permissions():
    l1_user = {"id": str(uuid.uuid4()), "role": "L1_ANALYST", "username": "analyst1"}
    mlro_user = {"id": str(uuid.uuid4()), "role": "MLRO", "username": "mlro1"}

    # L1 analyst has alerts:triage but not sar:approve
    perm_triage = PermissionChecker("alerts:triage")
    assert perm_triage(l1_user) == l1_user

    perm_approve = PermissionChecker("sar:approve")
    assert perm_approve(mlro_user) == mlro_user

    with pytest.raises(HTTPException) as exc_info:
        perm_approve(l1_user)
    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_m2m_api_key_generation_and_verification():
    tenant_id = "00000000-0000-0000-0000-000000000001"
    key_meta, raw_key = await generate_api_key(
        tenant_id=tenant_id,
        name="Core-Banking-Ingest",
        scopes=["transactions:ingest"]
    )
    assert raw_key.startswith("aml_live_")
    assert key_meta["name"] == "Core-Banking-Ingest"

    # Verify key
    verified = await verify_api_key(raw_key)
    assert verified is not None
    assert verified["role"] == "API_CONSUMER"
    assert verified["tenant_id"] == tenant_id
    assert "transactions:ingest" in verified["scopes"]

    # Verify invalid key
    invalid = await verify_api_key("aml_live_invalid_fakekey")
    assert invalid is None


def test_auditor_pii_masking():
    data = {
        "owner_name": "Alice Johnson",
        "account_number": "ACCT-9876543210",
        "tax_id": "TAX-123456",
        "risk_score": 0.85
    }

    # For analyst, PII remains intact
    analyst_view = mask_pii_data(data, role="ANALYST")
    assert analyst_view["owner_name"] == "Alice Johnson"
    assert analyst_view["account_number"] == "ACCT-9876543210"

    # For auditor, PII is masked
    auditor_view = mask_pii_data(data, role="AUDITOR")
    assert auditor_view["owner_name"] != "Alice Johnson"
    assert "Alice" not in auditor_view["owner_name"]
    assert auditor_view["account_number"].startswith("******")
    assert auditor_view["account_number"].endswith("3210")
    assert auditor_view["risk_score"] == 0.85


from routers.fincen import create_sar_draft, review_sar_draft, SARDraftCreate, SARDraftReview

@pytest.mark.asyncio
async def test_sar_drafting_and_four_eyes_dual_control():
    tenant_id = "00000000-0000-0000-0000-000000000001"
    alert_id = str(uuid.uuid4())
    drafter_id = str(uuid.uuid4())
    mlro_id = str(uuid.uuid4())

    drafter_user = {"id": drafter_id, "username": "analyst_sam", "role": "L1_ANALYST", "tenant_id": tenant_id}
    mlro_user = {"id": mlro_id, "username": "officer_dane", "role": "MLRO", "tenant_id": tenant_id}

    # Pre-seed alert in database to satisfy foreign key constraint
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        await conn.execute(
            """
            INSERT INTO alerts (id, tenant_id, rule_name, threat_level, ai_risk_score, status)
            VALUES ($1, $2, 'STRUCTURING', 'CRITICAL', 0.95, 'OPEN');
            """,
            uuid.UUID(alert_id), uuid.UUID(tenant_id)
        )

    # 1. Analyst creates SAR draft
    draft_req = SARDraftCreate(
        alert_id=alert_id,
        narrative="Customer conducted multiple structured wire transfers under reporting threshold."
    )
    draft_resp = await create_sar_draft(payload=draft_req, current_user=drafter_user)
    assert draft_resp["status"] == "PENDING_MLRO_REVIEW"
    draft_id = draft_resp["draft_id"]

    # 2. Drafter attempts to approve their own draft (Segregation of Duties violation)
    review_req = SARDraftReview(action="APPROVE")
    with pytest.raises(HTTPException) as exc:
        await review_sar_draft(id=draft_id, payload=review_req, current_user=drafter_user)
    assert exc.value.status_code == 403
    assert "Segregation of Duties" in exc.value.detail

    # 3. Independent MLRO approves the draft
    mlro_resp = await review_sar_draft(id=draft_id, payload=review_req, current_user=mlro_user)
    assert mlro_resp["status"] == "APPROVED"
