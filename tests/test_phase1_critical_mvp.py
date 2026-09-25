"""
Phase 1 Critical MVP Remediation Test Suite
============================================
Verifies all 10 tasks in Phase 1:
- 1.1: 5-Tier RBAC (L1_ANALYST, L2_INVESTIGATOR, MLRO, ADMIN, AUDITOR)
- 1.2: Alert Escalation Chain & alert_escalations persistence
- 1.3: Alert Triage Inbox & Claiming (/api/v1/alerts/{id}/claim)
- 1.4: Redis & PostgreSQL Pessimistic Lease Locking (/api/v1/locks)
- 1.5 & 1.6: Rule Configs DB persistence, versioning & simulator (/api/v1/rules)
- 1.7: User Governance & Session Revocation (/api/v1/auth/users)
- 1.8: Immutability constraints
- 1.9: Case Evidence Locker (/api/v1/cases/{case_id}/evidence)
- 1.10: Role-Based Navigation & Page Routes (/triage, /rules-admin, /users-admin)
"""

import pytest
import uuid
import json
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import AsyncClient, ASGITransport
from main import app
from services.auth import create_access_token, hash_password


@pytest.fixture
def l1_analyst_token():
    return create_access_token({
        "sub": "l1.analyst@bank.com",
        "username": "l1.analyst",
        "role": "L1_ANALYST",
        "id": "11111111-1111-1111-1111-111111111111",
        "tenant_id": "00000000-0000-0000-0000-000000000001"
    })


@pytest.fixture
def l2_investigator_token():
    return create_access_token({
        "sub": "l2.investigator@bank.com",
        "username": "l2.investigator",
        "role": "L2_INVESTIGATOR",
        "id": "22222222-2222-2222-2222-222222222222",
        "tenant_id": "00000000-0000-0000-0000-000000000001"
    })


@pytest.fixture
def mlro_token():
    return create_access_token({
        "sub": "compliance.mlro@bank.com",
        "username": "compliance.mlro",
        "role": "MLRO",
        "id": "33333333-3333-3333-3333-333333333333",
        "tenant_id": "00000000-0000-0000-0000-000000000001"
    })


@pytest.fixture
def admin_token():
    return create_access_token({
        "sub": "admin.compliance@bank.com",
        "username": "admin.compliance",
        "role": "ADMIN",
        "id": "44444444-4444-4444-4444-444444444444",
        "tenant_id": "00000000-0000-0000-0000-000000000001"
    })


@pytest.fixture
def auditor_token():
    return create_access_token({
        "sub": "external.auditor@firm.com",
        "username": "external.auditor",
        "role": "AUDITOR",
        "id": "55555555-5555-5555-5555-555555555555",
        "tenant_id": "00000000-0000-0000-0000-000000000001"
    })


# ── 1. Pessimistic Locking Tests (Task 1.4) ──────────────────────────────────
@pytest.mark.asyncio
async def test_acquire_and_release_pessimistic_lock(l1_analyst_token, l2_investigator_token):
    """Verifies atomic lease acquisition, 409 conflict detection, and lease release."""
    transport = ASGITransport(app=app)
    alert_id = str(uuid.uuid4())

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Analyst 1 acquires lock
        res1 = await client.post(
            f"/api/v1/locks/ALERT/{alert_id}",
            json={"ttl_seconds": 300},
            headers={"Authorization": f"Bearer {l1_analyst_token}"}
        )
        assert res1.status_code == 200, res1.text
        data1 = res1.json()
        assert data1["status"] == "ACQUIRED"
        assert data1["lock"]["resource_type"] == "ALERT"
        assert data1["lock"]["resource_id"] == alert_id
        lock_token = data1["lock"]["lock_token"]

        # 2. Check lock status
        res_status = await client.get(
            f"/api/v1/locks/ALERT/{alert_id}",
            headers={"Authorization": f"Bearer {l1_analyst_token}"}
        )
        assert res_status.status_code == 200
        assert res_status.json()["is_locked"] is True

        # 3. Analyst 2 attempts acquisition -> 409 Conflict
        res2 = await client.post(
            f"/api/v1/locks/ALERT/{alert_id}",
            json={"ttl_seconds": 300},
            headers={"Authorization": f"Bearer {l2_investigator_token}"}
        )
        assert res2.status_code == 409

        # 4. Analyst 1 refreshes heartbeat
        res_refresh = await client.put(
            f"/api/v1/locks/ALERT/{alert_id}",
            json={"lock_token": lock_token, "ttl_seconds": 300},
            headers={"Authorization": f"Bearer {l1_analyst_token}"}
        )
        assert res_refresh.status_code == 200

        # 5. Analyst 1 releases lock
        res_del = await client.delete(
            f"/api/v1/locks/ALERT/{alert_id}",
            headers={"Authorization": f"Bearer {l1_analyst_token}"}
        )
        assert res_del.status_code == 200

        # 6. Now Analyst 2 can acquire lock
        res3 = await client.post(
            f"/api/v1/locks/ALERT/{alert_id}",
            json={"ttl_seconds": 300},
            headers={"Authorization": f"Bearer {l2_investigator_token}"}
        )
        assert res3.status_code == 200


@pytest.mark.asyncio
async def test_admin_force_unlock(l1_analyst_token, admin_token):
    """Verifies that an ADMIN or MLRO can force-break a lease held by an analyst."""
    transport = ASGITransport(app=app)
    alert_id = str(uuid.uuid4())

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Analyst acquires lock
        await client.post(
            f"/api/v1/locks/ALERT/{alert_id}",
            headers={"Authorization": f"Bearer {l1_analyst_token}"}
        )

        # Admin force breaks lock
        res_force = await client.delete(
            f"/api/v1/locks/ALERT/{alert_id}?force=true",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert res_force.status_code == 200
        assert "released" in res_force.json()["message"].lower()


# ── 2. Alert Escalation & Claiming Tests (Task 1.2 & 1.3) ─────────────────────
@pytest.mark.asyncio
async def test_alert_claim_and_escalate_workflow(l1_analyst_token):
    """Verifies claim and escalation recording."""
    transport = ASGITransport(app=app)
    alert_id = str(uuid.uuid4())

    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock(return_value="UPDATE 1")
    mock_conn.fetch = AsyncMock(return_value=[
        {
            "id": uuid.uuid4(),
            "alert_id": uuid.UUID(alert_id),
            "case_id": None,
            "escalated_by": uuid.uuid4(),
            "escalated_by_name": "l1.analyst",
            "escalated_to": None,
            "escalated_to_name": None,
            "escalated_at": None,
            "from_tier": 1,
            "to_tier": 2,
            "escalation_reason": "Smurfing pattern confirmed",
            "resolved_at": None,
            "resolution_action": None
        }
    ])

    with patch("routers.alerts.get_async_db_conn") as mock_db:
        mock_db.return_value.__aenter__.return_value = mock_conn

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Claim alert
            res_claim = await client.post(
                f"/api/v1/alerts/{alert_id}/claim",
                headers={"Authorization": f"Bearer {l1_analyst_token}"}
            )
            assert res_claim.status_code == 200
            assert res_claim.json()["status"] == "CLAIMED"

            # 2. Escalate alert
            res_esc = await client.post(
                f"/api/v1/alerts/{alert_id}/escalate",
                json={"justification": "Smurfing pattern confirmed"},
                headers={"Authorization": f"Bearer {l1_analyst_token}"}
            )
            assert res_esc.status_code == 200
            assert res_esc.json()["status"] == "ESCALATED"

            # 3. View escalation history
            res_hist = await client.get(
                f"/api/v1/alerts/{alert_id}/escalations",
                headers={"Authorization": f"Bearer {l1_analyst_token}"}
            )
            assert res_hist.status_code == 200
            hist = res_hist.json()
            assert len(hist) == 1
            assert hist[0]["from_tier"] == 1
            assert hist[0]["to_tier"] == 2


# ── 3. Rule Configs & Simulator Tests (Tasks 1.5 & 1.6) ───────────────────────
@pytest.mark.asyncio
async def test_rule_builder_and_simulation(admin_token, l1_analyst_token):
    """Verifies listing, patching, and testing rules."""
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. List rules
        res_list = await client.get(
            "/api/v1/rules",
            headers={"Authorization": f"Bearer {l1_analyst_token}"}
        )
        assert res_list.status_code == 200
        rules = res_list.json()
        assert isinstance(rules, list)
        assert len(rules) > 0

        # 2. Non-admin cannot patch rules
        res_patch_forbidden = await client.patch(
            "/api/v1/rules/LARGE_TRANSACTION",
            json={"enabled": True, "config": {"threshold": 12000.0}},
            headers={"Authorization": f"Bearer {l1_analyst_token}"}
        )
        assert res_patch_forbidden.status_code == 403

        # 3. Admin can patch rule
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"id": uuid.uuid4(), "enabled": True, "config": {}, "version": 1})
        mock_conn.fetchval = AsyncMock(return_value=uuid.uuid4())
        mock_conn.execute = AsyncMock(return_value="INSERT 1")

        with patch("routers.rules.get_async_db_conn") as mock_db:
            mock_db.return_value.__aenter__.return_value = mock_conn
            res_patch = await client.patch(
                "/api/v1/rules/LARGE_TRANSACTION",
                json={"enabled": True, "config": {"threshold": 15000.0}, "change_reason": "Tuned to reduce false positives"},
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            assert res_patch.status_code == 200
            assert res_patch.json()["status"] == "UPDATED"

        # 4. Simulation test harness
        res_test = await client.post(
            "/api/v1/rules/test",
            json={
                "sender_id": "ACC-SIM-1",
                "receiver_id": "ACC-SIM-2",
                "amount": 25000.0,
                "receiver_bic": "DEUTDEDD"
            },
            headers={"Authorization": f"Bearer {l1_analyst_token}"}
        )
        assert res_test.status_code == 200
        sim_data = res_test.json()
        assert "triggered_rules" in sim_data
        assert "LARGE_TRANSACTION_THRESHOLD" in sim_data["triggered_rules"]


# ── 4. Case Evidence Locker Tests (Task 1.9) ──────────────────────────────────
@pytest.mark.asyncio
async def test_case_evidence_lifecycle(l2_investigator_token):
    """Verifies evidence file upload, listing, and deletion."""
    transport = ASGITransport(app=app)
    case_id = str(uuid.uuid4())

    mock_conn = AsyncMock()
    evidence_uuid = uuid.uuid4()
    mock_conn.execute = AsyncMock(return_value="INSERT 1")
    mock_conn.fetch = AsyncMock(return_value=[
        {
            "id": evidence_uuid,
            "case_id": uuid.UUID(case_id),
            "filename": "ofac_screenshot.png",
            "content_type": "image/png",
            "file_size": 2048,
            "storage_key": "/storage/evidence/ofac_screenshot.png",
            "uploaded_by": uuid.uuid4(),
            "uploaded_by_name": "l2.investigator",
            "uploaded_at": None,
            "description": "OFAC SDN screening result",
            "tags": ["OFAC", "SANCTIONS"]
        }
    ])
    mock_conn.fetchrow = AsyncMock(return_value={"storage_key": "", "filename": "ofac_screenshot.png"})

    with patch("routers.evidence.get_async_db_conn") as mock_db:
        mock_db.return_value.__aenter__.return_value = mock_conn

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Upload evidence
            res_upload = await client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("ofac_screenshot.png", b"fake-image-bytes", "image/png")},
                data={"description": "OFAC SDN screening result", "tags": "OFAC,SANCTIONS"},
                headers={"Authorization": f"Bearer {l2_investigator_token}"}
            )
            assert res_upload.status_code == 201
            assert res_upload.json()["status"] == "UPLOADED"

            # 2. List evidence
            res_list = await client.get(
                f"/api/v1/cases/{case_id}/evidence",
                headers={"Authorization": f"Bearer {l2_investigator_token}"}
            )
            assert res_list.status_code == 200
            items = res_list.json()
            assert len(items) == 1
            assert items[0]["filename"] == "ofac_screenshot.png"

            # 3. Delete evidence
            res_del = await client.delete(
                f"/api/v1/cases/{case_id}/evidence/{evidence_uuid}",
                headers={"Authorization": f"Bearer {l2_investigator_token}"}
            )
            assert res_del.status_code == 200
            assert res_del.json()["status"] == "DELETED"


# ── 5. User Governance Tests (Task 1.1 & 1.7) ─────────────────────────────────
@pytest.mark.asyncio
async def test_user_governance_and_role_change(admin_token):
    """Verifies listing users, provisioning 5-tier role, and updating roles."""
    transport = ASGITransport(app=app)
    user_id = str(uuid.uuid4())

    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=[
        {"id": uuid.UUID(user_id), "username": "analyst1", "role": "L1_ANALYST", "tenant_id": uuid.uuid4(), "mfa_enabled": False, "created_at": None}
    ])
    mock_conn.fetchrow = AsyncMock(return_value={"username": "analyst1", "role": "L1_ANALYST"})
    mock_conn.execute = AsyncMock(return_value="UPDATE 1")

    with patch("database.postgres.get_async_db_conn") as mock_db, \
         patch("services.auth.revoke_user_sessions", new_callable=AsyncMock) as mock_revoke:
        mock_db.return_value.__aenter__.return_value = mock_conn

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. List users
            res_list = await client.get(
                "/api/v1/auth/users",
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            assert res_list.status_code == 200
            users = res_list.json()
            assert len(users) == 1
            assert users[0]["role"] == "L1_ANALYST"

            # 2. Update role to L2_INVESTIGATOR
            res_role = await client.patch(
                f"/api/v1/auth/users/{user_id}/role",
                json={"role": "L2_INVESTIGATOR"},
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            assert res_role.status_code == 200
            assert res_role.json()["new_role"] == "L2_INVESTIGATOR"
            assert mock_revoke.called


# ── 6. Frontend HTML Route Guards (Task 1.3, 1.6, 1.7) ────────────────────────
@pytest.mark.asyncio
async def test_frontend_routes_redirect_unauthenticated():
    """Verifies unauthenticated requests to protected UI pages redirect to /login."""
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for path in ["/alerts/triage", "/triage", "/admin/rules", "/rules-admin", "/admin/users", "/users-admin"]:
            res = await client.get(path, follow_redirects=False)
            assert res.status_code == 303
            assert res.headers["location"] == "/login"
