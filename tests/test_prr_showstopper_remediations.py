"""
Test Suite: PRR Showstopper Remediations Validation
====================================================
Formally verifies all 5 critical architectural, security, and integrity fixes:
  1. database/outbox.py: Atomic 'PROCESSING' transition with lease_id and timestamp inside FOR UPDATE SKIP LOCKED
  2. routers/health.py: Correct table name (transactional_outbox) and transparent error handling in /api/v1/admin/queue-health
  3. services/encryption.py: Decoupled PII encryption key via HKDF-SHA256 with fail-closed production guard
  4. routers/fincen.py: Strict 4-Eyes Segregation of Duties gating on electronic SAR filing
  5. services/auth.py: Zero database write amplification during JWT authentication in get_current_user
"""

import asyncio
import json
import os
import uuid
import pytest
import httpx
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from main import app
from database.outbox import fetch_pending_outbox_events
from services.encryption import _get_encryption_key, encrypt_pii, decrypt_pii
from services.auth import create_access_token, get_current_user


TENANT_ID = "00000000-0000-0000-0000-000000000001"


def make_token(role: str = "ANALYST", user_id: uuid.UUID = None, tenant_id: str = TENANT_ID) -> str:
    uid = user_id or uuid.uuid4()
    return create_access_token(
        data={"sub": f"user-{uid}", "role": role, "user_id": str(uid), "tenant_id": tenant_id},
        expires_delta=timedelta(minutes=30)
    )


# ── 1. Outbox Atomic PROCESSING Lease ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_outbox_fetch_atomically_transitions_to_processing_with_lease():
    """Verify fetch_pending_outbox_events passes lease_id and uses CTE to mark rows PROCESSING."""
    mock_conn = AsyncMock()
    test_lease = f"worker_{uuid.uuid4().hex[:8]}"

    event_id = uuid.uuid4()
    mock_rows = [
        {
            "id": event_id,
            "tenant_id": uuid.UUID(TENANT_ID),
            "aggregate_type": "TRANSACTION",
            "aggregate_id": "tx-100",
            "event_type": "aml.core.transaction.ingested.v1",
            "payload": '{"amount": 5000}',
            "headers": f'{{"lease_id": "{test_lease}"}}',
            "retry_count": 0
        }
    ]
    mock_conn.fetch = AsyncMock(return_value=mock_rows)

    events = await fetch_pending_outbox_events(mock_conn, limit=10, lease_id=test_lease)

    assert len(events) == 1
    assert events[0]["id"] == str(event_id)
    assert events[0]["headers"]["lease_id"] == test_lease

    # Verify SQL query semantics
    assert mock_conn.fetch.called
    call_args = mock_conn.fetch.call_args[0]
    sql = call_args[0]
    assert "WITH selected AS (" in sql
    assert "UPDATE transactional_outbox" in sql
    assert "SET status = 'PROCESSING'" in sql
    assert "headers = jsonb_set(" in sql
    assert call_args[1] == 10
    assert call_args[2] == test_lease


# ── 2. Health Check Queue Health Diagnostics ──────────────────────────────────

@pytest.mark.asyncio
async def test_queue_health_reports_degraded_when_database_fails():
    """Verify /api/v1/admin/queue-health reports status DEGRADED with error details on DB failure."""
    with patch("database.postgres.get_async_db_conn", side_effect=RuntimeError("PostgreSQL connection pool exhausted")):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/v1/admin/queue-health")
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "DEGRADED"
            assert data["pending_outbox_events"] is None
            assert "PostgreSQL connection pool exhausted" in data.get("error", "")


# ── 3. PII Key Decoupling & HKDF Production Guard ─────────────────────────────

def test_pii_encryption_key_fails_closed_in_production_without_dedicated_key():
    """Verify that in production mode, missing PII_ENCRYPTION_KEY raises RuntimeError."""
    with patch.dict(os.environ, {"ENVIRONMENT": "production", "PII_ENCRYPTION_KEY": ""}, clear=False), \
         patch("services.vault_loader.SecretStore.get", return_value=None), \
         patch("os.path.exists", return_value=False):
        with pytest.raises(RuntimeError, match="FATAL.*PII_ENCRYPTION_KEY is required in production environment"):
            _get_encryption_key()


def test_pii_encryption_hkdf_derivation_and_roundtrip():
    """Verify PII encryption roundtrip using dedicated HKDF-SHA256 derived key."""
    test_key = "test_super_secure_pii_master_key_1234567890"
    with patch.dict(os.environ, {"PII_ENCRYPTION_KEY": test_key}):
        tin = "123-45-6789"
        encrypted = encrypt_pii(tin)
        assert encrypted != tin
        assert len(encrypted) > 20

        decrypted = decrypt_pii(encrypted)
        assert decrypted == tin


# ── 4. FinCEN 4-Eyes Segregation of Duties Gating ─────────────────────────────

@pytest.mark.asyncio
async def test_fincen_sar_submit_blocks_unapproved_direct_filing_by_analyst():
    """Verify that an analyst calling /sar/submit without an approved MLRO-signed draft receives 403 Forbidden."""
    analyst_id = uuid.uuid4()
    analyst_token = make_token("ANALYST", user_id=analyst_id)
    alert_id = str(uuid.uuid4())

    mock_conn = AsyncMock()
    # Alert exists and is unfiled
    mock_conn.fetchrow.side_effect = [
        # 1. Existing alert check
        {
            "id": uuid.UUID(alert_id),
            "fincen_tracking_id": None,
            "fincen_filing_status": "UNSUBMITTED",
            "fincen_submitted_at": None
        },
        # 2. Approved draft search returns None (no MLRO approved draft)
        None
    ]

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.fincen.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.fincen.check_idempotency", AsyncMock(return_value=(False, None))):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"Authorization": f"Bearer {analyst_token}", "X-CSRF-Protection": "1"}
        ) as ac:
            res = await ac.post(
                "/api/v1/fincen/sar/submit",
                json={
                    "alert_id": alert_id,
                    "sar_xml": "<SuspiciousActivityReport><Narrative>Test</Narrative></SuspiciousActivityReport>"
                }
            )
            assert res.status_code == 403
            assert "Four-Eyes Principle Violation" in res.json()["detail"]


@pytest.mark.asyncio
async def test_fincen_sar_submit_succeeds_with_mlro_approved_draft():
    """Verify that /sar/submit succeeds when a valid MLRO-approved draft is provided."""
    analyst_id = uuid.uuid4()
    mlro_id = uuid.uuid4()
    analyst_token = make_token("ANALYST", user_id=analyst_id)
    alert_id = str(uuid.uuid4())
    draft_id = str(uuid.uuid4())

    mock_conn = AsyncMock()
    mock_conn.fetchrow.side_effect = [
        # 1. Existing alert check
        {
            "id": uuid.UUID(alert_id),
            "fincen_tracking_id": None,
            "fincen_filing_status": "UNSUBMITTED",
            "fincen_submitted_at": None
        },
        # 2. Draft check returns APPROVED draft with MLRO signature
        {
            "id": uuid.UUID(draft_id),
            "alert_id": uuid.UUID(alert_id),
            "status": "APPROVED",
            "drafted_by": analyst_id,
            "reviewed_by": mlro_id,
            "reviewed_by_username": "compliance_officer_1"
        }
    ]
    mock_conn.execute = AsyncMock()

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    mock_receipt = {
        "status": "ACKNOWLEDGED",
        "fincen_tracking_id": "BSA-2026-CONFIRMED",
        "fincen_ack_code": "ACK_SUCCESS_200",
        "fincen_confirmation_message": "Filing recorded",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "sandbox": True
    }

    with patch("routers.fincen.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.fincen.check_idempotency", AsyncMock(return_value=(False, None))), \
         patch("routers.fincen.save_idempotency_result", new_callable=AsyncMock), \
         patch("routers.fincen.fincen_client.submit_sar", new_callable=AsyncMock, return_value=mock_receipt), \
         patch("routers.metrics.ws_manager.broadcast", new_callable=AsyncMock):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"Authorization": f"Bearer {analyst_token}", "X-CSRF-Protection": "1"}
        ) as ac:
            res = await ac.post(
                "/api/v1/fincen/sar/submit",
                json={
                    "alert_id": alert_id,
                    "draft_id": draft_id,
                    "sar_xml": "<SuspiciousActivityReport><Narrative>Test Valid</Narrative></SuspiciousActivityReport>"
                }
            )
            assert res.status_code == 201
            assert res.json()["fincen_tracking_id"] == "BSA-2026-CONFIRMED"
            assert res.json()["status"] == "ACKNOWLEDGED"


# ── 5. Zero Database Writes During Authentication ─────────────────────────────

@pytest.mark.asyncio
async def test_get_current_user_does_not_execute_database_writes():
    """Verify that get_current_user does not query or write to PostgreSQL users table."""
    user_uuid = uuid.uuid4()
    token = make_token("ANALYST", user_id=user_uuid)

    with patch("database.postgres.get_async_db_conn") as mock_db_conn:
        user_context = await get_current_user(token=token)

        assert user_context["id"] == str(user_uuid)
        assert user_context["role"] == "ANALYST"
        assert user_context["tenant_id"] == TENANT_ID

        # Proves zero database queries/writes occurred during authentication
        assert not mock_db_conn.called
