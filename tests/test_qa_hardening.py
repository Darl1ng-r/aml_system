"""
QA Hardening Regression Suite
Verifies all 4 concrete runtime/compliance defects uncovered during the end-to-end AML QA audit:
  1. Audit hash-chain concurrency serialization (pg_advisory_xact_lock) -> VALID chain
  2. PostgreSQL pep_entities fallback schema alignment in routers/screening.py
  3. Non-UUID account_number resolution in services/rules.py + clean retail transfer materiality floor
  4. Self-transfer rejection (HTTP 422) at Pydantic TransactionRequest layer
"""
import asyncio
from datetime import datetime, timezone
import logging
import pytest
from httpx import AsyncClient, ASGITransport

from main import app
from database.postgres import init_db_pool, get_async_db_conn, get_async_db_read_conn
from routers.auth import create_access_token
from services.audit import record_audit_event_tx

DEFAULT_TENANT = "00000000-0000-0000-0000-000000000001"


async def _admin_headers() -> dict:
    await init_db_pool()
    async with get_async_db_read_conn(tenant_id=DEFAULT_TENANT) as conn:
        u = await conn.fetchrow(
            "SELECT id, username, role, tenant_id FROM users WHERE role IN ('ADMIN', 'MLRO') LIMIT 1;"
        )
    token = create_access_token(
        {
            "sub": u["username"],
            "user_id": str(u["id"]),
            "role": u["role"],
            "tenant_id": str(u["tenant_id"]),
        }
    )
    return {"Authorization": f"Bearer {token}", "X-Requested-With": "XMLHttpRequest"}


@pytest.mark.anyio
async def test_qa_1_concurrent_audit_hash_chain_remains_valid():
    headers = await _admin_headers()

    async def write_one(i: int):
        async with get_async_db_conn(tenant_id=DEFAULT_TENANT) as conn:
            async with conn.transaction():
                await record_audit_event_tx(
                    conn=conn,
                    action="QA_CONCURRENCY_CHECK",
                    actor_id="qa-harness",
                    actor_role="ADMIN",
                    resource_type="SYSTEM",
                    resource_id=f"qa-concurrent-{i}",
                    tenant_id=DEFAULT_TENANT,
                    details={"seq": i},
                )

    await asyncio.gather(*(write_one(i) for i in range(6)))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.get("/api/v1/audit/verify-chain", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "VALID", body
        assert body["tampered"] is False


@pytest.mark.anyio
async def test_qa_2_screening_pg_fallback_has_no_column_errors(caplog):
    headers = await _admin_headers()
    caplog.set_level(logging.WARNING, logger="routers.screening")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            "/api/v1/screening/search",
            headers=headers,
            json={"name": "Vladimir Putin", "entity_type": "INDIVIDUAL"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["match_found"] is True

    warning_text = " ".join(r.getMessage() for r in caplog.records)
    assert "source_database" not in warning_text
    assert "pep_tier" not in warning_text


@pytest.mark.anyio
async def test_qa_3_rules_sandbox_non_uuid_and_clean_retail_transfer(caplog):
    headers = await _admin_headers()
    caplog.set_level(logging.ERROR, logger="services.rules")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            "/api/v1/rules/test",
            headers=headers,
            json={
                "sender_id": "ACC-QA-CLEAN-991",
                "receiver_id": "ACC-QA-CLEAN-992",
                "amount": 42.50,
                "sender_name": "Alice Retail",
                "receiver_name": "Bob Bakery",
                "sender_bic": "DEUTDEDD",
                "receiver_bic": "CHASUS33",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["triggered_count"] == 0, data

    error_text = " ".join(r.getMessage() for r in caplog.records)
    assert "invalid UUID" not in error_text


@pytest.mark.anyio
async def test_qa_4_transaction_rejects_self_transfer_422():
    headers = await _admin_headers()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        resp = await ac.post(
            "/api/v1/transactions",
            headers=headers,
            json={
                "sender_account": "ACC-SELF-001",
                "receiver_account": "ACC-SELF-001",
                "amount": 250.0,
                "currency": "USD",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
        assert resp.status_code == 422
        assert "different" in resp.text.lower()
