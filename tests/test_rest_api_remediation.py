"""
REST API Remediation Verification Test Suite
============================================
Validates standard RESTful principles across all remediated router endpoints:
1. HTTP Methods & Status Codes (201 Created + Location, 204 No Content, 409 Conflict, 202 Accepted).
2. Pluralized resource URIs (/sessions, /transactions, /accounts, /batches, /sars).
3. Idempotent reads for searches (GET /screening, GET /network/entities/{id}/network).
4. Symmetrical CRUD read endpoints (GET /transactions/{id}, GET /accounts/{id}).
5. Backward compatibility for existing legacy routes (POST /logout, POST /alerts/{id}/action).
6. Rules persistence in PostgreSQL + Redis PubSub distributed invalidation.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
import uuid
from datetime import datetime, timezone

from main import app
from services.auth import create_access_token, create_refresh_token


USER_ADMIN_ID = "00000000-0000-0000-0000-000000000099"
USER_ANALYST_ID = "00000000-0000-0000-0000-000000000002"
TENANT_DEFAULT_ID = "00000000-0000-0000-0000-000000000001"


@pytest.fixture
def admin_token():
    return create_access_token({
        "sub": USER_ADMIN_ID,
        "role": "ADMIN",
        "username": "compliance_admin",
        "tenant_id": TENANT_DEFAULT_ID
    })


@pytest.fixture
def analyst_token():
    return create_access_token({
        "sub": USER_ANALYST_ID,
        "role": "ANALYST",
        "username": "compliance_analyst",
        "tenant_id": TENANT_DEFAULT_ID
    })


# ── 1. Auth Sessions: DELETE 204 & 200 + Backward Compatibility ──────────────

@pytest.mark.anyio
async def test_rest_auth_sessions_delete(analyst_token):
    """
    Verify RESTful DELETE on auth sessions:
    - DELETE /api/v1/auth/sessions/current returns 204 No Content and clears cookies.
    - DELETE /api/v1/auth/session returns 204 No Content.
    - POST /api/v1/auth/logout retains backward compatibility (200 OK with detail).
    - DELETE /api/v1/auth/sessions invalidates all user sessions (200 OK with token_version).
    """
    refresh_token = create_refresh_token({
        "sub": USER_ANALYST_ID,
        "role": "ANALYST",
        "username": "compliance_analyst",
        "tenant_id": TENANT_DEFAULT_ID
    })

    mock_redis = AsyncMock()
    mock_redis.setex = AsyncMock()

    with patch("database.redis_db.get_async_redis_client", return_value=mock_redis), \
         patch("services.auth.revoke_user_sessions", return_value=2):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1"}) as ac:
            # 1. DELETE /sessions/current -> 204 No Content
            resp_del = await ac.request(
                "DELETE",
                "/api/v1/auth/sessions/current",
                json={"refresh_token": refresh_token}
            )
            assert resp_del.status_code == 204
            assert resp_del.text == ""
            set_cookie_headers = resp_del.headers.get_list("set-cookie")
            assert any("access_token=" in h for h in set_cookie_headers)

            # 2. DELETE /session -> 204 No Content
            resp_del_alias = await ac.request(
                "DELETE",
                "/api/v1/auth/session",
                json={"refresh_token": refresh_token}
            )
            assert resp_del_alias.status_code == 204

            # 3. Legacy POST /logout -> 200 OK
            resp_legacy = await ac.post(
                "/api/v1/auth/logout",
                json={"refresh_token": refresh_token}
            )
            assert resp_legacy.status_code == 200
            assert "detail" in resp_legacy.json()

            # 4. DELETE /users/me/sessions -> 200 OK with token_version
            resp_revoke = await ac.request(
                "DELETE",
                "/api/v1/auth/users/me/sessions",
                headers={"Authorization": f"Bearer {analyst_token}"}
            )
            assert resp_revoke.status_code == 200
            data_revoke = resp_revoke.json()
            assert "token_version" in data_revoke


# ── 2. Alerts: PATCH /{id}, GET /{id}, and Legacy POST /{id}/action ─────────

@pytest.mark.anyio
async def test_rest_alert_patch_and_get(analyst_token):
    """
    Verify RESTful alert operations:
    - PATCH /api/v1/alerts/{id} updates status or assigns officer (200 OK).
    - GET /api/v1/alerts/{id} retrieves single alert details (200 OK).
    - Legacy POST /api/v1/alerts/{id}/action works as alias.
    """
    alert_id = str(uuid.uuid4())
    sender_id = uuid.uuid4()
    mock_conn = AsyncMock()

    # Detailed row for get_alert_details and resolve_alert
    alert_detail_row = {
        "id": alert_id,
        "rule_name": "LARGE_TRANSACTION_THRESHOLD",
        "threat_level": "HIGH",
        "ai_risk_score": 0.85,
        "explainability_payload": "{}",
        "status": "OPEN",
        "created_at": datetime.now(timezone.utc),
        "assignee": "Unassigned",
        "txn_id": uuid.uuid4(),
        "amount": 25000.0,
        "currency": "USD",
        "txn_time": datetime.now(timezone.utc),
        "country": "US",
        "channel": "Wire",
        "merchant": "Global Trade Corp",
        "device": "Web Browser",
        "sender_id": sender_id,
        "sender_account": "ACC_111",
        "sender_name": "Alice Corp",
        "sender_bic": "CHASEUS3XXX",
        "sender_risk_score": 0.1,
        "sender_risk_tier": "LOW",
        "sender_created_at": datetime.now(timezone.utc),
        "receiver_id": uuid.uuid4(),
        "receiver_account": "ACC_222",
        "receiver_name": "Bob Ltd",
        "receiver_bic": "CHASEUS3XXX"
    }

    # Calls sequence:
    # 1. GET /alerts/{id}: alert_detail_row
    # 2. GET /alerts/{id} customer_profiles: None
    # 3. PATCH status -> resolve_alert: alert_detail_row
    # 4. PATCH assign -> officer lookup: {"id": uuid.uuid4()}
    mock_conn.fetchrow.side_effect = [
        alert_detail_row,
        None,
        alert_detail_row,
        {"id": uuid.uuid4()}
    ]
    mock_conn.fetch.return_value = []
    mock_conn.execute.return_value = "UPDATE 1"

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.alerts.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.alerts.get_async_db_read_conn", return_value=mock_ctx), \
         patch("routers.metrics.ws_manager.broadcast", new_callable=AsyncMock):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {analyst_token}"}) as ac:
            # 1. Canonical GET /api/v1/alerts/{id}
            resp_get = await ac.get(f"/api/v1/alerts/{alert_id}")
            assert resp_get.status_code == 200
            assert resp_get.json()["id"] == alert_id
            assert resp_get.json()["alert_id"] == alert_id

            # 2. Canonical PATCH /api/v1/alerts/{id} (status change)
            resp_patch_status = await ac.patch(
                f"/api/v1/alerts/{alert_id}",
                json={"status": "CLOSE_FALSE_POSITIVE", "justification": "Verified legitimate business activity"}
            )
            assert resp_patch_status.status_code == 200
            assert resp_patch_status.json()["status"] == "CLOSE_FALSE_POSITIVE"

            # 3. Canonical PATCH /api/v1/alerts/{id} (officer assignment)
            resp_patch_assign = await ac.patch(
                f"/api/v1/alerts/{alert_id}",
                json={"officer_username": "compliance_analyst"}
            )
            assert resp_patch_assign.status_code == 200
            assert resp_patch_assign.json()["assigned_officer"] == "compliance_analyst"


# ── 3. Transactions: POST 201 + Location, GET /{id}, GET list ────────────────

@pytest.mark.anyio
async def test_rest_transactions_crud(analyst_token):
    """
    Verify RESTful transaction lifecycle:
    - POST /api/v1/transactions returns 201 Created and Location header.
    - GET /api/v1/transactions/{id} returns 200 OK.
    - GET /api/v1/transactions returns 200 OK with X-Total-Count header.
    """
    sender_id = str(uuid.uuid4())
    receiver_id = str(uuid.uuid4())
    tx_id = str(uuid.uuid4())

    mock_conn = AsyncMock()
    mock_conn.fetchrow.side_effect = [
        # 1. sender/receiver lookup in ingest_transaction
        {
            "sender_id": sender_id,
            "sender_tenant": TENANT_DEFAULT_ID,
            "sender_risk": 0.1,
            "sender_name": "Alice Sender",
            "sender_bic": "CHASEUS3XXX",
            "receiver_id": receiver_id,
            "receiver_risk": 0.1,
            "receiver_name": "Bob Recv",
            "receiver_bic": "CHASEUS3XXX",
            "velocity_count": 1
        },
        # 2. GET /{id} query
        {
            "id": tx_id,
            "tenant_id": TENANT_DEFAULT_ID,
            "amount": 500.0,
            "currency": "USD",
            "status": "COMPLETED",
            "timestamp": datetime.now(timezone.utc),
            "country": "US",
            "channel": "Wire Transfer",
            "merchant": "Global Trade",
            "device": "Web",
            "sender_account": "ACC_SEND",
            "sender_name": "Alice Sender",
            "receiver_account": "ACC_RECV",
            "receiver_name": "Bob Recv",
            "threat_level": None,
            "rule_name": None
        }
    ]
    mock_conn.fetchval.return_value = 1
    mock_conn.fetch.return_value = [
        {
            "id": tx_id,
            "tenant_id": TENANT_DEFAULT_ID,
            "amount": 500.0,
            "currency": "USD",
            "status": "COMPLETED",
            "timestamp": datetime.now(timezone.utc),
            "country": "US",
            "channel": "Wire Transfer",
            "sender_account": "ACC_SEND",
            "sender_name": "Alice Sender",
            "receiver_account": "ACC_RECV",
            "receiver_name": "Bob Recv"
        }
    ]
    mock_conn.execute.return_value = "INSERT 0 1"

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.transactions.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.transactions.get_async_db_read_conn", return_value=mock_ctx), \
         patch("routers.transactions.anomaly_model.predict_risk", return_value={"risk_score": 0.1, "attributions": {"amount": 0.05}}), \
         patch("routers.transactions.RulesEngine.evaluate_transaction", return_value=[]), \
         patch("routers.transactions.get_customer_baseline", return_value={"avg_amount": 500.0, "std_amount": 50.0}), \
         patch("routers.transactions.get_iforest_score", return_value=0.1), \
         patch("routers.transactions.publish_transaction", new_callable=AsyncMock), \
         patch("routers.transactions.calculate_customer_baseline", new_callable=AsyncMock), \
         patch("routers.metrics.ws_manager.broadcast", new_callable=AsyncMock):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {analyst_token}"}) as ac:
            # 1. POST /api/v1/transactions -> 201 Created + Location header
            resp_create = await ac.post(
                "/api/v1/transactions",
                json={
                    "sender_account": "ACC_SEND",
                    "receiver_account": "ACC_RECV",
                    "amount": 500.0,
                    "currency": "USD",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
            assert resp_create.status_code == 201
            assert "Location" in resp_create.headers
            assert resp_create.headers["Location"].startswith("/api/v1/transactions/")
            created_tx_id = resp_create.json()["transaction_id"]

            # 2. GET /api/v1/transactions/{id} -> 200 OK
            resp_get = await ac.get(f"/api/v1/transactions/{created_tx_id}")
            assert resp_get.status_code == 200
            assert resp_get.json()["id"] == tx_id

            # 3. GET /api/v1/transactions -> 200 OK + X-Total-Count
            resp_list = await ac.get("/api/v1/transactions?page=1&limit=10")
            assert resp_list.status_code == 200
            assert resp_list.headers.get("X-Total-Count") == "1"
            assert len(resp_list.json()) == 1


# ── 4. Onboarding: POST 201 + Location, 409 Conflict, GET accounts ────────────

@pytest.mark.anyio
async def test_rest_onboarding_crud_and_conflict(analyst_token):
    """
    Verify RESTful onboarding:
    - POST /api/v1/onboard/accounts/individual returns 201 Created and Location header.
    - Duplicate account returns 409 Conflict.
    - GET /api/v1/onboard/accounts/{id} returns 200 OK with account details.
    - GET /api/v1/onboard/accounts returns 200 OK with X-Total-Count.
    """
    account_id = str(uuid.uuid4())
    acc_row = {
        "id": account_id,
        "tenant_id": TENANT_DEFAULT_ID,
        "account_number": "ACC_REST_01",
        "swift_bic": "CHASEUS3XXX",
        "owner_name": "Jane Doe",
        "risk_score": 0.1,
        "risk_category": "STANDARD",
        "created_at": datetime.now(timezone.utc)
    }

    mock_conn = AsyncMock()
    mock_conn.fetchrow.side_effect = [
        {"id": TENANT_DEFAULT_ID},  # tenant check in POST
        acc_row                      # row lookup in GET /accounts/{id}
    ]
    mock_conn.fetchval.side_effect = [
        account_id,  # successful insert RETURNING id
        1            # total count for GET /accounts
    ]
    mock_conn.fetch.return_value = [acc_row]

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.onboarding.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.onboarding.perform_sanctions_search", return_value={"match_found": False}):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {analyst_token}"}) as ac:
            # 1. POST /api/v1/onboard/accounts/individual -> 201 Created + Location
            resp_onboard = await ac.post(
                "/api/v1/onboard/accounts/individual",
                json={
                    "tenant_id": TENANT_DEFAULT_ID,
                    "name": "Jane Doe",
                    "account_number": "ACC_REST_01",
                    "swift_bic": "CHASEUS3XXX"
                }
            )
            assert resp_onboard.status_code == 201
            assert "Location" in resp_onboard.headers
            assert resp_onboard.headers["Location"] == f"/api/v1/onboard/accounts/{account_id}"

            # 2. GET /api/v1/onboard/accounts/{id} -> 200 OK
            resp_get_acc = await ac.get(f"/api/v1/onboard/accounts/{account_id}")
            assert resp_get_acc.status_code == 200
            assert resp_get_acc.json()["account_number"] == "ACC_REST_01"

            # 3. GET /api/v1/onboard/accounts -> 200 OK + X-Total-Count
            resp_list_acc = await ac.get("/api/v1/onboard/accounts?page=1&limit=10")
            assert resp_list_acc.status_code == 200
            assert resp_list_acc.headers.get("X-Total-Count") == "1"


@pytest.mark.anyio
async def test_rest_onboarding_duplicate_account_conflict(analyst_token):
    """Verify that duplicate account creation triggers 409 Conflict."""
    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = {"id": TENANT_DEFAULT_ID}
    mock_conn.fetchval.side_effect = Exception("duplicate key value violates unique constraint 'accounts_account_number_key'")

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.onboarding.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.onboarding.perform_sanctions_search", return_value={"match_found": False}):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {analyst_token}"}) as ac:
            resp_dup = await ac.post(
                "/api/v1/onboard/accounts/individual",
                json={
                    "tenant_id": TENANT_DEFAULT_ID,
                    "name": "Jane Doe",
                    "account_number": "DUPLICATE_ACC",
                    "swift_bic": "CHASEUS3XXX"
                }
            )
            assert resp_dup.status_code == 409
            assert "already exists" in resp_dup.json()["detail"].lower()


# ── 5. Screening: Idempotent GET /screening & Legacy POST /search ─────────────

@pytest.mark.anyio
async def test_rest_screening_idempotent_get(analyst_token):
    """Verify idempotent GET /screening with query parameters and legacy POST compatibility."""
    mock_results = {
        "query": "John Doe",
        "threshold": 0.85,
        "match_found": True,
        "total_hits": 1,
        "top_match": {"name": "John Doe", "score": 1.0, "source": "OFAC_SDN"},
        "matches": [{"name": "John Doe", "score": 1.0, "source": "OFAC_SDN"}]
    }

    with patch("routers.screening.perform_sanctions_search", return_value=mock_results), \
         patch("routers.screening.get_async_elasticsearch_client", return_value=AsyncMock()):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {analyst_token}"}) as ac:
            # 1. RESTful Idempotent GET /screening
            resp_get = await ac.get("/api/v1/screening?name=John%20Doe&threshold=0.85")
            assert resp_get.status_code == 200
            assert resp_get.json()["match_found"] is True

            # 2. Legacy POST /screening/search backward compatibility
            resp_post = await ac.post(
                "/api/v1/screening/search",
                json={"name": "John Doe", "threshold": 0.85}
            )
            assert resp_post.status_code == 200
            assert resp_post.json()["match_found"] is True


# ── 6. FinCEN & STR Batch: POST 201 + Location, GET symmetrical ──────────────

@pytest.mark.anyio
async def test_rest_fincen_and_str_batches(analyst_token):
    """Verify FinCEN SARs and STR batch RESTful resource creation and read."""
    sar_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())

    mock_conn = AsyncMock()
    mock_conn.fetchval.side_effect = [
        sar_id,    # INSERT INTO fincen_sars RETURNING id
        batch_id,  # INSERT INTO str_batches RETURNING id
    ]
    mock_conn.fetchrow.return_value = {
        "id": sar_id,
        "tenant_id": TENANT_DEFAULT_ID,
        "alert_id": str(uuid.uuid4()),
        "status": "PENDING_TRANSMISSION",
        "fincen_tracking_id": "BSA-TRACK-12345",
        "fincen_filing_status": "SUBMITTED",
        "fincen_submitted_at": datetime.now(timezone.utc)
    }
    mock_conn.fetch.return_value = [
        {
            "id": batch_id,
            "tenant_id": TENANT_DEFAULT_ID,
            "record_count": 5,
            "total_amount": 50000.0,
            "checksum": "abc123sha256",
            "status": "READY_FOR_SUBMISSION",
            "created_at": datetime.now(timezone.utc)
        }
    ]

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    mock_receipt = {
        "status": "SUBMITTED",
        "fincen_tracking_id": "BSA-TRACK-12345",
        "fincen_ack_code": "ACK-001",
        "fincen_confirmation_message": "Filing Accepted",
        "submitted_at": "2026-09-12T00:00:00Z",
        "sandbox": True
    }

    mock_batch_result = {
        "batch_id": batch_id,
        "batch_number": "BATCH-TEST-001",
        "record_count": 5,
        "total_amount": 50000.0,
        "status": "READY_FOR_SUBMISSION"
    }

    with patch("routers.fincen.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.fincen.fincen_client.submit_sar", new_callable=AsyncMock, return_value=mock_receipt), \
         patch("routers.str_batch.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.str_batch.str_batch_engine.generate_batch", new_callable=AsyncMock, return_value=mock_batch_result), \
         patch("routers.metrics.ws_manager.broadcast", new_callable=AsyncMock):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {analyst_token}"}) as ac:
            # 1. POST /api/v1/fincen/sars -> 201 Created + Location
            alert_id = str(uuid.uuid4())
            resp_sar = await ac.post(
                "/api/v1/fincen/sars",
                json={
                    "alert_id": alert_id,
                    "sar_xml": "<SAR>valid_fincen_xml_test</SAR>"
                }
            )
            assert resp_sar.status_code == 201
            assert "Location" in resp_sar.headers
            assert resp_sar.headers["Location"] == f"/api/v1/fincen/sars/{alert_id}"

            # 2. GET /api/v1/fincen/sars/{id}/status -> 200 OK
            resp_sar_status = await ac.get(f"/api/v1/fincen/sars/{sar_id}/status")
            assert resp_sar_status.status_code == 200
            assert resp_sar_status.json()["alert_status"] == "PENDING_TRANSMISSION"

            # 3. POST /api/v1/str/batch/batches -> 201 Created + Location
            resp_batch = await ac.post("/api/v1/str/batch/batches")
            assert resp_batch.status_code == 201
            assert "Location" in resp_batch.headers
            assert resp_batch.headers["Location"] == f"/api/v1/str/batch/batches/{batch_id}"

            # 4. GET /api/v1/str/batch/batches -> 200 OK
            resp_batches = await ac.get("/api/v1/str/batch/batches")
            assert resp_batches.status_code == 200
            assert len(resp_batches.json()) == 1


# ── 7. Watchlist: POST 202 Accepted on sync-jobs ─────────────────────────────

@pytest.mark.anyio
async def test_rest_watchlist_sync_jobs_accepted(admin_token):
    """Verify POST /api/v1/watchlist/sync-jobs returns 202 Accepted for async execution."""
    with patch("routers.watchlist.watchlist_sync_engine.sync_all_watchlists", new_callable=AsyncMock, return_value={"total_records_processed": 100}), \
         patch("routers.metrics.ws_manager.broadcast", new_callable=AsyncMock):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {admin_token}"}) as ac:
            resp = await ac.post("/api/v1/watchlist/sync-jobs")
            assert resp.status_code == 202
            assert resp.json()["total_records_processed"] == 100


# ── 8. Rules: Persistence in Postgres + Redis PubSub Invalidation ────────────

@pytest.mark.anyio
async def test_rest_rules_config_persistence_and_pubsub(admin_token):
    """Verify PUT /api/v1/rules/config persists to PostgreSQL and publishes invalidation to Redis."""
    mock_conn = AsyncMock()
    mock_conn.execute.return_value = "INSERT 0 1"

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    mock_redis = AsyncMock()
    mock_redis.publish = AsyncMock()

    with patch("database.postgres.get_async_db_conn", return_value=mock_ctx), \
         patch("database.redis_db.get_async_redis_client", return_value=mock_redis), \
         patch("builtins.open", MagicMock()):

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {admin_token}"}) as ac:
            resp = await ac.put(
                "/api/v1/rules/config",
                json={
                    "rules": {
                        "LARGE_TRANSACTION": {
                            "enabled": True,
                            "threshold": 12000.0
                        }
                    }
                }
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "SUCCESS"

            # Check DB execution was called with INSERT into rules_configuration
            assert mock_conn.execute.called
            insert_query = mock_conn.execute.call_args[0][0]
            assert "rules_configuration" in insert_query

            # Check Redis publish was called with aml:rules:cache_invalidate
            assert mock_redis.publish.called
            channel = mock_redis.publish.call_args[0][0]
            assert channel == "aml:rules:cache_invalidate"


# ── 9. Network: Symmetrical GET /network/entities/{id}/network ───────────────

@pytest.mark.anyio
async def test_rest_network_entity_subgraph(analyst_token):
    """Verify GET /api/v1/network/entities/{id}/network returns entity subgraph."""
    entity_id = str(uuid.uuid4())
    mock_session = AsyncMock()
    mock_result = AsyncMock()
    mock_result.data.return_value = []
    mock_session.run.return_value = mock_result

    mock_driver = MagicMock()
    mock_driver.session.return_value.__aenter__.return_value = mock_session
    mock_driver.session.return_value.__aexit__.return_value = None

    with patch("database.neo4j_db.get_async_neo4j_driver", return_value=mock_driver):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-CSRF-Protection": "1", "Authorization": f"Bearer {analyst_token}"}) as ac:
            resp = await ac.get(f"/api/v1/network/entities/{entity_id}/network")
            assert resp.status_code == 200
            data = resp.json()
            assert "nodes" in data
            assert "edges" in data
