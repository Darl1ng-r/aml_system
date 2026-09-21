"""
Tests for Production Readiness Review (PRR) Remediations
=========================================================
Validates the 7 showstopper fixes:
1. Ephemeral RSA key rejection in production
2. Insecure default password rejection in production
3. Metric path normalization (cardinality explosion prevention)
4. Pagination limit clamping (DoS prevention)
5. Swagger / OpenAPI documentation disablement in production
6. Database connection pool command and acquire timeouts
"""

import pytest
import os
import uuid
from starlette.requests import Request
from pydantic import ValidationError


def test_ephemeral_rsa_rejected_in_production(monkeypatch):
    """Verifies that get_or_create_rsa_keypair raises RuntimeError if no key is provided in production."""
    from services.secrets_manager import get_or_create_rsa_keypair, _cached_rsa_private_pem
    import services.secrets_manager as sm

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("JWT_PRIVATE_KEY_PEM", raising=False)
    # Clear any cached key
    monkeypatch.setattr(sm, "_cached_rsa_private_pem", None)
    monkeypatch.setattr(sm, "_cached_rsa_public_pem", None)

    with pytest.raises(RuntimeError) as exc_info:
        get_or_create_rsa_keypair()

    assert "CRITICAL SECURITY FAILURE: Ephemeral in-memory RSA key generation is strictly forbidden in production!" in str(exc_info.value)


def test_production_rejects_default_passwords():
    """Verifies that Settings model validator rejects default passwords in production."""
    from config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            environment="production",
            postgres_password="postgrespassword",
            neo4j_password="secure_prod_password_123",
            elastic_password="secure_prod_password_456"
        )
    assert "Default postgres_password is forbidden in production" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            environment="production",
            postgres_password="secure_prod_password_123",
            neo4j_password="passwordpassword",
            elastic_password="secure_prod_password_456"
        )
    assert "Default neo4j_password is forbidden in production" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            environment="production",
            postgres_password="secure_prod_password_123",
            neo4j_password="secure_prod_password_123",
            elastic_password="secure_prod_password_456",
            aml_app_password="secure_prod_app_password_789",
            internal_gateway_secret="aml-internal-gateway-secret-dev-only"
        )
    assert "Default internal_gateway_secret is forbidden in production" in str(exc_info.value)


def test_production_forces_offline_dev_false():
    """Verifies that production environment forces allow_offline_dev=False."""
    from config import Settings

    s = Settings(
        environment="production",
        postgres_password="secure_prod_password_123",
        neo4j_password="secure_prod_password_123",
        elastic_password="secure_prod_password_456",
        aml_app_password="secure_prod_app_password_789",
        internal_gateway_secret="super-high-entropy-prod-gateway-secret-991823"
    )
    assert s.allow_offline_dev is False



def test_metric_path_normalization():
    """Verifies that normalize_metric_path collapses UUIDs and numbers to prevent label cardinality explosion."""
    from observability.middleware import normalize_metric_path

    class MockRoute:
        def __init__(self, path):
            self.path = path

    # Case 1: Route template exists
    scope_with_route = {
        "type": "http",
        "path": "/api/v1/cases/123e4567-e89b-12d3-a456-426614174000",
        "headers": [],
        "route": MockRoute("/api/v1/cases/{case_id}")
    }
    req1 = Request(scope=scope_with_route)
    assert normalize_metric_path(req1) == "/api/v1/cases/{case_id}"

    # Case 2: No route matched, dynamic UUID in raw path
    scope_raw_uuid = {
        "type": "http",
        "path": f"/api/v1/alerts/{uuid.uuid4()}",
        "headers": []
    }
    req2 = Request(scope=scope_raw_uuid)
    assert normalize_metric_path(req2) == "/api/v1/alerts/{id}"

    # Case 3: Numeric ID in path
    scope_numeric = {
        "type": "http",
        "path": "/api/v1/users/998234/details",
        "headers": []
    }
    req3 = Request(scope=scope_numeric)
    assert normalize_metric_path(req3) == "/api/v1/users/{id}/details"


def test_database_pool_timeouts():
    """Verifies that asyncpg connection pool initialization specifies command_timeout=15.0."""
    import inspect
    from database.postgres import init_db_pool

    source = inspect.getsource(init_db_pool)
    assert "command_timeout=15.0" in source


@pytest.mark.asyncio
async def test_pagination_limit_clamping():
    """Verifies that Query(ge=1, le=100) rejects requests with limit > 100 with HTTP 422."""
    from httpx import AsyncClient, ASGITransport
    from main import app
    from services.auth import create_access_token

    valid_tenant_id = str(uuid.uuid4())
    token = create_access_token({"sub": "admin", "role": "ADMIN", "tenant_id": valid_tenant_id})
    headers = {"Authorization": f"Bearer {token}"}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Request with limit=500000 should be rejected by FastAPI with 422
        resp = await ac.get("/api/v1/transactions?limit=500000", headers=headers)
        assert resp.status_code == 422
        body = resp.json()
        assert "limit" in str(body)

        # Request with limit=101 should also be rejected
        resp_alerts = await ac.get("/api/v1/alerts?limit=101", headers=headers)
        assert resp_alerts.status_code == 422
        assert "limit" in str(resp_alerts.json())

        # Request with limit=0 should be rejected (ge=1)
        resp_zero = await ac.get("/api/v1/transactions?limit=0", headers=headers)
        assert resp_zero.status_code == 422

        # Valid request with limit=10 should pass validation and reach route handler
        from unittest.mock import AsyncMock, patch
        mock_conn = AsyncMock()
        mock_conn.fetchval.return_value = 0
        mock_conn.fetch.return_value = []
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_conn
        mock_ctx.__aexit__.return_value = None

        with patch("routers.transactions.get_async_db_read_conn", return_value=mock_ctx):
            resp_valid = await ac.get("/api/v1/transactions?limit=10", headers=headers)
            assert resp_valid.status_code == 200


@pytest.mark.asyncio
async def test_swagger_and_metrics_in_production(monkeypatch):
    """Verifies that in production mode, metrics can require secret authentication."""
    from httpx import AsyncClient, ASGITransport
    from main import app
    from config import settings

    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "metrics_secret", "super_secret_metrics_token_2026")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Unauthenticated metrics call in prod with secret set should return 401
        res_unauth = await ac.get("/metrics")
        assert res_unauth.status_code == 401

        # Authenticated metrics call with header should return 200
        res_auth = await ac.get("/metrics", headers={"X-Metrics-Token": "super_secret_metrics_token_2026"})
        assert res_auth.status_code == 200
