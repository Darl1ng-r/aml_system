"""
Test Suite: Standalone IAM Microservice & Auth Client
=====================================================
Tests the isolated IAM application routes and downstream token validation client.
"""

from unittest.mock import MagicMock
import httpx
import pytest
from fastapi import Request

from services.iam.app import iam_app
from services.iam.client import DownstreamAuthValidator, UserClaims
from services.auth import create_access_token


def test_iam_service_routes_registered():
    """Verifies that IAM app exposes authentication and cryptographic discovery endpoints."""
    routes = [route.path for route in iam_app.routes]
    assert "/.well-known/jwks.json" in routes
    assert "/health/liveness" in routes
    assert "/health/readiness" in routes
    assert "/api/v1/auth/login" in routes or any("/auth" in r for r in routes)


@pytest.mark.anyio
async def test_iam_jwks_discovery_endpoint():
    """Verifies that the JWKS endpoint returns valid RFC 7517 JSON Web Key Set."""
    transport = httpx.ASGITransport(app=iam_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/.well-known/jwks.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "keys" in data
        assert isinstance(data["keys"], list)


@pytest.mark.anyio
async def test_iam_liveness_probe():
    """Verifies Kubernetes liveness probe."""
    transport = httpx.ASGITransport(app=iam_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health/liveness")
        assert resp.status_code == 200
        assert resp.json()["status"] == "UP"
        assert resp.json()["service"] == "iam-service"


def test_downstream_auth_validator_with_gateway_headers():
    """Verifies that downstream services accept pre-validated gateway headers."""
    validator = DownstreamAuthValidator()

    # Simulate request with Envoy-injected trusted headers
    mock_request = MagicMock(spec=Request)
    mock_request.headers = {
        "x-user-id": "usr-12345",
        "x-tenant-id": "ten-99999",
        "x-user-roles": "ComplianceOfficer,Analyst",
        "x-user-name": "alice_compliance",
        "x-mfa-verified": "true",
    }

    claims = validator.validate_request(mock_request)
    assert isinstance(claims, UserClaims)
    assert claims.user_id == "usr-12345"
    assert claims.tenant_id == "ten-99999"
    assert claims.username == "alice_compliance"
    assert "ComplianceOfficer" in claims.roles
    assert "Analyst" in claims.roles
    assert claims.is_mfa_authenticated is True


def test_downstream_auth_validator_with_jwt():
    """Verifies that downstream validator parses signed JWT correctly."""
    token = create_access_token(
        data={
            "sub": "usr-88888",
            "username": "bob_analyst",
            "tenant_id": "ten-77777",
            "roles": ["Auditor"],
            "type": "access",
        }
    )

    validator = DownstreamAuthValidator()
    mock_request = MagicMock(spec=Request)
    mock_request.headers = {
        "Authorization": f"Bearer {token}",
    }

    claims = validator.validate_request(mock_request)
    assert claims.user_id == "usr-88888"
    assert claims.tenant_id == "ten-77777"
    assert claims.username == "bob_analyst"
    assert claims.roles == ["Auditor"]
