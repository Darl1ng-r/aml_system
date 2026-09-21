"""
IAM Client & Downstream Auth Validator
======================================
Enables downstream microservices to validate authentication tokens without
coupling to the IAM database or making synchronous per-request network calls.

Validates:
1. Direct internal headers injected by the API Gateway (X-User-Id, X-Tenant-Id, X-User-Roles)
2. Direct Bearer JWTs validated against cached JWKS (RFC 7517)
"""

import logging
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from fastapi import Request, HTTPException, status
import jwt
from jwt import PyJWKClient

logger = logging.getLogger(__name__)


@dataclass
class UserClaims:
    user_id: str
    tenant_id: str
    username: str
    roles: List[str]
    is_mfa_authenticated: bool = False
    raw_payload: Optional[Dict[str, Any]] = None


class DownstreamAuthValidator:
    """
    Validates identity tokens locally using JWKS caching or trusted gateway headers.
    """

    def __init__(self, jwks_url: Optional[str] = None, cache_keys: bool = True):
        self.jwks_url = jwks_url
        self._jwks_client: Optional[PyJWKClient] = (
            PyJWKClient(jwks_url, cache_keys=cache_keys) if jwks_url else None
        )

    def validate_request(self, request: Request) -> UserClaims:
        """
        FastAPI dependency helper to authenticate incoming microservice requests.
        """
        # 1. Check for trusted headers injected by the API Gateway
        x_user_id = request.headers.get("x-user-id")
        x_tenant_id = request.headers.get("x-tenant-id")
        x_roles = request.headers.get("x-user-roles")
        inbound_gateway_token = request.headers.get("x-internal-gateway-token")

        if x_user_id and x_tenant_id:
            from config import settings
            expected_secret = getattr(settings, "internal_gateway_secret", None)
            if expected_secret:
                if not inbound_gateway_token or inbound_gateway_token != expected_secret:
                    logger.warning("Untrusted internal identity headers detected without valid gateway token.")
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied: Spoofed or unverified internal gateway headers.",
                    )

            roles = [r.strip() for r in x_roles.split(",")] if x_roles else []
            return UserClaims(
                user_id=x_user_id,
                tenant_id=x_tenant_id,
                username=request.headers.get("x-user-name", "gateway_authenticated"),
                roles=roles,
                is_mfa_authenticated=request.headers.get("x-mfa-verified", "false").lower() == "true",
            )

        # 2. Otherwise extract and validate Bearer JWT token
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or malformed Authorization header.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header[7:].strip()
        payload = self.decode_token(token)

        user_id = payload.get("sub") or payload.get("user_id")
        tenant_id = payload.get("tenant_id")
        if not user_id or not tenant_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token payload missing required identity claims.",
            )

        roles = payload.get("roles", [])
        if isinstance(roles, str):
            roles = [r.strip() for r in roles.split(",")]

        return UserClaims(
            user_id=str(user_id),
            tenant_id=str(tenant_id),
            username=payload.get("username", str(user_id)),
            roles=roles,
            is_mfa_authenticated=payload.get("mfa_verified", False),
            raw_payload=payload,
        )

    def decode_token(self, token: str) -> Dict[str, Any]:
        """
        Decodes and verifies a JWT against JWKS or local fallback secrets.
        """
        # Try JWKS verification first if client is configured
        if self._jwks_client:
            try:
                signing_key = self._jwks_client.get_signing_key_from_jwt(token)
                return jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["RS256", "ES256"],
                    options={"verify_exp": True, "verify_aud": False},
                )
            except Exception as jwks_err:
                logger.debug(f"JWKS verification failed, trying fallback: {jwks_err}")

        # Fallback to local secrets manager rotation decoder
        try:
            from services.secrets_manager import decode_jwt_with_rotation
            payload = decode_jwt_with_rotation(token)
            if payload:
                return payload
        except Exception as e:
            logger.debug(f"Local secrets decoder failed: {e}")

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
        )


# Global singleton validator
default_validator = DownstreamAuthValidator()


def get_current_user_claims(request: Request) -> UserClaims:
    """FastAPI dependency for microservice endpoints."""
    return default_validator.validate_request(request)
