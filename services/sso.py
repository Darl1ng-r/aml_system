"""
Enterprise OpenID Connect (OIDC) SSO Service (P0-6)
===================================================
Supports Okta, Microsoft Entra ID (Azure AD), Google Workspace, and Auth0 via:
  - OIDC Discovery (`/.well-known/openid-configuration`) cached in Redis (1h TTL)
  - RFC 7636 PKCE (`S256`) + cryptographic single-use `state` & `nonce` (Redis 300s TTL)
  - JWKS ID-token signature, issuer, audience, and nonce verification (`PyJWKClient`)
  - Least-privilege IdP group -> 5-tier AML RBAC role resolution
"""

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

import httpx
import jwt
from jwt import PyJWKClient

from database.redis_db import get_async_redis_client
from services.siem_forwarder import validate_siem_destination_url

logger = logging.getLogger("aml.sso")

SSO_STATE_TTL_SECONDS = 300
DISCOVERY_CACHE_TTL_SECONDS = 3600

# Bounded in-process fallback state store for single-node dev when Redis is offline
_LOCAL_STATE_MAX = 1000
_local_sso_states: OrderedDict[str, Tuple[float, Dict[str, Any]]] = OrderedDict()

# Strictly ranked 5-tier RBAC hierarchy (IdP groups NEVER auto-grant SUPER_ADMIN)
ROLE_RANK: Dict[str, int] = {
    "AUDITOR": 1,
    "L1_ANALYST": 2,
    "L2_INVESTIGATOR": 3,
    "ANALYST": 3,
    "MLRO": 4,
    "ADMIN": 5,
    "TENANT_ADMIN": 5,
}
ALLOWED_SSO_ROLES = set(ROLE_RANK.keys())


def generate_pkce_pair() -> Tuple[str, str]:
    """Generates RFC 7636 PKCE (code_verifier, S256 code_challenge)."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def resolve_role_from_groups(
    idp_groups: List[str] | str | None,
    group_role_mapping: Dict[str, str] | None,
    default_role: str = "L1_ANALYST",
) -> str:
    """
    Maps IdP group memberships to the highest-privilege permitted AML role.
    Prevents automatic SUPER_ADMIN escalation from external IdP claims.
    """
    fallback = default_role.upper() if str(default_role).upper() in ALLOWED_SSO_ROLES else "L1_ANALYST"
    if not idp_groups or not group_role_mapping:
        return fallback

    groups = [idp_groups] if isinstance(idp_groups, str) else list(idp_groups)
    best_role = None
    best_rank = -1

    for group_name in groups:
        mapped = group_role_mapping.get(str(group_name))
        if not mapped:
            continue
        role_upper = str(mapped).upper().strip()
        if role_upper not in ALLOWED_SSO_ROLES:
            continue
        rank = ROLE_RANK[role_upper]
        if rank > best_rank:
            best_rank = rank
            best_role = role_upper

    return best_role or fallback


async def store_sso_state(state_token: str, payload: Dict[str, Any]) -> None:
    """Persists single-use PKCE + nonce state in Redis (300s TTL) with bounded local fallback."""
    try:
        redis = await get_async_redis_client()
        if redis:
            await redis.set(f"sso:state:{state_token}", json.dumps(payload), ex=SSO_STATE_TTL_SECONDS)
            return
    except Exception as exc:
        logger.debug(f"Redis SSO state write fallback: {exc}")

    _local_sso_states[state_token] = (time.monotonic() + SSO_STATE_TTL_SECONDS, payload)
    _local_sso_states.move_to_end(state_token)
    while len(_local_sso_states) > _LOCAL_STATE_MAX:
        _local_sso_states.popitem(last=False)


async def consume_sso_state(state_token: str) -> Optional[Dict[str, Any]]:
    """Atomically consumes a single-use SSO state entry (prevents CSRF & replay attacks)."""
    if not state_token:
        return None

    # Always pop local fallback first so a split-brain Redis timeout-after-write can NEVER allow replay
    local_entry = _local_sso_states.pop(state_token, None)
    local_payload = local_entry[1] if (local_entry and local_entry[0] >= time.monotonic()) else None

    try:
        redis = await get_async_redis_client()
        if redis:
            key = f"sso:state:{state_token}"
            if hasattr(redis, "getdel"):
                raw = await redis.getdel(key)
            else:
                raw = await redis.get(key)
                if raw:
                    await redis.delete(key)
            if raw:
                return json.loads(raw)
    except Exception as exc:
        logger.debug(f"Redis SSO state consume fallback: {exc}")

    return local_payload


async def fetch_oidc_discovery(issuer_url: str) -> Dict[str, Any]:
    """Fetches & caches an IdP's OpenID Connect Discovery metadata (HTTPS + anti-SSRF)."""
    clean_issuer = validate_siem_destination_url(issuer_url).rstrip("/")
    discovery_url = f"{clean_issuer}/.well-known/openid-configuration"
    cache_key = f"sso:discovery:{hashlib.sha256(clean_issuer.encode('utf-8')).hexdigest()[:16]}"

    redis = None
    try:
        redis = await get_async_redis_client()
        if redis:
            cached = await redis.get(cache_key)
            if cached:
                return json.loads(cached)
    except Exception:
        redis = None

    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
        resp = await client.get(discovery_url)
        if resp.status_code != 200:
            raise ValueError(f"OIDC discovery failed for '{discovery_url}' (HTTP {resp.status_code}).")
        doc = resp.json()

    for req_field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not doc.get(req_field):
            raise ValueError(f"OIDC discovery document missing mandatory field '{req_field}'.")
        # AUTHN-07: Validate every nested OIDC discovery URL against SSRF / non-HTTPS / metadata IPs
        doc[req_field] = validate_siem_destination_url(str(doc[req_field]))

    if redis:
        try:
            await redis.set(cache_key, json.dumps(doc), ex=DISCOVERY_CACHE_TTL_SECONDS)
        except Exception:
            pass

    return doc


def verify_oidc_id_token(
    id_token: str,
    jwks_uri: str,
    client_id: str,
    issuer: str,
    expected_nonce: str,
    signing_key_override: Any = None,
) -> Dict[str, Any]:
    """
    Cryptographically verifies an OIDC ID Token using the IdP's JWKS keys,
    validating signature, exp, aud, iss, and nonce claims.
    """
    if not expected_nonce:
        raise jwt.InvalidTokenError("Missing expected OIDC nonce.")

    if signing_key_override is not None:
        key = signing_key_override
    else:
        safe_jwks_uri = validate_siem_destination_url(jwks_uri)
        jwk_client = PyJWKClient(safe_jwks_uri, cache_keys=True)
        key = jwk_client.get_signing_key_from_jwt(id_token).key

    claims = jwt.decode(
        id_token,
        key,
        algorithms=["RS256", "ES256", "RS384", "RS512"],
        audience=client_id,
        issuer=issuer,
        options={"verify_exp": True, "verify_aud": True, "verify_iss": True, "require": ["exp", "sub", "iss", "aud"]},
    )

    token_nonce = str(claims.get("nonce") or "")
    if not token_nonce or not hmac.compare_digest(token_nonce, str(expected_nonce)):
        raise jwt.InvalidTokenError("OIDC ID token nonce mismatch (possible replay attack).")

    return claims
