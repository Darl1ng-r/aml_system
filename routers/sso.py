"""
Enterprise OpenID Connect (OIDC) SSO Router (P0-6)
==================================================
Endpoints:
  - GET    /api/v1/auth/sso/providers/public      (Login UI discovery — non-secret metadata)
  - GET    /api/v1/auth/sso/providers             (Admin provider listing)
  - POST   /api/v1/auth/sso/providers             (Admin register OIDC IdP)
  - DELETE /api/v1/auth/sso/providers/{id}        (Admin remove OIDC IdP)
  - GET    /api/v1/auth/sso/{id}/authorize        (Start PKCE + state OIDC flow)
  - GET    /api/v1/auth/sso/{id}/callback         (Exchange code, verify ID token, JIT provision & issue cookies)
"""

import hashlib
import hmac
import json
import logging
import secrets
import uuid
from typing import Dict, Optional
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field, HttpUrl

from config import settings
from database.postgres import get_async_db_conn, get_async_db_read_conn, get_db_pool
from observability.logging import log_audit_event
from observability.sanitizer import sanitize_text
from routers.auth import set_auth_cookies
from services.auth import (
    RoleChecker,
    create_access_token,
    create_refresh_token,
    enforce_tenant_data_scope,
)
from services.encryption import encrypt_pii, decrypt_pii, DecryptionError
from services.rate_limiter import RateLimiter
from services.siem_forwarder import validate_siem_destination_url
from services.sso import (
    ALLOWED_SSO_ROLES,
    consume_sso_state,
    fetch_oidc_discovery,
    generate_pkce_pair,
    resolve_role_from_groups,
    store_sso_state,
    verify_oidc_id_token,
    verify_oidc_id_token_async,
)

_ORIGINAL_VERIFY_OIDC_ID_TOKEN = verify_oidc_id_token
logger = logging.getLogger("aml.sso.router")

router = APIRouter(prefix="/api/v1/auth/sso", tags=["Enterprise SSO (OIDC)"])


class SSOProviderCreate(BaseModel):
    provider_name: str = Field(..., min_length=2, max_length=120)
    issuer_url: HttpUrl
    client_id: str = Field(..., min_length=2, max_length=255)
    client_secret: Optional[str] = Field(default="", max_length=512)
    scopes: str = Field(default="openid profile email groups", max_length=255)
    group_role_mapping: Dict[str, str] = Field(default_factory=dict)
    default_role: str = Field(default="L1_ANALYST")
    enabled: bool = True


@router.get("/providers/public")
async def list_public_sso_providers(
    tenant_id: str = Query(default="00000000-0000-0000-0000-000000000001"),
    _rate_limit=Depends(RateLimiter(limit=30, window=60, ip_only=True)),
):
    """Returns minimal public metadata (id + provider_name) so login.html can render active SSO buttons."""
    try:
        uuid.UUID(tenant_id)
    except ValueError:
        return []

    try:
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
            rows = await conn.fetch(
                """
                SELECT id, provider_name
                FROM sso_providers
                WHERE enabled = TRUE
                ORDER BY provider_name ASC;
                """
            )
            return [{"id": str(r["id"]), "provider_name": r["provider_name"]} for r in rows]
    except Exception:
        return []


@router.get("/providers")
async def list_sso_providers_admin(
    current_user: dict = Depends(RoleChecker(["ADMIN", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, provider_name, issuer_url, client_id, scopes,
                   group_role_mapping, default_role, enabled, created_at
            FROM sso_providers
            ORDER BY created_at DESC;
            """
        )
        return [
            {
                "id": str(r["id"]),
                "provider_name": r["provider_name"],
                "issuer_url": r["issuer_url"],
                "client_id": r["client_id"],
                "scopes": r["scopes"],
                "group_role_mapping": (
                    json.loads(r["group_role_mapping"])
                    if isinstance(r["group_role_mapping"], str)
                    else (r["group_role_mapping"] or {})
                ),
                "default_role": r["default_role"],
                "enabled": bool(r["enabled"]),
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]


@router.post("/providers", status_code=status.HTTP_201_CREATED)
async def create_sso_provider(
    payload: SSOProviderCreate,
    current_user: dict = Depends(RoleChecker(["ADMIN", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=15, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        safe_issuer = validate_siem_destination_url(str(payload.issuer_url)).rstrip("/")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    default_role = payload.default_role.upper().strip()
    if default_role not in ALLOWED_SSO_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid default_role '{default_role}'. Allowed: {sorted(ALLOWED_SSO_ROLES)}")

    for grp, role in payload.group_role_mapping.items():
        if str(role).upper().strip() not in ALLOWED_SSO_ROLES:
            raise HTTPException(status_code=400, detail=f"Invalid mapped role '{role}' for group '{grp}'.")

    enc_secret = encrypt_pii(payload.client_secret, tenant_id=str(tenant_id)) if payload.client_secret else ""
    safe_name = sanitize_text(payload.provider_name)

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        pid = await conn.fetchval(
            """
            INSERT INTO sso_providers (
                tenant_id, provider_name, issuer_url, client_id, client_secret_enc,
                scopes, group_role_mapping, default_role, enabled
            )
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
            RETURNING id;
            """,
            str(tenant_id),
            safe_name,
            safe_issuer,
            payload.client_id.strip(),
            enc_secret,
            payload.scopes.strip(),
            json.dumps(payload.group_role_mapping),
            default_role,
            payload.enabled,
        )

    log_audit_event(
        event_type="SSO_PROVIDER_CREATED",
        actor_id=str(current_user.get("id", "")),
        actor_role=current_user.get("role", "ADMIN"),
        action="CREATE_SSO_PROVIDER",
        resource_type="SSO_PROVIDER",
        resource_id=str(pid),
        tenant_id=str(tenant_id),
        details={"provider_name": safe_name, "issuer_url": safe_issuer},
    )

    return {
        "id": str(pid),
        "provider_name": safe_name,
        "issuer_url": safe_issuer,
        "client_id": payload.client_id.strip(),
        "default_role": default_role,
        "enabled": payload.enabled,
    }


@router.delete("/providers/{provider_id}")
async def delete_sso_provider(
    provider_id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=15, window=60)),
):
    try:
        p_uuid = uuid.UUID(provider_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid SSO provider ID.")

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        deleted = await conn.fetchval("DELETE FROM sso_providers WHERE id = $1 RETURNING id;", p_uuid)
        if not deleted:
            raise HTTPException(status_code=404, detail="SSO provider not found.")
        from services.audit import record_audit_event_tx
        await record_audit_event_tx(
            conn=conn,
            action="DELETE_SSO_PROVIDER",
            actor_id=str(current_user.get("id", "")),
            actor_username=current_user.get("username", "admin"),
            actor_role=current_user.get("role", "ADMIN"),
            resource_type="SSO_PROVIDER",
            resource_id=provider_id,
            tenant_id=str(tenant_id),
            details={"provider_id": provider_id},
        )
    return {"status": "DELETED", "id": provider_id}


async def _load_provider_for_login(provider_id: str, tenant_id: str) -> dict:
    try:
        p_uuid = uuid.UUID(provider_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid SSO provider ID.")

    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        row = await conn.fetchrow(
            """
            SELECT id, tenant_id, provider_name, issuer_url, client_id, client_secret_enc,
                   scopes, group_role_mapping, default_role, enabled
            FROM sso_providers
            WHERE id = $1 AND enabled = TRUE;
            """,
            p_uuid,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Enabled SSO provider not found.")
        return dict(row)


def _sso_state_cookie_digest(state: str) -> str:
    return hashlib.sha256(f"sso-state-bind:{state}".encode("utf-8")).hexdigest()


def _resolve_sso_redirect_uri(request: Request, provider_id: str) -> str:
    """Builds canonical OIDC redirect_uri from configured PUBLIC_BASE_URL to prevent Host header poisoning (AUTHN-02)."""
    canonical = (getattr(settings, "public_base_url", "") or "").strip().rstrip("/")
    if canonical:
        return f"{canonical}/api/v1/auth/sso/{provider_id}/callback"
    return str(request.url_for("sso_callback", provider_id=provider_id))


@router.get("/{provider_id}/authorize")
async def sso_authorize(
    provider_id: str,
    request: Request,
    response: Response,
    tenant_id: str = Query(default="00000000-0000-0000-0000-000000000001"),
    _rate_limit=Depends(RateLimiter(limit=30, window=60, ip_only=True)),
):
    """Initiates OIDC Authorization Code Flow with PKCE (S256), browser-bound state cookie, and nonce."""
    provider = await _load_provider_for_login(provider_id, tenant_id)
    try:
        discovery = await fetch_oidc_discovery(provider["issuer_url"])
    except Exception:
        logger.exception("Failed to load IdP OIDC discovery for provider %s", provider_id)
        raise HTTPException(status_code=502, detail="Failed to load Identity Provider discovery metadata.")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(24)
    code_verifier, code_challenge = generate_pkce_pair()
    redirect_uri = _resolve_sso_redirect_uri(request, provider_id)
    state_binding = _sso_state_cookie_digest(state)

    await store_sso_state(
        state,
        {
            "provider_id": str(provider["id"]),
            "tenant_id": str(provider["tenant_id"]),
            "nonce": nonce,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
            "state_binding": state_binding,
        },
    )

    params = urlencode(
        {
            "response_type": "code",
            "client_id": provider["client_id"],
            "redirect_uri": redirect_uri,
            "scope": provider["scopes"] or "openid profile email groups",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    auth_url = f"{discovery['authorization_endpoint']}?{params}"
    is_secure = bool(settings.enable_tls or settings.is_production)

    if "application/json" in request.headers.get("accept", ""):
        response.set_cookie(
            key="sso_state_binding",
            value=state_binding,
            max_age=300,
            httponly=True,
            samesite="lax",
            secure=is_secure,
            path="/api/v1/auth/sso",
        )
        return {"authorization_url": auth_url, "state": state}

    redirect_resp = RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)
    redirect_resp.set_cookie(
        key="sso_state_binding",
        value=state_binding,
        max_age=300,
        httponly=True,
        samesite="lax",
        secure=is_secure,
        path="/api/v1/auth/sso",
    )
    return redirect_resp


@router.get("/{provider_id}/callback", name="sso_callback")
async def sso_callback(
    provider_id: str,
    request: Request,
    response: Response,
    code: str = Query(...),
    state: str = Query(...),
    _rate_limit=Depends(RateLimiter(limit=30, window=60, ip_only=True)),
):
    """
    Completes OIDC PKCE callback:
      - Verifies single-use state + browser-bound CSRF cookie (`sso_state_binding`)
      - Fails closed if encrypted client_secret fails decryption
      - Verifies ID token via JWKS + constant-time nonce
      - Requires `email_verified == True` when using email
      - Provisions / matches strictly by deterministic `(issuer, sub)` UUID scoped to `tenant_id`
        (never collides with or overwrites local password-managed accounts!)
    """
    state_data = await consume_sso_state(state)
    if not state_data or state_data.get("provider_id") != str(provider_id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired SSO state token.")

    # AUTHN-02: Enforce RFC 6749 §10.12 browser state-binding cookie to block OAuth Login CSRF
    expected_binding = state_data.get("state_binding") or _sso_state_cookie_digest(state)
    cookie_binding = request.cookies.get("sso_state_binding") or ""
    if not cookie_binding or not hmac.compare_digest(cookie_binding, str(expected_binding)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SSO login CSRF validation failed: missing or mismatched browser state binding cookie.",
        )

    tenant_id = str(state_data["tenant_id"])
    provider = await _load_provider_for_login(provider_id, tenant_id)
    discovery = await fetch_oidc_discovery(provider["issuer_url"])

    # AUTHN-02: Fail closed if confidential client_secret_enc fails integrity/decryption
    client_secret = ""
    if provider.get("client_secret_enc"):
        try:
            client_secret = decrypt_pii(provider["client_secret_enc"], tenant_id=tenant_id) or ""
        except (DecryptionError, Exception):
            logger.error("Failed to decrypt OIDC client_secret for provider %s", provider_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="SSO provider credentials could not be decrypted.",
            )

    token_form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": state_data["redirect_uri"],
        "client_id": provider["client_id"],
        "code_verifier": state_data["code_verifier"],
    }
    if client_secret:
        token_form["client_secret"] = client_secret

    try:
        from services.http_client import request_with_resilience
        token_resp = await request_with_resilience(
            "POST",
            discovery["token_endpoint"],
            target="oidc_token_exchange",
            timeout=httpx.Timeout(connect=2.0, read=5.0, write=3.0, pool=2.0),
            follow_redirects=False,
            retries=0,
            data=token_form,
        )
        if token_resp.status_code != 200:
            raise HTTPException(status_code=401, detail="IdP token exchange failed.")
        token_data = token_resp.json()
    except HTTPException:
        raise
    except Exception:
        logger.exception("IdP token exchange error for provider %s", provider_id)
        raise HTTPException(status_code=502, detail="IdP token exchange failed.")

    id_token = token_data.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="IdP response missing mandatory id_token.")

    try:
        if verify_oidc_id_token is not _ORIGINAL_VERIFY_OIDC_ID_TOKEN:
            import inspect as _inspect
            maybe_claims = verify_oidc_id_token(
                id_token=id_token,
                jwks_uri=discovery["jwks_uri"],
                client_id=provider["client_id"],
                issuer=discovery.get("issuer", provider["issuer_url"]),
                expected_nonce=state_data["nonce"],
            )
            claims = await maybe_claims if _inspect.isawaitable(maybe_claims) else maybe_claims
        else:
            claims = await verify_oidc_id_token_async(
                id_token=id_token,
                jwks_uri=discovery["jwks_uri"],
                client_id=provider["client_id"],
                issuer=discovery.get("issuer", provider["issuer_url"]),
                expected_nonce=state_data["nonce"],
            )
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid OIDC ID token.")

    sub_claim = str(claims.get("sub") or "").strip()
    if not sub_claim:
        raise HTTPException(status_code=401, detail="OIDC ID token missing subject claim.")

    # AUTHN-02: Require verified email before trusting email claim (prevents unverified-email takeover)
    email = str(claims.get("email") or "").strip()
    if email and claims.get("email_verified") is not True:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="OIDC identity email address is not verified by the Identity Provider.",
        )

    username = (email.split("@")[0] if "@" in email else str(claims.get("preferred_username") or "")) or f"sso_{sub_claim[:12]}"
    raw_mapping = provider.get("group_role_mapping")
    mapping = json.loads(raw_mapping) if isinstance(raw_mapping, str) else (raw_mapping or {})
    idp_groups = claims.get("groups") or claims.get("roles") or []
    assigned_role = resolve_role_from_groups(idp_groups, mapping, default_role=provider.get("default_role", "L1_ANALYST"))

    # AUTHN-02: Strict deterministic SSO identity binding scoped to (tenant_id, issuer, sub).
    # NEVER match or overwrite existing local password-managed accounts by local-part username!
    user_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{tenant_id}:{provider['issuer_url']}:{sub_claim}"))
    sso_marker = f"sso_managed:{provider['id']}"
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        existing = await conn.fetchrow(
            "SELECT id, token_version, password_hash, is_active FROM users WHERE id = $1::uuid AND tenant_id = $2::uuid;",
            user_id,
            tenant_id,
        )
        if existing:
            if existing.get("is_active") is False:
                raise HTTPException(status_code=403, detail="SSO user account has been disabled.")
            if not str(existing.get("password_hash") or "").startswith("sso_managed:"):
                raise HTTPException(status_code=409, detail="Account collision with local user denied.")
            token_version = int(existing["token_version"] or 1)
            await conn.execute(
                "UPDATE users SET role = $1 WHERE id = $2::uuid AND tenant_id = $3::uuid;",
                assigned_role,
                user_id,
                tenant_id,
            )
        else:
            # Ensure username does not collide with an existing local user in this or any tenant
            collision = await conn.fetchrow("SELECT id FROM users WHERE username = $1;", username)
            if collision:
                username = f"{username}_sso_{user_id[:6]}"
            token_version = 1
            await conn.execute(
                """
                INSERT INTO users (id, username, role, tenant_id, password_hash)
                VALUES ($1::uuid, $2, $3, $4::uuid, $5);
                """,
                user_id,
                username,
                assigned_role,
                tenant_id,
                sso_marker,
            )

    family_id = f"fam_{uuid.uuid4().hex}"
    access_token = create_access_token({
        "sub": user_id,
        "role": assigned_role,
        "username": username,
        "email": email or f"{username}@sso.local",
        "tenant_id": tenant_id,
        "token_version": token_version,
    })
    refresh_token = create_refresh_token({
        "sub": user_id,
        "role": assigned_role,
        "username": username,
        "tenant_id": tenant_id,
        "token_version": token_version,
        "family_id": family_id,
    })

    log_audit_event(
        event_type="USER_LOGIN_SSO",
        actor_id=user_id,
        actor_role=assigned_role,
        action="SSO_LOGIN",
        resource_type="SESSION",
        resource_id=user_id,
        tenant_id=tenant_id,
        details={"username": username, "provider": provider["provider_name"], "role": assigned_role},
    )

    is_secure = bool(settings.enable_tls or settings.is_production)
    if "application/json" in request.headers.get("accept", ""):
        response.delete_cookie("sso_state_binding", path="/api/v1/auth/sso", httponly=True, samesite="lax", secure=is_secure)
        set_auth_cookies(response, access_token, refresh_token)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "username": username,
            "role": assigned_role,
            "tenant_id": tenant_id,
        }

    redirect_resp = RedirectResponse(url="/dashboard/executive", status_code=status.HTTP_302_FOUND)
    redirect_resp.delete_cookie("sso_state_binding", path="/api/v1/auth/sso", httponly=True, samesite="lax", secure=is_secure)
    set_auth_cookies(redirect_resp, access_token, refresh_token)
    return redirect_resp
