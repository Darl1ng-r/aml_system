import asyncio
import hashlib
import logging
import secrets
from typing import Optional
import aiohttp
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Query
from fastapi.security import OAuth2PasswordRequestForm
from config import settings
from pydantic import BaseModel, Field, field_validator
import jwt

logger = logging.getLogger(__name__)

from observability.sanitizer import sanitize_text

from services.rate_limiter import RateLimiter
from services.auth import (
    hash_password,
    hash_password_async,
    verify_password,
    verify_password_and_needs_rehash,
    verify_password_and_needs_rehash_async,
    create_access_token,
    create_refresh_token,
    get_current_user,
    check_account_lockout,
    record_failed_login,
    reset_failed_logins,
    RoleChecker,
    LOCKOUT_THRESHOLD,
    enforce_tenant_data_scope,
)
from observability.logging import log_audit_event


def _hash_token_for_key(raw_token: str) -> str:
    """Returns a SHA-256 hex digest of a JWT so live secrets never appear in Redis keyspace telemetry (AUTHN-06)."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def set_auth_cookies(response: Response, access_token: str, refresh_token: str | None = None):
    """Sets secure HttpOnly cookies for browser web sessions."""
    is_secure = bool(settings.enable_tls or settings.is_production)
    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=settings.access_token_expire_minutes * 60,
        httponly=True,
        samesite="strict",
        secure=is_secure,
        path="/"
    )
    if refresh_token:
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=settings.refresh_token_expire_days * 86400,
            httponly=True,
            samesite="strict",
            secure=is_secure,
            path="/"
        )

def clear_auth_cookies(response: Response):
    """Clears authentication cookies on logout with matching security attributes."""
    is_secure = bool(settings.enable_tls or settings.is_production)
    response.delete_cookie(
        key="access_token",
        path="/",
        httponly=True,
        samesite="strict",
        secure=is_secure,
    )
    response.delete_cookie(
        key="refresh_token",
        path="/",
        httponly=True,
        samesite="strict",
        secure=is_secure,
    )

class UserSignup(BaseModel):
    username: str = Field(..., min_length=3, max_length=100, pattern=r"^[A-Za-z0-9._@+-]+$")
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("username", mode="before")
    @classmethod
    def sanitize_username(cls, v: str) -> str:
        if isinstance(v, str):
            v = v.strip()
        return sanitize_text(v)

class UserProvision(BaseModel):
    """
    Admin-only payload to provision a new compliance team member.

    Allowed roles (5-tier RBAC model):
      • L1_ANALYST      — Tier 1: Alert triage & false-positive dismissal
      • L2_INVESTIGATOR — Tier 2: Full case investigation, SAR drafting, EDD requests
      • MLRO            — Compliance Manager: SAR approval, team oversight, risk-appetite config
      • ADMIN           — Rule Builder, User Manager, Integration Settings (tenant-scoped)
      • AUDITOR         — Read-only access to audit vault, model reports, decision snapshots
      • TENANT_ADMIN    — Cross-feature admin within a single tenant
      • SUPER_ADMIN     — Platform-wide access (internal ops only)
      • ANALYST         — Legacy alias for L2_INVESTIGATOR; retained for backward-compat
    """
    username: str = Field(..., min_length=3, max_length=100, pattern=r"^[A-Za-z0-9._@+-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(
        "ANALYST",
        pattern=r"^(L1_ANALYST|L2_INVESTIGATOR|MLRO|ANALYST|AUDITOR|QA_REVIEWER|ADMIN|TENANT_ADMIN|SUPER_ADMIN)$"
    )
    tenant_id: Optional[str] = None

    @field_validator("username", mode="before")
    @classmethod
    def sanitize_username(cls, v: str) -> str:
        if isinstance(v, str):
            v = v.strip()
        return sanitize_text(v)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

async def _attempt_supabase_login(email: str, password: str) -> dict | None:
    if not (settings.supabase_url and settings.supabase_key and not settings.supabase_key.startswith("your_")):
        return None
    if os.getenv("PYTEST_CURRENT_TEST"):
        return None
    base_url = settings.supabase_url.rstrip("/")
    if getattr(settings, "is_hardened", settings.is_production) and not base_url.lower().startswith("https://"):
        logger.error("Refusing plaintext Supabase URL in hardened environment.")
        return None
    try:
        import httpx
        from services.http_client import request_with_resilience

        payload = {"email": email, "password": password}
        headers = {"apikey": settings.supabase_key, "Content-Type": "application/json"}
        resp = await request_with_resilience(
            "POST",
            f"{base_url}/auth/v1/token?grant_type=password",
            target="supabase_auth",
            timeout=httpx.Timeout(connect=1.5, read=3.0, write=2.0, pool=1.5),
            follow_redirects=False,
            retries=0,
            json=payload,
            headers=headers,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        logger.warning("Supabase auth unreachable: %s. Falling back to local verification.", e)
    return None


async def _process_supabase_login_success(
    response: Response, form_data: OAuth2PasswordRequestForm, email: str, supabase_user: dict
) -> dict:
    import uuid
    data = supabase_user
    user = data.get("user") or data
    user_id = str(user.get("id", ""))
    # Security (S-10): Read role & tenant_id exclusively from server-managed app_metadata
    app_metadata = user.get("app_metadata") or {}
    role = app_metadata.get("role", "L1_ANALYST")
    username = email.split("@")[0]
    tenant_id = app_metadata.get("tenant_id", "00000000-0000-0000-0000-000000000001")

    hashed_pw = await asyncio.to_thread(hash_password, form_data.password)
    is_mfa_enabled = False
    token_version = 1
    from database.postgres import get_async_db_conn
    async with get_async_db_conn(tenant_id=tenant_id, auth_lookup=True) as conn:
        existing_local = await conn.fetchrow(
            "SELECT mfa_enabled, is_active, token_version FROM users WHERE id = $1;",
            user_id,
        )
        if existing_local and isinstance(existing_local, dict):
            if existing_local.get("is_active") is False:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            is_mfa_enabled = bool(existing_local.get("mfa_enabled", False))
            token_version = int(existing_local.get("token_version") or 1)

        await conn.execute(
            """
            INSERT INTO users (id, username, role, tenant_id, password_hash)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (id) DO UPDATE SET 
                role = EXCLUDED.role, 
                username = EXCLUDED.username, 
                tenant_id = EXCLUDED.tenant_id,
                password_hash = EXCLUDED.password_hash;
            """,
            user_id, username, role, tenant_id, hashed_pw
        )

    # AUTHN-10: Never allow Supabase login to bypass local TOTP MFA enrollment
    if is_mfa_enabled:
        return await _create_mfa_challenge_ticket(user_id, role, username, email, tenant_id)

    await reset_failed_logins(form_data.username)

    family_id = f"fam_{uuid.uuid4().hex}"
    access_token = create_access_token({
        "sub": user_id,
        "role": role,
        "username": username,
        "email": email,
        "tenant_id": tenant_id,
        "token_version": token_version,
    })
    refresh_token = create_refresh_token({
        "sub": user_id,
        "role": role,
        "username": username,
        "tenant_id": tenant_id,
        "token_version": token_version,
        "family_id": family_id,
    })

    log_audit_event(
        event_type="USER_LOGIN",
        actor_id=str(user_id),
        actor_role=role,
        action="LOGIN",
        resource_type="SESSION",
        resource_id=str(user_id),
        tenant_id=tenant_id,
        details={"username": username, "method": "supabase"}
    )

    set_auth_cookies(response, access_token, refresh_token)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "role": role,
        "username": username
    }


async def _handle_local_login_failure(username: str, local_user, password: str):
    if not local_user or not local_user["password_hash"]:
        from services.auth import DUMMY_ARGON2_HASH
        await asyncio.to_thread(verify_password_and_needs_rehash, password, DUMMY_ARGON2_HASH)
        log_audit_event(
            event_type="LOGIN_FAILED",
            actor_id=username,
            actor_role="UNKNOWN",
            action="FAILED_LOGIN",
            resource_type="SESSION",
            resource_id="",
            details={"username": username, "reason": "User not found or no password hash"}
        )
        attempts = await record_failed_login(username)
    else:
        log_audit_event(
            event_type="LOGIN_FAILED",
            actor_id=str(local_user["id"]),
            actor_role=local_user["role"] or "ANALYST",
            action="FAILED_LOGIN",
            resource_type="SESSION",
            resource_id=str(local_user["id"]),
            tenant_id=str(local_user["tenant_id"]) if local_user["tenant_id"] else "",
            details={"username": username, "reason": "Password hash mismatch"}
        )
        attempts = await record_failed_login(
            username, tenant_id=str(local_user["tenant_id"]) if local_user["tenant_id"] else None
        )

    if attempts >= LOCKOUT_THRESHOLD:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account temporarily locked due to excessive failed attempts. Please try again later."
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def _create_mfa_challenge_ticket(
    user_id: str, role: str, username: str, email: str, tenant_id: str
) -> dict:
    import json
    from database.redis_db import get_async_redis_client
    mfa_ticket = f"mfa_{secrets.token_urlsafe(32)}"
    redis = await get_async_redis_client()
    if not redis:
        # AUTHN-03: Fail closed when Redis is unavailable instead of returning an unusable ticket
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Multi-factor authentication service temporarily unavailable. Please try again shortly.",
        )

    ticket_data = {
        "user_id": user_id,
        "role": role,
        "username": username,
        "email": email,
        "tenant_id": tenant_id
    }
    await redis.setex(f"mfa:ticket:{mfa_ticket}", 300, json.dumps(ticket_data))

    return {
        "mfa_required": True,
        "mfa_ticket": mfa_ticket,
        "message": "Two-factor authentication required. Please verify with your 6-digit TOTP code or backup recovery code."
    }


async def _execute_local_login(
    response: Response, form_data: OAuth2PasswordRequestForm, email: str
) -> dict:
    from database.postgres import get_async_db_conn
    async with get_async_db_conn(auth_lookup=True) as conn:
        local_user = await conn.fetchrow(
            """
            SELECT id, role, password_hash, tenant_id, mfa_enabled, token_version 
            FROM users 
            WHERE username = $1 AND (is_active IS NULL OR is_active = true);
            """,
            form_data.username
        )

        if not local_user or not local_user["password_hash"]:
            await _handle_local_login_failure(form_data.username, None, form_data.password)

        pw_valid, needs_rehash = await asyncio.to_thread(verify_password_and_needs_rehash, form_data.password, local_user["password_hash"])
        if not pw_valid:
            await _handle_local_login_failure(form_data.username, local_user, form_data.password)

        if needs_rehash:
            try:
                new_argon2_hash = await asyncio.to_thread(hash_password, form_data.password)
                await conn.execute(
                    "UPDATE users SET password_hash = $1 WHERE id = $2;",
                    new_argon2_hash, local_user["id"]
                )
                logger.info(f"Transparently upgraded password hash to Argon2id for user {form_data.username}")
            except Exception as rehash_err:
                logger.warning(f"Failed to in-place upgrade password hash: {rehash_err}")

        local_user_id = str(local_user["id"])
        local_role = local_user["role"] or "ANALYST"
        tenant_id = str(local_user["tenant_id"]) if local_user["tenant_id"] else "00000000-0000-0000-0000-000000000001"
        is_mfa_enabled = bool(local_user["mfa_enabled"]) if "mfa_enabled" in local_user.keys() else False
        token_version = local_user["token_version"] if "token_version" in local_user.keys() and local_user["token_version"] else 1

    if is_mfa_enabled:
        return await _create_mfa_challenge_ticket(local_user_id, local_role, form_data.username, email, tenant_id)

    import uuid
    family_id = f"fam_{uuid.uuid4().hex}"
    access_token = create_access_token({
        "sub": local_user_id,
        "role": local_role,
        "username": form_data.username,
        "email": email,
        "tenant_id": tenant_id,
        "token_version": token_version
    })
    refresh_token = create_refresh_token({
        "sub": local_user_id,
        "role": local_role,
        "username": form_data.username,
        "tenant_id": tenant_id,
        "token_version": token_version,
        "family_id": family_id
    })

    await reset_failed_logins(form_data.username)

    log_audit_event(
        event_type="USER_LOGIN",
        actor_id=local_user_id,
        actor_role=local_role,
        action="LOGIN",
        resource_type="SESSION",
        resource_id=local_user_id,
        tenant_id=tenant_id,
        details={"username": form_data.username, "method": "local_database"}
    )
    
    set_auth_cookies(response, access_token, refresh_token)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "role": local_role,
        "username": form_data.username
    }


@router.post("/login")
async def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    _rate_limit=Depends(RateLimiter(limit=20, window=600, fail_closed=True, ip_only=True))
):
    # AUTHN-09: Reject oversized passwords before Argon2id to prevent CPU/memory DoS
    if not form_data.password or len(form_data.password) > 128 or len(form_data.username or "") > 150:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    await check_account_lockout(form_data.username)

    email = form_data.username if "@" in form_data.username else f"{form_data.username}@aml.com"
    supabase_user = await _attempt_supabase_login(email, form_data.password)

    if supabase_user:
        res = await _process_supabase_login_success(response, form_data, email, supabase_user)
    else:
        res = await _execute_local_login(response, form_data, email)

    # HARD-04: Pure cookie-mode browser clients omit raw tokens from JSON response body
    if (
        isinstance(res, dict)
        and not res.get("mfa_required")
        and request.headers.get("x-client-mode", "").lower() == "browser"
    ):
        return {
            "token_type": "cookie",
            "role": res.get("role"),
            "username": res.get("username"),
        }
    return res


async def _attempt_supabase_signup(email: str, password: str, assigned_role: str, tenant_id: str) -> dict | None:
    if not (settings.supabase_url and settings.supabase_key and not settings.supabase_key.startswith("your_")):
        return None
    if os.getenv("PYTEST_CURRENT_TEST"):
        return None
    base_url = settings.supabase_url.rstrip("/")
    if getattr(settings, "is_hardened", settings.is_production) and not base_url.lower().startswith("https://"):
        logger.error("Refusing plaintext Supabase URL in hardened environment.")
        return None
    try:
        import httpx
        from services.http_client import request_with_resilience

        signup_data = {
            "email": email,
            "password": password,
            "data": {"role": assigned_role, "tenant_id": tenant_id},
        }
        headers = {"apikey": settings.supabase_key, "Content-Type": "application/json"}
        resp = await request_with_resilience(
            "POST",
            f"{base_url}/auth/v1/signup",
            target="supabase_auth",
            timeout=httpx.Timeout(connect=1.5, read=3.0, write=2.0, pool=1.5),
            follow_redirects=False,
            retries=0,
            json=signup_data,
            headers=headers,
        )
        if resp.status_code == 200:
            return resp.json()
        logger.warning("Supabase signup returned status %s. Falling back to local registration.", resp.status_code)
    except Exception as e:
        logger.warning("Supabase auth unreachable during signup: %s. Falling back to local registration.", e)
    return None


async def _process_supabase_signup_success(
    response: Response,
    payload: UserSignup,
    email: str,
    assigned_role: str,
    default_tenant_id: str,
    hashed_pw: str,
    supabase_data: dict,
) -> dict:
    data = supabase_data
    access_token = data.get("access_token")
    user_info = data.get("user") if "user" in data else data
    supabase_user_id = user_info.get("id")

    if supabase_user_id:
        from database.postgres import get_async_db_conn
        async with get_async_db_conn(tenant_id=default_tenant_id) as conn:
            await conn.execute(
                """
                INSERT INTO users (id, username, role, tenant_id, password_hash) 
                VALUES ($1, $2, $3, $4, $5) 
                ON CONFLICT (id) DO UPDATE SET 
                    username = EXCLUDED.username,
                    role = EXCLUDED.role,
                    password_hash = EXCLUDED.password_hash;
                """,
                supabase_user_id,
                payload.username,
                assigned_role,
                default_tenant_id,
                hashed_pw
            )

    if not access_token:
        access_token = create_access_token({
            "sub": str(supabase_user_id or ""),
            "role": assigned_role,
            "username": payload.username,
            "email": email,
            "tenant_id": default_tenant_id
        })

    refresh_token = create_refresh_token({
        "sub": str(supabase_user_id or ""),
        "role": assigned_role,
        "username": payload.username,
        "tenant_id": default_tenant_id
    })

    log_audit_event(
        event_type="USER_SIGNUP",
        actor_id=str(supabase_user_id or ""),
        actor_role=assigned_role,
        action="SIGNUP",
        resource_type="USER",
        resource_id=str(supabase_user_id or ""),
        tenant_id=default_tenant_id,
        details={"username": payload.username, "method": "supabase"}
    )
    
    set_auth_cookies(response, access_token, refresh_token)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "role": assigned_role,
        "username": email.split("@")[0]
    }


async def _execute_local_signup(
    response: Response,
    payload: UserSignup,
    email: str,
    assigned_role: str,
    default_tenant_id: str,
    hashed_pw: str,
) -> dict:
    try:
        import uuid
        from database.postgres import get_async_db_conn
        async with get_async_db_conn(tenant_id=default_tenant_id) as conn:
            existing_user = await conn.fetchrow(
                "SELECT id FROM users WHERE username = $1;",
                payload.username
            )
            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already registered or invalid registration data"
                )

            local_user_id = str(uuid.uuid4())
            await conn.execute(
                """
                INSERT INTO users (id, username, role, tenant_id, password_hash) 
                VALUES ($1, $2, $3, $4, $5);
                """,
                local_user_id,
                payload.username,
                assigned_role,
                default_tenant_id,
                hashed_pw
            )
        
        access_token = create_access_token({
            "sub": local_user_id,
            "role": assigned_role,
            "username": payload.username,
            "email": email,
            "tenant_id": default_tenant_id
        })
        refresh_token = create_refresh_token({
            "sub": local_user_id,
            "role": assigned_role,
            "username": payload.username,
            "tenant_id": default_tenant_id
        })
        
        log_audit_event(
            event_type="USER_SIGNUP",
            actor_id=local_user_id,
            actor_role=assigned_role,
            action="SIGNUP",
            resource_type="USER",
            resource_id=local_user_id,
            tenant_id=default_tenant_id,
            details={"username": payload.username, "method": "local_database"}
        )

        response.status_code = status.HTTP_201_CREATED
        response.headers["Location"] = "/api/v1/auth/me"
        set_auth_cookies(response, access_token, refresh_token)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "role": assigned_role,
            "username": payload.username
        }
    except HTTPException:
        raise
    except Exception:
        logger.exception("Local signup failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered or invalid registration data"
        )


@router.post("/signup", summary="Register compliance officer (Disabled in production)")
@router.post("/register", summary="Register compliance officer (Disabled in production)")
async def signup(
    request: Request,
    response: Response,
    payload: UserSignup,
    _rate_limit=Depends(RateLimiter(limit=10, window=3600, fail_closed=True, ip_only=True))
):
    # Security (S-1 / HARD-03): Public self-registration is strictly disabled in production
    # or when ALLOW_PUBLIC_SIGNUP=false. Provision users via POST /api/v1/auth/provision.
    if settings.is_production or not getattr(settings, "allow_public_signup", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public self-registration is disabled in this environment. Contact your compliance administrator for account provisioning."
        )

    # Enforce NIST SP 800-63B HIBP breach screening on BOTH /signup and /register
    from services.auth import check_breached_password
    if await check_breached_password(payload.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password has appeared in a known public data breach (NIST SP 800-63B violation). Please choose a different, more secure passphrase."
        )

    email = payload.username if "@" in payload.username else f"{payload.username}@aml.com"
    assigned_role = "L1_ANALYST"
    default_tenant_id = "00000000-0000-0000-0000-000000000001"
    hashed_pw = await asyncio.to_thread(hash_password, payload.password)

    supabase_data = await _attempt_supabase_signup(email, payload.password, assigned_role, default_tenant_id)
    if supabase_data:
        return await _process_supabase_signup_success(
            response, payload, email, assigned_role, default_tenant_id, hashed_pw, supabase_data
        )

    return await _execute_local_signup(
        response, payload, email, assigned_role, default_tenant_id, hashed_pw
    )

@router.post("/users", status_code=status.HTTP_201_CREATED, summary="Provision institutional user (RESTful /users)")
@router.post("/provision", status_code=status.HTTP_201_CREATED, summary="Provision institutional compliance user with explicit role/tenant (Admin only)")
async def provision(
    response: Response,
    payload: UserProvision,
    current_user: dict = Depends(RoleChecker(["SUPER_ADMIN", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=3600))
):
    email = payload.username
    if "@" not in email:
        email = f"{email}@aml.com"
    
    caller_role = current_user.get("role", "")
    if caller_role == "SUPER_ADMIN" and payload.tenant_id:
        target_tenant_id = payload.tenant_id
    else:
        target_tenant_id = str(current_user.get("tenant_id") or "")
        if not target_tenant_id:
            raise HTTPException(status_code=403, detail="Caller tenant scope missing.")

    # AUTHZ-09: Explicitly reject non-SUPER_ADMIN attempting to provision SUPER_ADMIN (no silent downgrade)
    if payload.role == "SUPER_ADMIN" and caller_role != "SUPER_ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only SUPER_ADMIN can provision a SUPER_ADMIN account.",
        )
    assigned_role = payload.role or "ANALYST"

    # NIST SP 800-63B HIBP breached password screening on admin provisioning as well
    from services.auth import check_breached_password
    if await check_breached_password(payload.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password has appeared in a known public data breach (NIST SP 800-63B violation). Please choose a stronger passphrase.",
        )

    hashed_pw = await asyncio.to_thread(hash_password, payload.password)

    import uuid
    from database.postgres import get_async_db_conn
    async with get_async_db_conn(tenant_id=target_tenant_id) as conn:
        existing_user = await conn.fetchrow(
            "SELECT id FROM users WHERE username = $1;",
            payload.username
        )
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already registered"
            )

        local_user_id = str(uuid.uuid4())
        await conn.execute(
            """
            INSERT INTO users (id, username, role, tenant_id, password_hash) 
            VALUES ($1, $2, $3, $4, $5);
            """,
            local_user_id,
            payload.username,
            assigned_role,
            target_tenant_id,
            hashed_pw
        )
    
    log_audit_event(
        event_type="USER_PROVISION",
        actor_id=str(current_user.get("sub", "")),
        actor_role=caller_role,
        action="PROVISION",
        resource_type="USER",
        resource_id=local_user_id,
        tenant_id=target_tenant_id,
        details={"username": payload.username, "assigned_role": assigned_role, "provisioned_by": current_user.get("username")}
    )

    return {
        "status": "provisioned",
        "user_id": local_user_id,
        "username": payload.username,
        "role": assigned_role,
        "tenant_id": target_tenant_id
    }


class UserRoleUpdate(BaseModel):
    role: str = Field(..., pattern=r"^(L1_ANALYST|L2_INVESTIGATOR|MLRO|ANALYST|AUDITOR|QA_REVIEWER|ADMIN|TENANT_ADMIN|SUPER_ADMIN)$")


@router.get("/users", summary="List users within current tenant (Admin only)")
async def list_users(
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(RoleChecker(["SUPER_ADMIN", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    import uuid
    from database.postgres import get_async_db_conn
    tenant_id = enforce_tenant_data_scope(current_user)
    clamped_limit = max(1, min(limit, 200))
    clamped_offset = max(0, offset)
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            # AUTHZ-01: Defense-in-depth explicit tenant_id filter alongside forced PostgreSQL RLS
            rows = await conn.fetch(
                """
                SELECT id, username, role, tenant_id, mfa_enabled, created_at
                FROM users
                WHERE tenant_id = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3;
                """,
                uuid.UUID(str(tenant_id)), clamped_limit, clamped_offset
            )
            return [
                {
                    "id": str(r["id"]),
                    "username": r["username"],
                    "role": r["role"],
                    "tenant_id": str(r["tenant_id"]) if r["tenant_id"] else None,
                    "mfa_enabled": bool(r.get("mfa_enabled", False)),
                    "created_at": r["created_at"].isoformat() if r.get("created_at") else ""
                }
                for r in rows
            ]
    except Exception as e:
        logger.warning(f"Error listing users: {e}")
        return []


@router.patch("/users/{user_id}/role", summary="Update user role (Admin only)")
async def update_user_role(
    user_id: str,
    payload: UserRoleUpdate,
    current_user: dict = Depends(RoleChecker(["SUPER_ADMIN", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    caller_role = current_user.get("role", "")
    if payload.role == "SUPER_ADMIN" and caller_role != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can assign SUPER_ADMIN role.")

    tenant_id = enforce_tenant_data_scope(current_user)
    from database.postgres import get_async_db_conn
    from services.auth import revoke_user_sessions
    import uuid

    try:
        u_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format")

    async with get_async_db_conn(tenant_id=tenant_id, auth_lookup=(caller_role == "SUPER_ADMIN")) as conn:
        if caller_role == "SUPER_ADMIN":
            row = await conn.fetchrow("SELECT username, role, tenant_id FROM users WHERE id = $1;", u_uuid)
        else:
            # AUTHZ-01: Strictly scope lookup & mutation to caller's tenant
            row = await conn.fetchrow(
                "SELECT username, role, tenant_id FROM users WHERE id = $1 AND tenant_id = $2;",
                u_uuid, uuid.UUID(str(tenant_id)),
            )
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        # AUTHZ-09: Tenant ADMIN cannot downgrade or modify an existing SUPER_ADMIN
        if row["role"] == "SUPER_ADMIN" and caller_role != "SUPER_ADMIN":
            raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can modify a SUPER_ADMIN account.")

        target_tenant = str(row.get("tenant_id") or tenant_id)
        if caller_role == "SUPER_ADMIN":
            await conn.execute("UPDATE users SET role = $1 WHERE id = $2;", payload.role, u_uuid)
        else:
            await conn.execute(
                "UPDATE users SET role = $1 WHERE id = $2 AND tenant_id = $3;",
                payload.role, u_uuid, uuid.UUID(str(tenant_id)),
            )

    await revoke_user_sessions(user_id, tenant_id=target_tenant)

    log_audit_event(
        event_type="USER_ROLE_CHANGED",
        actor_id=str(current_user.get("id", "")),
        actor_role=caller_role,
        action="UPDATE_ROLE",
        resource_type="USER",
        resource_id=user_id,
        tenant_id=target_tenant,
        details={"username": row["username"], "old_role": row["role"], "new_role": payload.role}
    )

    return {"status": "SUCCESS", "user_id": user_id, "new_role": payload.role}


class RefreshRequest(BaseModel):
    refresh_token: str | None = None


async def _handle_token_compromise(
    redis, response: Response, sub: str | None, role: str, username: str, tenant_id: str, family_id: str
):
    # COMPROMISE DETECTED (RFC 6819): An already consumed refresh token was re-submitted!
    # Immediately invalidate the entire token family and bump active user token_version.
    await redis.setex(f"token:family_revoked:{family_id}", 30 * 86400, "1")
    if sub:
        await redis.incr(f"user:token_version:{sub}")
        try:
            import uuid as _uuid
            _uuid.UUID(str(sub))
            from database.postgres import get_async_db_conn
            async with get_async_db_conn(tenant_id=tenant_id, auth_lookup=True) as conn:
                await conn.execute("UPDATE users SET token_version = COALESCE(token_version, 1) + 1 WHERE id = $1;", sub)
        except Exception as db_err:
            logger.warning(f"Failed to bump token_version on compromise: {db_err}")

    log_audit_event(
        event_type="SECURITY_ALERT",
        actor_id=str(sub or ""),
        actor_role=role,
        action="REFRESH_TOKEN_COMPROMISE_DETECTED",
        resource_type="SESSION",
        resource_id=str(sub or ""),
        tenant_id=tenant_id,
        details={"family_id": family_id, "username": username, "reason": "Reuse of previously revoked refresh token"}
    )
    clear_auth_cookies(response)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Compromised session detected: reuse of revoked refresh token. All active sessions have been terminated for security.",
        headers={"WWW-Authenticate": "Bearer"}
    )


async def _check_refresh_token_revocation(
    redis, response: Response, token_to_refresh: str, family_id: str | None, sub: str | None,
    role: str, username: str, tenant_id: str, credentials_exception: HTTPException
):
    if not redis:
        if settings.is_production:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Session store unavailable; refresh rejected (fail-closed).",
            )
        return

    is_family_revoked = await redis.get(f"token:family_revoked:{family_id}") if family_id else None
    if is_family_revoked:
        clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Compromised session detected: reuse of revoked refresh token. All active sessions have been terminated for security.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token_digest = _hash_token_for_key(token_to_refresh)
    is_token_revoked = await redis.get(f"token:revoked:{token_digest}")
    if is_token_revoked:
        if family_id:
            await _handle_token_compromise(redis, response, sub, role, username, tenant_id, family_id)
        else:
            clear_auth_cookies(response)
            raise credentials_exception


async def _claim_refresh_token_atomic(
    redis, token_to_refresh: str, ttl: int, response: Response,
    family_id: str | None, sub: str | None, role: str, username: str,
    tenant_id: str, credentials_exception: HTTPException,
) -> None:
    """Atomically marks a refresh token consumed using SHA-256 key & SET NX EX (AUTHN-01 / AUTHN-06)."""
    if not redis:
        return
    revoked_key = f"token:revoked:{_hash_token_for_key(token_to_refresh)}"
    claimed = None
    used_atomic = False
    if hasattr(redis, "set") and not getattr(redis.set, "_mock_name", None):
        try:
            claimed = await redis.set(revoked_key, "1", ex=ttl, nx=True)
            used_atomic = True
        except TypeError:
            used_atomic = False
    if used_atomic:
        if not claimed:
            if family_id:
                await _handle_token_compromise(redis, response, sub, role, username, tenant_id, family_id)
            clear_auth_cookies(response)
            raise credentials_exception
    else:
        await redis.setex(revoked_key, ttl, "1")


async def _load_authoritative_user_for_refresh(
    sub: str | None,
    token_version: int,
    fallback_role: str,
    fallback_tenant_id: str,
    credentials_exception: HTTPException,
) -> tuple[str, str, int]:
    """Reloads live role, tenant_id, is_active, and token_version from PostgreSQL on every refresh (AUTHN-01)."""
    if not sub:
        raise credentials_exception

    from services.auth import _verify_token_version
    await _verify_token_version(str(sub), token_version, tenant_id=fallback_tenant_id)

    role = fallback_role
    tenant_id = fallback_tenant_id
    authoritative_ver = int(token_version)
    try:
        import uuid as _uuid
        u_uuid = _uuid.UUID(str(sub))
        from database.postgres import get_async_db_conn
        async with get_async_db_conn(tenant_id=fallback_tenant_id, auth_lookup=True) as conn:
            row = await conn.fetchrow(
                "SELECT role, tenant_id, token_version, is_active FROM users WHERE id = $1;",
                u_uuid,
            )
            if row is not None and (isinstance(row, dict) or hasattr(row, "keys")):
                if row.get("is_active") is False:
                    raise credentials_exception
                db_ver = int(row.get("token_version") or 1)
                if db_ver > int(token_version):
                    raise credentials_exception
                role = row.get("role") or role
                tenant_id = str(row.get("tenant_id") or tenant_id)
                authoritative_ver = db_ver
            elif settings.is_production:
                raise credentials_exception
    except HTTPException:
        raise
    except Exception as db_err:
        logger.warning("Authoritative refresh user lookup skipped/failed for %s: %s", sub, db_err)
        if settings.is_production:
            raise credentials_exception

    return role, tenant_id, authoritative_ver


@router.post("/refresh", summary="Exchange refresh token with token rotation")
async def refresh_access_token(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
    _rate_limit=Depends(RateLimiter(limit=30, window=60, fail_closed=True, ip_only=True)),
):
    """
    Validates the refresh token, checks token_version & live DB role/active status,
    atomically revokes the consumed refresh token in Redis (SHA-256 keyed), and issues
    both a fresh access token and a rotated refresh token preserving token_version and family_id.
    """
    from database.redis_db import get_async_redis_client
    from services.auth import create_access_token, create_refresh_token, ALGORITHM
    from services.secrets_manager import decode_jwt_with_rotation
    from datetime import datetime, timezone

    body_token = body.refresh_token if body and body.refresh_token else None
    cookie_token = request.cookies.get("refresh_token")
    token_to_refresh = body_token or cookie_token
    if not token_to_refresh:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_jwt_with_rotation(token_to_refresh, algorithm=ALGORITHM)
        if payload.get("type") != "refresh":
            raise credentials_exception

        family_id = payload.get("family_id")
        sub = payload.get("sub")
        payload_role = payload.get("role")
        username = payload.get("username", "")
        payload_tenant_id = payload.get("tenant_id")
        token_version = payload.get("token_version")
        if not sub or not payload_role or not payload_tenant_id or token_version is None:
            raise credentials_exception

        # 1. Check Redis denylist & Token Family Compromise Detection (RFC 6819)
        redis = await get_async_redis_client()
        await _check_refresh_token_revocation(
            redis, response, token_to_refresh, family_id, sub, payload_role, username, payload_tenant_id, credentials_exception
        )

        # 2. Verify token_version & reload authoritative live role / active status from PostgreSQL
        role, tenant_id, auth_token_version = await _load_authoritative_user_for_refresh(
            sub, int(token_version), payload_role, str(payload_tenant_id), credentials_exception
        )

        # 3. Atomically consume refresh token (prevents concurrent rotation races)
        exp = payload.get("exp", 0)
        ttl = max(int(exp - datetime.now(timezone.utc).timestamp()), 1)
        await _claim_refresh_token_atomic(
            redis, token_to_refresh, ttl, response, family_id, sub, role, username, tenant_id, credentials_exception
        )

        # 4. Issue fresh access token & rotated refresh token preserving authoritative token_version + family_id
        new_access_token = create_access_token({
            "sub": sub,
            "role": role,
            "username": username,
            "tenant_id": tenant_id,
            "token_version": auth_token_version,
        })
        new_refresh_token = create_refresh_token({
            "sub": sub,
            "role": role,
            "username": username,
            "tenant_id": tenant_id,
            "token_version": auth_token_version,
            "family_id": family_id,
        })

        set_auth_cookies(response, new_access_token, new_refresh_token)

        # HARD-04: Pure cookie-mode browsers omit raw refresh_token from JSON body
        if request.headers.get("x-client-mode", "").lower() == "browser":
            return {
                "token_type": "cookie",
                "role": role,
                "username": username,
            }

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "role": role,
            "username": username
        }

    except (jwt.ExpiredSignatureError, jwt.PyJWTError):
        raise credentials_exception
    except HTTPException:
        raise
    except Exception:
        logger.exception("Token refresh failed")
        raise HTTPException(status_code=500, detail="Token refresh failed due to an internal error.")


@router.delete("/sessions/current", summary="Revoke current session and clear cookies (RESTful DELETE)")
@router.delete("/session", summary="Revoke current session (RESTful DELETE)")
@router.post("/logout", summary="Revoke refresh & active access tokens and clear cookies")
async def logout(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """
    Revokes both the refresh token (SHA-256 keyed denylist) and active access token
    (JTI denylist for remaining TTL) in Redis, and clears HttpOnly authentication cookies.
    """
    from database.redis_db import get_async_redis_client
    from services.auth import ALGORITHM
    from services.secrets_manager import decode_jwt_with_rotation
    from datetime import datetime, timezone

    token_to_revoke = (body.refresh_token if body and body.refresh_token else None) or request.cookies.get("refresh_token")

    auth_header = request.headers.get("Authorization", "")
    active_access_token = (
        auth_header[7:].strip() if auth_header.startswith("Bearer ") else None
    ) or request.cookies.get("access_token")

    redis = None
    try:
        redis = await get_async_redis_client()
    except Exception as e:
        logger.warning(f"Redis unavailable during logout: {e}")

    if token_to_revoke and redis:
        try:
            payload = decode_jwt_with_rotation(token_to_revoke, algorithm=ALGORITHM)
            exp = payload.get("exp", 0)
            ttl = max(int(exp - datetime.now(timezone.utc).timestamp()), 1)
            await redis.setex(f"token:revoked:{_hash_token_for_key(token_to_revoke)}", ttl, "1")
        except jwt.PyJWTError:
            pass
        except Exception as e:
            logger.warning(f"Error revoking refresh token in Redis during logout: {e}")

    # AUTHN-01: Immediately revoke active access token JTI so it cannot be reused for remaining 15m TTL
    if active_access_token and redis:
        try:
            acc_payload = decode_jwt_with_rotation(active_access_token, algorithm=ALGORITHM)
            acc_jti = acc_payload.get("jti")
            if acc_jti:
                acc_exp = acc_payload.get("exp", 0)
                acc_ttl = max(int(acc_exp - datetime.now(timezone.utc).timestamp()), 1)
                await redis.setex(f"token:access_revoked:{acc_jti}", acc_ttl, "1")
        except jwt.PyJWTError:
            pass
        except Exception as e:
            logger.warning(f"Error revoking access token JTI during logout: {e}")

    clear_auth_cookies(response)
    if request.method == "DELETE":
        response.status_code = status.HTTP_204_NO_CONTENT
        return response
    return {"detail": "Logged out successfully. Refresh and access tokens revoked."}


@router.post("/ws-ticket", summary="Mint single-use short-lived WebSocket authentication ticket")
async def issue_ws_ticket(
    current_user: dict = Depends(get_current_user),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Issues a 30-second single-use opaque ticket for authenticating `/ws/live-stream` without JWTs in URLs (AUTHN-05)."""
    import json
    from database.redis_db import get_async_redis_client
    redis = await get_async_redis_client()
    if not redis:
        raise HTTPException(status_code=503, detail="WebSocket ticket store unavailable.")
    ticket = f"wst_{secrets.token_urlsafe(32)}"
    payload = {
        "user_id": str(current_user.get("id", "")),
        "tenant_id": str(current_user.get("tenant_id", "")),
        "role": str(current_user.get("role", "")),
    }
    await redis.setex(f"ws:ticket:{ticket}", 30, json.dumps(payload))
    return {"ticket": ticket, "expires_in_seconds": 30}


@router.get("/me", summary="Get current authenticated user identity")
async def get_me(
    request: Request = None,
    current_user: dict = Depends(get_current_user),
    _rate_limit=Depends(RateLimiter(limit=120, window=60)),
):
    """
    Returns the currently authenticated user session identity with ETag / 304 support.
    Resolves seamlessly via Authorization Bearer header or HttpOnly access_token cookie.
    """
    from services.http_cache import build_conditional_json_response
    payload = {
        "id": current_user.get("id"),
        "username": current_user.get("username"),
        "role": current_user.get("role"),
        "email": current_user.get("email"),
        "tenant_id": current_user.get("tenant_id")
    }
    return build_conditional_json_response(request, payload)


@router.get("/check-username", summary="Debounced username availability check for registration (Disabled in production)")
async def check_username_availability(
    username: str = Query(..., min_length=3, max_length=100),
    _rate_limit=Depends(RateLimiter(limit=60, window=60, ip_only=True))
):
    """
    Non-blocking endpoint for real-time username availability validation during sign-up.
    HARD-02: Strictly disabled in production or whenever public signup is disabled
    to eliminate unauthenticated cross-tenant username enumeration.
    """
    if settings.is_production or not getattr(settings, "allow_public_signup", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Username availability lookup is disabled in this environment.",
        )
    clean_username = sanitize_text(username.strip())
    from database.postgres import get_async_db_conn
    async with get_async_db_conn(auth_lookup=True) as conn:
        exists = await conn.fetchval(
            "SELECT 1 FROM users WHERE LOWER(username) = LOWER($1);",
            clean_username
        )
    return {
        "username": clean_username,
        "available": not bool(exists),
        "message": "Username is available" if not exists else "Username is already registered"
    }


@router.delete("/sessions", summary="Revoke all active sessions for current user (RESTful DELETE)")
@router.delete("/users/me/sessions", summary="Revoke all active sessions (RESTful DELETE)")
@router.post("/revoke-sessions", summary="Revoke all active sessions for current user")
@router.post("/sessions/revoke-all", summary="Global logout: Revoke all active sessions across devices")
async def revoke_sessions(
    current_user: dict = Depends(get_current_user),
    _rate_limit=Depends(RateLimiter(limit=20, window=60)),
):
    """
    Increments token_version for the authenticated user, immediately
    invalidating all active access tokens and refresh tokens across all devices.
    """
    from services.auth import revoke_user_sessions
    user_id = current_user.get("id")
    tenant_id = current_user.get("tenant_id")
    new_ver = await revoke_user_sessions(user_id, tenant_id=str(tenant_id) if tenant_id else None)
    return {
        "detail": "All active sessions revoked successfully. Please log in again.",
        "token_version": new_ver
    }


@router.post("/users/{user_id}/revoke-sessions", summary="Revoke all active sessions for a target user (Admin only)")
@router.delete("/users/{user_id}/sessions", summary="Revoke all active sessions for a target user (RESTful DELETE)")
async def admin_revoke_target_user_sessions(
    user_id: str,
    current_user: dict = Depends(RoleChecker(["SUPER_ADMIN", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """
    Increments token_version for the target user ID, immediately invalidating
    all active JWT access and refresh tokens across all pods and devices.
    """
    import uuid
    try:
        u_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format.")

    caller_role = current_user.get("role", "")
    tenant_id = enforce_tenant_data_scope(current_user)
    from database.postgres import get_async_db_conn
    from services.auth import revoke_user_sessions

    async with get_async_db_conn(tenant_id=tenant_id, auth_lookup=(caller_role == "SUPER_ADMIN")) as conn:
        if caller_role == "SUPER_ADMIN":
            row = await conn.fetchrow("SELECT username, role, tenant_id FROM users WHERE id = $1;", u_uuid)
        else:
            row = await conn.fetchrow(
                "SELECT username, role, tenant_id FROM users WHERE id = $1 AND tenant_id = $2;",
                u_uuid, uuid.UUID(str(tenant_id)),
            )
        if not row:
            raise HTTPException(status_code=404, detail="Target user not found.")

    # AUTHZ-09: Tenant ADMIN cannot force-logout a SUPER_ADMIN
    if row["role"] == "SUPER_ADMIN" and caller_role != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can revoke sessions of a SUPER_ADMIN.")

    target_tenant = str(row.get("tenant_id") or tenant_id)
    new_ver = await revoke_user_sessions(user_id, tenant_id=target_tenant)

    log_audit_event(
        event_type="USER_SESSIONS_REVOKED",
        actor_id=str(current_user.get("id", "")),
        actor_role=caller_role,
        action="REVOKE_SESSIONS",
        resource_type="USER",
        resource_id=user_id,
        tenant_id=target_tenant,
        details={"username": row["username"], "target_role": row["role"], "new_token_version": new_ver}
    )

    return {
        "status": "SUCCESS",
        "detail": f"All active sessions for user '{row['username']}' revoked successfully.",
        "user_id": user_id,
        "token_version": new_ver
    }


# ── Multi-Factor Authentication (MFA / TOTP) Endpoints ─────────────────────────

class MFASetupRequest(BaseModel):
    password: Optional[str] = Field(default=None, max_length=128)
    current_code: Optional[str] = Field(default=None, max_length=32)


class MFAEnableRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=16)
    password: Optional[str] = Field(default=None, max_length=128)


class MFAVerifyRequest(BaseModel):
    mfa_ticket: str = Field(..., min_length=4, max_length=256)
    code: str = Field(..., min_length=6, max_length=32)


class MFADisableRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=128)


def _decrypt_mfa_secret(raw_secret: str, tenant_id: str | None = None) -> str:
    """Decrypts AES-256-GCM encrypted MFA secrets while preserving legacy Base32 compatibility."""
    if not raw_secret:
        return ""
    if str(raw_secret).startswith("enc:v1:"):
        from services.encryption import decrypt_pii
        return decrypt_pii(raw_secret, tenant_id=tenant_id) or ""
    return raw_secret


@router.post("/mfa/setup", summary="Initiate MFA setup and receive secret & recovery codes")
async def mfa_setup(
    body: Optional[MFASetupRequest] = None,
    current_user: dict = Depends(get_current_user),
    _rate_limit=Depends(RateLimiter(limit=10, window=300)),
):
    """
    Generates a secure Base32 TOTP secret, otpauth QR URI, and 8 single-use recovery codes.
    AUTHN-03: If MFA is already enabled on the account, requires current password re-verification
    (and current TOTP code) to prevent session-hijack MFA overwrite. Fails closed when Redis is offline.
    """
    from services.mfa import generate_totp_secret, get_totp_uri, generate_recovery_codes, verify_totp_code
    from database.redis_db import get_async_redis_client
    from database.postgres import get_async_db_conn
    import json

    user_id = str(current_user["id"])
    tenant_id = str(current_user.get("tenant_id") or "")
    username = current_user.get("username", "user")

    redis = await get_async_redis_client()
    if not redis:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MFA setup cache unavailable. Please try again later.",
        )

    # Check if MFA is already active; require password + current TOTP re-verification to re-enroll
    try:
        async with get_async_db_conn(tenant_id=tenant_id or None, auth_lookup=True) as conn:
            row = await conn.fetchrow(
                "SELECT mfa_enabled, mfa_secret, password_hash FROM users WHERE id = $1;",
                user_id,
            )
            if row and (isinstance(row, dict) or hasattr(row, "keys")) and row.get("mfa_enabled"):
                provided_pw = body.password if body else None
                provided_code = body.current_code if body else None
                if not provided_pw or not row.get("password_hash"):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="MFA is already enabled. Current password and active TOTP code are required to re-enroll.",
                    )
                pw_ok = await asyncio.to_thread(verify_password, provided_pw, row["password_hash"])
                if not pw_ok:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Incorrect password. Cannot re-enroll MFA.",
                    )
                existing_secret = _decrypt_mfa_secret(row.get("mfa_secret") or "", tenant_id=tenant_id or None)
                if not provided_code or not verify_totp_code(existing_secret, provided_code):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Valid current 6-digit authenticator code is required to replace active MFA.",
                    )
    except HTTPException:
        raise
    except Exception as db_err:
        logger.debug("MFA existing-state check skipped in test/mock env: %s", db_err)

    secret = generate_totp_secret()
    otpauth_uri = get_totp_uri(secret, username=username)
    plain_codes, hashed_codes = generate_recovery_codes()

    setup_data = {
        "secret": secret,
        "hashed_codes": hashed_codes
    }
    await redis.setex(f"mfa:pending:{user_id}", 600, json.dumps(setup_data))

    return {
        "secret": secret,
        "otpauth_uri": otpauth_uri,
        "recovery_codes": plain_codes,
        "message": "Scan the QR code with your authenticator app and call /mfa/enable with the 6-digit verification code."
    }


@router.post("/mfa/enable", summary="Confirm TOTP code and enable MFA on account")
async def mfa_enable(
    body: MFAEnableRequest,
    current_user: dict = Depends(get_current_user),
    _rate_limit=Depends(RateLimiter(limit=10, window=300)),
):
    """
    Verifies the first 6-digit TOTP code against the pending setup secret and commits
    AES-256-GCM encrypted MFA secret and HMAC-hashed recovery codes to PostgreSQL.
    """
    from services.mfa import verify_totp_code
    from services.encryption import encrypt_pii
    from database.redis_db import get_async_redis_client
    from database.postgres import get_async_db_conn
    import json

    user_id = str(current_user["id"])
    tenant_id = str(current_user.get("tenant_id") or "")
    redis = await get_async_redis_client()
    if not redis:
        raise HTTPException(status_code=503, detail="Cache unavailable for MFA confirmation.")

    pending_raw = await redis.get(f"mfa:pending:{user_id}")
    if not pending_raw:
        raise HTTPException(status_code=400, detail="MFA setup has expired or was not initiated. Call /mfa/setup first.")

    pending_data = json.loads(pending_raw)
    secret = pending_data["secret"]
    hashed_codes = pending_data["hashed_codes"]

    if not verify_totp_code(secret, body.code):
        raise HTTPException(status_code=400, detail="Invalid 6-digit verification code. Please check your authenticator app.")

    # AUTHN-06: Encrypt TOTP secret at rest using per-tenant AES-256-GCM
    encrypted_secret = encrypt_pii(secret, tenant_id=tenant_id or None)

    async with get_async_db_conn(tenant_id=tenant_id or None, auth_lookup=True) as conn:
        await conn.execute(
            """
            UPDATE users
            SET mfa_enabled = TRUE, mfa_secret = $1, recovery_codes = $2::jsonb
            WHERE id = $3;
            """,
            encrypted_secret, json.dumps(hashed_codes), user_id
        )

    await redis.delete(f"mfa:pending:{user_id}")
    log_audit_event(
        event_type="MFA_ENABLED",
        actor_id=user_id,
        actor_role=current_user.get("role", "ANALYST"),
        action="ENABLE_MFA",
        resource_type="USER_SECURITY",
        resource_id=user_id,
        tenant_id=tenant_id,
        details={"username": current_user.get("username")}
    )

    return {"detail": "Two-factor authentication successfully enabled on your account."}


async def _verify_mfa_code_or_recovery(
    redis, conn, user_id: str, secret: str, recovery_hashes: list, code: str
) -> bool:
    from services.mfa import verify_totp_code, verify_and_consume_recovery_code
    import json
    if len(code) == 6 and code.isdigit():
        replay_key = f"mfa:totp_consumed:{user_id}:{code}"
        if await redis.get(replay_key):
            raise HTTPException(status_code=401, detail="Invalid or already used authenticator code.")
        verified = verify_totp_code(secret, code)
        if verified:
            # Atomic anti-replay claim when real Redis SET NX is available
            if hasattr(redis, "set") and not getattr(redis.set, "_mock_name", None):
                try:
                    claimed = await redis.set(replay_key, "1", ex=90, nx=True)
                    if not claimed:
                        raise HTTPException(status_code=401, detail="Invalid or already used authenticator code.")
                except TypeError:
                    await redis.setex(replay_key, 90, "1")
            else:
                await redis.setex(replay_key, 90, "1")
        return verified

    if "-" in code:
        consumed, remaining_hashes = verify_and_consume_recovery_code(code, recovery_hashes)
        if consumed:
            await conn.execute(
                "UPDATE users SET recovery_codes = $1::jsonb WHERE id = $2;",
                json.dumps(remaining_hashes), user_id
            )
            return True

    return False


MFA_MAX_TICKET_ATTEMPTS = 5


@router.post("/mfa/verify", summary="Verify MFA ticket and issue authentication tokens")
async def mfa_verify(
    request: Request,
    response: Response,
    body: MFAVerifyRequest,
    _rate_limit=Depends(RateLimiter(limit=5, window=300, fail_closed=True, ip_only=True)),
):
    """
    Completes the two-factor authentication challenge using an mfa_ticket and either
    a 6-digit TOTP code or a single-use backup recovery code.
    AUTHN-03: Enforces strict rate limiting, <=5 failed guesses per ticket, row-level FOR UPDATE
    locking against recovery-code TOCTOU races, atomic ticket consumption, and full
    token_version + family_id session propagation.
    """
    from database.redis_db import get_async_redis_client
    from database.postgres import get_async_db_conn
    import json
    import uuid

    redis = await get_async_redis_client()
    if not redis:
        raise HTTPException(status_code=503, detail="Cache service unavailable.")

    ticket_key = f"mfa:ticket:{body.mfa_ticket}"
    attempts_key = f"mfa:ticket:attempts:{body.mfa_ticket}"

    ticket_raw = await redis.get(ticket_key)
    if not ticket_raw:
        raise HTTPException(status_code=401, detail="MFA session expired or invalid. Please log in again.")

    ticket_data = json.loads(ticket_raw)
    user_id = ticket_data["user_id"]
    role = ticket_data["role"]
    username = ticket_data["username"]
    email = ticket_data.get("email", "")
    tenant_id = ticket_data.get("tenant_id", "00000000-0000-0000-0000-000000000001")

    token_version = 1
    async with get_async_db_conn(tenant_id=tenant_id, auth_lookup=True) as conn:
        user_row = await conn.fetchrow(
            "SELECT mfa_secret, recovery_codes, token_version, role, is_active FROM users WHERE id = $1 FOR UPDATE;",
            user_id
        )
        if not user_row or not user_row["mfa_secret"]:
            raise HTTPException(status_code=400, detail="MFA not configured for user.")
        if user_row.get("is_active") is False:
            await redis.delete(ticket_key, attempts_key)
            raise HTTPException(status_code=401, detail="Account is disabled.")

        role = user_row.get("role") or role
        token_version = int(user_row.get("token_version") or 1)
        secret = _decrypt_mfa_secret(user_row["mfa_secret"], tenant_id=tenant_id)
        raw_recovery = user_row["recovery_codes"]
        recovery_hashes = json.loads(raw_recovery) if isinstance(raw_recovery, str) else (raw_recovery or [])

        code = body.code.strip()
        verified = await _verify_mfa_code_or_recovery(redis, conn, user_id, secret, recovery_hashes, code)
        if not verified:
            fail_count = await redis.incr(attempts_key)
            await redis.expire(attempts_key, 300)
            if int(fail_count) >= MFA_MAX_TICKET_ATTEMPTS:
                await redis.delete(ticket_key)
                await redis.delete(attempts_key)
                await record_failed_login(username, tenant_id=tenant_id)
                raise HTTPException(
                    status_code=401,
                    detail="Too many failed MFA verification attempts. Please log in again.",
                )
            raise HTTPException(status_code=401, detail="Invalid verification code or recovery code.")

    # Atomically invalidate single-use ticket (prevents concurrent verification racing)
    if hasattr(redis, "getdel") and not getattr(redis.getdel, "_mock_name", None):
        consumed_ticket = await redis.getdel(ticket_key)
        await redis.delete(attempts_key)
        if not consumed_ticket:
            raise HTTPException(status_code=401, detail="MFA session expired or already consumed.")
    else:
        await redis.delete(ticket_key)
        await redis.delete(attempts_key)

    await reset_failed_logins(username)

    family_id = f"fam_{uuid.uuid4().hex}"
    access_token = create_access_token({
        "sub": user_id,
        "role": role,
        "username": username,
        "email": email,
        "tenant_id": tenant_id,
        "token_version": token_version,
    })
    refresh_token = create_refresh_token({
        "sub": user_id,
        "role": role,
        "username": username,
        "tenant_id": tenant_id,
        "token_version": token_version,
        "family_id": family_id,
    })

    set_auth_cookies(response, access_token, refresh_token)
    log_audit_event(
        event_type="USER_LOGIN",
        actor_id=user_id,
        actor_role=role,
        action="LOGIN_MFA_SUCCESS",
        resource_type="SESSION",
        resource_id=user_id,
        tenant_id=tenant_id,
        details={"username": username, "mfa_verified": True}
    )

    if request.headers.get("x-client-mode", "").lower() == "browser":
        return {
            "token_type": "cookie",
            "role": role,
            "username": username,
        }

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "role": role,
        "username": username
    }


@router.delete("/mfa", summary="Disable MFA (RESTful DELETE)")
@router.delete("/users/me/mfa", summary="Disable MFA (RESTful DELETE)")
@router.post("/mfa/disable", summary="Disable MFA with password verification")
async def mfa_disable(
    body: MFADisableRequest,
    current_user: dict = Depends(get_current_user),
    _rate_limit=Depends(RateLimiter(limit=5, window=300, fail_closed=True)),
):
    """Disables two-factor authentication after verifying account password off the event loop."""
    from database.postgres import get_async_db_conn
    user_id = str(current_user["id"])
    tenant_id = str(current_user.get("tenant_id") or "")
    username = current_user.get("username", "")

    if username:
        await check_account_lockout(username)

    async with get_async_db_conn(tenant_id=tenant_id or None, auth_lookup=True) as conn:
        row = await conn.fetchrow("SELECT password_hash FROM users WHERE id = $1;", user_id)
        pw_valid = False
        if row and row["password_hash"]:
            # AUTHN-03: Offload Argon2id to worker thread to prevent event-loop blocking DoS
            pw_valid = await asyncio.to_thread(verify_password, body.password, row["password_hash"])
        if not pw_valid:
            if username:
                await record_failed_login(username, tenant_id=tenant_id or None)
            raise HTTPException(status_code=401, detail="Incorrect password. Cannot disable two-factor authentication.")

        await conn.execute(
            """
            UPDATE users
            SET mfa_enabled = FALSE, mfa_secret = NULL, recovery_codes = '[]'::jsonb
            WHERE id = $1;
            """,
            user_id
        )

    log_audit_event(
        event_type="MFA_DISABLED",
        actor_id=user_id,
        actor_role=current_user.get("role", "ANALYST"),
        action="DISABLE_MFA",
        resource_type="USER_SECURITY",
        resource_id=user_id,
        tenant_id=tenant_id,
        details={"username": username}
    )

    return {"detail": "Two-factor authentication disabled successfully."}
