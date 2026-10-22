import logging
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
    verify_password,
    verify_password_and_needs_rehash,
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

def set_auth_cookies(response: Response, access_token: str, refresh_token: str | None = None):
    """Sets secure HttpOnly cookies for browser web sessions."""
    is_secure = bool(settings.enable_tls or str(settings.environment).lower() == "production")
    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=900,  # 15 minutes
        httponly=True,
        samesite="strict",
        secure=is_secure,
        path="/"
    )
    if refresh_token:
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=30 * 86400,  # 30 days
            httponly=True,
            samesite="strict",
            secure=is_secure,
            path="/"
        )

def clear_auth_cookies(response: Response):
    """Clears authentication cookies on logout."""
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/")

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
        pattern=r"^(L1_ANALYST|L2_INVESTIGATOR|MLRO|ANALYST|AUDITOR|ADMIN|TENANT_ADMIN|SUPER_ADMIN)$"
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
    try:
        payload = {"email": email, "password": password}
        headers = {"apikey": settings.supabase_key, "Content-Type": "application/json"}
        async with (
            aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session,
            session.post(
                f"{settings.supabase_url}/auth/v1/token?grant_type=password",
                json=payload,
                headers=headers
            ) as resp
        ):
            if resp.status == 200:
                return await resp.json()
    except Exception as e:
        logger.warning(f"Supabase auth unreachable: {e}. Falling back to local verification.")
    return None


async def _process_supabase_login_success(
    response: Response, form_data: OAuth2PasswordRequestForm, email: str, supabase_user: dict
) -> dict:
    await reset_failed_logins(form_data.username)
    data = supabase_user
    access_token = data.get("access_token", "")
    user = data.get("user") or data
    user_id = user.get("id", "")
    user_metadata = user.get("user_metadata", {})
    role = user_metadata.get("role", "ANALYST")
    username = email.split("@")[0]
    tenant_id = user_metadata.get("tenant_id", "00000000-0000-0000-0000-000000000001")

    hashed_pw = hash_password(form_data.password)
    from database.postgres import get_async_db_conn
    async with get_async_db_conn() as conn:
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

    refresh_token = create_refresh_token({
        "sub": user_id,
        "role": role,
        "username": username,
        "tenant_id": tenant_id
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
        verify_password_and_needs_rehash(password, DUMMY_ARGON2_HASH)
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
            detail="Account temporarily locked due to excessive failed attempts. Try again in 1800 seconds."
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def _create_mfa_challenge_ticket(
    user_id: str, role: str, username: str, email: str, tenant_id: str
) -> dict:
    import uuid
    import json
    from database.redis_db import get_async_redis_client
    mfa_ticket = f"mfa_{uuid.uuid4().hex}"
    redis = await get_async_redis_client()
    if redis:
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
    async with get_async_db_conn() as conn:
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

        pw_valid, needs_rehash = verify_password_and_needs_rehash(form_data.password, local_user["password_hash"])
        if not pw_valid:
            await _handle_local_login_failure(form_data.username, local_user, form_data.password)

        if needs_rehash:
            try:
                new_argon2_hash = hash_password(form_data.password)
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
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    _rate_limit=Depends(RateLimiter(limit=20, window=600))
):
    await check_account_lockout(form_data.username)

    email = form_data.username if "@" in form_data.username else f"{form_data.username}@aml.com"
    supabase_user = await _attempt_supabase_login(email, form_data.password)

    if supabase_user:
        return await _process_supabase_login_success(response, form_data, email, supabase_user)

    return await _execute_local_login(response, form_data, email)


async def _attempt_supabase_signup(email: str, password: str, assigned_role: str, tenant_id: str) -> dict | None:
    if not (settings.supabase_url and settings.supabase_key and not settings.supabase_key.startswith("your_")):
        return None
    try:
        signup_data = {
            "email": email,
            "password": password,
            "data": {
                "role": assigned_role,
                "tenant_id": tenant_id
            }
        }
        headers = {
            "apikey": settings.supabase_key,
            "Content-Type": "application/json"
        }
        async with (
            aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session,
            session.post(
                f"{settings.supabase_url}/auth/v1/signup",
                json=signup_data,
                headers=headers
            ) as resp
        ):
            if resp.status == 200:
                return await resp.json()
            logger.warning(f"Supabase signup returned status {resp.status}. Falling back to local registration.")
    except Exception as e:
        logger.warning(f"Supabase auth unreachable during signup: {e}. Falling back to local registration.")
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
        async with get_async_db_conn() as conn:
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
        async with get_async_db_conn() as conn:
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


@router.post("/signup", summary="Register compliance officer (Defaults strictly to ANALYST)")
@router.post("/register", summary="Register compliance officer (Enterprise registration)")
async def signup(
    request: Request,
    response: Response,
    payload: UserSignup,
    _rate_limit=Depends(RateLimiter(limit=10, window=3600))
):
    if request.url.path.endswith("/register"):
        from services.auth import check_breached_password
        if await check_breached_password(payload.password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password has appeared in a known public data breach (NIST SP 800-63B violation). Please choose a different, more secure passphrase."
            )

    email = payload.username if "@" in payload.username else f"{payload.username}@aml.com"
    assigned_role = "ANALYST"
    default_tenant_id = "00000000-0000-0000-0000-000000000001"
    hashed_pw = hash_password(payload.password)

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
    
    caller_role = current_user.get("role", "ADMIN")
    if caller_role == "SUPER_ADMIN" and payload.tenant_id:
        target_tenant_id = payload.tenant_id
    else:
        target_tenant_id = str(current_user.get("tenant_id") or "00000000-0000-0000-0000-000000000001")

    # Allow ADMIN / SUPER_ADMIN to assign permitted 5-tier role (Task 1.1 / 1.7)
    if payload.role == "SUPER_ADMIN" and caller_role != "SUPER_ADMIN":
        assigned_role = "ADMIN"
    else:
        assigned_role = payload.role or "ANALYST"
    hashed_pw = hash_password(payload.password)

    import uuid
    from database.postgres import get_async_db_conn
    async with get_async_db_conn() as conn:
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
    role: str = Field(..., pattern=r"^(L1_ANALYST|L2_INVESTIGATOR|MLRO|ANALYST|AUDITOR|ADMIN|TENANT_ADMIN|SUPER_ADMIN)$")


@router.get("/users", summary="List users within current tenant (Admin only)")
async def list_users(
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(RoleChecker(["SUPER_ADMIN", "ADMIN"])),
):
    from database.postgres import get_async_db_conn
    tenant_id = enforce_tenant_data_scope(current_user)
    clamped_limit = max(1, min(limit, 200))
    clamped_offset = max(0, offset)
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            rows = await conn.fetch(
                """
                SELECT id, username, role, tenant_id, mfa_enabled, created_at
                FROM users
                ORDER BY created_at DESC
                LIMIT $1 OFFSET $2;
                """,
                clamped_limit, clamped_offset
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
):
    caller_role = current_user.get("role", "ADMIN")
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

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        row = await conn.fetchrow("SELECT username, role FROM users WHERE id = $1;", u_uuid)
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        await conn.execute("UPDATE users SET role = $1 WHERE id = $2;", payload.role, u_uuid)

    await revoke_user_sessions(user_id)

    log_audit_event(
        event_type="USER_ROLE_CHANGED",
        actor_id=str(current_user.get("id", "")),
        actor_role=caller_role,
        action="UPDATE_ROLE",
        resource_type="USER",
        resource_id=user_id,
        tenant_id=tenant_id,
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
            async with get_async_db_conn() as conn:
                await conn.execute("UPDATE users SET token_version = token_version + 1 WHERE id = $1;", sub)
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
        return

    is_family_revoked = await redis.get(f"token:family_revoked:{family_id}") if family_id else None
    if is_family_revoked:
        clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Compromised session detected: reuse of revoked refresh token. All active sessions have been terminated for security.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    is_token_revoked = await redis.get(f"token:revoked:{token_to_refresh}")
    if is_token_revoked:
        if family_id:
            await _handle_token_compromise(redis, response, sub, role, username, tenant_id, family_id)
        else:
            clear_auth_cookies(response)
            raise credentials_exception


@router.post("/refresh", summary="Exchange refresh token with token rotation")
async def refresh_access_token(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
):
    """
    Validates the refresh token, revokes it in Redis, and issues both a new
    short-lived access token and a new rotated refresh token (Refresh Token Rotation).
    Supports token from request JSON body or HttpOnly cookie.
    """
    from database.redis_db import get_async_redis_client
    from services.auth import create_access_token, create_refresh_token, ALGORITHM
    from services.secrets_manager import decode_jwt_with_rotation
    from datetime import datetime, timezone

    token_to_refresh = (body.refresh_token if body and body.refresh_token else None) or request.cookies.get("refresh_token")
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
        role = payload.get("role", "ANALYST")
        username = payload.get("username", "")
        tenant_id = payload.get("tenant_id", "00000000-0000-0000-0000-000000000001")

        # Check Redis denylist & Token Family Compromise Detection (RFC 6819)
        redis = await get_async_redis_client()
        await _check_refresh_token_revocation(
            redis, response, token_to_refresh, family_id, sub, role, username, tenant_id, credentials_exception
        )

        if redis:
            # Token Rotation: Revoke consumed refresh token immediately
            exp = payload.get("exp", 0)
            ttl = max(int(exp - datetime.now(timezone.utc).timestamp()), 1)
            await redis.setex(f"token:revoked:{token_to_refresh}", ttl, "1")

        # Issue fresh access token AND new rotated refresh token in the SAME family
        new_access_token = create_access_token({
            "sub": sub,
            "role": role,
            "username": username,
            "tenant_id": tenant_id,
        })
        new_refresh_token = create_refresh_token({
            "sub": sub,
            "role": role,
            "username": username,
            "tenant_id": tenant_id,
            "family_id": family_id
        })

        set_auth_cookies(response, new_access_token, new_refresh_token)

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
@router.post("/logout", summary="Revoke refresh token and clear cookies")
async def logout(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
):
    """
    Adds the refresh token to the Redis denylist (TTL = remaining token lifetime)
    and clears HttpOnly authentication cookies.
    """
    from database.redis_db import get_async_redis_client
    from services.auth import ALGORITHM
    from services.secrets_manager import decode_jwt_with_rotation
    from datetime import datetime, timezone

    token_to_revoke = (body.refresh_token if body and body.refresh_token else None) or request.cookies.get("refresh_token")

    if token_to_revoke:
        try:
            payload = decode_jwt_with_rotation(token_to_revoke, algorithm=ALGORITHM)
            exp = payload.get("exp", 0)
            ttl = max(int(exp - datetime.now(timezone.utc).timestamp()), 1)

            redis = await get_async_redis_client()
            if redis:
                await redis.setex(f"token:revoked:{token_to_revoke}", ttl, "1")
        except jwt.PyJWTError:
            pass
        except Exception as e:
            logger.warning(f"Error revoking token in Redis during logout: {e}")

    clear_auth_cookies(response)
    if request.method == "DELETE":
        response.status_code = status.HTTP_204_NO_CONTENT
        return response
    return {"detail": "Logged out successfully. Refresh token revoked."}


@router.get("/me", summary="Get current authenticated user identity")
async def get_me(current_user: dict = Depends(get_current_user)):
    """
    Returns the currently authenticated user session identity.
    Resolves seamlessly via Authorization Bearer header or HttpOnly access_token cookie.
    """
    return {
        "id": current_user.get("id"),
        "username": current_user.get("username"),
        "role": current_user.get("role"),
        "email": current_user.get("email"),
        "tenant_id": current_user.get("tenant_id")
    }


@router.get("/check-username", summary="Debounced username availability check for registration")
async def check_username_availability(
    username: str = Query(..., min_length=3, max_length=100),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    """
    Non-blocking endpoint for real-time username availability validation during sign-up.
    Rate-limited to prevent automated bulk harvesting.
    """
    clean_username = sanitize_text(username.strip())
    from database.postgres import get_async_db_conn
    async with get_async_db_conn() as conn:
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
async def revoke_sessions(current_user: dict = Depends(get_current_user)):
    """
    Increments token_version for the authenticated user, immediately
    invalidating all active access tokens and refresh tokens across all devices.
    """
    from services.auth import revoke_user_sessions
    user_id = current_user.get("id")
    new_ver = await revoke_user_sessions(user_id)
    return {
        "detail": "All active sessions revoked successfully. Please log in again.",
        "token_version": new_ver
    }


@router.post("/users/{user_id}/revoke-sessions", summary="Revoke all active sessions for a target user (Admin only)")
@router.delete("/users/{user_id}/sessions", summary="Revoke all active sessions for a target user (RESTful DELETE)")
async def admin_revoke_target_user_sessions(
    user_id: str,
    current_user: dict = Depends(RoleChecker(["SUPER_ADMIN", "ADMIN"])),
):
    """
    Increments token_version for the target user ID, immediately invalidating
    all active JWT access and refresh tokens across all pods and devices.
    """
    import uuid
    try:
        uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    from database.postgres import get_async_db_conn
    from services.auth import revoke_user_sessions

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        row = await conn.fetchrow("SELECT username, role FROM users WHERE id = $1;", uuid.UUID(user_id))
        if not row:
            raise HTTPException(status_code=404, detail="Target user not found.")

    new_ver = await revoke_user_sessions(user_id)

    log_audit_event(
        event_type="USER_SESSIONS_REVOKED",
        actor_id=str(current_user.get("id", "")),
        actor_role=current_user.get("role", "ADMIN"),
        action="REVOKE_SESSIONS",
        resource_type="USER",
        resource_id=user_id,
        tenant_id=tenant_id,
        details={"username": row["username"], "target_role": row["role"], "new_token_version": new_ver}
    )

    return {
        "status": "SUCCESS",
        "detail": f"All active sessions for user '{row['username']}' revoked successfully.",
        "user_id": user_id,
        "token_version": new_ver
    }


# ── Multi-Factor Authentication (MFA / TOTP) Endpoints ─────────────────────────

class MFAEnableRequest(BaseModel):
    code: str

class MFAVerifyRequest(BaseModel):
    mfa_ticket: str
    code: str

class MFADisableRequest(BaseModel):
    password: str


@router.post("/mfa/setup", summary="Initiate MFA setup and receive secret & recovery codes")
async def mfa_setup(current_user: dict = Depends(get_current_user)):
    """
    Generates a secure Base32 TOTP secret, otpauth QR URI, and 8 single-use recovery codes.
    Stores setup state temporarily in Redis until confirmed via /mfa/enable.
    """
    from services.mfa import generate_totp_secret, get_totp_uri, generate_recovery_codes
    from database.redis_db import get_async_redis_client
    import json

    user_id = str(current_user["id"])
    username = current_user.get("username", "user")
    secret = generate_totp_secret()
    otpauth_uri = get_totp_uri(secret, username=username)
    plain_codes, hashed_codes = generate_recovery_codes()

    redis = await get_async_redis_client()
    if redis:
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
async def mfa_enable(body: MFAEnableRequest, current_user: dict = Depends(get_current_user)):
    """
    Verifies the first 6-digit TOTP code against the pending setup secret and commits
    MFA activation and recovery codes to the database.
    """
    from services.mfa import verify_totp_code
    from database.redis_db import get_async_redis_client
    from database.postgres import get_async_db_conn
    import json

    user_id = str(current_user["id"])
    redis = await get_async_redis_client()
    if not redis:
        raise HTTPException(status_code=500, detail="Cache unavailable for MFA confirmation.")

    pending_raw = await redis.get(f"mfa:pending:{user_id}")
    if not pending_raw:
        raise HTTPException(status_code=400, detail="MFA setup has expired or was not initiated. Call /mfa/setup first.")

    pending_data = json.loads(pending_raw)
    secret = pending_data["secret"]
    hashed_codes = pending_data["hashed_codes"]

    if not verify_totp_code(secret, body.code):
        raise HTTPException(status_code=400, detail="Invalid 6-digit verification code. Please check your authenticator app.")

    async with get_async_db_conn() as conn:
        await conn.execute(
            """
            UPDATE users
            SET mfa_enabled = TRUE, mfa_secret = $1, recovery_codes = $2::jsonb
            WHERE id = $3;
            """,
            secret, json.dumps(hashed_codes), user_id
        )

    await redis.delete(f"mfa:pending:{user_id}")
    log_audit_event(
        event_type="MFA_ENABLED",
        actor_id=user_id,
        actor_role=current_user.get("role", "ANALYST"),
        action="ENABLE_MFA",
        resource_type="USER_SECURITY",
        resource_id=user_id,
        tenant_id=current_user.get("tenant_id", ""),
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


@router.post("/mfa/verify", summary="Verify MFA ticket and issue authentication tokens")
async def mfa_verify(response: Response, body: MFAVerifyRequest):
    """
    Completes the two-factor authentication challenge using an mfa_ticket and either
    a 6-digit TOTP code or a single-use backup recovery code.
    """
    from database.redis_db import get_async_redis_client
    from database.postgres import get_async_db_conn
    import json

    redis = await get_async_redis_client()
    if not redis:
        raise HTTPException(status_code=500, detail="Cache service unavailable.")

    ticket_raw = await redis.get(f"mfa:ticket:{body.mfa_ticket}")
    if not ticket_raw:
        raise HTTPException(status_code=401, detail="MFA session expired or invalid. Please log in again.")

    ticket_data = json.loads(ticket_raw)
    user_id = ticket_data["user_id"]
    role = ticket_data["role"]
    username = ticket_data["username"]
    email = ticket_data.get("email", "")
    tenant_id = ticket_data.get("tenant_id", "00000000-0000-0000-0000-000000000001")

    async with get_async_db_conn() as conn:
        user_row = await conn.fetchrow(
            "SELECT mfa_secret, recovery_codes FROM users WHERE id = $1;",
            user_id
        )
        if not user_row or not user_row["mfa_secret"]:
            raise HTTPException(status_code=400, detail="MFA not configured for user.")

        secret = user_row["mfa_secret"]
        raw_recovery = user_row["recovery_codes"]
        recovery_hashes = json.loads(raw_recovery) if isinstance(raw_recovery, str) else (raw_recovery or [])

        code = body.code.strip()
        verified = await _verify_mfa_code_or_recovery(redis, conn, user_id, secret, recovery_hashes, code)
        if not verified:
            raise HTTPException(status_code=401, detail="Invalid verification code or recovery code.")

    # Invalidate ticket
    await redis.delete(f"mfa:ticket:{body.mfa_ticket}")

    access_token = create_access_token({
        "sub": user_id,
        "role": role,
        "username": username,
        "email": email,
        "tenant_id": tenant_id
    })
    refresh_token = create_refresh_token({
        "sub": user_id,
        "role": role,
        "username": username,
        "tenant_id": tenant_id
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
async def mfa_disable(body: MFADisableRequest, current_user: dict = Depends(get_current_user)):
    """Disables two-factor authentication after verifying account password."""
    from database.postgres import get_async_db_conn
    user_id = str(current_user["id"])

    async with get_async_db_conn() as conn:
        row = await conn.fetchrow("SELECT password_hash FROM users WHERE id = $1;", user_id)
        if not row or not row["password_hash"] or not verify_password(body.password, row["password_hash"]):
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
        tenant_id=current_user.get("tenant_id", ""),
        details={"username": current_user.get("username")}
    )

    return {"detail": "Two-factor authentication disabled successfully."}
