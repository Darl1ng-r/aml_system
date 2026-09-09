import aiohttp
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from config import settings
from pydantic import BaseModel, Field
import jwt

from pydantic import BaseModel, Field, field_validator
from observability.sanitizer import sanitize_text

from services.rate_limiter import RateLimiter
from services.auth import hash_password, verify_password, create_access_token, create_refresh_token
from observability.logging import log_audit_event

def set_auth_cookies(response: Response, access_token: str, refresh_token: str | None = None):
    """Sets secure HttpOnly cookies for browser web sessions."""
    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=900,  # 15 minutes
        httponly=True,
        samesite="lax",
        secure=settings.enable_tls,
        path="/"
    )
    if refresh_token:
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=30 * 86400,  # 30 days
            httponly=True,
            samesite="lax",
            secure=settings.enable_tls,
            path="/"
        )

def clear_auth_cookies(response: Response):
    """Clears authentication cookies on logout."""
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/")

class UserSignup(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("username", mode="before")
    @classmethod
    def sanitize_username(cls, v: str) -> str:
        return sanitize_text(v)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

@router.post("/login")
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    _rate_limit=Depends(RateLimiter(limit=5, window=600))
):
    email = form_data.username
    if "@" not in email:
        email = f"{email}@aml.com"
        
    payload = {
        "email": email,
        "password": form_data.password
    }
    
    headers = {
        "apikey": settings.supabase_key,
        "Content-Type": "application/json"
    }
    
    supabase_user = None
    if settings.supabase_url and settings.supabase_key and not settings.supabase_key.startswith("your_"):
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
                async with session.post(
                    f"{settings.supabase_url}/auth/v1/token?grant_type=password",
                    json=payload,
                    headers=headers
                ) as resp:
                    if resp.status == 200:
                        supabase_user = await resp.json()
        except Exception as e:
            logger.warning(f"Supabase auth unreachable: {e}. Falling back to local verification.")
            supabase_user = None

    if supabase_user:
        # Supabase authentication succeeded
        data = supabase_user
        access_token = data.get("access_token", "")
        user = data.get("user") or data
        user_id = user.get("id", "")
        user_metadata = user.get("user_metadata", {})
        role = user_metadata.get("role", "ANALYST")
        username = email.split("@")[0]
        tenant_id = user_metadata.get("tenant_id", "00000000-0000-0000-0000-000000000001")

        # Replicate/update Supabase user to local PostgreSQL with password hash for offline resilience
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

    # Fallback to local secure credential verification
    from database.postgres import get_async_db_conn
    async with get_async_db_conn() as conn:
        local_user = await conn.fetchrow(
            """
            SELECT id, role, password_hash, tenant_id 
            FROM users 
            WHERE username = $1 AND (is_active IS NULL OR is_active = true);
            """,
            form_data.username
        )

        # ZERO-BYPASS ENFORCEMENT: Never issue token without password verification
        if not local_user or not local_user["password_hash"]:
            log_audit_event(
                event_type="LOGIN_FAILED",
                actor_id=form_data.username,
                actor_role="UNKNOWN",
                action="FAILED_LOGIN",
                resource_type="SESSION",
                resource_id="",
                details={"username": form_data.username, "reason": "User not found or no password hash"}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not verify_password(form_data.password, local_user["password_hash"]):
            log_audit_event(
                event_type="LOGIN_FAILED",
                actor_id=str(local_user["id"]),
                actor_role=local_user["role"] or "ANALYST",
                action="FAILED_LOGIN",
                resource_type="SESSION",
                resource_id=str(local_user["id"]),
                tenant_id=str(local_user["tenant_id"]) if local_user["tenant_id"] else "",
                details={"username": form_data.username, "reason": "Password hash mismatch"}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        local_user_id = str(local_user["id"])
        local_role = local_user["role"] or "ANALYST"
        tenant_id = str(local_user["tenant_id"]) if local_user["tenant_id"] else "00000000-0000-0000-0000-000000000001"
    
    access_token = create_access_token({
        "sub": local_user_id,
        "role": local_role,
        "username": form_data.username,
        "email": email,
        "tenant_id": tenant_id
    })
    refresh_token = create_refresh_token({
        "sub": local_user_id,
        "role": local_role,
        "username": form_data.username,
        "tenant_id": tenant_id
    })

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

@router.post("/signup")
async def signup(
    response: Response,
    payload: UserSignup,
    _rate_limit=Depends(RateLimiter(limit=10, window=3600))
):
    email = payload.username
    if "@" not in email:
        email = f"{email}@aml.com"
    
    # Enforce Least Privilege: All self-registered users are strictly ANALYST
    assigned_role = "ANALYST"
    default_tenant_id = "00000000-0000-0000-0000-000000000001"
    hashed_pw = hash_password(payload.password)
        
    signup_data = {
        "email": email,
        "password": payload.password,
        "data": {
            "role": assigned_role,
            "tenant_id": default_tenant_id
        }
    }
    
    headers = {
        "apikey": settings.supabase_key,
        "Content-Type": "application/json"
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{settings.supabase_url}/auth/v1/signup",
                json=signup_data,
                headers=headers
            ) as resp:
                if resp.status != 200:
                    # Fallback: create local user with verified password hash
                    import uuid
                    local_user_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{payload.username}.aml.com"))
                    
                    from database.postgres import get_async_db_conn
                    async with get_async_db_conn() as conn:
                        await conn.execute(
                            """
                            INSERT INTO users (id, username, role, tenant_id, password_hash) 
                            VALUES ($1, $2, $3, $4, $5) 
                            ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash;
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

                    set_auth_cookies(response, access_token, refresh_token)
                    return {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "token_type": "bearer",
                        "role": assigned_role,
                        "username": payload.username
                    }
                    
                data = await resp.json()
                access_token = data.get("access_token")
                
                # Replicate user to local PostgreSQL database
                user_info = data.get("user") if "user" in data else data
                supabase_user_id = user_info.get("id")
                if supabase_user_id:
                    from database.postgres import get_async_db_conn
                    async with get_async_db_conn() as conn:
                        await conn.execute(
                            """
                            INSERT INTO users (id, username, role, tenant_id, password_hash) 
                            VALUES ($1, $2, $3, $4, $5) 
                            ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash;
                            """,
                            supabase_user_id,
                            payload.username,
                            assigned_role,
                            default_tenant_id,
                            hashed_pw
                        )

                refresh_token = create_refresh_token({
                    "sub": str(supabase_user_id),
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
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Registration failed: {str(e)}"
        )


class RefreshRequest(BaseModel):
    refresh_token: str | None = None


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

        # Check Redis denylist
        redis = await get_async_redis_client()
        if redis:
            is_revoked = await redis.get(f"token:revoked:{token_to_refresh}")
            if is_revoked:
                raise credentials_exception

            # Token Rotation: Revoke consumed refresh token immediately
            exp = payload.get("exp", 0)
            ttl = max(int(exp - datetime.now(timezone.utc).timestamp()), 1)
            await redis.setex(f"token:revoked:{token_to_refresh}", ttl, "1")

        # Issue fresh access token AND new rotated refresh token
        sub = payload.get("sub")
        role = payload.get("role", "ANALYST")
        username = payload.get("username", "")
        tenant_id = payload.get("tenant_id", "00000000-0000-0000-0000-000000000001")

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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token refresh failed: {str(e)}")


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
    return {"detail": "Logged out successfully. Refresh token revoked."}
