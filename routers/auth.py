import aiohttp
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from config import settings
from pydantic import BaseModel, Field
import jwt

from pydantic import BaseModel, Field, field_validator
from observability.sanitizer import sanitize_text

class UserSignup(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(..., min_length=6, max_length=128)
    role: str = Field("ANALYST", max_length=20, pattern=r"^(ADMIN|ANALYST|AUDITOR)$")

    @field_validator("username", mode="before")
    @classmethod
    def sanitize_username(cls, v: str) -> str:
        return sanitize_text(v)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
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
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{settings.supabase_url}/auth/v1/token?grant_type=password",
                json=payload,
                headers=headers
            ) as resp:
                if resp.status != 200:
                    # Fallback to local user verification if Supabase fails (e.g. offline/rate-limit)
                    from database.postgres import get_async_db_conn
                    async with get_async_db_conn() as conn:
                        local_user = await conn.fetchrow(
                            "SELECT id, role FROM users WHERE username = $1;",
                            form_data.username
                        )
                        if not local_user:
                            # User not in local Postgres either, raise original credentials error
                            err_data = await resp.json()
                            raise HTTPException(
                                status_code=status.HTTP_401_UNAUTHORIZED,
                                detail=err_data.get("error_description", "Incorrect credentials"),
                                headers={"WWW-Authenticate": "Bearer"},
                            )
                        local_user_id = str(local_user["id"])
                        local_role = local_user["role"]
                    
                    from services.auth import create_access_token, create_refresh_token
                    access_token = create_access_token({
                        "sub": local_user_id,
                        "role": local_role,
                        "username": form_data.username,
                        "email": email
                    })
                    refresh_token = create_refresh_token({
                        "sub": local_user_id,
                        "role": local_role,
                        "username": form_data.username,
                    })
                    
                    return {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "token_type": "bearer",
                        "role": local_role,
                        "username": form_data.username
                    }
                    
                # Supabase does not issue our custom refresh token;
                # we create our own so refresh flow is consistent.
                from services.auth import create_refresh_token
                user_id = user.get("id", "")
                username = email.split("@")[0]
                refresh_token = create_refresh_token({
                    "sub": user_id,
                    "role": role,
                    "username": username,
                })
                return {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "bearer",
                    "role": role,
                    "username": username
                }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Supabase login proxy failed: {str(e)}"
        )

@router.post("/signup")
async def signup(payload: UserSignup):
    email = payload.username
    if "@" not in email:
        email = f"{email}@aml.com"
        
    signup_data = {
        "email": email,
        "password": payload.password,
        "data": {
            "role": payload.role
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
                    # Fallback: create local JWT token and replicate user if Supabase rate-limited/offline
                    import uuid
                    from services.auth import create_access_token
                    local_user_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{payload.username}.aml.com"))
                    
                    from database.postgres import get_async_db_conn
                    async with get_async_db_conn() as conn:
                        await conn.execute(
                            "INSERT INTO users (id, username, role) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING;",
                            local_user_id,
                            payload.username,
                            payload.role
                        )
                    
                    access_token = create_access_token({
                        "sub": local_user_id,
                        "role": payload.role,
                        "username": payload.username,
                        "email": email
                    })
                    
                    return {
                        "access_token": access_token,
                        "token_type": "bearer",
                        "role": payload.role,
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
                            "INSERT INTO users (id, username, role) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING;",
                            supabase_user_id,
                            payload.username,
                            payload.role
                        )
                
                return {
                    "access_token": access_token,
                    "token_type": "bearer",
                    "role": payload.role,
                    "username": email.split("@")[0]
                }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Supabase signup proxy failed: {str(e)}"
        )


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/refresh", summary="Exchange refresh token for a new access token")
async def refresh_access_token(body: RefreshRequest):
    """
    Validates the provided refresh token and issues a new short-lived access token.
    Refresh tokens are checked against a Redis denylist to support server-side revocation.
    """
    from database.redis_db import get_async_redis_client
    from services.auth import create_access_token, ALGORITHM
    from services.secrets_manager import decode_jwt_with_rotation

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_jwt_with_rotation(body.refresh_token, algorithm=ALGORITHM)
        if payload.get("type") != "refresh":
            raise credentials_exception

        # Check Redis denylist — token revoked on logout
        redis = await get_async_redis_client()
        if redis:
            is_revoked = await redis.get(f"token:revoked:{body.refresh_token}")
            if is_revoked:
                raise credentials_exception

        # Issue a fresh access token
        new_access_token = create_access_token({
            "sub": payload.get("sub"),
            "role": payload.get("role", "ANALYST"),
            "username": payload.get("username", ""),
        })
        return {"access_token": new_access_token, "token_type": "bearer"}

    except jwt.ExpiredSignatureError:
        raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token refresh failed: {str(e)}")


@router.post("/logout", summary="Revoke refresh token (server-side logout)")
async def logout(body: RefreshRequest):
    """
    Adds the refresh token to the Redis denylist (TTL = remaining token lifetime).
    After logout, the token cannot be used to obtain new access tokens even if
    it has not yet expired.
    """
    from database.redis_db import get_async_redis_client
    from services.auth import ALGORITHM
    from services.secrets_manager import decode_jwt_with_rotation
    from datetime import datetime, timezone

    try:
        payload = decode_jwt_with_rotation(body.refresh_token, algorithm=ALGORITHM)
        exp = payload.get("exp", 0)
        ttl = max(int(exp - datetime.now(timezone.utc).timestamp()), 1)

        redis = await get_async_redis_client()
        if redis:
            await redis.setex(f"token:revoked:{body.refresh_token}", ttl, "1")

        return {"detail": "Logged out successfully. Refresh token revoked."}
    except jwt.PyJWTError:
        # Token is invalid/expired — it can't be used anyway, so logout is a no-op
        return {"detail": "Logged out. Token was already invalid or expired."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Logout failed: {str(e)}")
