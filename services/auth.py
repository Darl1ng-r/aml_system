import hashlib
import hmac
import secrets
import jwt
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from config import settings
from database.postgres import get_async_db_conn

SECRET_KEY = settings.jwt_secret_key
ALGORITHM = settings.jwt_algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        600000
    )
    return f"pbkdf2_sha256$600000${salt}${dk.hex()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        parts = hashed_password.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = parts[2]
        stored_hash = parts[3]
        dk = hashlib.pbkdf2_hmac(
            'sha256',
            plain_password.encode('utf-8'),
            salt.encode('utf-8'),
            iterations
        )
        return hmac.compare_digest(dk.hex(), stored_hash)
    except Exception:
        return False

from services.secrets_manager import get_jwt_signing_key, decode_jwt_with_rotation

# In-memory cache for replicated users to avoid hammering PostgreSQL on every request
_synced_users: set[str] = set()

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Issues a short-lived access token (default 30 min) signed with the active primary key."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "type": "access"})
    signing_key = get_jwt_signing_key()
    return jwt.encode(to_encode, signing_key, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    """
    Issues a long-lived refresh token (7 days).
    Stored server-side in Redis; rotated on each use.
    The client uses this to silently obtain a new access token
    without prompting for credentials again.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire, "type": "refresh"})
    signing_key = get_jwt_signing_key()
    return jwt.encode(to_encode, signing_key, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # 1. Attempt Local JWT Verification with key rotation fallback support
    try:
        payload = decode_jwt_with_rotation(token, algorithm=ALGORITHM)
        user_id = payload.get("sub")
        role = payload.get("role", "ANALYST")
        username = payload.get("username", "anonymous")
        email = payload.get("email", f"{username}@aml.com")
        tenant_id = payload.get("tenant_id", "00000000-0000-0000-0000-000000000001")
        
        if user_id:
            from observability.middleware import user_id_var, tenant_id_var
            user_id_var.set(str(user_id))
            tenant_id_var.set(str(tenant_id))

            # Only sync to local PostgreSQL database if not already synced during this process lifecycle
            cache_key = f"{user_id}:{role}:{tenant_id}"
            if cache_key not in _synced_users:
                try:
                    from database.postgres import get_async_db_conn
                    async with get_async_db_conn() as conn:
                        await conn.execute(
                            "INSERT INTO users (id, username, role, tenant_id) VALUES ($1, $2, $3, $4) "
                            "ON CONFLICT (id) DO UPDATE SET role = EXCLUDED.role, username = EXCLUDED.username, tenant_id = EXCLUDED.tenant_id;",
                            user_id, username, role, tenant_id
                        )
                    _synced_users.add(cache_key)
                except Exception:
                    pass  # Non-fatal if DB is temporarily unreachable for user replication
            return {
                "id": user_id,
                "username": username,
                "role": role,
                "email": email,
                "tenant_id": tenant_id
            }
    except jwt.PyJWTError:
        pass  # Fall back to Supabase check if local decode fails

    # 2. Fallback to Supabase verification
    headers = {
        "Authorization": f"Bearer {token}",
        "apikey": settings.supabase_key
    }
    
    import aiohttp
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{settings.supabase_url}/auth/v1/user", headers=headers) as resp:
                if resp.status != 200:
                    raise credentials_exception
                user_data = await resp.json()
                
                user_metadata = user_data.get("user_metadata", {})
                role = user_metadata.get("role", "ANALYST")
                email = user_data.get("email", "")
                username = email.split("@")[0] if email else "anonymous"
                tenant_id = user_metadata.get("tenant_id", "00000000-0000-0000-0000-000000000001")
                
                user_id = user_data.get("id")
                from observability.middleware import user_id_var, tenant_id_var
                user_id_var.set(str(user_id))
                tenant_id_var.set(str(tenant_id))
                
                # Replicate user to local PostgreSQL database if not present
                from database.postgres import get_async_db_conn
                async with get_async_db_conn() as conn:
                    await conn.execute(
                        "INSERT INTO users (id, username, role, tenant_id) VALUES ($1, $2, $3, $4) "
                        "ON CONFLICT (id) DO UPDATE SET role = EXCLUDED.role, username = EXCLUDED.username, tenant_id = EXCLUDED.tenant_id;",
                        user_id,
                        username,
                        role,
                        tenant_id
                    )
                
                return {
                    "id": user_id,
                    "username": username,
                    "role": role,
                    "email": email,
                    "tenant_id": tenant_id
                }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Auth verification offline or failed: {str(e)}"
        )


class RoleChecker:
    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: dict = Depends(get_current_user)):
        if current_user.get("role") not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted for this user role.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return current_user


def enforce_tenant_data_scope(current_user: dict, target_tenant_id: str | None = None) -> str:
    """
    Enforces Data-Level RBAC scoping.
    - Roles 'SUPER_ADMIN' and 'GLOBAL_AUDITOR' can access cross-tenant data.
    - Roles 'ANALYST', 'AUDITOR', 'ADMIN' are strictly scoped to their assigned tenant_id.

    Returns the authorized tenant_id to use for queries.
    Raises HTTP 403 Forbidden if a user attempts cross-tenant data access without authorization.
    """
    user_role = current_user.get("role", "ANALYST")
    user_tenant_id = str(current_user.get("tenant_id", ""))

    # Super Admin and Global Auditor bypass single-tenant scoping
    if user_role in ["SUPER_ADMIN", "GLOBAL_AUDITOR"]:
        return target_tenant_id or user_tenant_id

    # If target_tenant_id is explicitly requested, verify it matches user's tenant
    if target_tenant_id and str(target_tenant_id) != user_tenant_id:
        from observability.logging import log_audit_event
        log_audit_event(
            event_type="RBAC_VIOLATION",
            actor_id=str(current_user.get("id", "")),
            actor_role=user_role,
            action="UNAUTHORIZED_TENANT_ACCESS",
            resource_type="TENANT",
            resource_id=str(target_tenant_id),
            tenant_id=user_tenant_id,
            details={
                "username": current_user.get("username"),
                "attempted_tenant": target_tenant_id
            }
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Data access is restricted to your assigned tenant."
        )

    return user_tenant_id

