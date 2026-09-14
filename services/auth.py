import hashlib
import hmac
import secrets
import jwt
import logging
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from config import settings
from database.postgres import get_async_db_conn

logger = logging.getLogger(__name__)

SECRET_KEY = settings.jwt_secret_key
ALGORITHM = settings.jwt_algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login", auto_error=False)

# ── Account Lockout & Brute-Force Shield Configuration ────────────────────────
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW_SECONDS = 1800       # 30 minutes rolling window
LOCKOUT_DURATION_SECONDS = 1800     # 30 minutes lockout duration

async def check_account_lockout(username: str) -> None:
    """Checks if a user account is temporarily locked out due to excessive failed logins."""
    try:
        from database.redis_db import get_async_redis_client
        redis = await get_async_redis_client()
        if redis is None:
            return
        is_locked = await redis.get(f"failed_logins:lockout:{username}")
        if is_locked:
            ttl = await redis.ttl(f"failed_logins:lockout:{username}")
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account temporarily locked due to excessive failed attempts. Try again in {max(1, ttl)} seconds."
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Failed to check account lockout in Redis: {e}")

async def record_failed_login(username: str, tenant_id: str | None = None) -> int:
    """Records a failed login attempt; locks account if threshold is reached."""
    try:
        from database.redis_db import get_async_redis_client
        from observability.logging import log_audit_event
        redis = await get_async_redis_client()
        if redis is None:
            return 1
        attempts_key = f"failed_logins:{username}"
        attempts = await redis.incr(attempts_key)
        if attempts == 1:
            await redis.expire(attempts_key, LOCKOUT_WINDOW_SECONDS)

        if attempts >= LOCKOUT_THRESHOLD:
            lockout_key = f"failed_logins:lockout:{username}"
            await redis.setex(lockout_key, LOCKOUT_DURATION_SECONDS, "locked")
            log_audit_event(
                event_type="SECURITY_ALERT",
                actor_id=username,
                actor_role="UNKNOWN",
                action="ACCOUNT_LOCKED",
                resource_type="USER",
                resource_id=username,
                tenant_id=tenant_id or "00000000-0000-0000-0000-000000000001",
                details={
                    "username": username,
                    "failed_attempts": attempts,
                    "lockout_duration_seconds": LOCKOUT_DURATION_SECONDS
                }
            )
        return attempts
    except Exception as e:
        logger.warning(f"Failed to record failed login in Redis: {e}")
        return 1

async def reset_failed_logins(username: str) -> None:
    """Resets failed attempt counters on successful login."""
    try:
        from database.redis_db import get_async_redis_client
        redis = await get_async_redis_client()
        if redis is None:
            return
        await redis.delete(f"failed_logins:{username}", f"failed_logins:lockout:{username}")
    except Exception as e:
        logger.warning(f"Failed to reset failed login counters in Redis: {e}")

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

_argon2_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def hash_password(password: str) -> str:
    """Hashes a password using modern Argon2id with RFC 9106 recommended parameters."""
    return _argon2_hasher.hash(password)

def verify_password_and_needs_rehash(plain_password: str, hashed_password: str) -> tuple[bool, bool]:
    """
    Verifies plain password against stored hash.
    Supports both Argon2id ($argon2id$) and legacy PBKDF2 (pbkdf2_sha256$).
    Returns (is_valid, needs_rehash).
    """
    if not hashed_password:
        return False, False
        
    if hashed_password.startswith("$argon2"):
        try:
            is_valid = _argon2_hasher.verify(hashed_password, plain_password)
            needs_rehash = _argon2_hasher.check_needs_rehash(hashed_password)
            return True, needs_rehash
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False, False
        except Exception:
            return False, False
    elif hashed_password.startswith("pbkdf2_sha256$"):
        try:
            parts = hashed_password.split("$")
            if len(parts) != 4:
                return False, False
            iterations = int(parts[1])
            salt = parts[2]
            stored_hash = parts[3]
            dk = hashlib.pbkdf2_hmac(
                'sha256',
                plain_password.encode('utf-8'),
                salt.encode('utf-8'),
                iterations
            )
            is_valid = hmac.compare_digest(dk.hex(), stored_hash)
            # Legacy PBKDF2 matched; trigger automatic upgrade to Argon2id!
            return is_valid, is_valid
        except Exception:
            return False, False
    return False, False

def verify_password(plain_password: str, hashed_password: str) -> bool:
    is_valid, _ = verify_password_and_needs_rehash(plain_password, hashed_password)
    return is_valid

from services.secrets_manager import get_jwt_signing_key, decode_jwt_with_rotation

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Issues a short-lived access token (default 15 min) signed with the active primary key."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({
        "exp": expire,
        "type": "access",
        "token_version": data.get("token_version", 1)
    })
    signing_key = get_jwt_signing_key()
    return jwt.encode(to_encode, signing_key, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    """
    Issues a long-lived refresh token (7 days).
    Stored server-side in Redis; rotated on each use.
    The client uses this to silently obtain a new access token
    without prompting for credentials again.
    """
    import uuid
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({
        "exp": expire,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
        "token_version": data.get("token_version", 1)
    })
    signing_key = get_jwt_signing_key()
    return jwt.encode(to_encode, signing_key, algorithm=ALGORITHM)

async def get_current_user(
    request: Request = None,
    bearer_token: str | None = Depends(oauth2_scheme),
    token: str | None = None
) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if isinstance(request, str):
        resolved_token = request
        request = None
    else:
        cookie_token = None
        if request is not None and hasattr(request, "cookies"):
            cookie_token = request.cookies.get("access_token")
        resolved_token = token or bearer_token or cookie_token

    if not resolved_token:
        raise credentials_exception
    
    # 1. Attempt Local JWT Verification with key rotation fallback support
    try:
        payload = decode_jwt_with_rotation(resolved_token, algorithm=ALGORITHM)
        user_id = payload.get("sub")
        role = payload.get("role", "ANALYST")
        username = payload.get("username", "anonymous")
        email = payload.get("email", f"{username}@aml.com")
        tenant_id = payload.get("tenant_id", "00000000-0000-0000-0000-000000000001")
        token_version = payload.get("token_version")
        
        if user_id:
            # Check active token_version to immediately invalidate revoked sessions
            if token_version is not None:
                try:
                    from database.redis_db import get_async_redis_client
                    redis = await get_async_redis_client()
                    if redis:
                        cached_ver = await redis.get(f"user:token_version:{user_id}")
                        if cached_ver is not None and int(cached_ver) > int(token_version):
                            raise credentials_exception
                except HTTPException:
                    raise
                except Exception:
                    pass

            from observability.middleware import user_id_var, tenant_id_var
            user_id_var.set(str(user_id))
            tenant_id_var.set(str(tenant_id))

            # Idempotent sync to PostgreSQL database (cluster-safe, no local in-memory cache)
            try:
                from database.postgres import get_async_db_conn
                async with get_async_db_conn() as conn:
                    await conn.execute(
                        "INSERT INTO users (id, username, role, tenant_id) VALUES ($1, $2, $3, $4) "
                        "ON CONFLICT (id) DO UPDATE SET role = EXCLUDED.role, username = EXCLUDED.username, tenant_id = EXCLUDED.tenant_id;",
                        user_id, username, role, tenant_id
                    )
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
    if settings.supabase_url and settings.supabase_key and not settings.supabase_key.startswith("your_"):
        headers = {
            "Authorization": f"Bearer {resolved_token}",
            "apikey": settings.supabase_key
        }
        
        import aiohttp
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
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
            logger.warning(f"Supabase auth verification failed: {e}")
            raise credentials_exception

    raise credentials_exception


async def revoke_user_sessions(user_id: str) -> int:
    """
    Increments token_version in PostgreSQL and updates Redis cache,
    immediately revoking all outstanding sessions/JWTs for this user across clusters.
    """
    from database.postgres import get_async_db_conn
    from database.redis_db import get_async_redis_client
    
    new_version = 1
    try:
        async with get_async_db_conn() as conn:
            row = await conn.fetchrow(
                """
                UPDATE users 
                SET token_version = COALESCE(token_version, 1) + 1 
                WHERE id = $1 
                RETURNING token_version;
                """,
                user_id
            )
            if row and "token_version" in row.keys():
                new_version = row["token_version"]
    except Exception as e:
        logger.warning(f"Failed to update token_version in PostgreSQL: {e}")
            
    try:
        redis = await get_async_redis_client()
        if redis:
            await redis.set(f"user:token_version:{user_id}", new_version)
    except Exception as e:
        logger.warning(f"Failed to update token_version in Redis: {e}")
        
    return new_version


ROLE_HIERARCHY = {
    "SUPER_ADMIN": ["*"],
    "TENANT_ADMIN": ["users:*", "rules:*", "cases:*", "alerts:*", "transactions:*", "sar:*", "reports:*", "kyc:*", "ctr:*"],
    "ADMIN": ["users:*", "rules:*", "cases:*", "alerts:*", "transactions:*", "sar:*", "reports:*", "kyc:*", "ctr:*"],
    "MLRO": ["sar:approve", "sar:submit", "cases:*", "alerts:*", "transactions:read", "edd:review", "accounts:freeze", "kyc:*", "ctr:approve", "ctr:submit", "reports:*"],
    "L2_INVESTIGATOR": ["cases:*", "alerts:*", "transactions:read", "sar:draft", "edd:request", "kyc:review"],
    "L1_ANALYST": ["alerts:read", "alerts:triage", "transactions:read", "cases:read", "cases:triage"],
    "ANALYST": ["alerts:read", "alerts:triage", "alerts:action", "cases:*", "transactions:*", "sar:draft", "edd:request", "kyc:review"],
    "AUDITOR": ["audit_log:read", "reports:read", "cases:read", "alerts:read", "transactions:read", "pii:masked"],
    "GLOBAL_AUDITOR": ["audit_log:read", "reports:read", "cases:read", "alerts:read", "transactions:read", "cross_tenant:read"],
    "API_CONSUMER": ["transactions:ingest", "screening:query", "alerts:read"],
    "SYSTEM": ["*"]
}

ROLE_ALIASES = {
    "ADMIN": ["ADMIN", "TENANT_ADMIN", "SUPER_ADMIN"],
    "ANALYST": ["ANALYST", "L1_ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN", "TENANT_ADMIN", "SUPER_ADMIN"],
    "AUDITOR": ["AUDITOR", "GLOBAL_AUDITOR", "ADMIN", "SUPER_ADMIN"],
    "L1_ANALYST": ["L1_ANALYST", "ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN", "TENANT_ADMIN", "SUPER_ADMIN"],
    "L2_INVESTIGATOR": ["L2_INVESTIGATOR", "MLRO", "ADMIN", "TENANT_ADMIN", "SUPER_ADMIN"],
    "MLRO": ["MLRO", "ADMIN", "TENANT_ADMIN", "SUPER_ADMIN"]
}


class RoleChecker:
    def __init__(self, allowed_roles: list[str]):
        expanded = set(allowed_roles)
        for r in allowed_roles:
            if r in ROLE_ALIASES:
                expanded.update(ROLE_ALIASES[r])
            if r == "L1_ANALYST":
                expanded.update(["L2_INVESTIGATOR", "MLRO", "TENANT_ADMIN", "ADMIN", "SUPER_ADMIN"])
            elif r == "L2_INVESTIGATOR":
                expanded.update(["MLRO", "TENANT_ADMIN", "ADMIN", "SUPER_ADMIN"])
            elif r == "MLRO":
                expanded.update(["TENANT_ADMIN", "ADMIN", "SUPER_ADMIN"])
        self.allowed_roles = list(expanded)

    def __call__(self, current_user: dict = Depends(get_current_user)):
        user_role = current_user.get("role", "ANALYST")
        if user_role not in self.allowed_roles and "SUPER_ADMIN" not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted for user role '{user_role}'.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return current_user


class PermissionChecker:
    def __init__(self, required_permission: str):
        self.required_permission = required_permission

    def __call__(self, current_user: dict = Depends(get_current_user)):
        user_role = current_user.get("role", "ANALYST")
        permissions = ROLE_HIERARCHY.get(user_role, [])
        if "*" in permissions or self.required_permission in permissions:
            return current_user
        scope = self.required_permission.split(":")[0] + ":*"
        if scope in permissions:
            return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User role '{user_role}' lacks required permission '{self.required_permission}'.",
            headers={"WWW-Authenticate": "Bearer"}
        )


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

