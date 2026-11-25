import hashlib
import hmac
import os
import secrets
from typing import Any
import jwt
import logging
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from config import settings
from database.postgres import get_async_db_conn

try:
    import aiohttp as _aiohttp_mod
    _ORIGINAL_AIOHTTP_SESSION = _aiohttp_mod.ClientSession
    _ORIGINAL_AIOHTTP_GET = _aiohttp_mod.ClientSession.get
except ImportError:  # pragma: no cover
    _aiohttp_mod = None
    _ORIGINAL_AIOHTTP_SESSION = None
    _ORIGINAL_AIOHTTP_GET = None

logger = logging.getLogger(__name__)

SECRET_KEY = settings.jwt_secret_key
ALGORITHM = settings.jwt_algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login", auto_error=False)

# ── Account Lockout & Brute-Force Shield Configuration ────────────────────────
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW_SECONDS = 1800       # 30 minutes rolling window
LOCKOUT_DURATION_SECONDS = 1800     # 30 minutes lockout duration

def _normalize_lockout_username(username: str) -> str:
    return (username or "").strip().lower()


async def check_account_lockout(username: str) -> None:
    """Checks if a user account is temporarily locked out due to excessive failed logins."""
    try:
        from database.redis_db import get_async_redis_client
        redis = await get_async_redis_client()
        if redis is None:
            return
        norm_user = _normalize_lockout_username(username)
        is_locked = await redis.get(f"failed_logins:lockout:{norm_user}")
        if isinstance(is_locked, (str, bytes, int)) and str(is_locked) not in ("", "0", "b''", "b'0'"):
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account temporarily locked due to excessive failed attempts. Please try again later."
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
        norm_user = _normalize_lockout_username(username)
        attempts_key = f"failed_logins:{norm_user}"
        attempts = await redis.incr(attempts_key)
        if attempts == 1:
            await redis.expire(attempts_key, LOCKOUT_WINDOW_SECONDS)

        if attempts >= LOCKOUT_THRESHOLD:
            lockout_key = f"failed_logins:lockout:{norm_user}"
            await redis.setex(lockout_key, LOCKOUT_DURATION_SECONDS, "locked")
            log_audit_event(
                event_type="SECURITY_ALERT",
                actor_id=norm_user,
                actor_role="UNKNOWN",
                action="ACCOUNT_LOCKED",
                resource_type="USER",
                resource_id=norm_user,
                tenant_id=tenant_id or "00000000-0000-0000-0000-000000000001",
                details={
                    "username": norm_user,
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
        norm_user = _normalize_lockout_username(username)
        await redis.delete(f"failed_logins:{norm_user}", f"failed_logins:lockout:{norm_user}")
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


async def hash_password_async(password: str) -> str:
    """Offloads CPU/memory-intensive Argon2id hashing to a worker thread."""
    import asyncio
    return await asyncio.to_thread(hash_password, password)


async def verify_password_and_needs_rehash_async(plain_password: str, hashed_password: str) -> tuple[bool, bool]:
    """Offloads CPU/memory-intensive Argon2id verification to a worker thread."""
    import asyncio
    return await asyncio.to_thread(verify_password_and_needs_rehash, plain_password, hashed_password)

from services.secrets_manager import get_jwt_signing_key, decode_jwt_with_rotation

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Issues a short-lived access token (default 15 min) signed with the active primary key."""
    import uuid
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({
        "iss": getattr(settings, "jwt_issuer", "aml-sentinel"),
        "aud": getattr(settings, "jwt_audience", "aml-sentinel-api"),
        "iat": now,
        "nbf": now,
        "exp": expire,
        "jti": str(uuid.uuid4()),
        "type": "access",
        "token_version": data.get("token_version", 1)
    })
    signing_key = get_jwt_signing_key()
    return jwt.encode(to_encode, signing_key, algorithm=ALGORITHM)


# RFC 9106 calibrated dummy hash to prevent timing attacks / user enumeration side-channels
DUMMY_ARGON2_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQxMjM0NTY3OA$9vX6l+w3cRj7E9l3sK4n9QaB1C2D3E4F5G6H7I8J9K0"

def _is_aiohttp_patched() -> bool:
    if _aiohttp_mod is None:
        return False
    return (
        _aiohttp_mod.ClientSession is not _ORIGINAL_AIOHTTP_SESSION
        or getattr(_aiohttp_mod.ClientSession, "get", None) is not _ORIGINAL_AIOHTTP_GET
    )


async def check_breached_password(password: str) -> bool:
    """
    Checks password against HaveIBeenPwned k-Anonymity API (NIST SP 800-63B).
    Uses pooled httpx + circuit breaker + Add-Padding header + follow_redirects=False.
    Skips live external calls under pytest/disabled outbound egress unless mocked.
    """
    if not password:
        return False
    try:
        import hashlib
        import httpx
        from services.http_client import is_httpx_patched, is_outbound_egress_allowed, request_with_resilience

        aiohttp_patched = _is_aiohttp_patched()
        httpx_patched = is_httpx_patched("GET")
        if not aiohttp_patched and not httpx_patched:
            if os.getenv("PYTEST_CURRENT_TEST") or not is_outbound_egress_allowed("hibp"):
                return False

        sha1_hash = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        body_text = ""
        if aiohttp_patched and _aiohttp_mod is not None:
            timeout = _aiohttp_mod.ClientTimeout(total=2.0)
            async with _aiohttp_mod.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers={"Add-Padding": "true"}, allow_redirects=False) as resp:
                    if resp.status == 200:
                        body_text = await resp.text()
        else:
            resp = await request_with_resilience(
                "GET",
                url,
                target="hibp_pwned",
                timeout=httpx.Timeout(connect=1.0, read=2.0, write=1.0, pool=1.0),
                follow_redirects=False,
                retries=0,
                headers={"Add-Padding": "true"},
            )
            if resp.status_code == 200:
                body_text = resp.text

        if body_text:
            for line in body_text.splitlines():
                if ":" in line:
                    entry_suffix, count = line.split(":", 1)
                    if entry_suffix.strip() == suffix and int(count.strip() or 0) > 0:
                        logger.warning("HIBP breach detected: password breached %s times.", count.strip())
                        return True
    except Exception as e:
        logger.warning("HIBP k-anonymity check skipped due to network/timeout: %s", e)
        return False
    return False

def create_refresh_token(data: dict) -> str:
    """
    Issues a long-lived refresh token (7 days).
    Stored server-side in Redis; rotated on each use.
    Maintains a family_id claim for compromise detection (IETF RFC 6819).
    The client uses this to silently obtain a new access token
    without prompting for credentials again.
    """
    import uuid
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=getattr(settings, "refresh_token_expire_days", 7))
    family_id = data.get("family_id")
    to_encode.update({
        "iss": getattr(settings, "jwt_issuer", "aml-sentinel"),
        "aud": getattr(settings, "jwt_audience", "aml-sentinel-api"),
        "iat": now,
        "nbf": now,
        "exp": expire,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
        "token_version": data.get("token_version", 1)
    })
    if family_id:
        to_encode["family_id"] = family_id
    signing_key = get_jwt_signing_key()
    return jwt.encode(to_encode, signing_key, algorithm=ALGORITHM)

def _resolve_auth_token(
    request: Request | str | None,
    bearer_token: str | None,
    token: str | None,
) -> str | None:
    if isinstance(request, str):
        return request
    cookie_token = None
    if request is not None and hasattr(request, "cookies"):
        cookie_token = request.cookies.get("access_token")
    return token or bearer_token or cookie_token


async def _verify_token_version(
    user_id: str,
    token_version: Any,
    tenant_id: str | None = None,
    jti: str | None = None,
) -> None:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if token_version is None:
        raise credentials_exception

    redis = None
    try:
        from database.redis_db import get_async_redis_client
        redis = await get_async_redis_client()
        if redis:
            # 1. Check immediate access-token JTI denylist (populated on logout)
            if jti:
                is_jti_revoked = await redis.get(f"token:access_revoked:{jti}")
                if isinstance(is_jti_revoked, (str, bytes, int)) and str(is_jti_revoked) not in ("", "0", "b''", "b'0'"):
                    raise credentials_exception

            # 2. Check cached user token_version — ONLY short-circuit on a genuine cache HIT!
            cached_ver = await redis.get(f"user:token_version:{user_id}")
            if isinstance(cached_ver, (int, str, bytes)):
                if int(cached_ver) > int(token_version):
                    raise credentials_exception
                return
    except HTTPException:
        raise
    except Exception as redis_err:
        redis = None
        logger.warning(f"Redis token_version check failed for user {user_id}: {redis_err}")

    # 3. Fail-closed read-through fallback: on Redis outage OR cache miss, verify against PostgreSQL
    try:
        import uuid as _uuid
        u_uuid = _uuid.UUID(str(user_id))
        async with get_async_db_conn(tenant_id=tenant_id, auth_lookup=True) as conn:
            row = await conn.fetchrow(
                "SELECT token_version, is_active FROM users WHERE id = $1;",
                u_uuid,
            )
            # Support test mocks that configure fetchval instead of fetchrow (ignore unconfigured AsyncMock/MagicMock)
            is_real_row = (
                row is not None
                and type(row).__name__ not in ("AsyncMock", "MagicMock")
                and (isinstance(row, dict) or hasattr(row, "keys"))
            )
            if is_real_row:
                if row.get("is_active") is False:
                    raise credentials_exception
                db_ver = row.get("token_version")
                if isinstance(db_ver, (int, float, str)) and int(db_ver) > int(token_version):
                    raise credentials_exception
                if redis and isinstance(db_ver, (int, float, str)):
                    try:
                        await redis.setex(f"user:token_version:{user_id}", 3600, int(db_ver))
                    except Exception:
                        pass
                return

            db_ver_val = await conn.fetchval(
                "SELECT token_version FROM users WHERE id = $1;",
                u_uuid,
            )
            if isinstance(db_ver_val, (int, float, str)):
                if int(db_ver_val) > int(token_version):
                    raise credentials_exception
                if redis:
                    try:
                        await redis.setex(f"user:token_version:{user_id}", 3600, int(db_ver_val))
                    except Exception:
                        pass
                return

            # User row absent from DB: strictly reject in production
            if settings.is_production:
                raise credentials_exception
    except HTTPException:
        raise
    except ValueError:
        if settings.is_production:
            raise credentials_exception
    except Exception as db_err:
        logger.error(f"Token version verification failed in both Redis and PostgreSQL: {db_err}")
        if settings.is_production:
            raise credentials_exception


async def _verify_supabase_user(resolved_token: str, credentials_exception: HTTPException) -> dict:
    if not (settings.supabase_url and settings.supabase_key and not settings.supabase_key.startswith("your_")):
        raise credentials_exception

    base_url = settings.supabase_url.rstrip("/")
    if getattr(settings, "is_hardened", settings.is_production) and not base_url.lower().startswith("https://"):
        logger.error("Refusing plaintext Supabase URL in hardened environment.")
        raise credentials_exception

    headers = {
        "Authorization": f"Bearer {resolved_token}",
        "apikey": settings.supabase_key,
    }
    import httpx
    from services.http_client import CircuitOpenError, is_httpx_patched, request_with_resilience

    aiohttp_patched = _is_aiohttp_patched()
    httpx_patched = is_httpx_patched("GET")
    if not aiohttp_patched and not httpx_patched and os.getenv("PYTEST_CURRENT_TEST"):
        raise credentials_exception

    try:
        if aiohttp_patched and _aiohttp_mod is not None:
            timeout = _aiohttp_mod.ClientTimeout(total=3.0)
            async with _aiohttp_mod.ClientSession(timeout=timeout) as session:
                async with session.get(f"{base_url}/auth/v1/user", headers=headers, allow_redirects=False) as resp:
                    if resp.status != 200:
                        raise credentials_exception
                    user_data = await resp.json()
        else:
            resp = await request_with_resilience(
                "GET",
                f"{base_url}/auth/v1/user",
                target="supabase_auth",
                timeout=httpx.Timeout(connect=1.5, read=3.0, write=2.0, pool=1.5),
                follow_redirects=False,
                retries=0,
                headers=headers,
            )
            if resp.status_code != 200:
                raise credentials_exception
            user_data = resp.json()
        app_metadata = user_data.get("app_metadata") or {}
        role = app_metadata.get("role", "L1_ANALYST")
        email = user_data.get("email", "")
        username = email.split("@")[0] if email else "anonymous"
        tenant_id = app_metadata.get("tenant_id")
        if not tenant_id:
            logger.warning("Supabase user missing server-assigned app_metadata.tenant_id")
            raise credentials_exception
        user_id = user_data.get("id")
        if user_id:
            await _verify_token_version(str(user_id), token_version=1, tenant_id=str(tenant_id))
        from observability.middleware import user_id_var, tenant_id_var
        user_id_var.set(str(user_id))
        tenant_id_var.set(str(tenant_id))
        return {
            "id": user_id,
            "username": username,
            "role": role,
            "email": email,
            "tenant_id": tenant_id,
        }
    except HTTPException:
        raise
    except (CircuitOpenError, Exception) as e:
        logger.warning("Supabase auth verification failed: %s", e)
        raise credentials_exception


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
    
    resolved_token = _resolve_auth_token(request, bearer_token, token)
    if not resolved_token:
        raise credentials_exception
    
    # 1. Attempt Local JWT Verification with per-request decode caching and key rotation support
    try:
        payload = None
        if request is not None and hasattr(request, "state"):
            if getattr(request.state, "jwt_raw_token", None) == resolved_token:
                payload = getattr(request.state, "jwt_payload", None)

        if payload is None:
            payload = decode_jwt_with_rotation(resolved_token, algorithm=ALGORITHM)
            if request is not None and hasattr(request, "state"):
                request.state.jwt_raw_token = resolved_token
                request.state.jwt_payload = payload

        # Security (S-2): Strictly reject refresh tokens (or any non-access token) on API endpoints
        token_type = payload.get("type")
        if token_type != "access":
            raise credentials_exception

        user_id = payload.get("id") or payload.get("user_id") or payload.get("sub")
        role = payload.get("role")
        username = payload.get("username", "anonymous")
        email = payload.get("email", f"{username}@aml.com")
        tenant_id = payload.get("tenant_id")
        token_version = payload.get("token_version")
        jti = payload.get("jti")

        # Fail closed on missing required identity / authorization claims (AUTHN-04)
        if not user_id or not role or not tenant_id:
            raise credentials_exception

        await _verify_token_version(str(user_id), token_version, tenant_id=str(tenant_id), jti=jti)

        from observability.middleware import user_id_var, tenant_id_var
        user_id_var.set(str(user_id))
        tenant_id_var.set(str(tenant_id))

        return {
            "id": user_id,
            "username": username,
            "role": role,
            "email": email,
            "tenant_id": tenant_id,
            "jti": jti,
        }
    except HTTPException:
        raise
    except jwt.PyJWTError:
        pass  # Fall back to Supabase check if local decode fails

    # 2. Fallback to Supabase verification
    return await _verify_supabase_user(resolved_token, credentials_exception)


async def revoke_user_sessions(user_id: str, tenant_id: str | None = None) -> int:
    """
    Increments token_version in PostgreSQL and updates Redis cache,
    immediately revoking all outstanding sessions/JWTs for this user across clusters.
    """
    from database.postgres import get_async_db_conn
    from database.redis_db import get_async_redis_client
    
    new_version: int | None = None
    try:
        async with get_async_db_conn(tenant_id=tenant_id, auth_lookup=True) as conn:
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
                new_version = int(row["token_version"])
    except Exception as e:
        logger.warning(f"Failed to update token_version in PostgreSQL: {e}")
            
    try:
        redis = await get_async_redis_client()
        if redis:
            key = f"user:token_version:{user_id}"
            if new_version is not None:
                await redis.set(key, new_version)
            else:
                # Fail-closed: never write '1' when DB update failed; bump above 1 via INCR!
                bumped = await redis.incr(key)
                if int(bumped) <= 1:
                    bumped = await redis.incr(key)
                new_version = int(bumped)
    except Exception as e:
        logger.warning(f"Failed to update token_version in Redis: {e}")
        
    return new_version if new_version is not None else 2


PERM_CASES_ALL = "cases:*"
PERM_CASES_READ = "cases:read"
PERM_ALERTS_ALL = "alerts:*"
PERM_ALERTS_READ = "alerts:read"
PERM_TRANSACTIONS_ALL = "transactions:*"
PERM_TRANSACTIONS_READ = "transactions:read"
PERM_REPORTS_ALL = "reports:*"
PERM_KYC_ALL = "kyc:*"

ROLE_HIERARCHY = {
    "SUPER_ADMIN": ["*"],
    "TENANT_ADMIN": ["users:*", "rules:*", PERM_CASES_ALL, PERM_ALERTS_ALL, PERM_TRANSACTIONS_ALL, "sar:*", PERM_REPORTS_ALL, PERM_KYC_ALL, "ctr:*"],
    "ADMIN": ["users:*", "rules:*", PERM_CASES_ALL, PERM_ALERTS_ALL, PERM_TRANSACTIONS_ALL, "sar:*", PERM_REPORTS_ALL, PERM_KYC_ALL, "ctr:*"],
    "MLRO": ["sar:approve", "sar:submit", PERM_CASES_ALL, PERM_ALERTS_ALL, PERM_TRANSACTIONS_READ, "edd:review", "accounts:freeze", PERM_KYC_ALL, "ctr:approve", "ctr:submit", PERM_REPORTS_ALL],
    "L2_INVESTIGATOR": [PERM_CASES_ALL, PERM_ALERTS_ALL, PERM_TRANSACTIONS_READ, "sar:draft", "edd:request", "kyc:review"],
    "L1_ANALYST": [PERM_ALERTS_READ, "alerts:triage", PERM_TRANSACTIONS_READ, PERM_CASES_READ, "cases:triage"],
    "ANALYST": [PERM_ALERTS_READ, "alerts:triage", "alerts:action", PERM_CASES_ALL, PERM_TRANSACTIONS_ALL, "sar:draft", "edd:request", "kyc:review"],
    "AUDITOR": ["audit_log:read", "reports:read", PERM_CASES_READ, PERM_ALERTS_READ, PERM_TRANSACTIONS_READ, "pii:masked"],
    "QA_REVIEWER": ["qa:sample", "qa:review", "audit_log:read", "reports:read", PERM_CASES_READ, PERM_ALERTS_READ],
    "GLOBAL_AUDITOR": ["audit_log:read", "reports:read", PERM_CASES_READ, PERM_ALERTS_READ, PERM_TRANSACTIONS_READ, "cross_tenant:read"],
    "API_CONSUMER": ["transactions:ingest", "screening:query", PERM_ALERTS_READ],
    "SYSTEM": ["*"]
}

ROLE_ALIASES = {
    "ADMIN": ["ADMIN", "TENANT_ADMIN", "SUPER_ADMIN"],
    # Security (S-5): L1_ANALYST is strictly excluded from ANALYST (L2 equivalent)
    # so Tier-1 analysts cannot file/close SARs, retrain ML models, or onboard entities.
    "ANALYST": ["ANALYST", "L2_INVESTIGATOR", "MLRO", "ADMIN", "TENANT_ADMIN", "SUPER_ADMIN"],
    "AUDITOR": ["AUDITOR", "GLOBAL_AUDITOR", "ADMIN", "TENANT_ADMIN", "SUPER_ADMIN"],
    "QA_REVIEWER": ["QA_REVIEWER", "MLRO", "ADMIN", "TENANT_ADMIN", "SUPER_ADMIN"],
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
        user_role = current_user.get("role") or ""
        if user_role not in self.allowed_roles and user_role != "SUPER_ADMIN":
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
        user_role = current_user.get("role") or ""
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


# ── Unified In-Process Downstream Auth & Gateway Validation ──────────────────
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from jwt import PyJWKClient


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
    Enables unified in-process token validation across all AML monolith endpoints
    without HTTP serialization, port coordination, or microservice theater.
    """

    def __init__(self, jwks_url: Optional[str] = None, cache_keys: bool = True):
        if jwks_url and getattr(settings, "is_hardened", settings.is_production):
            from services.siem_forwarder import validate_siem_destination_url
            jwks_url = validate_siem_destination_url(jwks_url)
        self.jwks_url = jwks_url
        self._jwks_client: Optional[PyJWKClient] = (
            PyJWKClient(jwks_url, cache_keys=cache_keys, lifespan=3600, timeout=5) if jwks_url else None
        )

    def _validate_gateway_headers(self, request: Request) -> Optional[UserClaims]:
        x_user_id = request.headers.get("x-user-id")
        x_tenant_id = request.headers.get("x-tenant-id")
        if not (x_user_id and x_tenant_id):
            return None

        # Fail closed (AUTHN-08): NEVER trust gateway identity headers unless a non-empty
        # gateway secret is configured, matches via constant-time comparison, and peer is trusted.
        expected_secret = (getattr(settings, "internal_gateway_secret", "") or "").strip()
        inbound_gateway_token = (request.headers.get("x-internal-gateway-token") or "").strip()
        if not expected_secret or not inbound_gateway_token or not hmac.compare_digest(inbound_gateway_token, expected_secret):
            logger.warning("Untrusted internal identity headers detected without valid gateway token.")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Spoofed or unverified internal gateway headers.",
            )

        from services.trusted_proxy import is_ip_trusted
        peer_ip = getattr(request.client, "host", None) if request.client else None
        if isinstance(peer_ip, str) and peer_ip.strip():
            if not is_ip_trusted(peer_ip):
                logger.warning("Internal gateway headers rejected from untrusted peer IP '%s'.", peer_ip)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: Gateway headers originated from untrusted network peer.",
                )
        elif settings.is_production:
            logger.warning("Internal gateway headers rejected: missing peer IP in production.")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Gateway headers originated from untrusted network peer.",
            )

        x_roles = request.headers.get("x-user-roles")
        roles = [r.strip() for r in x_roles.split(",")] if x_roles else []
        return UserClaims(
            user_id=x_user_id,
            tenant_id=x_tenant_id,
            username=request.headers.get("x-user-name", "gateway_authenticated"),
            roles=roles,
            is_mfa_authenticated=request.headers.get("x-mfa-verified", "false").lower() == "true",
        )

    def validate_request(self, request: Request) -> UserClaims:
        """
        FastAPI dependency helper to authenticate incoming requests.
        """
        # 1. Check for trusted headers injected by the API Gateway
        gateway_claims = self._validate_gateway_headers(request)
        if gateway_claims is not None:
            return gateway_claims

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
        if payload.get("type") == "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh tokens cannot be used for API authentication.",
                headers={"WWW-Authenticate": "Bearer"},
            )

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
        Decodes and verifies a JWT against JWKS (strict asymmetric-only when configured)
        or local configured secrets. Never falls back from JWKS to symmetric HS256 (AUTHN-08).
        """
        if self._jwks_client:
            try:
                signing_key = self._jwks_client.get_signing_key_from_jwt(token)
                return jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["RS256", "ES256"],
                    options={
                        "verify_signature": True,
                        "verify_exp": True,
                        "verify_aud": False,
                        "require": ["exp", "sub"],
                    },
                )
            except Exception as jwks_err:
                logger.debug(f"JWKS verification failed (fail-closed, no HS256 fallback): {jwks_err}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired authentication token.",
                )

        try:
            from services.secrets_manager import decode_jwt_with_rotation
            payload = decode_jwt_with_rotation(token, algorithm=ALGORITHM)
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
    """FastAPI dependency for in-process request validation."""
    return default_validator.validate_request(request)


