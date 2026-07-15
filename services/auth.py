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
        100000
    )
    return f"pbkdf2_sha256$100000${salt}${dk.hex()}"

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
        # hmac.compare_digest prevents timing attacks by guaranteeing
        # constant-time comparison regardless of where strings diverge.
        return hmac.compare_digest(dk.hex(), stored_hash)
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Issues a short-lived access token (default 30 min)."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


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
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # 1. Attempt Local JWT Verification (useful for testing or fallback local users)
    if SECRET_KEY:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = payload.get("sub")
            role = payload.get("role", "ANALYST")
            username = payload.get("username", "anonymous")
            email = payload.get("email", f"{username}@aml.com")
            
            if user_id:
                # Replicate user to local PostgreSQL database if not present
                from database.postgres import get_async_db_conn
                async with get_async_db_conn() as conn:
                    await conn.execute(
                        "INSERT INTO users (id, username, role) VALUES ($1, $2, $3) "
                        "ON CONFLICT (id) DO UPDATE SET role = EXCLUDED.role, username = EXCLUDED.username;",
                        user_id, username, role
                    )
                return {
                    "id": user_id,
                    "username": username,
                    "role": role,
                    "email": email
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
                
                user_id = user_data.get("id")
                
                # Replicate user to local PostgreSQL database if not present
                from database.postgres import get_async_db_conn
                async with get_async_db_conn() as conn:
                    await conn.execute(
                        "INSERT INTO users (id, username, role) VALUES ($1, $2, $3) "
                        "ON CONFLICT (id) DO UPDATE SET role = EXCLUDED.role, username = EXCLUDED.username;",
                        user_id,
                        username,
                        role
                    )
                
                return {
                    "id": user_id,
                    "username": username,
                    "role": role,
                    "email": email
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
