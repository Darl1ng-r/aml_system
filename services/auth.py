import hashlib
import secrets
import jwt
from datetime import datetime, timedelta
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
        return dk.hex() == stored_hash
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate Supabase credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
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
            detail=f"Supabase Auth verification offline or failed: {str(e)}"
        )
