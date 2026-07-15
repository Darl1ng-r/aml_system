import aiohttp
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from config import settings
from pydantic import BaseModel, Field

class UserSignup(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    role: str = "ANALYST"

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
                    err_data = await resp.json()
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=err_data.get("error_description", "Incorrect credentials"),
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                data = await resp.json()
                access_token = data.get("access_token")
                user = data.get("user", {})
                role = user.get("user_metadata", {}).get("role", "ANALYST")
                
                return {
                    "access_token": access_token,
                    "token_type": "bearer",
                    "role": role,
                    "username": email.split("@")[0]
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
                    err_data = await resp.json()
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=err_data.get("msg", "Registration failed")
                    )
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
