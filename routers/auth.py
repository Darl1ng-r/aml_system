from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from services.auth import verify_password, create_access_token, hash_password
from database.postgres import get_async_db_conn
from pydantic import BaseModel, Field

class UserSignup(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    role: str = "ANALYST"

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        async with get_async_db_conn() as conn:
            user = await conn.fetchrow(
                "SELECT id, username, hashed_password, role FROM users WHERE username = $1;",
                form_data.username
            )
            
            if not user or not verify_password(form_data.password, user[2]):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
                
            access_token = create_access_token(
                data={"sub": user[1], "role": user[3]}
            )
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "role": user[3],
                "username": user[1]
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Login authentication failed: {str(e)}"
        )

@router.post("/signup")
async def signup(payload: UserSignup):
    try:
        async with get_async_db_conn() as conn:
            existing = await conn.fetchval(
                "SELECT id FROM users WHERE username = $1;",
                payload.username
            )
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already registered"
                )
                
            hashed = hash_password(payload.password)
            user_id = await conn.fetchval(
                """
                INSERT INTO users (username, hashed_password, role)
                VALUES ($1, $2, $3)
                RETURNING id;
                """,
                payload.username, hashed, payload.role
            )
            
            access_token = create_access_token(
                data={"sub": payload.username, "role": payload.role}
            )
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "role": payload.role,
                "username": payload.username
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Registration failed: {str(e)}"
        )
