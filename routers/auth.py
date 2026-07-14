from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from services.auth import verify_password, create_access_token
from database.postgres import get_async_db_conn

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
