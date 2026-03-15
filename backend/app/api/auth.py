"""
Authentication Routes — Full JWT implementation
Amendments #19 (blacklist), #22 (rate limiting)
"""

import hashlib
import secrets
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.tz import utc_now
from app.core.auth import (
    create_access_token, create_refresh_token, decode_token,
    get_current_user, hash_password, revoke_token, verify_password,
)
from app.core.database import get_db
from app.core.redis import blacklist_all_user_tokens
from app.models.enums import UserRole
from app.models.models import User

router = APIRouter()


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    display_name: str = Field(min_length=1, max_length=100)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)

class UserProfileResponse(BaseModel):
    id: str
    email: str
    display_name: str
    role: str
    is_active: bool
    created_at: datetime
    class Config:
        from_attributes = True


@router.get("/setup-status")
async def setup_status(db: AsyncSession = Depends(get_db)):
    """Check if the platform needs initial setup (no users exist yet)."""
    result = await db.execute(select(func.count()).select_from(User))
    return {"needs_setup": result.scalar() == 0}


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(data: RegisterRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == data.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    # First registered user becomes admin — ensures the platform is usable
    # without needing direct DB access or the CLI script.
    user_count = await db.execute(select(func.count()).select_from(User))
    is_first_user = user_count.scalar() == 0

    user = User(
        email=data.email,
        password_hash=hash_password(data.password),
        display_name=data.display_name,
        role=UserRole.ADMIN if is_first_user else UserRole.TESTER,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    from app.core.config import get_settings
    s = get_settings()
    return TokenResponse(
        access_token=create_access_token(str(user.id), user.role.value),
        expires_in=s.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")
    user.last_login_at = utc_now()
    await db.commit()
    access_token = create_access_token(str(user.id), user.role.value)
    refresh_token, refresh_jti, refresh_expires = create_refresh_token(str(user.id))
    response.set_cookie(
        key="refresh_token", value=refresh_token,
        httponly=True, secure=True, samesite="lax",
        max_age=7 * 24 * 3600, path="/api/v1/auth",
    )
    from app.core.config import get_settings
    s = get_settings()
    return TokenResponse(
        access_token=access_token,
        expires_in=s.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: Request, db: AsyncSession = Depends(get_db)):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")
    payload = decode_token(token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")
    from app.core.redis import is_token_blacklisted
    jti = payload.get("jti")
    if jti and await is_token_blacklisted(jti):
        raise HTTPException(status_code=401, detail="Refresh token revoked")
    user = await db.get(User, payload.get("sub"))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    from app.core.config import get_settings
    s = get_settings()
    return TokenResponse(
        access_token=create_access_token(str(user.id), user.role.value),
        expires_in=s.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout")
async def logout(request: Request, response: Response, user: User = Depends(get_current_user)):
    token = request.cookies.get("refresh_token")
    if token:
        try:
            payload = decode_token(token)
            jti = payload.get("jti")
            exp = datetime.utcfromtimestamp(payload.get("exp", 0))
            if jti:
                await revoke_token(jti, exp)
        except Exception:
            pass
    response.delete_cookie("refresh_token", path="/api/v1/auth")
    return {"status": "logged_out"}


@router.post("/change-password")
async def change_password(
    data: ChangePasswordRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db),
):
    if not verify_password(data.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    user.password_hash = hash_password(data.new_password)
    await db.commit()
    await blacklist_all_user_tokens(str(user.id))
    return {"status": "password_changed", "message": "All sessions invalidated"}


@router.get("/me", response_model=UserProfileResponse)
async def get_profile(user: User = Depends(get_current_user)):
    return UserProfileResponse(
        id=str(user.id), email=user.email, display_name=user.display_name,
        role=user.role.value, is_active=user.is_active, created_at=user.created_at,
    )


@router.post("/api-key")
async def generate_api_key(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    raw_key = f"sentinel_{secrets.token_urlsafe(32)}"
    user.api_key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    await db.commit()
    return {"api_key": raw_key, "warning": "This key will not be shown again."}
