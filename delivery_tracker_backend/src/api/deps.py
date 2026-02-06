from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.db import get_db_session
from src.api.security import decode_and_validate_token

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class CurrentUser:
    id: UUID
    role: str
    email: Optional[str]
    is_active: bool


async def _load_user(session: AsyncSession, user_id: UUID) -> CurrentUser:
    res = await session.execute(
        text("SELECT id, email, role, is_active FROM users WHERE id = :id"),
        {"id": str(user_id)},
    )
    row = res.mappings().first()
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if not row["is_active"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")
    return CurrentUser(id=UUID(str(row["id"])), role=str(row["role"]), email=row["email"], is_active=bool(row["is_active"]))


# PUBLIC_INTERFACE
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_db_session),
) -> CurrentUser:
    """Resolve and validate the current authenticated user from Bearer access token."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    token = credentials.credentials
    try:
        payload = decode_and_validate_token(token, expected_type="access")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    try:
        user_id = UUID(str(payload["sub"]))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")

    user = await _load_user(session, user_id)
    return user


# PUBLIC_INTERFACE
async def require_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Require current user to have role=admin."""
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user


# PUBLIC_INTERFACE
async def require_driver_or_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Require current user to be driver or admin."""
    if user.role not in ("driver", "admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Driver or admin role required")
    return user
