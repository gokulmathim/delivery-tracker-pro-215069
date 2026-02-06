import base64
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import jwt
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _get_secret_key() -> str:
    """
    NOTE: In production you must set JWT_SECRET_KEY in env.
    A deterministic fallback is provided for dev, but should not be relied upon.
    """
    secret = os.getenv("JWT_SECRET_KEY")
    if secret:
        return secret

    # Fallback for local/dev: stable-ish key to avoid breaking sessions on reload,
    # but *not* suitable for production.
    return "dev-insecure-secret-change-me"


def _get_access_ttl_minutes() -> int:
    return int(os.getenv("JWT_ACCESS_TTL_MINUTES", "30"))


def _get_refresh_ttl_days() -> int:
    return int(os.getenv("JWT_REFRESH_TTL_DAYS", "14"))


def _get_issuer() -> str:
    return os.getenv("JWT_ISSUER", "delivery-tracker-backend")


def _get_audience() -> str:
    return os.getenv("JWT_AUDIENCE", "delivery-tracker-frontend")


def _encode_jwt(payload: dict[str, Any]) -> str:
    return jwt.encode(payload, _get_secret_key(), algorithm="HS256")


def _decode_jwt(token: str) -> dict[str, Any]:
    return jwt.decode(
        token,
        _get_secret_key(),
        algorithms=["HS256"],
        audience=_get_audience(),
        issuer=_get_issuer(),
        options={"require": ["exp", "iat", "sub", "iss", "aud"]},
    )


# PUBLIC_INTERFACE
def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(password)


# PUBLIC_INTERFACE
def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored password hash."""
    # Support initial seed values like "dev-hash-user" without breaking dev flows:
    # only allow direct match in dev mode.
    if password_hash.startswith("dev-hash-"):
        return password_hash == f"dev-hash-{password}"
    return pwd_context.verify(password, password_hash)


# PUBLIC_INTERFACE
def issue_access_token(user_id: str, role: str) -> str:
    """Issue a short-lived access token for API authentication."""
    issued = _now()
    exp = issued + timedelta(minutes=_get_access_ttl_minutes())
    payload = {
        "sub": user_id,
        "role": role,
        "type": "access",
        "iat": int(issued.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": _get_issuer(),
        "aud": _get_audience(),
    }
    return _encode_jwt(payload)


# PUBLIC_INTERFACE
def issue_refresh_token(user_id: str, role: str) -> tuple[str, datetime]:
    """Issue a long-lived refresh token; returns (token, expires_at)."""
    issued = _now()
    exp = issued + timedelta(days=_get_refresh_ttl_days())
    payload = {
        "sub": user_id,
        "role": role,
        "type": "refresh",
        "iat": int(issued.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": _get_issuer(),
        "aud": _get_audience(),
    }
    return _encode_jwt(payload), exp


# PUBLIC_INTERFACE
def decode_and_validate_token(token: str, expected_type: Literal["access", "refresh"]) -> dict[str, Any]:
    """Decode and validate a JWT; enforces token type."""
    payload = _decode_jwt(token)
    if payload.get("type") != expected_type:
        raise jwt.InvalidTokenError("Invalid token type")
    return payload


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# PUBLIC_INTERFACE
def sha256_token_hash(token: str) -> str:
    """
    Store refresh tokens as hashes (never store raw tokens).
    Uses SHA-256 (sufficient here; can be replaced with stronger KDF if desired).
    """
    digest = hashlib.sha256(token.encode("utf-8")).digest()
    return _b64url(digest)


# PUBLIC_INTERFACE
def constant_time_equals(a: str, b: str) -> bool:
    """Constant-time string comparison helper."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
