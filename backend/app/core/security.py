import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import HTTPException, status
from pwdlib import PasswordHash

from app.core.config import get_settings

password_hash = PasswordHash.recommended()
DUMMY_PASSWORD_HASH = password_hash.hash("MineGuardDummyPassword123")
MEDIA_TOKEN_AUDIENCE = "mineguard-media"


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return password_hash.verify(password, hashed_password)


def create_access_token(subject: str, role: str, auth_version: int = 0) -> str:
    settings = get_settings()
    issued_at = datetime.now(UTC)
    expires = issued_at + timedelta(minutes=settings.access_token_minutes)
    return jwt.encode(
        {
            "sub": subject,
            "role": role,
            "ver": auth_version,
            "iss": settings.token_issuer,
            "jti": secrets.token_hex(16),
            "exp": expires,
            "iat": issued_at,
        },
        settings.secret_key,
        algorithm="HS256",
    )


def decode_access_token(token: str) -> dict:
    try:
        settings = get_settings()
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"],
            issuer=settings.token_issuer,
            options={"require": ["sub", "role", "ver", "iss", "jti", "exp", "iat"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def create_media_token(subject: str, auth_version: int) -> str:
    settings = get_settings()
    issued_at = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": subject,
            "ver": auth_version,
            "iss": settings.token_issuer,
            "aud": MEDIA_TOKEN_AUDIENCE,
            "type": "media",
            "jti": secrets.token_hex(16),
            "iat": issued_at,
            "exp": issued_at + timedelta(minutes=settings.access_token_minutes),
        },
        settings.secret_key,
        algorithm="HS256",
    )


def decode_media_token(token: str) -> dict:
    try:
        settings = get_settings()
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"],
            issuer=settings.token_issuer,
            audience=MEDIA_TOKEN_AUDIENCE,
            options={
                "require": ["sub", "ver", "iss", "aud", "type", "jti", "exp", "iat"]
            },
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired media session",
        ) from exc


def create_refresh_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(48)
    return token, hash_refresh_token(token)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_service_key(prefix: str = "mg_edge") -> tuple[str, str]:
    token = f"{prefix}_{secrets.token_urlsafe(40)}"
    return token, hashlib.sha256(token.encode()).hexdigest()


def hash_service_key(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
