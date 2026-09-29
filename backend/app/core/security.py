from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from pwdlib import PasswordHash

from backend.app.core.config import get_settings

password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, encoded_hash: str) -> bool:
    return password_hash.verify(password, encoded_hash)


def create_access_token(subject: str, role: str) -> str:
    settings = get_settings()
    if (
        settings.jwt_secret is None
        or len(settings.jwt_secret.get_secret_value()) < 32
        or "replace-with" in settings.jwt_secret.get_secret_value().lower()
    ):
        raise RuntimeError("JWT_SECRET must contain at least 32 characters")
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret.get_secret_value(), algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    if (
        settings.jwt_secret is None
        or len(settings.jwt_secret.get_secret_value()) < 32
        or "replace-with" in settings.jwt_secret.get_secret_value().lower()
    ):
        raise RuntimeError("JWT_SECRET must contain at least 32 characters")
    return jwt.decode(token, settings.jwt_secret.get_secret_value(), algorithms=["HS256"])
