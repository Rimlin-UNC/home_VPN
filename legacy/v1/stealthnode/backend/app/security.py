# ============================================================
# StealthNode — криптография и токены.
# * Пароль: Argon2id (по ТЗ).
# * Access JWT: 30 минут (автовыход по ТЗ).
# * Refresh: ротируемый, в БД хранится только SHA-256 хеш;
#   повторное использование отозванного токена => отзыв всех сессий
#   (защита от кражи refresh-токена).
# ============================================================
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from .config import settings

ALGORITHM = "HS256"
_ph = PasswordHasher()  # параметры Argon2id по умолчанию (RFC 9106 low-mem: 64MB/3/4)


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(admin_id: int, username: str) -> str:
    """Короткоживущий access-токен (30 минут — автовыход по ТЗ)."""
    payload = {
        "sub": str(admin_id),
        "username": username,
        "type": "access",
        "jti": secrets.token_hex(8),
        "iat": _now(),
        "exp": _now() + timedelta(minutes=settings.access_ttl_min),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def create_refresh_token() -> tuple[str, str, datetime]:
    """Возвращает (токен, sha256-хеш, срок годности). В БД пишем только хеш."""
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires = (_now() + timedelta(days=settings.refresh_ttl_days)).replace(tzinfo=None)
    return token, token_hash, expires


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def decode_access_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            return None
        return payload
    except jwt.PyJWTError:
        return None
