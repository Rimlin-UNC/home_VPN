# ============================================================
# StealthNode — аутентификация в панели.
# * Argon2id-хеш пароля (см. security.py);
# * JWT access (30 мин) + refresh с ротацией;
# * rate-limit: 5 неудачных попыток -> бан IP на 24 часа (по ТЗ),
#   записи хранятся в БД (работает и после перезапуска);
# * дополнительный in-memory лимит: 5 попыток в минуту с одного IP.
# ============================================================
import time
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import client_ip, get_current_admin
from ..models import AdminUser, LoginBan, RefreshToken
from ..security import (
    create_access_token, create_refresh_token, hash_refresh_token, verify_password,
)
from ..services.audit import audit

router = APIRouter(prefix="/api/auth", tags=["auth"])

# In-memory rate limit: {ip: [метки времени попыток]} — 5 попыток/минуту
_attempts: dict[str, list[float]] = {}


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int


class RefreshIn(BaseModel):
    refresh_token: str


def _check_rate(ip: str) -> None:
    """In-memory лимит 5 попыток в минуту (по ТЗ)."""
    now = time.monotonic()
    lst = [t for t in _attempts.get(ip, []) if now - t < 60]
    if len(lst) >= 5:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "Слишком много попыток. Повторите через минуту.")
    lst.append(now)
    _attempts[ip] = lst


def _check_ban(db: Session, ip: str) -> None:
    row = db.query(LoginBan).filter(LoginBan.ip == ip).first()
    if row and row.banned_until and row.banned_until > datetime.utcnow():
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "IP заблокирован на 24 часа из-за неудачных попыток входа")


def _register_fail(db: Session, ip: str) -> None:
    row = db.query(LoginBan).filter(LoginBan.ip == ip).first()
    if row is None:
        row = LoginBan(ip=ip, fails=0)
        db.add(row)
    row.fails = (row.fails or 0) + 1
    if row.fails >= 5:  # порог бана — по ТЗ (Fail2ban-аналог)
        row.banned_until = datetime.utcnow() + timedelta(hours=24)
    db.commit()


def _clear_fails(db: Session, ip: str) -> None:
    row = db.query(LoginBan).filter(LoginBan.ip == ip).first()
    if row:
        row.fails = 0
        row.banned_until = None
        db.commit()


def _issue_pair(db: Session, admin: AdminUser) -> TokenPair:
    token, token_hash, expires = create_refresh_token()
    db.add(RefreshToken(admin_id=admin.id, token_hash=token_hash, expires_at=expires))
    db.commit()
    from ..config import settings
    return TokenPair(
        access_token=create_access_token(admin.id, admin.username),
        refresh_token=token,
        expires_in=settings.access_ttl_min * 60,
    )


@router.post("/login", response_model=TokenPair)
def login(data: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    _check_ban(db, ip)
    _check_rate(ip)

    admin = db.query(AdminUser).filter(AdminUser.username == data.username).first()
    if admin is None or not verify_password(data.password, admin.password_hash):
        _register_fail(db, ip)
        audit(db, "auth.fail", f"Неудачный вход ({data.username})", ip)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Неверный логин или пароль")

    _clear_fails(db, ip)
    audit(db, "auth.login", "Вход в панель", ip)
    return _issue_pair(db, admin)


@router.post("/refresh", response_model=TokenPair)
def refresh(data: RefreshIn, request: Request, db: Session = Depends(get_db)):
    """Ротация refresh-токена: старый гасится, выдаётся новая пара."""
    ip = client_ip(request)
    token_hash = hash_refresh_token(data.refresh_token)
    row = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()

    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Недействительный токен")

    if row.revoked or row.expires_at < datetime.utcnow():
        # Повторное использование отозванного токена — возможна кража:
        # отзываем ВСЕ сессии администратора (защитная мера)
        if row.revoked:
            db.query(RefreshToken).filter(RefreshToken.admin_id == row.admin_id).update(
                {"revoked": True}
            )
            audit(db, "auth.token_reuse", "Обнаружено повторное использование refresh-токена", ip)
            db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Токен истёк или отозван")

    row.revoked = True
    admin = db.get(AdminUser, row.admin_id)
    return _issue_pair(db, admin)


@router.post("/logout")
def logout(data: RefreshIn, request: Request,
           admin: AdminUser = Depends(get_current_admin),
           db: Session = Depends(get_db)):
    token_hash = hash_refresh_token(data.refresh_token)
    db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash, RefreshToken.admin_id == admin.id
    ).update({"revoked": True})
    audit(db, "auth.logout", "Выход из панели", client_ip(request))
    db.commit()
    return {"ok": True}
