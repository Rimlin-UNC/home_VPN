# ============================================================
# StealthNode — общие зависимости FastAPI (аутентификация, IP клиента).
# ============================================================
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .database import get_db
from .models import AdminUser
from .security import decode_access_token

_bearer = HTTPBearer(auto_error=False)


def get_current_admin(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> AdminUser:
    """Проверка access-JWT; при отсутствии/протухании — 401 (клиент обновит токен)."""
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Требуется авторизация")
    payload = decode_access_token(creds.credentials)
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Недействительный или истёкший токен")
    admin = db.get(AdminUser, int(payload["sub"]))
    if admin is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Пользователь не найден")
    return admin


def client_ip(request: Request) -> str:
    """IP клиента (за Caddy-прокси берём X-Forwarded-For)."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
