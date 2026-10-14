# ============================================================
# StealthNode — настройки VPN, бэкап/восстановление, аудит-лог,
# смена пароля администратора.
# ============================================================
import io
import re
import zipfile
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..config import settings as cfg
from ..database import get_db
from ..deps import client_ip, get_current_admin
from ..models import AdminUser, AuditLog, RefreshToken
from ..security import hash_password, verify_password
from ..services import docker_client, xray_manager
from ..services.audit import audit

router = APIRouter(prefix="/api", tags=["settings"])

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,63}$")


@router.get("/settings/links")
def owner_links(admin: AdminUser = Depends(get_current_admin),
                db: Session = Depends(get_db)):
    """Все ссылки владельца: три транспорта Xray + резервный Hysteria2."""
    from ..models import Device

    owner = db.query(Device).filter(Device.is_admin_device.is_(True)).first()
    links: dict[str, str] = {}
    if owner:
        links = xray_manager.share_links(owner.name, owner.public_key)
    links["hy2"] = xray_manager.hy2_link()
    return links


@router.get("/settings/reality")
def get_reality_settings(admin: AdminUser = Depends(get_current_admin)):
    return {
        "sni": xray_manager.current_sni(),
        "public_key": xray_manager.reality_public_key(),
        "warning": "После смены домена обновите настройки на ВСЕХ Xray-клиентах!",
    }


class RealityIn(BaseModel):
    sni: str = Field(min_length=4, max_length=253)


@router.put("/settings/reality")
def put_reality_settings(data: RealityIn, request: Request,
                         admin: AdminUser = Depends(get_current_admin),
                         db: Session = Depends(get_db)):
    sni = data.sni.strip().lower()
    if not DOMAIN_RE.match(sni):
        raise HTTPException(400, "Некорректное доменное имя")
    if sni in ("google.com", "microsoft.com", "www.google.com", "www.microsoft.com"):
        raise HTTPException(400, "google.com и microsoft.com использовать нельзя — "
                                 "цензоры мониторят их (см. ТЗ)")
    xray_manager.set_sni(sni)
    ok, msg = docker_client.action(cfg.xray_container, "restart")
    audit(db, "settings.reality", f"SNI -> {sni}", client_ip(request))
    db.commit()
    if not ok:
        raise HTTPException(502, f"Конфиг обновлён, но перезапуск не удался: {msg}")
    return {"ok": True, "message": f"Домен маскировки изменён на {sni}. Обновите Xray-клиентов!"}


# ---------------- Бэкап / восстановление ----------------

_BACKUP_FILES = [
    "/etc/xray/config.json",
]


@router.get("/settings/backup")
def backup(admin: AdminUser = Depends(get_current_admin)):
    """ZIP-архив: конфиг Xray, база панели, bot.env."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in _BACKUP_FILES:
            try:
                with open(path, "rb") as fh:
                    zf.writestr(path.lstrip("/"), fh.read())
            except FileNotFoundError:
                pass
        # База данных панели
        db_path = cfg.data_dir / "stealthnode.db"
        if db_path.is_file():
            zf.writestr("data/stealthnode.db", db_path.read_bytes())
        # Настройки бота
        if cfg.bot_env_path.is_file():
            zf.writestr("bot/bot.env", cfg.bot_env_path.read_bytes())
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="stealthnode-backup-{stamp}.zip"'},
    )


@router.post("/settings/restore")
async def restore(file: UploadFile, request: Request,
                  admin: AdminUser = Depends(get_current_admin),
                  db: Session = Depends(get_db)):
    """
    Восстановление из ZIP-бэкапа: конфиги + БД + bot.env.
    После восстановления управляемые контейнеры перезапускаются.
    """
    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(400, "Архив слишком большой (>50 МБ)")
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        raise HTTPException(400, "Файл не является ZIP-архивом")
    names = set(zf.namelist())
    if "etc/xray/config.json" not in names:
        raise HTTPException(400, "В архиве нет config.json — это не бэкап StealthNode")

    restored: list[str] = []
    mapping = {
        "etc/xray/config.json": cfg.xray_conf_path,
        "data/stealthnode.db": cfg.data_dir / "stealthnode.db",
        "bot/bot.env": cfg.bot_env_path,
    }
    for arcname, dest in mapping.items():
        if arcname in names:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(zf.read(arcname))
            restored.append(arcname)

    # Перезапуск ядра, чтобы подхватить восстановленную конфигурацию
    docker_client.action(cfg.xray_container, "restart")

    audit(db, "settings.restore", f"Восстановлено файлов: {len(restored)}", client_ip(request))
    db.commit()
    return {"ok": True, "restored": restored,
            "message": "Восстановление выполнено. Перезайдите в панель (база заменена)."}


# ---------------- Аудит-лог ----------------

@router.get("/audit")
def audit_log(limit: int = 100, admin: AdminUser = Depends(get_current_admin),
              db: Session = Depends(get_db)):
    limit = max(1, min(limit, 1000))
    rows = (db.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all())
    return [
        {"id": r.id, "ts": r.ts.isoformat() if r.ts else None,
         "action": r.action, "detail": r.detail, "ip": r.ip}
        for r in rows
    ]


# ---------------- Смена пароля ----------------

class PasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=16, max_length=128)


@router.post("/settings/password")
def change_password(data: PasswordIn, request: Request,
                    admin: AdminUser = Depends(get_current_admin),
                    db: Session = Depends(get_db)):
    if not verify_password(data.current_password, admin.password_hash):
        raise HTTPException(400, "Текущий пароль неверен")
    admin.password_hash = hash_password(data.new_password)
    # Отзываем все refresh-токены: сессии должны перезайти
    db.query(RefreshToken).filter(RefreshToken.admin_id == admin.id).update({"revoked": True})
    audit(db, "settings.password", "Пароль администратора изменён", client_ip(request))
    db.commit()
    return {"ok": True, "message": "Пароль изменён. Войдите заново."}
