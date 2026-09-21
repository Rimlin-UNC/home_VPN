# ============================================================
# StealthNode — API управления торговым ботом OKX.
# Старт/стоп/рестарт, статус + PnL, логи, редактирование bot.env.
# ============================================================
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import client_ip, get_current_admin
from ..models import AdminUser
from ..services import bot_manager
from ..services.audit import audit

router = APIRouter(prefix="/api/bot", tags=["bot"])


@router.get("/status")
def bot_status(admin: AdminUser = Depends(get_current_admin)):
    """Статус бота: контейнер (uptime, CPU/RAM) + торговые метрики из status.json."""
    return bot_manager.full_status()


@router.get("/logs")
def bot_logs(tail: int = 100, admin: AdminUser = Depends(get_current_admin)):
    """Последние N строк логов бота (по ТЗ — 100 строк)."""
    tail = max(1, min(tail, 1000))
    return {"logs": bot_manager.logs(tail)}


@router.post("/{action}")
def bot_action(action: str, request: Request,
               admin: AdminUser = Depends(get_current_admin),
               db: Session = Depends(get_db)):
    if action not in ("start", "stop", "restart"):
        raise HTTPException(400, "Действие: start|stop|restart")
    ok, msg = bot_manager.restart() if action == "restart" else (
        bot_manager.start() if action == "start" else bot_manager.stop()
    )
    audit(db, f"bot.{action}", msg, client_ip(request))
    db.commit()
    if not ok:
        raise HTTPException(502, msg)
    return {"ok": True, "message": msg}


@router.get("/env")
def get_env(admin: AdminUser = Depends(get_current_admin)):
    """Настройки бота (API-ключи замаскированы — не светим секреты)."""
    return bot_manager.read_env(mask_secrets=True)


class EnvUpdate(BaseModel):
    values: dict[str, str]
    restart: bool = True


@router.put("/env")
def put_env(data: EnvUpdate, request: Request,
            admin: AdminUser = Depends(get_current_admin),
            db: Session = Depends(get_db)):
    bot_manager.write_env(data.values)
    msg = "Настройки сохранены"
    if data.restart:
        ok, msg = bot_manager.restart()
        if not ok:
            raise HTTPException(502, f"Сохранено, но перезапуск не удался: {msg}")
        msg = "Настройки сохранены, бот перезапущен"
    audit(db, "bot.env_update", "Изменены ключи: " + ", ".join(sorted(k for k in data.values)),
          client_ip(request))
    db.commit()
    return {"ok": True, "message": msg}
