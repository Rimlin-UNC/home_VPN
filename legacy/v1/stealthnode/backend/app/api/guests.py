# ============================================================
# StealthNode — гостевые аккаунты (до 5, по ТЗ).
# Лимиты трафика, временное окно, срок действия, приоритет-метка.
# Ограничено VLESS-клиенты (там есть per-user статистика для квот).
# ============================================================
import csv
import io
import re
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import client_ip, get_current_admin
from ..models import AdminUser, Device, Guest, TrafficSnapshot
from ..services import quota_manager, xray_manager
from ..services.audit import audit

router = APIRouter(prefix="/api/guests", tags=["guests"])

MAX_GUESTS = 5  # по ТЗ
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class GuestIn(BaseModel):
    name: str = Field(min_length=1, max_length=32)
    quota_daily_mb: int | None = Field(default=None, ge=1)
    quota_weekly_mb: int | None = Field(default=None, ge=1)
    quota_monthly_mb: int | None = Field(default=None, ge=1)
    quota_total_mb: int | None = Field(default=None, ge=1)
    window_start: str | None = None  # "HH:MM"
    window_end: str | None = None
    expires_at: datetime | None = None
    priority: str = Field(default="normal", pattern="^(low|normal|high)$")


def _validate(g: GuestIn) -> None:
    if not NAME_RE.match(g.name):
        raise HTTPException(400, "Имя: только латиница, цифры, дефис, подчёркивание (до 32)")
    for t in (g.window_start, g.window_end):
        if t is not None and not TIME_RE.match(t):
            raise HTTPException(400, "Время окна в формате HH:MM")
    if (g.window_start is None) != (g.window_end is None):
        raise HTTPException(400, "Укажите обе границы окна доступа или ни одной")


def _guest_out(g: Guest) -> dict:
    d = g.device
    return {
        "id": g.id, "name": d.name, "enabled": d.enabled, "device_id": d.id,
        "quota_daily_mb": g.quota_daily_mb, "quota_weekly_mb": g.quota_weekly_mb,
        "quota_monthly_mb": g.quota_monthly_mb, "quota_total_mb": g.quota_total_mb,
        "window_start": g.window_start, "window_end": g.window_end,
        "expires_at": g.expires_at.isoformat() if g.expires_at else None,
        "priority": g.priority, "status": g.status, "status_detail": g.status_detail,
    }


@router.get("")
def list_guests(admin: AdminUser = Depends(get_current_admin),
                db: Session = Depends(get_db)):
    return [_guest_out(g) for g in db.query(Guest).order_by(Guest.id).all()]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_guest(data: GuestIn, request: Request,
                 admin: AdminUser = Depends(get_current_admin),
                 db: Session = Depends(get_db)):
    ip = client_ip(request)
    _validate(data)
    if db.query(Guest).count() >= MAX_GUESTS:
        raise HTTPException(400, f"Достигнут максимум гостей ({MAX_GUESTS})")
    if db.query(Device).filter(Device.name == data.name).first():
        raise HTTPException(409, "Имя уже занято")

    # Гость — VLESS-клиент (сразу во всех транспортах) + запись лимитов
    new_uuid = xray_manager.add_client(email=data.name)
    dev = Device(name=data.name, kind="xray", public_key=new_uuid, enabled=True)
    db.add(dev)
    db.flush()
    guest = Guest(
        device_id=dev.id,
        quota_daily_mb=data.quota_daily_mb, quota_weekly_mb=data.quota_weekly_mb,
        quota_monthly_mb=data.quota_monthly_mb, quota_total_mb=data.quota_total_mb,
        window_start=data.window_start, window_end=data.window_end,
        expires_at=data.expires_at, priority=data.priority,
    )
    db.add(guest)
    db.flush()

    # Сразу применяем автоматику (окно/срок могли быть заданы в прошлое)
    quota_manager.check_guest(guest, db, datetime.utcnow())
    audit(db, "guest.create", data.name, ip)
    db.commit()
    db.refresh(guest)
    return _guest_out(guest)


@router.patch("/{guest_id}")
def update_guest(guest_id: int, data: GuestIn, request: Request,
                 admin: AdminUser = Depends(get_current_admin),
                 db: Session = Depends(get_db)):
    ip = client_ip(request)
    _validate(data)
    guest = db.get(Guest, guest_id)
    if guest is None:
        raise HTTPException(404, "Гость не найден")
    for field_ in ("quota_daily_mb", "quota_weekly_mb", "quota_monthly_mb",
                   "quota_total_mb", "window_start", "window_end",
                   "expires_at", "priority"):
        setattr(guest, field_, getattr(data, field_))
    quota_manager.check_guest(guest, db, datetime.utcnow())
    audit(db, "guest.update", guest.device.name, ip)
    db.commit()
    return _guest_out(guest)


@router.delete("/{guest_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_guest(guest_id: int, request: Request,
                 admin: AdminUser = Depends(get_current_admin),
                 db: Session = Depends(get_db)):
    guest = db.get(Guest, guest_id)
    if guest is None:
        raise HTTPException(404, "Гость не найден")
    dev = guest.device
    xray_manager.remove_client(dev.public_key)
    name = dev.name
    db.delete(dev)  # каскадно удалит гостя и снапшоты
    audit(db, "guest.delete", name, client_ip(request))
    db.commit()


@router.get("/{guest_id}/export.csv")
def export_guest_csv(guest_id: int,
                     admin: AdminUser = Depends(get_current_admin),
                     db: Session = Depends(get_db)):
    """Экспорт журнала трафика гостя в CSV (по ТЗ)."""
    guest = db.get(Guest, guest_id)
    if guest is None:
        raise HTTPException(404, "Гость не найден")
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp_utc", "cum_upload_bytes", "cum_download_bytes"])
    for s in (db.query(TrafficSnapshot)
              .filter(TrafficSnapshot.device_id == guest.device_id)
              .order_by(TrafficSnapshot.ts).all()):
        writer.writerow([s.ts.isoformat(), s.cum_rx, s.cum_tx])
    name = guest.device.name
    return Response(
        content=buf.getvalue().encode("utf-8-sig"),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="guest_{name}_traffic.csv"'},
    )
