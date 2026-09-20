# ============================================================
# StealthNode — управление VPN-устройствами.
# AWG-пиры и Xray-клиенты: создание, конфиг + QR, вкл/выкл, удаление.
# ============================================================
import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import client_ip, get_current_admin
from ..models import AdminUser, Device
from ..services import wg_manager, xray_manager
from ..services.audit import audit
from ..utils.qr import qr_png

router = APIRouter(prefix="/api/devices", tags=["devices"])

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class DeviceIn(BaseModel):
    name: str = Field(min_length=1, max_length=32)
    kind: str = Field(default="awg", pattern="^(awg|xray)$")


def _persist_awg_peers(db: Session) -> None:
    """Перезапись awg0.conf из БД (все включённые AWG-устройства)."""
    enabled = [
        {"name": d.name, "public_key": d.public_key, "psk": d.psk, "tunnel_ip": d.tunnel_ip}
        for d in db.query(Device).filter(Device.kind == "awg", Device.enabled.is_(True)).all()
    ]
    wg_manager.rewrite_conf(enabled)


def _device_out(d: Device) -> dict:
    return {
        "id": d.id, "name": d.name, "kind": d.kind, "tunnel_ip": d.tunnel_ip,
        "public_key": d.public_key, "enabled": d.enabled,
        "is_admin_device": d.is_admin_device,
        "created_at": d.created_at.isoformat() if d.created_at else None,
        "last_handshake": d.last_handshake.isoformat() if d.last_handshake else None,
        "guest_id": d.guest.id if d.guest else None,
    }


@router.get("")
def list_devices(admin: AdminUser = Depends(get_current_admin),
                 db: Session = Depends(get_db)):
    return [_device_out(d) for d in db.query(Device).order_by(Device.id).all()]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_device(data: DeviceIn, request: Request,
                  admin: AdminUser = Depends(get_current_admin),
                  db: Session = Depends(get_db)):
    ip = client_ip(request)
    if not NAME_RE.match(data.name):
        raise HTTPException(400, "Имя: только латиница, цифры, дефис, подчёркивание (до 32)")
    if db.query(Device).filter(Device.name == data.name).first():
        raise HTTPException(409, "Устройство с таким именем уже существует")

    if data.kind == "awg":
        priv, pub = wg_manager.generate_keypair()
        psk = wg_manager.generate_psk()
        used = {d.tunnel_ip for d in db.query(Device).all() if d.tunnel_ip}
        tunnel_ip = wg_manager.free_tunnel_ip(used)
        ok, msg = wg_manager.add_peer(pub, psk, tunnel_ip)
        if not ok:
            raise HTTPException(502, f"Не удалось добавить пира: {msg}")
        dev = Device(name=data.name, kind="awg", tunnel_ip=tunnel_ip,
                     public_key=pub, private_key=priv, psk=psk, enabled=True)
        db.add(dev)
        db.flush()
        _persist_awg_peers(db)
        audit(db, "device.create", f"AWG-устройство {data.name} ({tunnel_ip})", ip)
    else:
        new_uuid = xray_manager.add_client(email=data.name)
        dev = Device(name=data.name, kind="xray", tunnel_ip=None,
                     public_key=new_uuid, private_key="", psk="", enabled=True)
        db.add(dev)
        db.flush()
        audit(db, "device.create", f"Xray-клиент {data.name}", ip)

    db.commit()
    db.refresh(dev)
    return _device_out(dev)


def _get_device(db: Session, device_id: int) -> Device:
    dev = db.get(Device, device_id)
    if dev is None:
        raise HTTPException(404, "Устройство не найдено")
    return dev


def _config_text(dev: Device) -> str:
    if dev.kind == "awg":
        if not dev.private_key or not dev.psk or not dev.tunnel_ip:
            raise HTTPException(409, "Для устройства нет полного набора ключей (импортировано?)")
        return wg_manager.build_client_config(dev.name, dev.private_key, dev.psk, dev.tunnel_ip)
    return xray_manager.share_link(dev.name, dev.public_key)


@router.get("/{device_id}/config")
def device_config(device_id: int, admin: AdminUser = Depends(get_current_admin),
                  db: Session = Depends(get_db)):
    """Скачивание клиентского конфига (.conf для AWG / ссылка для Xray)."""
    dev = _get_device(db, device_id)
    return {"name": dev.name, "config": _config_text(dev)}


@router.get("/{device_id}/qr")
def device_qr(device_id: int, admin: AdminUser = Depends(get_current_admin),
              db: Session = Depends(get_db)):
    """QR-код (PNG) для сканирования в AmneziaVPN / v2rayNG."""
    dev = _get_device(db, device_id)
    return Response(content=qr_png(_config_text(dev)), media_type="image/png")


@router.post("/{device_id}/enable")
def enable_device(device_id: int, request: Request,
                  admin: AdminUser = Depends(get_current_admin),
                  db: Session = Depends(get_db)):
    dev = _get_device(db, device_id)
    if dev.kind == "awg":
        ok, msg = wg_manager.add_peer(dev.public_key, dev.psk, dev.tunnel_ip)
        if not ok:
            raise HTTPException(502, f"Не удалось включить пира: {msg}")
        if dev.guest:
            dev.guest.status = "active"
            dev.guest.status_detail = ""
    else:
        # Xray: возвращаем клиента с тем же UUID в конфиг
        xray_manager.add_client(email=dev.name, client_uuid=dev.public_key)
    dev.enabled = True
    _persist_awg_peers(db)
    audit(db, "device.enable", dev.name, client_ip(request))
    db.commit()
    return {"ok": True}


@router.post("/{device_id}/disable")
def disable_device(device_id: int, request: Request,
                   admin: AdminUser = Depends(get_current_admin),
                   db: Session = Depends(get_db)):
    """Мгновенный разрыв соединения (awg set ... remove) — по ТЗ."""
    dev = _get_device(db, device_id)
    if dev.kind == "awg":
        ok, msg = wg_manager.remove_peer(dev.public_key)
        if not ok:
            raise HTTPException(502, f"Не удалось отключить пира: {msg}")
        if dev.guest:
            dev.guest.status = "disabled_admin"
            dev.guest.status_detail = "Отключён администратором"
    else:
        # Xray: удаляем клиента из конфига (UUID сохраняется в БД для включения)
        xray_manager.remove_client(dev.public_key)
    dev.enabled = False
    _persist_awg_peers(db)
    audit(db, "device.disable", dev.name, client_ip(request))
    db.commit()
    return {"ok": True}


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device(device_id: int, request: Request,
                  admin: AdminUser = Depends(get_current_admin),
                  db: Session = Depends(get_db)):
    dev = _get_device(db, device_id)
    if dev.kind == "awg" and dev.enabled:
        wg_manager.remove_peer(dev.public_key)
    elif dev.kind == "xray":
        xray_manager.remove_client(dev.public_key)
    name = dev.name
    db.delete(dev)  # гость и снапшоты удаляются каскадно
    _persist_awg_peers(db)
    audit(db, "device.delete", name, client_ip(request))
    db.commit()
