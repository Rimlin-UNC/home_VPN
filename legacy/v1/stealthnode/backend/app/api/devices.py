# ============================================================
# StealthNode — управление VPN-устройствами.
# Устройство = пользователь Xray (один UUID/email сразу в трёх
# транспортах: TCP/Vision :443, gRPC и XHTTP). Выдаём 3 ссылки.
# ============================================================
import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import client_ip, get_current_admin
from ..models import AdminUser, Device
from ..services import xray_manager
from ..services.audit import audit
from ..utils.qr import qr_png

router = APIRouter(prefix="/api/devices", tags=["devices"])

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class DeviceIn(BaseModel):
    name: str = Field(min_length=1, max_length=32)


def _device_out(d: Device) -> dict:
    return {
        "id": d.id, "name": d.name, "kind": d.kind,
        "public_key": d.public_key, "enabled": d.enabled,
        "is_admin_device": d.is_admin_device,
        "created_at": d.created_at.isoformat() if d.created_at else None,
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

    new_uuid = xray_manager.add_client(email=data.name)
    dev = Device(name=data.name, kind="xray", public_key=new_uuid, enabled=True)
    db.add(dev)
    audit(db, "device.create", f"VLESS-клиент {data.name}", ip)
    db.commit()
    db.refresh(dev)
    return _device_out(dev)


def _get_device(db: Session, device_id: int) -> Device:
    dev = db.get(Device, device_id)
    if dev is None:
        raise HTTPException(404, "Устройство не найдено")
    return dev


@router.get("/{device_id}/config")
def device_config(device_id: int, admin: AdminUser = Depends(get_current_admin),
                  db: Session = Depends(get_db)):
    """Три ссылки устройства (TCP/gRPC/XHTTP) + общий контейнер текста."""
    dev = _get_device(db, device_id)
    links = xray_manager.share_links(dev.name, dev.public_key)
    text = "\n".join(links.values())
    return {"name": dev.name, "links": links, "config": text}


@router.get("/{device_id}/qr")
def device_qr(device_id: int, transport: str = "tcp",
              admin: AdminUser = Depends(get_current_admin),
              db: Session = Depends(get_db)):
    """QR-код (PNG) для сканирования в клиенте (по умолчанию — основной TCP)."""
    dev = _get_device(db, device_id)
    links = xray_manager.share_links(dev.name, dev.public_key)
    link = links.get(transport) or links["tcp"]
    return Response(content=qr_png(link), media_type="image/png")


@router.post("/{device_id}/enable")
def enable_device(device_id: int, request: Request,
                  admin: AdminUser = Depends(get_current_admin),
                  db: Session = Depends(get_db)):
    dev = _get_device(db, device_id)
    xray_manager.add_client(email=dev.name, client_uuid=dev.public_key)
    if dev.guest:
        dev.guest.status = "active"
        dev.guest.status_detail = ""
    dev.enabled = True
    audit(db, "device.enable", dev.name, client_ip(request))
    db.commit()
    return {"ok": True}


@router.post("/{device_id}/disable")
def disable_device(device_id: int, request: Request,
                   admin: AdminUser = Depends(get_current_admin),
                   db: Session = Depends(get_db)):
    """Мгновенный разрыв: клиент удаляется из всех транспортов."""
    dev = _get_device(db, device_id)
    xray_manager.remove_client(dev.public_key)
    if dev.guest:
        dev.guest.status = "disabled_admin"
        dev.guest.status_detail = "Отключён администратором"
    dev.enabled = False
    audit(db, "device.disable", dev.name, client_ip(request))
    db.commit()
    return {"ok": True}


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device(device_id: int, request: Request,
                  admin: AdminUser = Depends(get_current_admin),
                  db: Session = Depends(get_db)):
    dev = _get_device(db, device_id)
    xray_manager.remove_client(dev.public_key)
    name = dev.name
    db.delete(dev)  # гость и снапшоты удаляются каскадно
    audit(db, "device.delete", name, client_ip(request))
    db.commit()
