# ============================================================
# StealthNode — статистика для дашборда:
# нагрузка сервера, статусы сервисов, онлайн-пиры, суммы трафика.
# ============================================================
from datetime import datetime, timedelta

import psutil
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import get_current_admin
from ..models import AdminUser, Device
from ..services import docker_client, xray_manager
from ..services.traffic_monitor import monitor, traffic_in_window

router = APIRouter(prefix="/api/stats", tags=["stats"])

_BOOT_TIME = datetime.fromtimestamp(psutil.boot_time())


def _system_load() -> dict:
    """CPU / RAM / диск / аптайм / сетевая нагрузка хоста."""
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    return {
        "cpu_pct": cpu,
        "mem_pct": mem.percent, "mem_used_mb": round(mem.used / 2**20), "mem_total_mb": round(mem.total / 2**20),
        "disk_pct": disk.percent, "disk_used_gb": round(disk.used / 2**30, 1), "disk_total_gb": round(disk.total / 2**30, 1),
        "uptime_hours": round((datetime.now() - _BOOT_TIME).total_seconds() / 3600, 1),
        "net_rx_bytes": net.bytes_recv, "net_tx_bytes": net.bytes_sent,
    }


@router.get("/overview")
def overview(admin: AdminUser = Depends(get_current_admin)):
    return _system_load()


@router.get("/services")
def services(admin: AdminUser = Depends(get_current_admin)):
    """Статусы всех контейнеров стека (включая торгового бота)."""
    return [docker_client.container_status(name) for name in settings.container_list()]


@router.get("/peers")
def peers(admin: AdminUser = Depends(get_current_admin),
          db: Session = Depends(get_db)):
    """Пользователи VPN: накопленный трафик и признак активности."""
    devices = {d.name: d for d in db.query(Device).all()}
    cum = monitor.cumulative(xray_manager.user_traffic())
    out = []
    for email, counters in cum.items():
        dev = devices.get(email)
        out.append({
            "device_id": dev.id if dev else None,
            "name": email,
            "online": monitor.is_online(email),
            "cum_rx": counters["rx"], "cum_tx": counters["tx"],
        })
    return out


@router.get("/traffic")
def traffic(period: str = "day", admin: AdminUser = Depends(get_current_admin),
            db: Session = Depends(get_db)):
    """Суммарный трафик по устройствам за период: day|week|month|all."""
    now = datetime.utcnow()
    since_map = {
        "day": now - timedelta(days=1),
        "week": now - timedelta(days=7),
        "month": now - timedelta(days=30),
        "all": datetime(2000, 1, 1),
    }
    since = since_map.get(period, since_map["day"])
    rows, tot_rx, tot_tx = [], 0, 0
    for dev in db.query(Device).all():
        rx, tx = traffic_in_window(dev.id, since, db)
        rows.append({"device_id": dev.id, "name": dev.name, "rx": rx, "tx": tx, "total": rx + tx})
        tot_rx, tot_tx = tot_rx + rx, tot_tx + tx
    return {"period": period, "since": since.isoformat(), "devices": rows,
            "total_rx": tot_rx, "total_tx": tot_tx, "total": tot_rx + tot_tx}
