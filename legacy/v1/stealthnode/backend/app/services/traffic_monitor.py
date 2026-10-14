# ============================================================
# StealthNode — монитор трафика пользователей Xray.
# Встроенная статистика Xray обнуляется при перезапуске контейнера,
# поэтому ведём офсеты и склеиваем непрерывный кумулятивный ряд.
# Фоновая задача раз в 60 секунд пишет снапшоты в БД
# (из них считаются суммы за день/неделю/месяц и квоты гостей).
# Также трекаем «последнюю активность» — признак online для панели.
# ============================================================
import asyncio
import json
import logging
import time
from datetime import datetime, timedelta

from ..database import SessionLocal
from ..models import Device, Setting, TrafficSnapshot
from . import xray_manager

log = logging.getLogger("stealthnode.traffic")

_KEY_OFFSETS = "traffic_offsets"   # Setting: {email: {"rx": int, "tx": int}}
_KEY_LAST = "traffic_last_seen"    # Setting: {email: {"rx": int, "tx": int}} сырые значения


class TrafficMonitor:
    def __init__(self) -> None:
        self.offsets: dict[str, dict[str, int]] = {}
        self.last_raw: dict[str, dict[str, int]] = {}
        self.last_change: dict[str, float] = {}   # email -> время последнего роста трафика
        self._loaded = False

    # ---------- загрузка/сохранение состояния в БД ----------
    def _load(self) -> None:
        if self._loaded:
            return
        db = SessionLocal()
        try:
            for key, target in ((_KEY_OFFSETS, self.offsets), (_KEY_LAST, self.last_raw)):
                row = db.get(Setting, key)
                if row and row.value:
                    target.update(json.loads(row.value))
        finally:
            db.close()
        self._loaded = True

    def _save(self) -> None:
        db = SessionLocal()
        try:
            for key, source in ((_KEY_OFFSETS, self.offsets), (_KEY_LAST, self.last_raw)):
                row = db.get(Setting, key) or Setting(key=key, value="")
                row.value = json.dumps(source)
                db.merge(row)
            db.commit()
        finally:
            db.close()

    # ---------- основной расчёт ----------
    def cumulative(self, raw: dict[str, dict[str, int]] | None = None) -> dict[str, dict[str, int]]:
        """
        Кумулятивные счётчики: {email: {"rx": .., "tx": ..}}.
        rx = uplink (загрузка КЛИЕНТА), tx = downlink (скачивание клиента).
        Обнаруживает обнуление Xray: переносит прежний хвост в офсет.
        """
        self._load()
        if raw is None:
            raw = xray_manager.user_traffic()
        result: dict[str, dict[str, int]] = {}
        for email, counters in raw.items():
            raw_rx = counters.get("uplink", 0)
            raw_tx = counters.get("downlink", 0)
            last = self.last_raw.get(email, {"rx": 0, "tx": 0})
            off = self.offsets.setdefault(email, {"rx": 0, "tx": 0})
            if raw_rx < last["rx"]:
                off["rx"] += last["rx"]  # счётчики Xray обнулились (рестарт)
            if raw_tx < last["tx"]:
                off["tx"] += last["tx"]
            if raw_rx > last["rx"] or raw_tx > last["tx"]:
                self.last_change[email] = time.monotonic()
            self.last_raw[email] = {"rx": raw_rx, "tx": raw_tx}
            result[email] = {"rx": raw_rx + off["rx"], "tx": raw_tx + off["tx"]}
        return result

    def is_online(self, email: str, window_sec: float = 120.0) -> bool:
        """online = трафик по пользователю рос в последние N секунд."""
        ts = self.last_change.get(email)
        return ts is not None and (time.monotonic() - ts) < window_sec


monitor = TrafficMonitor()


async def snapshot_loop(period_sec: int = 60) -> None:
    """Фоновая задача: снапшоты трафика в БД (для сумм и квот)."""
    while True:
        try:
            cum = monitor.cumulative()
            monitor._save()
            db = SessionLocal()
            try:
                devices = {d.name: d.id for d in db.query(Device).all()}
                now = datetime.utcnow()
                for email, counters in cum.items():
                    dev_id = devices.get(email)
                    if dev_id is None:
                        continue
                    db.add(TrafficSnapshot(
                        ts=now, device_id=dev_id,
                        cum_rx=counters["rx"], cum_tx=counters["tx"],
                    ))
                db.commit()
                # Чистим снапшоты старше 400 дней, чтобы БД не разрасталась
                cutoff = now - timedelta(days=400)
                db.query(TrafficSnapshot).filter(TrafficSnapshot.ts < cutoff).delete()
                db.commit()
            finally:
                db.close()
        except Exception as exc:
            log.warning("Сбой снапшота трафика: %s", exc)
        await asyncio.sleep(period_sec)


def traffic_in_window(device_id: int, since: datetime, db) -> tuple[int, int]:
    """
    Трафик (rx, tx) устройства за период [since, сейчас]:
    разность кумулятивных счётчиков на границах окна.
    """
    first = (
        db.query(TrafficSnapshot)
        .filter(TrafficSnapshot.device_id == device_id)
        .order_by(TrafficSnapshot.ts.asc())
        .first()
    )
    base = (
        db.query(TrafficSnapshot)
        .filter(TrafficSnapshot.device_id == device_id, TrafficSnapshot.ts <= since)
        .order_by(TrafficSnapshot.ts.desc())
        .first()
    )
    latest = (
        db.query(TrafficSnapshot)
        .filter(TrafficSnapshot.device_id == device_id)
        .order_by(TrafficSnapshot.ts.desc())
        .first()
    )
    if latest is None:
        return 0, 0
    anchor = base or first
    if anchor is None or anchor.id == latest.id:
        return 0, 0
    return max(0, latest.cum_rx - anchor.cum_rx), max(0, latest.cum_tx - anchor.cum_tx)
