# ============================================================
# StealthNode — применение гостевых лимитов.
# Фоновая задача (каждые 5 минут — по ТЗ «cron-задача каждые 5 минут»):
#   * срок действия аккаунта (expires_at);
#   * временное окно доступа (HH:MM–HH:MM по времени сервера);
#   * квоты трафика (дневная/недельная/месячная/общая) по снапшотам
#     и nftables-счётчикам (счётчики nft ведутся в контейнере,
#     а продолжительные суммы — по снапшотам БД).
# Автосброс: при наступлении нового периода квота-отключение снимается.
# ============================================================
import asyncio
import logging
from datetime import datetime, time, timedelta

from ..database import SessionLocal
from ..models import Guest
from . import traffic_monitor, xray_manager

log = logging.getLogger("stealthnode.quota")

CHECK_PERIOD = 300  # 5 минут (по ТЗ)


def _in_window(start_s: str | None, end_s: str | None, now: datetime) -> bool:
    """Проверка попадания текущего времени в окно (поддержка окна через полночь)."""
    if not start_s or not end_s:
        return True
    try:
        start = time.fromisoformat(start_s)
        end = time.fromisoformat(end_s)
    except ValueError:
        return True
    cur = now.time()
    if start <= end:
        return start <= cur <= end
    return cur >= start or cur <= end  # окно вида 22:00–06:00


def _set_enabled(guest: Guest, enabled: bool, status: str, detail: str = "") -> None:
    """Включить/выключить гостя: клиент удаляется/добавляется во все
    транспорты Xray (мгновенный разрыв текущих сессий)."""
    dev = guest.device
    guest.status = status
    guest.status_detail = detail
    if enabled:
        if not dev.enabled:
            xray_manager.add_client(dev.name, client_uuid=dev.public_key)
            dev.enabled = True
            log.info("Гость %s включён (%s)", dev.name, status)
    else:
        if dev.enabled:
            if xray_manager.remove_client(dev.public_key):
                dev.enabled = False
                log.info("Гость %s отключён: %s (%s)", dev.name, status, detail)
            else:
                log.warning("Не удалось отключить клиента %s", dev.name)


def check_guest(guest: Guest, db, now: datetime) -> None:
    dev = guest.device

    # Ручное отключение админом — автоматика не трогает
    if guest.status == "disabled_admin":
        return

    # 1. Срок действия
    if guest.expires_at and now >= guest.expires_at:
        _set_enabled(guest, False, "expired", f"Истёк срок действия ({guest.expires_at})")
        return

    # 2. Временное окно
    if not _in_window(guest.window_start, guest.window_end, now):
        _set_enabled(guest, False, "window",
                     f"Вне окна доступа {guest.window_start}–{guest.window_end}")
        return

    # 3. Квоты трафика (сумма rx+tx за период)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = day_start - timedelta(days=now.weekday())
    month_start = day_start.replace(day=1)
    checks: list[tuple[int | None, datetime, str]] = [
        (guest.quota_daily_mb, day_start, "дневной"),
        (guest.quota_weekly_mb, week_start, "недельный"),
        (guest.quota_monthly_mb, month_start, "месячный"),
    ]
    for quota_mb, since, label in checks:
        if not quota_mb:
            continue
        rx, tx = traffic_monitor.traffic_in_window(dev.id, since, db)
        used_mb = (rx + tx) / 1024 / 1024
        if used_mb >= quota_mb:
            _set_enabled(guest, False, "quota",
                         f"Исчерпан {label} лимит: {used_mb:.0f}/{quota_mb} МБ")
            return
    if guest.quota_total_mb:
        rx, tx = traffic_monitor.traffic_in_window(dev.id, datetime(2000, 1, 1), db)
        used_mb = (rx + tx) / 1024 / 1024
        if used_mb >= guest.quota_total_mb:
            _set_enabled(guest, False, "quota",
                         f"Исчерпан общий лимит: {used_mb:.0f}/{guest.quota_total_mb} МБ")
            return

    # Всё в норме — включаем (в т.ч. автосброс квотных/оконных отключений)
    _set_enabled(guest, True, "active")


async def quota_loop() -> None:
    """Периодическая проверка всех гостей (каждые 5 минут)."""
    await asyncio.sleep(20)  # даём стеку подняться после старта
    while True:
        try:
            db = SessionLocal()
            try:
                now = datetime.utcnow()
                for guest in db.query(Guest).all():
                    check_guest(guest, db, now)
                db.commit()
            finally:
                db.close()
        except Exception as exc:
            log.warning("Сбой проверки квот: %s", exc)
        await asyncio.sleep(CHECK_PERIOD)
