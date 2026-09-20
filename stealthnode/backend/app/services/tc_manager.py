# ============================================================
# StealthNode — ограничение скорости гостей через tc + ifb (по ТЗ §6.1).
#
# Направления:
#   * СКАЧИВАНИЕ клиента  = пакеты egress на awg0   -> класс на awg0;
#   * ЗАГРУЗКА клиента    = пакеты ingress на awg0  -> редирект на ifb0
#     (mirred), шейпинг hfsc-классом на ifb0.
# Классы hfsc нумеруются 1:100+N (N = id гостя), фильтры — по IP /32.
# ============================================================
import logging

from ..config import settings
from . import docker_client

# Приоритеты QoS (зарезервированная полоса hfsc sc rate при конкуренции)
_PRIO_FACTOR = {"low": 50, "normal": 80, "high": 100}  # % от лимита

log = logging.getLogger("stealthnode.tc")


def _tc(cmd: str) -> tuple[int, str]:
    return docker_client.exec_in(settings.awg_container, cmd)


def apply_limits(tunnel_ip: str, down_mbps: int | None, up_mbps: int | None,
                 priority: str, guest_no: int) -> tuple[bool, str]:
    """
    Применить лимиты для IP гостя. None — направление без лимита.
    Сначала снимаем старые правила (идемпотентность).
    """
    remove_limits(tunnel_ip, guest_no)
    factor = _PRIO_FACTOR.get(priority, 80)
    cid = 100 + guest_no
    errors: list[str] = []

    # --- Скачивание: egress на awg0 ---
    if down_mbps:
        guaranteed = max(1, down_mbps * factor // 100)
        cmds = [
            f"tc class add dev awg0 parent 1:1 classid 1:{cid} "
            f"hfsc sc rate {guaranteed}mbit ul rate {down_mbps}mbit",
            f"tc filter add dev awg0 parent 1: protocol ip prio {guest_no} u32 "
            f"match ip dst {tunnel_ip}/32 flowid 1:{cid}",
        ]
        for c in cmds:
            code, out = _tc(c)
            if code != 0:
                errors.append(f"download: {out.strip()}")

    # --- Загрузка: ifb0 ---
    if up_mbps:
        guaranteed = max(1, up_mbps * factor // 100)
        cmds = [
            f"tc class add dev ifb0 parent 1:1 classid 1:{cid} "
            f"hfsc sc rate {guaranteed}mbit ul rate {up_mbps}mbit",
            f"tc filter add dev ifb0 parent 1: protocol ip prio {guest_no} u32 "
            f"match ip src {tunnel_ip}/32 flowid 1:{cid}",
        ]
        for c in cmds:
            code, out = _tc(c)
            if code != 0:
                errors.append(f"upload: {out.strip()}")

    if errors:
        log.warning("tc для %s: %s", tunnel_ip, errors)
        return False, "; ".join(errors)
    return True, f"Лимиты применены: ↓{down_mbps or '∞'} Мбит/с ↑{up_mbps or '∞'} Мбит/с"


def remove_limits(tunnel_ip: str, guest_no: int) -> None:
    """Снять все фильтры/классы гостя (ошибки игнорируем — их могло не быть)."""
    cid = 100 + guest_no
    for cmd in [
        f"tc filter del dev awg0 parent 1: prio {guest_no} u32 match ip dst {tunnel_ip}/32",
        f"tc filter del dev ifb0 parent 1: prio {guest_no} u32 match ip src {tunnel_ip}/32",
        f"tc class del dev awg0 classid 1:{cid}",
        f"tc class del dev ifb0 classid 1:{cid}",
    ]:
        _tc(cmd)


def re_apply_all(guests: list) -> None:
    """Повторное применение всех лимитов (после перезапуска контейнера)."""
    for g in guests:
        if g.device and g.device.tunnel_ip and (g.speed_down_mbps or g.speed_up_mbps):
            apply_limits(
                g.device.tunnel_ip, g.speed_down_mbps, g.speed_up_mbps,
                g.priority, g.id,
            )
