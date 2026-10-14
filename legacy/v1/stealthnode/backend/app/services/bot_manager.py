# ============================================================
# StealthNode — управление торговым ботом OKX.
# Бот изолирован в своём контейнере и сети; бэкенд общается с ним
# через Docker API (старт/стоп/логи) и общий том с status.json
# (PnL, сделки, позиции — бот пишет, панель читает).
# ============================================================
import json
import logging
from pathlib import Path

from ..config import settings
from . import docker_client

log = logging.getLogger("stealthnode.bot")

# Ключи, значения которых НЕ отдаём в панель в открытом виде
SECRET_KEYS = {"OKX_API_KEY", "OKX_API_SECRET", "OKX_API_PASSPHRASE"}


def read_status() -> dict:
    """status.json, который бот пишет в общий том (последнее состояние торговли)."""
    status_file = Path(settings.bot_logs_dir) / "status.json"
    if not status_file.is_file():
        return {}
    try:
        return json.loads(status_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("status.json бота: %s", exc)
        return {}


def full_status() -> dict:
    """Полный статус: контейнер (uptime, CPU/RAM) + торговые метрики."""
    cont = docker_client.container_status(settings.bot_container)
    trade = read_status()
    return {
        "container": cont,
        "dry_run": trade.get("dry_run"),
        "symbol": trade.get("symbol"),
        "equity_usdt": trade.get("equity_usdt"),
        "pnl_day_usdt": trade.get("pnl_day_usdt"),
        "pnl_total_usdt": trade.get("pnl_total_usdt"),
        "trades_day": trade.get("trades_day"),
        "trades_total": trade.get("trades_total"),
        "positions": trade.get("positions", []),
        "last_price": trade.get("last_price"),
        "updated": trade.get("updated"),
    }


def logs(tail: int = 100) -> str:
    return docker_client.last_log_lines(settings.bot_container, tail)


def start() -> tuple[bool, str]:
    return docker_client.action(settings.bot_container, "start")


def stop() -> tuple[bool, str]:
    return docker_client.action(settings.bot_container, "stop")


def restart() -> tuple[bool, str]:
    return docker_client.action(settings.bot_container, "restart")


# ---------------- Редактор bot.env ----------------

def read_env(mask_secrets: bool = True) -> dict[str, str]:
    """Чтение bot.env; секреты по умолчанию маскируются (по ТЗ — не светить ключи)."""
    result: dict[str, str] = {}
    path = Path(settings.bot_env_path)
    if not path.is_file():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        k, v = k.strip(), v.strip()
        if mask_secrets and k in SECRET_KEYS:
            result[k] = "••••••••" if v else ""
        else:
            result[k] = v
    return result


def write_env(updates: dict[str, str]) -> None:
    """
    Обновление bot.env: меняем/добавляем ключи, осТАЛЬНОЕ сохраняем.
    Значение '••••••••' означает «не менять» (замаскированное поле формы).
    После правки — restart бота (делает вызывающий код).
    """
    path = Path(settings.bot_env_path)
    current: dict[str, str] = read_env(mask_secrets=False)
    for k, v in updates.items():
        if v == "••••••••":
            continue
        # Разрешаем редактировать только известные ключи бота
        if k.startswith("OKX_"):
            current[k] = v
    lines = [
        "# StealthNode — настройки торгового бота OKX",
        "# Отредактировано через веб-панель. Права файла должны быть 600.",
    ]
    for k in sorted(current):
        lines.append(f"{k}={current[k]}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
