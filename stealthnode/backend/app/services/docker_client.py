# ============================================================
# StealthNode — обёртка над Docker API.
# Используется для: exec внутри контейнера AmneziaWG (awg/tc/nft),
# управления торговым ботом (старт/стоп/логи), статусов сервисов.
# ============================================================
import logging

import docker
from docker.errors import APIError, DockerException, NotFound

log = logging.getLogger("stealthnode.docker")

_client: docker.DockerClient | None = None


def get_client() -> docker.DockerClient | None:
    """Docker-клиент или None, если демон недоступен (не бросает исключение)."""
    global _client
    if _client is None:
        try:
            _client = docker.from_env()
            _client.ping()
        except DockerException as exc:
            log.warning("Docker-демон недоступен: %s", exc)
            return None
    return _client


def get_container(name: str):
    """Контейнер по имени или None (не бросает исключение)."""
    client = get_client()
    if client is None:
        return None
    try:
        return client.containers.get(name)
    except (NotFound, APIError, DockerException) as exc:
        log.warning("Контейнер %s недоступен: %s", name, exc)
        return None


def exec_in(container_name: str, cmd: str, timeout: int = 30) -> tuple[int, str]:
    """
    Выполнить shell-команду внутри контейнера.
    Возвращает (код_возврата, stdout+stderr).
    """
    container = get_container(container_name)
    if container is None:
        return 127, f"контейнер {container_name} не найден"
    try:
        result = container.exec_run(["sh", "-c", cmd], demux=True)
        out = (result.output[0] or b"") + (result.output[1] or b"")
        return result.exit_code, out.decode("utf-8", "replace")
    except (APIError, DockerException) as exc:
        return 1, str(exc)


def container_status(name: str) -> dict:
    """Статус контейнера для дашборда: состояние, uptime, CPU/RAM."""
    container = get_container(name)
    if container is None:
        return {"name": name, "state": "отсутствует", "health": "-", "cpu_pct": 0.0, "mem_mb": 0.0}
    container.reload()
    state = container.status  # running / exited / restarting ...
    health = (container.attrs.get("State", {}).get("Health") or {}).get("Status", "-")
    cpu_pct, mem_mb = 0.0, 0.0
    if state == "running":
        try:
            # Одноразовый снапшот статистики (без стрима)
            st = container.stats(stream=False)
            cpu_delta = st["cpu_stats"]["cpu_usage"]["total_usage"] - st["precpu_stats"]["cpu_usage"]["total_usage"]
            sys_delta = st["cpu_stats"]["system_cpu_usage"] - st["precpu_stats"]["system_cpu_usage"]
            ncpu = st["cpu_stats"].get("online_cpus", 1)
            if sys_delta > 0 and cpu_delta >= 0:
                cpu_pct = round(cpu_delta / sys_delta * ncpu * 100, 1)
            mem_mb = round(st["memory_stats"].get("usage", 0) / 1024 / 1024, 1)
        except Exception as exc:  # статистика — не критично
            log.debug("Статистика %s: %s", name, exc)
    return {"name": name, "state": state, "health": health, "cpu_pct": cpu_pct, "mem_mb": mem_mb}


def action(name: str, act: str) -> tuple[bool, str]:
    """start / stop / restart контейнера. Возвращает (успех, сообщение)."""
    container = get_container(name)
    if container is None:
        return False, f"Контейнер {name} не найден"
    try:
        if act == "start":
            container.start()
        elif act == "stop":
            container.stop(timeout=15)
        elif act == "restart":
            container.restart(timeout=15)
        else:
            return False, f"Неизвестное действие: {act}"
        return True, f"{name}: {act} выполнен"
    except APIError as exc:
        return False, str(exc)


def last_log_lines(name: str, tail: int = 100) -> str:
    """Последние N строк логов контейнера."""
    container = get_container(name)
    if container is None:
        return f"Контейнер {name} не найден"
    try:
        return container.logs(tail=tail, timestamps=True).decode("utf-8", "replace")
    except APIError as exc:
        return str(exc)
