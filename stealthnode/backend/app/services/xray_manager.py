# ============================================================
# StealthNode — менеджер Xray (VLESS + REALITY, три транспорта).
#
# * Клиенты: правка config.json + перезапуск контейнера (клиент
#   добавляется ВО ВСЕ профили TCP/gRPC/XHTTP с одним UUID/email —
#   пользователь видит три ссылки и выбирает рабочий транспорт).
# * Трафик: встроенная статистика Xray (StatsService на localhost
#   контейнера), опрос через `xray api statsquery` (docker exec).
# * Публичный ключ REALITY выводится из приватного (X25519).
# ============================================================
import json
import logging
import re
import uuid as uuid_mod
from urllib.parse import quote

from ..config import settings
from ..utils.crypto import x25519_public_from_private
from . import docker_client

log = logging.getLogger("stealthnode.xray")

# Транспорты, которые получает каждый клиент (порядок = приоритет для пользователя)
TRANSPORTS = ("tcp", "grpc", "xhttp")


# ---------------- Конфиг ----------------

def _load() -> dict:
    # Конфиг содержит // комментарии — вычищаем перед разбором JSON
    raw = settings.xray_conf_path.read_text(encoding="utf-8")
    cleaned = "\n".join(
        ln for ln in raw.splitlines()
        if not ln.strip().startswith("//")
    )
    return json.loads(cleaned)


def _save(cfg: dict) -> None:
    settings.xray_conf_path.write_text(
        json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def _vless_inbounds(cfg: dict) -> list[dict]:
    """Все VLESS-инбаунды в порядке следования (tcp, grpc, xhttp)."""
    return [inb for inb in cfg.get("inbounds", []) if inb.get("protocol") == "vless"]


def _restart() -> None:
    ok, msg = docker_client.action(settings.xray_container, "restart")
    if not ok:
        log.warning("Перезапуск xray: %s", msg)


# ---------------- Параметры REALITY ----------------

def _first_inbound(cfg: dict) -> dict:
    inbounds = _vless_inbounds(cfg)
    if not inbounds:
        raise RuntimeError("В конфиге Xray не найден vless-inbound")
    return inbounds[0]


def reality_public_key() -> str:
    """Публичный ключ REALITY (выводится из приватного ключа конфига)."""
    try:
        priv = _first_inbound(_load())["streamSettings"]["realitySettings"]["privateKey"]
        return x25519_public_from_private(priv)
    except Exception as exc:
        log.warning("Не удалось вывести публичный ключ REALITY: %s", exc)
        return ""


def current_sni() -> str:
    try:
        rs = _first_inbound(_load())["streamSettings"]["realitySettings"]
        names = rs.get("serverNames") or []
        return names[0] if names else settings.reality_sni
    except Exception:
        return settings.reality_sni


def set_sni(new_sni: str) -> None:
    """Смена домена маскировки ВО ВСЕХ транспортах. Клиенты нужно обновить!"""
    cfg = _load()
    for inb in _vless_inbounds(cfg):
        rs = inb["streamSettings"]["realitySettings"]
        rs["dest"] = f"{new_sni}:443"
        rs["serverNames"] = [new_sni]
    _save(cfg)


def short_id() -> str:
    try:
        rs = _first_inbound(_load())["streamSettings"]["realitySettings"]
        ids = rs.get("shortIds") or [""]
        return next((s for s in ids if s), "")
    except Exception:
        return settings.reality_short_id


# ---------------- Управление клиентами ----------------

def list_clients() -> list[tuple[str, str]]:
    """[(uuid, email)] из первого inbound'а (наборы идентичны во всех)."""
    try:
        return [
            (c["id"], c.get("email", ""))
            for c in _first_inbound(_load())["settings"]["clients"]
        ]
    except Exception:
        return []


def add_client(email: str, client_uuid: str | None = None) -> str:
    """
    Добавление клиента ВО ВСЕ транспорты. Возвращает UUID.
    client_uuid задан — восстановление существующего (включение).
    """
    cfg = _load()
    new_uuid = client_uuid or str(uuid_mod.uuid4())
    changed = False
    for inb in _vless_inbounds(cfg):
        clients = inb["settings"]["clients"]
        if any(c.get("id") == new_uuid for c in clients):
            continue
        entry: dict = {"id": new_uuid, "email": email}
        # flow vision применим только к TCP-транспорту (тег 'tcp' — первый)
        if inb.get("tag") == "tcp":
            entry["flow"] = "xtls-rprx-vision"
        clients.append(entry)
        changed = True
    if changed:
        _save(cfg)
        _restart()
    return new_uuid


def remove_client(client_uuid: str) -> bool:
    """Удаление клиента из всех транспортов (мгновенный разрыв)."""
    cfg = _load()
    changed = False
    for inb in _vless_inbounds(cfg):
        clients = inb["settings"]["clients"]
        new_clients = [c for c in clients if c.get("id") != client_uuid]
        if len(new_clients) != len(clients):
            inb["settings"]["clients"] = new_clients
            changed = True
    if changed:
        _save(cfg)
        _restart()
    return changed


# ---------------- Статистика трафика (per-user) ----------------

def user_traffic() -> dict[str, dict[str, int]]:
    """
    Счётчики трафика по email: {email: {"uplink": байт, "downlink": байт}}.
    Источник — StatsService Xray (обнуляется при перезапуске контейнера;
    склейку ряда делает traffic_monitor).
    uplink   = клиент -> сервер (загрузка клиента)
    downlink = сервер -> клиент (скачивание клиента)
    """
    code, out = docker_client.exec_in(
        settings.xray_container,
        f"xray api statsquery --server={settings.xray_api_addr} --pattern='user>>>'",
    )
    result: dict[str, dict[str, int]] = {}
    if code != 0 or not out.strip():
        return result
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        # Фолбэк: вытащить пары name/value регуляркой (формат CLI мог измениться)
        pairs = re.findall(r'"name":\s*"([^"]+)"[^}]*?"value":\s*"?(\d+)"?', out)
        data = {"stat": [{"name": n, "value": v} for n, v in pairs]}
    for item in data.get("stat", []):
        name = str(item.get("name", ""))
        try:
            value = int(item.get("value", 0))
        except (TypeError, ValueError):
            continue
        # Формат: user>>>EMAIL>>>traffic>>>uplink|downlink
        parts = name.split(">>>")
        if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
            continue
        email, direction = parts[1], parts[3]
        entry = result.setdefault(email, {"uplink": 0, "downlink": 0})
        if direction in ("uplink", "downlink"):
            entry[direction] += value
    return result


# ---------------- Ссылки для клиентов ----------------

def share_links(name: str, client_uuid: str) -> dict[str, str]:
    """
    Ссылки vless:// для импорта (v2rayNG, Streisand, Nekoray, Happ, Clash...):
      tcp   — основной профиль (vision), порт 443;
      grpc  — резерв №1 (после детекта vision ТСПУ в мае 2026);
      xhttp — резерв №2.
    """
    pbk = reality_public_key()
    sni = current_sni()
    sid = short_id()
    base = (
        f"security=reality&encryption=none&pbk={pbk}&fp=chrome&sni={sni}&sid={sid}"
    )
    tag = quote("StealthNode-" + name)
    links = {
        "tcp": (
            f"vless://{client_uuid}@{settings.server_public_ip}:443?{base}"
            f"&type=tcp&flow=xtls-rprx-vision#{tag}-tcp"
        ),
        "grpc": (
            f"vless://{client_uuid}@{settings.server_public_ip}:{settings.xray_grpc_port}"
            f"?{base}&type=grpc&serviceName={settings.grpc_service}&alpn=h2#{tag}-grpc"
        ),
        "xhttp": (
            f"vless://{client_uuid}@{settings.server_public_ip}:{settings.xray_xhttp_port}"
            f"?{base}&type=xhttp&path=%2F{settings.xhttp_path}&mode=auto#{tag}-xhttp"
        ),
    }
    return links


def hy2_link() -> str:
    """Ссылка резервного Hysteria2 (аккаунт владельца)."""
    sni = current_sni()
    params = (
        f"obfs=salamander&obfs-password={settings.salamander_password}"
        f"&sni={sni}&insecure=1"
    )
    return (
        f"hy2://{settings.hy2_password}@{settings.server_public_ip}:{settings.hy2_port}"
        f"/?{params}#{quote('StealthNode-HY2')}"
    )
