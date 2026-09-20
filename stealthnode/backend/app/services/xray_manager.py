# ============================================================
# StealthNode — менеджер Xray (VLESS + REALITY).
# Управление клиентами: правка config.json + перезапуск контейнера.
# Публичный ключ REALITY выводится из приватного (X25519) —
# отдельный запуск `xray x25519` не требуется.
# ============================================================
import json
import logging
import uuid as uuid_mod
from urllib.parse import quote

from ..config import settings
from . import docker_client, wg_manager

log = logging.getLogger("stealthnode.xray")


def _load() -> dict:
    # Конфиг содержит // комментарии — вычищаем их перед разбором JSON
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


def _vless_inbound(cfg: dict) -> dict:
    for inb in cfg.get("inbounds", []):
        if inb.get("protocol") == "vless":
            return inb
    raise RuntimeError("В конфиге Xray не найден vless-inbound")


def reality_public_key() -> str:
    """Публичный ключ REALITY (выводится из приватного ключа конфига)."""
    try:
        priv = _vless_inbound(_load())["streamSettings"]["realitySettings"]["privateKey"]
        return wg_manager.public_key_from_private(priv)
    except Exception as exc:
        log.warning("Не удалось вывести публичный ключ REALITY: %s", exc)
        return ""


def current_sni() -> str:
    try:
        rs = _vless_inbound(_load())["streamSettings"]["realitySettings"]
        names = rs.get("serverNames") or []
        return names[0] if names else settings.reality_sni
    except Exception:
        return settings.reality_sni


def set_sni(new_sni: str) -> None:
    """Смена домена маскировки: dest + serverNames. Клиенты нужно обновить!"""
    cfg = _load()
    rs = _vless_inbound(cfg)["streamSettings"]["realitySettings"]
    rs["dest"] = f"{new_sni}:443"
    rs["serverNames"] = [new_sni]
    _save(cfg)


def short_id() -> str:
    try:
        ids = _vless_inbound(_load())["streamSettings"]["realitySettings"].get("shortIds") or [""]
        return next((s for s in ids if s), "")
    except Exception:
        return ""


def list_client_uuids() -> list[str]:
    try:
        return [c["id"] for c in _vless_inbound(_load())["settings"]["clients"]]
    except Exception:
        return []


def add_client(email: str, client_uuid: str | None = None) -> str:
    """
    Добавление VLESS-клиента. Возвращает UUID.
    Если client_uuid задан — восстанавливаем существующего (включение).
    """
    cfg = _load()
    clients = _vless_inbound(cfg)["settings"]["clients"]
    new_uuid = client_uuid or str(uuid_mod.uuid4())
    if not any(c.get("id") == new_uuid for c in clients):
        clients.append({"id": new_uuid, "flow": "xtls-rprx-vision", "email": email})
        _save(cfg)
        ok, msg = docker_client.action(settings.xray_container, "restart")
        if not ok:
            log.warning("Перезапуск xray: %s", msg)
    return new_uuid


def remove_client(client_uuid: str) -> bool:
    cfg = _load()
    clients = _vless_inbound(cfg)["settings"]["clients"]
    new_clients = [c for c in clients if c.get("id") != client_uuid]
    if len(new_clients) == len(clients):
        return False
    _vless_inbound(cfg)["settings"]["clients"] = new_clients
    _save(cfg)
    docker_client.action(settings.xray_container, "restart")
    return True


def share_link(name: str, client_uuid: str) -> str:
    """
    Ссылка vless:// для импорта в клиент (v2rayNG/Nekoray/Streisand и QR).
    """
    pbk = reality_public_key()
    params = (
        "security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision"
        f"&pbk={pbk}&fp=chrome&sni={current_sni()}&sid={short_id()}"
    )
    return (
        f"vless://{client_uuid}@{settings.server_public_ip}:443?{params}"
        f"#{quote('StealthNode-' + name)}"
    )
