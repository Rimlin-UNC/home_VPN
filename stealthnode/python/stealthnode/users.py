"""Пользователи VPN: создание/удаление, ссылки, QR-коды.

Пользователь = клиент 3x-ui v3 с уникальным именем (поле email), привязанный
сразу к трём инбаундам StealthNode. Квота трафика и лимит IP — общие на все
протоколы, подписка (subId) — одна.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from . import config, links
from .config import ALL_TAGS, Settings
from .payloads import client_record
from .util import GIB, Console, atomic_write, human_bytes, run, which
from .xui import XuiClient, XuiError

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,31}$")


def validate_name(name: str) -> str:
    name = name.strip().lower()
    if not NAME_RE.match(name):
        raise ValueError("имя: 2-32 символа, латиница в нижнем регистре, цифры, '_', '.', '-' (например: mama, papa2)")
    return name


def sn_inbound_ids(xui: XuiClient) -> dict[str, int]:
    ids = {}
    for inb in xui.list_inbounds():
        if inb.get("tag") in ALL_TAGS:
            ids[inb["tag"]] = int(inb["id"])
    return ids


def _client_inbound_ids(client: dict) -> list[int]:
    return [int(i) for i in (client.get("inboundIds") or [])]


def list_users(xui: XuiClient) -> list[dict]:
    """Клиенты, привязанные хотя бы к одному инбаунду StealthNode."""
    ids = set(sn_inbound_ids(xui).values())
    return [c for c in xui.list_clients() if ids & set(_client_inbound_ids(c))]


def find_user(xui: XuiClient, name: str) -> dict | None:
    for c in xui.list_clients():
        if c.get("email") == name:
            return c
    return None


def add_user(
    xui: XuiClient,
    name: str,
    *,
    limit_gb: float,
    ip_limit: int,
    monthly: bool = True,
    days: int = 0,
    comment: str = "",
) -> dict:
    name = validate_name(name)
    if find_user(xui, name):
        raise ValueError(f"пользователь {name!r} уже существует")
    ids = sn_inbound_ids(xui)
    missing = [t for t in ALL_TAGS if t not in ids]
    if missing:
        raise XuiError(f"нет инбаундов StealthNode: {', '.join(missing)} (запустите: stealthnode provision)")
    expiry_ms = int((time.time() + days * 86400) * 1000) if days > 0 else 0
    client = client_record(
        name, limit_gb=limit_gb, limit_ip=ip_limit, monthly_reset=monthly, expiry_ms=expiry_ms, comment=comment
    )
    xui.add_client(client, [ids[t] for t in ALL_TAGS])
    return client


def ensure_user(xui: XuiClient, name: str, *, limit_gb: float, ip_limit: int, comment: str = "") -> tuple[dict, bool]:
    """Создать пользователя, если его нет; дописать недостающие привязки. (клиент, создан ли)."""
    existing = find_user(xui, name)
    if existing is None:
        return add_user(xui, name, limit_gb=limit_gb, ip_limit=ip_limit, comment=comment), True
    ensure_attached(xui, [existing])
    return existing, False


def ensure_attached(xui: XuiClient, clients: list[dict] | None = None) -> list[str]:
    """Привязать пользователей StealthNode ко всем трём инбаундам (например, после добавления нового)."""
    ids = sn_inbound_ids(xui)
    wanted = set(ids.values())
    fixed = []
    for c in clients if clients is not None else list_users(xui):
        have = set(_client_inbound_ids(c))
        missing = sorted(wanted - have)
        if missing:
            xui.attach_client(c["email"], missing)
            fixed.append(c["email"])
    return fixed


def record_to_client(rec: dict) -> dict:
    """ClientRecord (ответ clients/get) → model.Client (тело clients/update).

    Update в 3x-ui заменяет все поля, кроме учётных данных, поэтому передаём полный набор.
    """
    return {
        "id": rec.get("uuid", ""),
        "password": rec.get("password", ""),
        "auth": rec.get("auth", ""),
        "flow": rec.get("flow", ""),
        "email": rec.get("email", ""),
        "limitIp": int(rec.get("limitIp", 0) or 0),
        "totalGB": int(rec.get("totalGB", 0) or 0),
        "expiryTime": int(rec.get("expiryTime", 0) or 0),
        "enable": bool(rec.get("enable", True)),
        "tgId": int(rec.get("tgId", 0) or 0),
        "subId": rec.get("subId", ""),
        "group": rec.get("group", ""),
        "comment": rec.get("comment", ""),
        "reset": int(rec.get("reset", 0) or 0),
        "resetDay": int(rec.get("resetDay", 0) or 0),
        "resetWeekday": int(rec.get("resetWeekday", 0) or 0),
        "resetMax": int(rec.get("resetMax", 0) or 0),
        "trafficReset": rec.get("trafficReset") or "never",
        "trafficResetDay": int(rec.get("trafficResetDay", 1) or 1),
    }


def set_limits(xui: XuiClient, name: str, *, limit_gb: float | None = None, ip_limit: int | None = None) -> dict:
    obj = xui.get_client(name)
    if not obj:
        raise ValueError(f"пользователь {name!r} не найден")
    rec = obj.get("client", obj)
    client = record_to_client(rec)
    if limit_gb is not None:
        client["totalGB"] = int(limit_gb * GIB) if limit_gb > 0 else 0
        client["trafficReset"] = "monthly" if limit_gb > 0 else "never"
        client["trafficResetDay"] = 1
        client["enable"] = True
    if ip_limit is not None:
        client["limitIp"] = int(ip_limit)
    xui.update_client(name, client)
    return client


def delete_user(xui: XuiClient, name: str) -> None:
    if not find_user(xui, name):
        raise ValueError(f"пользователь {name!r} не найден")
    xui.delete_client(name)
    user_dir = config.sn_root() / "users" / name
    if user_dir.is_dir():
        for f in user_dir.iterdir():
            f.unlink()
        user_dir.rmdir()


def sub_url(s: Settings, client: dict) -> str:
    return s.sub_base_url + str(client.get("subId", ""))


def describe(client: dict, online: set[str] | None = None) -> str:
    traffic = client.get("traffic") or {}
    used = int(traffic.get("up", 0) or 0) + int(traffic.get("down", 0) or 0)
    total = int(client.get("totalGB", 0) or 0)
    limit = human_bytes(total) if total else "без лимита"
    ip = int(client.get("limitIp", 0) or 0)
    status = "вкл" if client.get("enable", True) and traffic.get("enable", True) else "ВЫКЛ"
    on = " • онлайн" if online and client.get("email") in online else ""
    reset = client.get("trafficReset") or ""
    reset_txt = ", сброс ежемесячно" if reset == "monthly" else ""
    exp = int(client.get("expiryTime", 0) or 0)
    exp_txt = "" if exp <= 0 else ", до " + time.strftime("%Y-%m-%d", time.localtime(exp / 1000))
    return (
        f"{client.get('email', '?'):<16} {status:<4} трафик {human_bytes(used)} / {limit}{reset_txt}{exp_txt}, "
        f"IP: {ip or '∞'}{on}"
    )


# --- Файлы со ссылками и QR ----------------------------------------------------


def qr_png(text: str, path: Path) -> bool:
    if not which("qrencode"):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    run(["qrencode", "-o", str(path), "-s", "6", "-m", "2", "-l", "M", text], timeout=30)
    path.chmod(0o600)
    return True


def qr_terminal(text: str) -> str:
    if not which("qrencode"):
        return "(qrencode не установлен: apt install qrencode)"
    return run(["qrencode", "-t", "ansiutf8", "-m", "1", text], timeout=30).stdout


PROFILE_TITLES = {
    "xhttp": "Основной: VLESS + XHTTP + REALITY (Android, Windows, macOS)",
    "vision": "iOS / резерв: VLESS + TCP + REALITY + Vision",
    "hysteria2": "Резерв по UDP: Hysteria2 + Salamander",
}


def write_user_files(xui: XuiClient, s: Settings, client: dict) -> Path:
    name = client["email"]
    user_dir = config.sn_root() / "users" / name
    user_dir.mkdir(parents=True, exist_ok=True)
    user_dir.chmod(0o700)
    url = sub_url(s, client)
    raw_links = xui.client_links(name)
    lines = [
        f"# StealthNode — профиль пользователя {name}",
        "# Секретно: не пересылайте ссылки посторонним.",
        "",
        "## Подписка (рекомендуется): добавьте в клиент как «подписку» — обновляется автоматически",
        url,
        "",
    ]
    for raw in raw_links:
        try:
            link = links.parse(raw)
            title = PROFILE_TITLES.get(link.kind, link.kind)
        except links.LinkError:
            title = "профиль"
        lines += [f"## {title}", raw, ""]
    atomic_write(user_dir / "links.txt", "\n".join(lines), mode=0o600)
    qr_png(url, user_dir / "qr-subscription.png")
    for raw in raw_links:
        try:
            kind = links.parse(raw).kind
        except links.LinkError:
            continue
        qr_png(raw, user_dir / f"qr-{kind}.png")
    return user_dir


def write_admin_links(xui: XuiClient, s: Settings) -> Path:
    """xray/share/admin-links.txt: ссылки владельца + подписки всех пользователей."""
    share = config.sn_root() / "xray" / "share"
    share.mkdir(parents=True, exist_ok=True)
    share.chmod(0o700)
    owner = s.get("SN_OWNER_NAME") or "owner"
    lines = [
        "# StealthNode — ссылки администратора (секретно)",
        f"# Панель: {s.panel_url}",
        "",
    ]
    users = list_users(xui)
    for c in users:
        if c.get("email") == owner:
            lines.append(f"## Владелец ({owner}) — подписка")
            lines.append(sub_url(s, c))
            lines.append("")
            for raw in xui.client_links(owner):
                lines.append(raw)
            lines.append("")
    lines.append("## Подписки пользователей")
    for c in users:
        lines.append(f"{c.get('email')}: {sub_url(s, c)}")
    path = share / "admin-links.txt"
    atomic_write(path, "\n".join(lines) + "\n", mode=0o600)
    return path


def write_all(xui: XuiClient, s: Settings, console: Console | None = None) -> None:
    for c in list_users(xui):
        d = write_user_files(xui, s, c)
        if console:
            console.ok(f"ссылки и QR для {c['email']}: {d}")
    path = write_admin_links(xui, s)
    if console:
        console.ok(f"ссылки администратора: {path}")
