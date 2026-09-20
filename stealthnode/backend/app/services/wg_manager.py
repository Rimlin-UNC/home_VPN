# ============================================================
# StealthNode — менеджер AmneziaWG.
# Все команды выполняются ВНУТРИ контейнера amneziawg через
# `docker exec` (интерфейс awg0 живёт в его network namespace).
#
# Генерация ключей — локально через cryptography:
# приватный ключ WireGuard/AmneziaWG = 32 байта X25519 (base64),
# что полностью совместимо с `wg genkey` / `awg genkey`.
# ============================================================
import base64
import ipaddress
import logging
import re
import secrets
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ..config import settings
from . import docker_client

log = logging.getLogger("stealthnode.awg")

B64_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


# ---------------- Ключи ----------------

def generate_keypair() -> tuple[str, str]:
    """(приватный, публичный) ключ в формате base64 (как wg genkey/pubkey)."""
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(priv_raw).decode(), base64.b64encode(pub_raw).decode()


def public_key_from_private(priv_b64: str) -> str:
    """Вывод публичного ключа из приватного (X25519 scalar multiplication)."""
    priv = X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(pub_raw).decode()


def generate_psk() -> str:
    """Pre-Shared Key (32 байта, base64) — уникальный для каждого пира (по ТЗ)."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


# ---------------- Работа с интерфейсом (внутри контейнера) ----------------

def interface_up() -> bool:
    code, _ = docker_client.exec_in(settings.awg_container, "awg show awg0 interfaces")
    return code == 0


def dump() -> list[dict]:
    """
    Сырые данные по пирам: `awg show awg0 dump`.
    Формат строки пира: pubkey, psk, endpoint, allowed-ips,
    latest-handshake, transfer-rx, transfer-tx, persistent-keepalive.
    """
    code, out = docker_client.exec_in(settings.awg_container, "awg show awg0 dump")
    peers: list[dict] = []
    if code != 0 or not out.strip():
        return peers
    lines = [ln for ln in out.strip().splitlines() if ln.strip()]
    for ln in lines[1:]:  # первая строка — интерфейс
        f = ln.split("\t")
        if len(f) < 8:
            continue
        handshake = int(f[4]) if f[4].isdigit() else 0
        peers.append({
            "public_key": f[0],
            "endpoint": f[2] if f[2] != "(none)" else "",
            "allowed_ips": f[3],
            "latest_handshake": handshake,
            "rx": int(f[5]) if f[5].isdigit() else 0,
            "tx": int(f[6]) if f[6].isdigit() else 0,
        })
    return peers


def add_peer(public_key: str, psk: str, tunnel_ip: str) -> tuple[bool, str]:
    """Добавление/обновление пира: `awg set awg0 peer ...` (без пересоздания)."""
    cmd = (
        f"printf '%s' '{psk}' > /tmp/psk_peer && "
        f"awg set awg0 peer {public_key} preshared-key /tmp/psk_peer "
        f"allowed-ips {tunnel_ip}/32 persistent-keepalive 25; "
        f"rc=$?; rm -f /tmp/psk_peer; exit $rc"
    )
    code, out = docker_client.exec_in(settings.awg_container, cmd)
    return code == 0, out.strip()


def remove_peer(public_key: str) -> tuple[bool, str]:
    """Мгновенный разрыв пира (по ТЗ — отключение устройства)."""
    code, out = docker_client.exec_in(
        settings.awg_container, f"awg set awg0 peer {public_key} remove"
    )
    return code == 0, out.strip()


# ---------------- Конфигурационный файл ----------------

def read_conf() -> str:
    try:
        return settings.awg_conf_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _parse_interface_params(conf: str) -> dict[str, str]:
    """Параметры секции [Interface] (обфускация и прочее) из текстового конфига."""
    params: dict[str, str] = {}
    in_iface = False
    for line in conf.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_iface = s.lower() == "[interface]"
            continue
        if in_iface and "=" in s and not s.startswith("#"):
            k, v = s.split("=", 1)
            params[k.strip()] = v.strip()
    return params


def get_obfuscation_params() -> dict[str, str]:
    """Текущие Jc/Jmin/Jmax/S1-S4/H1-H4 из [Interface]."""
    params = _parse_interface_params(read_conf())
    keys = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"]
    return {k: params.get(k, "") for k in keys}


def rewrite_conf(peers: list[dict]) -> None:
    """
    Полная перезапись awg0.conf: секция [Interface] сохраняется как есть
    (включая обфускацию), секции [Peer] пересоздаются из списка enabled-устройств.
    Вызывается после любого изменения устройств — конфиг всегда
    соответствует реальному состоянию и переживает перезапуск контейнера.
    """
    conf = read_conf()
    # Отделяем [Interface] от старых [Peer]
    head: list[str] = []
    for line in conf.splitlines():
        if line.strip().lower() == "[peer]":
            break
        head.append(line)
    out = "\n".join(head).rstrip() + "\n"
    for p in peers:
        out += (
            f"\n[Peer]\n# Имя: {p['name']}\n"
            f"PublicKey = {p['public_key']}\n"
            f"PresharedKey = {p['psk']}\n"
            f"AllowedIPs = {p['tunnel_ip']}/32\n"
            f"PersistentKeepalive = 25\n"
        )
    settings.awg_conf_path.write_text(out, encoding="utf-8")


def update_interface_obfuscation(new_params: dict[str, str]) -> None:
    """Обновление параметров обфускации в [Interface] (Jc, Jmin, ... H4)."""
    conf = read_conf()
    lines: list[str] = []
    in_iface = False
    written: set[str] = set()
    for line in conf.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_iface = s.lower() == "[interface]"
            lines.append(line)
            continue
        if in_iface and "=" in s and not s.startswith("#"):
            k = s.split("=", 1)[0].strip()
            if k in new_params:
                lines.append(f"{k} = {new_params[k]}")
                written.add(k)
                continue
        lines.append(line)
    # Дописываем отсутствующие ключи в конец [Interface]... (упрощение:
    # шаблон сгенерирован install.sh и содержит все ключи, поэтому
    # ветка выше покрывает реальный сценарий; если ключ исчез — логируем)
    missing = set(new_params) - written
    if missing:
        log.warning("В awg0.conf отсутствовали ключи: %s (добавьте вручную)", missing)
    settings.awg_conf_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------- Адресация клиентов ----------------

def free_tunnel_ip(used_ips: set[str]) -> str:
    """Первый свободный адрес 10.8.0.x (хост .1 — сервер)."""
    net = ipaddress.ip_network(settings.awg_subnet)
    for host in net.hosts():
        ip = str(host)
        if ip == settings.awg_server_ip:
            continue
        if ip not in used_ips:
            return ip
    raise RuntimeError("Свободных адресов в туннельной подсети не осталось")


# ---------------- Клиентский конфиг ----------------

def build_client_config(device_name: str, private_key: str, psk: str, tunnel_ip: str) -> str:
    """
    Текст клиентского .conf для AmneziaVPN (импорт/QR).
    Параметры обфускации копируются из серверного конфига.
    """
    iface = _parse_interface_params(read_conf())
    server_pub = public_key_from_private(iface.get("PrivateKey", ""))
    obf_keys = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"]
    obf = "\n".join(f"{k} = {iface[k]}" for k in obf_keys if iface.get(k))
    endpoint = f"{settings.server_public_ip}:{settings.awg_port}"
    return (
        f"[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {tunnel_ip}/32\n"
        f"DNS = {settings.awg_server_ip}\n"
        f"MTU = {settings.awg_mtu}\n"
        f"{obf}\n\n"
        f"[Peer]\n"
        f"PublicKey = {server_pub}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = 0.0.0.0/0\n"
        f"Endpoint = {endpoint}\n"
        f"PersistentKeepalive = 25\n"
    )


def sync_from_clients_dir(db) -> None:
    """
    Импорт устройств из awg0.conf/clients при первом запуске бэкенда:
    install.sh создал там admin.conf — восстанавливаем его в БД
    (имя, ключи, IP), чтобы панель сразу показала устройство.
    """
    from ..models import Device  # локальный импорт против цикличности

    if not settings.clients_dir.is_dir():
        return
    # Пиры, уже присутствующие в серверном конфиге
    conf_peers = set(re.findall(r"PublicKey = ([A-Za-z0-9+/]{43}=)", read_conf()))
    if not conf_peers:
        return
    for conf_file in sorted(settings.clients_dir.glob("*.conf")):
        text = conf_file.read_text(encoding="utf-8")
        m_priv = re.search(r"^PrivateKey = ([A-Za-z0-9+/]{43}=)$", text, re.M)
        m_ip = re.search(r"^Address = (\d+\.\d+\.\d+\.\d+)/32$", text, re.M)
        m_psk = re.search(r"^PresharedKey = ([A-Za-z0-9+/]{43}=)$", text, re.M)
        if not (m_priv and m_ip and m_psk):
            continue
        try:
            pub = public_key_from_private(m_priv.group(1))
        except Exception:
            continue
        if pub not in conf_peers:
            continue
        exists = db.query(Device).filter(Device.public_key == pub).first()
        if exists:
            continue
        name = conf_file.stem
        db.add(Device(
            name=name, kind="awg", tunnel_ip=m_ip.group(1), public_key=pub,
            private_key=m_priv.group(1), psk=m_psk.group(1), enabled=True,
            is_admin_device=(name == "admin"),
        ))
        log.info("Импортировано устройство из файла: %s", name)
    db.commit()


def handshake_to_dt(ts: int) -> datetime | None:
    if ts <= 0:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc)
