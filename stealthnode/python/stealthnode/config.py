"""Пути, параметры установки и генерация недостающих секретов.

Единственный источник правды о параметрах — ``/opt/stealthnode/.env`` (600).
Пользователи и их лимиты хранятся в базе 3x-ui (панель — источник правды).
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path

from . import envfile, x25519
from .util import LOWER_ALNUM, rand_hex, rand_str

# --- Пути --------------------------------------------------------------------


def sn_root() -> Path:
    return Path(os.environ.get("SN_ROOT", "/opt/stealthnode"))


def env_path() -> Path:
    return sn_root() / ".env"


def credentials_path() -> Path:
    return Path(os.environ.get("SN_CREDENTIALS_FILE", "/root/stealthnode-credentials.txt"))


XUI_DIR = Path(os.environ.get("SN_XUI_DIR", "/usr/local/x-ui"))
XUI_BIN = XUI_DIR / "x-ui"
XUI_DB = Path(os.environ.get("SN_XUI_DB", "/etc/x-ui/x-ui.db"))
XUI_LOG = Path("/var/log/x-ui/3xui.log")
CADDY_DATA = Path(os.environ.get("SN_CADDY_DATA", "/var/lib/caddy/.local/share/caddy"))


def xray_bin() -> Path | None:
    """Бинарник Xray, который поставляет 3x-ui (bin/xray-linux-<arch>)."""
    override = os.environ.get("SN_XRAY_BIN")
    if override:
        return Path(override)
    for cand in sorted((XUI_DIR / "bin").glob("xray-linux-*")):
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return None


# --- Константы ------------------------------------------------------------------

DEFAULT_SNI = "max.ru"
DEFAULT_FINGERPRINT = "firefox"
# Отпечатки uTLS, которые проходят и REALITY (Xray >= 26.9.8 требует X25519MLKEM768),
# и фильтр ТСПУ лета 2026 (Chrome/Safari/iOS при >3 сессиях к одному SNI замораживаются).
SAFE_FINGERPRINTS = {"firefox"}
# Отпечатки, которые Xray-клиент вообще сможет использовать с REALITY >= 26.9.8.
REALITY_CAPABLE_FINGERPRINTS = {"firefox", "chrome", "safari"}

RESERVED_PORTS = {22, 53, 80, 443, 2019, 2096, 8443, 11111, 62789}

# Пароль панели: сгенерированный — 24 символа; свой (stealthnode panel-password) — от 8.
PANEL_PASSWORD_MIN = 8
PANEL_PASSWORD_RECOMMENDED = 12

TAG_XHTTP = "sn-vless-xhttp"
TAG_VISION = "sn-vless-vision"
TAG_HY2 = "sn-hysteria2"
# Профили пользователей. Инбаунд выхода для моста (chain.TAG_BRIDGE_IN) сюда не входит:
# пользователи к нему не привязываются и в подписку он не попадает.
ALL_TAGS = (TAG_XHTTP, TAG_VISION, TAG_HY2)
EXIT_PORT_RANGE = (40000, 49999)

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
_PATH_RE = re.compile(r"^[A-Za-z0-9_-]{6,64}$")
_SHORT_ID_RE = re.compile(r"^[0-9a-f]{2,16}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value or ""))


def admin_ips(value: str) -> list[str]:
    """``SN_ADMIN_IP``: IP/подсети владельца через пробел или запятую (не банятся fail2ban)."""
    return [item for item in re.split(r"[\s,]+", value or "") if item]


def port_is_free(port: int, proto: str = "tcp") -> bool:
    """Проверка, что порт не занят (пробная привязка на 0.0.0.0)."""
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
        except OSError:
            return False
    return True


def pick_port(low: int, high: int, exclude: set[int]) -> int:
    import secrets

    for _ in range(200):
        port = low + secrets.randbelow(high - low + 1)
        if port in exclude or port in RESERVED_PORTS:
            continue
        if port_is_free(port, "tcp"):
            return port
    raise RuntimeError(f"не удалось подобрать свободный порт в диапазоне {low}-{high}")


# --- Параметры -----------------------------------------------------------------

ENV_ORDER = [
    "SN_VERSION",
    "SN_DOMAIN",
    "SN_PUBLIC_IP",
    "SN_ACME_EMAIL",
    "SN_TLS_MODE",
    "SN_REALITY_SNI",
    "SN_REALITY_TARGET",
    "SN_FINGERPRINT",
    "SN_REALITY_PRIVATE_KEY",
    "SN_REALITY_PUBLIC_KEY",
    "SN_REALITY_SHORT_ID",
    "SN_XHTTP_PORT",
    "SN_XHTTP_PATH",
    "SN_VISION_PORT",
    "SN_HY2_PORT",
    "SN_HY2_OBFS_PASSWORD",
    "SN_HY2_CERT_MODE",
    "SN_PANEL_PORT",
    "SN_PANEL_PATH",
    "SN_XUI_PORT",
    "SN_XUI_USERNAME",
    "SN_XUI_PASSWORD",
    "SN_XUI_API_TOKEN",
    "SN_SUB_PORT",
    "SN_SUB_PATH",
    "SN_SSH_PORT",
    "SN_ADMIN_IP",
    "SN_EXIT_BRIDGE_IP",
    "SN_EXIT_PORT",
    "SN_EXIT_PATH",
    "SN_BRIDGE_EXIT_LINK",
    "SN_BRIDGE_RU_DIRECT",
    "SN_FREEDOM_STRATEGY",
    "SN_TIMEZONE",
    "SN_DEFAULT_LIMIT_GB",
    "SN_DEFAULT_IP_LIMIT",
    "SN_OWNER_NAME",
]

ENV_HEADER = (
    "StealthNode: параметры и секреты установки. Права 600, владелец root.\n"
    "Не публикуйте этот файл. Повторный запуск install.sh сохраняет значения отсюда.\n"
    "Пользователи и лимиты хранятся в панели 3x-ui (/etc/x-ui/x-ui.db)."
)


@dataclass
class Settings:
    values: dict[str, str] = field(default_factory=dict)

    # Удобный доступ -------------------------------------------------------
    def get(self, key: str, default: str = "") -> str:
        return self.values.get(key, default)

    def int(self, key: str, default: int = 0) -> int:
        raw = self.values.get(key, "")
        return int(raw) if raw.strip() else default

    @property
    def domain(self) -> str:
        return self.get("SN_DOMAIN")

    @property
    def panel_url(self) -> str:
        return f"https://{self.domain}:{self.get('SN_PANEL_PORT')}/{self.get('SN_PANEL_PATH')}/"

    @property
    def sub_base_url(self) -> str:
        return f"https://{self.domain}:{self.get('SN_PANEL_PORT')}/{self.get('SN_SUB_PATH')}/"

    @property
    def is_exit(self) -> bool:
        """Зарубежный «выход»: принимает трафик российского моста (SN_EXIT_BRIDGE_IP)."""
        return bool(self.get("SN_EXIT_BRIDGE_IP"))

    @property
    def is_bridge(self) -> bool:
        """Российский «мост»: клиенты подключаются сюда, трафик уходит на выход (SN_BRIDGE_EXIT_LINK)."""
        return bool(self.get("SN_BRIDGE_EXIT_LINK"))

    @property
    def ru_direct(self) -> bool:
        return self.get("SN_BRIDGE_RU_DIRECT", "1") != "0"

    @property
    def xui_api_base(self) -> str:
        """Внутренний адрес API панели (только 127.0.0.1)."""
        return f"http://127.0.0.1:{self.get('SN_XUI_PORT')}/{self.get('SN_PANEL_PATH')}"

    def validate(self) -> list[str]:
        """Список ошибок конфигурации (пустой — всё хорошо)."""
        errors = []
        if not is_valid_domain(self.domain):
            errors.append(f"SN_DOMAIN: некорректный домен {self.domain!r}")
        sni = self.get("SN_REALITY_SNI")
        if not is_valid_domain(sni):
            errors.append(f"SN_REALITY_SNI: некорректный домен {sni!r}")
        for key in ("SN_XHTTP_PORT", "SN_VISION_PORT", "SN_HY2_PORT", "SN_PANEL_PORT", "SN_XUI_PORT", "SN_SUB_PORT"):
            try:
                port = self.int(key)
            except ValueError:
                errors.append(f"{key}: не число")
                continue
            if not 1 <= port <= 65535:
                errors.append(f"{key}: порт вне диапазона 1-65535")
        tcp_ports = [self.get(k) for k in ("SN_XHTTP_PORT", "SN_VISION_PORT", "SN_PANEL_PORT", "SN_XUI_PORT", "SN_SUB_PORT")]
        if len(set(tcp_ports)) != len(tcp_ports):
            errors.append("TCP-порты XHTTP/Vision/панели/подписки должны различаться")
        for key in ("SN_XHTTP_PATH", "SN_PANEL_PATH", "SN_SUB_PATH"):
            if not _PATH_RE.match(self.get(key)):
                errors.append(f"{key}: ожидается 6-64 символов [A-Za-z0-9_-]")
        if not _SHORT_ID_RE.match(self.get("SN_REALITY_SHORT_ID")):
            errors.append("SN_REALITY_SHORT_ID: ожидается 2-16 hex-символов")
        if len(self.get("SN_HY2_OBFS_PASSWORD")) < 16:
            errors.append("SN_HY2_OBFS_PASSWORD: минимум 16 символов")
        if len(self.get("SN_XUI_PASSWORD")) < PANEL_PASSWORD_MIN:
            errors.append(f"SN_XUI_PASSWORD: минимум {PANEL_PASSWORD_MIN} символов")
        for item in admin_ips(self.get("SN_ADMIN_IP")):
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                errors.append(f"SN_ADMIN_IP: некорректный IP или подсеть {item!r}")
        errors.extend(self._chain_errors())
        if self.get("SN_TLS_MODE") not in ("acme", "internal"):
            errors.append("SN_TLS_MODE: допустимо acme или internal")
        if self.get("SN_FINGERPRINT") not in REALITY_CAPABLE_FINGERPRINTS:
            errors.append(
                "SN_FINGERPRINT: с REALITY в Xray >= 26.9.8 работают только firefox/chrome/safari "
                "(рекомендуется firefox)"
            )
        email = self.get("SN_ACME_EMAIL")
        if email and not _EMAIL_RE.match(email):
            errors.append(f"SN_ACME_EMAIL: некорректный адрес {email!r}")
        if self.get("SN_FREEDOM_STRATEGY") not in ("UseIPv4", "UseIPv4v6", "UseIP", "AsIs"):
            errors.append("SN_FREEDOM_STRATEGY: допустимо UseIPv4, UseIPv4v6, UseIP, AsIs")
        try:
            priv = self.get("SN_REALITY_PRIVATE_KEY")
            if x25519.public_key(priv) != self.get("SN_REALITY_PUBLIC_KEY"):
                errors.append("SN_REALITY_PUBLIC_KEY не соответствует приватному ключу")
        except Exception:  # noqa: BLE001 - любой мусор в ключе = ошибка конфигурации
            errors.append("SN_REALITY_PRIVATE_KEY: некорректный ключ")
        return errors

    def _chain_errors(self) -> list[str]:
        """Проверка параметров связки «мост → выход» (см. chain.py, docs/RELAY.md)."""
        errors = []
        if self.is_exit:
            try:
                ipaddress.ip_address(self.get("SN_EXIT_BRIDGE_IP"))
            except ValueError:
                errors.append(f"SN_EXIT_BRIDGE_IP: ожидается IP-адрес моста, получено {self.get('SN_EXIT_BRIDGE_IP')!r}")
            port = self.get("SN_EXIT_PORT")
            if not port.isdigit() or not 1 <= int(port) <= 65535:
                errors.append("SN_EXIT_PORT: порт вне диапазона 1-65535")
            elif port in {self.get(k) for k in ("SN_XHTTP_PORT", "SN_VISION_PORT", "SN_PANEL_PORT", "SN_XUI_PORT",
                                                  "SN_SUB_PORT")}:
                errors.append(f"SN_EXIT_PORT: порт {port} уже занят другим профилем StealthNode")
            if not _PATH_RE.match(self.get("SN_EXIT_PATH")):
                errors.append("SN_EXIT_PATH: ожидается 6-64 символов [A-Za-z0-9_-]")
        if self.is_bridge:
            from . import links  # локальный импорт: links не зависит от config

            try:
                link = links.parse(self.get("SN_BRIDGE_EXIT_LINK"))
                if link.scheme != "vless" or link.params.get("security") != "reality":
                    raise links.LinkError("нужна ссылка vless:// с security=reality (stealthnode exit link на выходе)")
                if link.params.get("type", "tcp") not in ("xhttp", "tcp", "raw"):
                    raise links.LinkError(f"неподдерживаемый транспорт {link.params.get('type')!r}")
                if link.host in (self.domain, self.get("SN_PUBLIC_IP")):
                    raise links.LinkError("ссылка выхода указывает на этот же сервер")
            except links.LinkError as exc:
                errors.append(f"SN_BRIDGE_EXIT_LINK: {exc}")
        return errors

    def warnings(self) -> list[str]:
        warns = []
        if PANEL_PASSWORD_MIN <= len(self.get("SN_XUI_PASSWORD")) < PANEL_PASSWORD_RECOMMENDED:
            warns.append(f"пароль панели короче {PANEL_PASSWORD_RECOMMENDED} символов — лучше длиннее")
        if self.get("SN_FINGERPRINT") not in SAFE_FINGERPRINTS:
            warns.append(
                f"отпечаток {self.get('SN_FINGERPRINT')!r}: при >3 параллельных TLS-сессиях к одному SNI "
                "ТСПУ (с июня 2026) замораживает соединения с отпечатками Chrome/Safari — используйте firefox"
            )
        sni = self.get("SN_REALITY_SNI")
        if any(bad in sni for bad in ("google", "microsoft", "apple.com", "cloudflare")):
            warns.append(f"SNI {sni!r} не рекомендуется (крупные сервисы с CDN, часто в стоп-листах)")
        if self.domain.endswith((".ru", ".xn--p1ai", ".su")) or "vpn" in self.domain.split(".")[0]:
            warns.append(
                f"домен {self.domain!r}: зона .ru/«vpn» в имени и сертификат в CT-логах облегчают обнаружение "
                "(см. docs/TZ-REVIEW.md); можно сменить параметром --domain"
            )
        return warns


def fill_defaults(values: dict[str, str], version: str) -> dict[str, str]:
    """Дополнить параметры значениями по умолчанию и сгенерировать недостающие секреты.

    Уже существующие значения не меняются (идемпотентность повторной установки).
    """
    v = dict(values)

    def setdefault(key: str, factory):
        if not v.get(key):
            v[key] = factory() if callable(factory) else factory

    v["SN_VERSION"] = version
    v["SN_DOMAIN"] = v.get("SN_DOMAIN", "").strip().lower().rstrip(".")
    setdefault("SN_TLS_MODE", "acme")
    setdefault("SN_REALITY_SNI", DEFAULT_SNI)
    v["SN_REALITY_SNI"] = v["SN_REALITY_SNI"].strip().lower()
    setdefault("SN_REALITY_TARGET", lambda: f"{v['SN_REALITY_SNI']}:443")
    setdefault("SN_FINGERPRINT", DEFAULT_FINGERPRINT)
    if not v.get("SN_REALITY_PRIVATE_KEY"):
        priv, pub = x25519.generate_keypair()
        v["SN_REALITY_PRIVATE_KEY"], v["SN_REALITY_PUBLIC_KEY"] = priv, pub
    else:
        v["SN_REALITY_PUBLIC_KEY"] = x25519.public_key(v["SN_REALITY_PRIVATE_KEY"])
    setdefault("SN_REALITY_SHORT_ID", lambda: rand_hex(8))
    setdefault("SN_XHTTP_PORT", "443")
    setdefault("SN_XHTTP_PATH", lambda: rand_str(16, LOWER_ALNUM))
    setdefault("SN_VISION_PORT", "8443")
    setdefault("SN_HY2_PORT", "443")
    setdefault("SN_HY2_OBFS_PASSWORD", lambda: rand_str(32))
    setdefault("SN_HY2_CERT_MODE", "selfsigned")
    used = {int(v[k]) for k in ("SN_XHTTP_PORT", "SN_VISION_PORT") if v.get(k, "").isdigit()}
    setdefault("SN_SUB_PORT", "2096")
    used.add(int(v["SN_SUB_PORT"]))
    if v.get("SN_SSH_PORT", "").isdigit():
        used.add(int(v["SN_SSH_PORT"]))
    setdefault("SN_PANEL_PORT", lambda: str(pick_port(20000, 29999, used)))
    used.add(int(v["SN_PANEL_PORT"]))
    setdefault("SN_XUI_PORT", lambda: str(pick_port(30000, 39999, used)))
    setdefault("SN_PANEL_PATH", lambda: rand_str(18, LOWER_ALNUM))
    setdefault("SN_SUB_PATH", lambda: rand_str(16, LOWER_ALNUM))
    setdefault("SN_XUI_USERNAME", lambda: "sn" + rand_str(8, LOWER_ALNUM))
    setdefault("SN_XUI_PASSWORD", lambda: rand_str(24))
    setdefault("SN_XUI_API_TOKEN", "")
    setdefault("SN_SSH_PORT", "22")
    setdefault("SN_FREEDOM_STRATEGY", "UseIPv4")
    setdefault("SN_TIMEZONE", "Europe/Moscow")
    setdefault("SN_DEFAULT_LIMIT_GB", "50")
    setdefault("SN_DEFAULT_IP_LIMIT", "2")
    setdefault("SN_OWNER_NAME", "owner")
    setdefault("SN_PUBLIC_IP", "")
    setdefault("SN_ACME_EMAIL", "")
    if v.get("SN_EXIT_BRIDGE_IP"):
        # Порт и путь инбаунда выхода — только когда сервер служит выходом для моста.
        used.update(int(v[k]) for k in ("SN_XUI_PORT", "SN_SUB_PORT") if v.get(k, "").isdigit())
        setdefault("SN_EXIT_PORT", lambda: str(pick_port(*EXIT_PORT_RANGE, used)))
        setdefault("SN_EXIT_PATH", lambda: rand_str(16, LOWER_ALNUM))
    ordered = {k: v[k] for k in ENV_ORDER if k in v}
    ordered.update({k: val for k, val in v.items() if k not in ordered})
    return ordered


def load_settings(path: Path | None = None) -> Settings:
    return Settings(envfile.load(path or env_path()))


def save_settings(settings: Settings, path: Path | None = None) -> None:
    envfile.save(path or env_path(), settings.values, ENV_HEADER)
