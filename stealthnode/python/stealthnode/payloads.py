"""Построение объектов для API 3x-ui: инбаунды, клиенты, настройки, шаблон Xray.

Здесь только «чистые» функции без сети — их проверяют unit-тесты и локальный
E2E-тест протоколов (тот же JSON отдаётся настоящему Xray).

Ключевые решения (см. docs/TZ-REVIEW.md):
* XHTTP: ``mode=stream-one`` явно; никаких ``scMaxEachPostBytes``/``scMinPostsIntervalMs``
  (3x-ui 3.x подставлял их, и это триггерило ТСПУ летом 2026).
* REALITY: отпечаток ``firefox`` — единственный, который одновременно проходит
  фильтр ТСПУ (июнь 2026) и требование X25519MLKEM768 в Xray >= 26.9.8.
* flow ``xtls-rprx-vision`` задаётся клиенту один раз; 3x-ui сам убирает его там,
  где Vision невозможен (XHTTP, Hysteria2).
* Hysteria2 работает внутри Xray под управлением 3x-ui → общие лимиты и подписка.
"""

from __future__ import annotations

import copy
import uuid as uuidlib

from .config import TAG_HY2, TAG_VISION, TAG_XHTTP, Settings
from .util import GIB, rand_str

VISION_FLOW = "xtls-rprx-vision"

SNIFFING = {
    "enabled": True,
    "destOverride": ["http", "tls", "quic"],
    "metadataOnly": False,
    "routeOnly": True,
    "ipsExcluded": [],
    "domainsExcluded": [],
}

# Поля XHTTP, которые нельзя отдавать (детектируются ТСПУ, см. 3x-ui #5141).
FORBIDDEN_XHTTP_KEYS = ("scMaxEachPostBytes", "scMinPostsIntervalMs")


def reality_settings(s: Settings) -> dict:
    sni = s.get("SN_REALITY_SNI")
    return {
        "show": False,
        "xver": 0,
        "target": s.get("SN_REALITY_TARGET") or f"{sni}:443",
        "serverNames": [sni],
        "privateKey": s.get("SN_REALITY_PRIVATE_KEY"),
        "minClientVer": "",
        "maxClientVer": "",
        "maxTimediff": 0,
        "shortIds": [s.get("SN_REALITY_SHORT_ID")],
        "mldsa65Seed": "",
        # Клиентская часть — 3x-ui использует её только для генерации ссылок.
        "settings": {
            "publicKey": s.get("SN_REALITY_PUBLIC_KEY"),
            "fingerprint": s.get("SN_FINGERPRINT") or "firefox",
            "serverName": "",
            "spiderX": "/",
            "mldsa65Verify": "",
        },
    }


def _base_inbound(s: Settings, *, tag: str, remark: str, port: int, protocol: str, sort: int) -> dict:
    return {
        "remark": remark,
        "enable": True,
        "listen": "",
        "port": port,
        "protocol": protocol,
        "tag": tag,
        "expiryTime": 0,
        "total": 0,
        "trafficReset": "never",
        "subSortIndex": sort,
        # Адрес в ссылках = домен, а не IP из заголовка Host запроса.
        "shareAddrStrategy": "custom",
        "shareAddr": s.domain,
        "sniffing": copy.deepcopy(SNIFFING),
    }


def inbound_xhttp(s: Settings) -> dict:
    """VLESS + XHTTP + REALITY (основной профиль, Android/Windows)."""
    inb = _base_inbound(s, tag=TAG_XHTTP, remark="SN-XHTTP", port=s.int("SN_XHTTP_PORT", 443), protocol="vless", sort=1)
    inb["settings"] = {"clients": [], "decryption": "none", "encryption": "none", "fallbacks": []}
    inb["streamSettings"] = {
        "network": "xhttp",
        "security": "reality",
        "externalProxy": [],
        "realitySettings": reality_settings(s),
        "xhttpSettings": {
            "path": "/" + s.get("SN_XHTTP_PATH"),
            "host": "",
            "headers": {},
            # Явно stream-one: auto в связке с REALITY ломается у части клиентов.
            "mode": "stream-one",
        },
    }
    return inb


def inbound_vision(s: Settings) -> dict:
    """VLESS + TCP(RAW) + REALITY + Vision (iOS-клиенты без XHTTP)."""
    inb = _base_inbound(
        s, tag=TAG_VISION, remark="SN-TCP-iOS", port=s.int("SN_VISION_PORT", 8443), protocol="vless", sort=2
    )
    inb["settings"] = {"clients": [], "decryption": "none", "encryption": "none", "fallbacks": []}
    inb["streamSettings"] = {
        "network": "tcp",
        "security": "reality",
        "externalProxy": [],
        "realitySettings": reality_settings(s),
        "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}},
    }
    return inb


def inbound_hy2(s: Settings, cert_file: str, key_file: str, pin_sha256: str | None = None) -> dict:
    """Hysteria2 + Salamander поверх UDP (резерв, если режут TCP)."""
    inb = _base_inbound(s, tag=TAG_HY2, remark="SN-HY2", port=s.int("SN_HY2_PORT", 443), protocol="hysteria", sort=3)
    inb["sniffing"]["enabled"] = False
    tls_client: dict = {"fingerprint": "", "echConfigList": ""}
    if pin_sha256:
        # Self-signed: клиент проверяет отпечаток сертификата (pinSHA256), без insecure.
        tls_client["pinnedPeerCertSha256"] = [pin_sha256.lower()]
    inb["settings"] = {"version": 2, "clients": []}
    inb["streamSettings"] = {
        "network": "hysteria",
        "security": "tls",
        "externalProxy": [],
        "hysteriaSettings": {"version": 2, "udpIdleTimeout": 60},
        "tlsSettings": {
            "serverName": s.domain,
            "minVersion": "1.3",
            "maxVersion": "1.3",
            "cipherSuites": "",
            "rejectUnknownSni": False,
            "certificates": [
                {
                    "certificateFile": cert_file,
                    "keyFile": key_file,
                    "oneTimeLoading": False,
                    "usage": "encipherment",
                    "buildChain": False,
                }
            ],
            "alpn": ["h3"],
            "settings": tls_client,
        },
        "finalmask": {"udp": [{"type": "salamander", "settings": {"password": s.get("SN_HY2_OBFS_PASSWORD")}}]},
    }
    return inb


def desired_inbounds(s: Settings, cert_file: str, key_file: str, pin_sha256: str | None) -> dict[str, dict]:
    return {
        TAG_XHTTP: inbound_xhttp(s),
        TAG_VISION: inbound_vision(s),
        TAG_HY2: inbound_hy2(s, cert_file, key_file, pin_sha256),
    }


def client_record(
    name: str,
    *,
    limit_gb: float = 0,
    limit_ip: int = 0,
    monthly_reset: bool = True,
    reset_day: int = 1,
    expiry_ms: int = 0,
    sub_id: str | None = None,
    client_uuid: str | None = None,
    hy2_auth: str | None = None,
    comment: str = "",
    enable: bool = True,
) -> dict:
    """Клиент 3x-ui v3: одна запись на человека, общая квота на все инбаунды.

    ``totalGB`` в API 3x-ui — это БАЙТЫ (несмотря на имя поля).
    """
    total = int(limit_gb * GIB) if limit_gb and limit_gb > 0 else 0
    return {
        "id": client_uuid or str(uuidlib.uuid4()),
        "flow": VISION_FLOW,
        "auth": hy2_auth or rand_str(32),
        "email": name,
        "limitIp": int(limit_ip),
        "totalGB": total,
        "expiryTime": int(expiry_ms),
        "enable": enable,
        "tgId": 0,
        "subId": sub_id or rand_str(16).lower(),
        "comment": comment,
        "reset": 0,
        "trafficReset": "monthly" if (monthly_reset and total > 0) else "never",
        "trafficResetDay": int(reset_day) if (monthly_reset and total > 0) else 1,
    }


def settings_patch(s: Settings) -> dict:
    """Изменения в общих настройках панели (POST setting/update)."""
    # webListen/webPort/webBasePath задаются установщиком через `x-ui setting`
    # (до запуска панели), чтобы не потерять доступ к API посреди изменения.
    return {
        "trustedProxyCIDRs": "127.0.0.1/32,::1/128",
        # Подписка — тоже только локально, наружу через Caddy на порту панели.
        "subEnable": True,
        "subListen": "127.0.0.1",
        "subPort": s.int("SN_SUB_PORT", 2096),
        "subPath": "/" + s.get("SN_SUB_PATH") + "/",
        "subURI": s.sub_base_url,
        "subCertFile": "",
        "subKeyFile": "",
        "subTitle": "StealthNode",
        "subUpdates": 12,
        "subJsonEnable": False,
        "subClashEnable": False,
        "timeLocation": s.get("SN_TIMEZONE") or "Europe/Moscow",
        "tgLang": "ru-RU",
        "restartXrayOnClientDisable": True,
    }


def apply_settings_patch(current: dict, patch: dict) -> tuple[dict, list[str]]:
    """Наложить патч на полный объект настроек. Возвращает (новый объект, изменённые ключи)."""
    new = dict(current)
    changed = []
    for key, value in patch.items():
        if new.get(key) != value:
            # Числа панель отдаёт числами, строки — строками; сравнение по str для устойчивости.
            if str(new.get(key)) == str(value) and type(new.get(key)) is not bool:
                continue
            new[key] = value
            changed.append(key)
    return new, changed


def dns_block(strategy: str = "UseIPv4") -> dict:
    """DNS для Xray: dnscrypt-proxy по TCP напрямую (+local), резерв — DoH, затем системный.

    На серверах без IPv6 запрашиваются только A-записи (без лишних AAAA-запросов).
    """
    query = "UseIPv4" if strategy == "UseIPv4" else "UseIP"
    return {
        "tag": "dns-internal",
        "servers": [
            "tcp+local://127.0.2.1:53",
            "https+local://1.1.1.1/dns-query",
            "localhost",
        ],
        "queryStrategy": query,
        "disableCache": False,
    }


def patch_xray_template(template: dict, s: Settings) -> tuple[dict, bool]:
    """Внести DNS и стратегию freedom в шаблон Xray. Возвращает (шаблон, изменён ли)."""
    tpl = copy.deepcopy(template)
    before = repr(tpl)
    strategy = s.get("SN_FREEDOM_STRATEGY") or "UseIPv4"
    tpl["dns"] = dns_block(strategy)
    outbounds = tpl.setdefault("outbounds", [])
    direct = next((o for o in outbounds if o.get("protocol") == "freedom"), None)
    if direct is None:
        direct = {"protocol": "freedom", "tag": "direct", "settings": {}}
        outbounds.insert(0, direct)
    direct.setdefault("settings", {})
    if strategy == "AsIs":
        direct["settings"].pop("domainStrategy", None)
    else:
        direct["settings"]["domainStrategy"] = strategy
    # Журнал подключений не ведём (приватность пользователей); ошибки — warning.
    log = tpl.setdefault("log", {})
    log.setdefault("access", "none")
    log["loglevel"] = log.get("loglevel") or "warning"
    return tpl, repr(tpl) != before


def inbound_diff(current: dict, desired: dict) -> list[str]:
    """Какие управляемые поля инбаунда отличаются от желаемых (без учёта клиентов)."""
    diffs = []
    for key in ("port", "protocol", "listen", "enable", "remark", "shareAddrStrategy", "shareAddr"):
        if current.get(key) != desired.get(key):
            diffs.append(key)
    cur_stream = current.get("streamSettings") or {}
    des_stream = desired.get("streamSettings") or {}
    for key in des_stream:
        if key == "externalProxy":
            continue
        if cur_stream.get(key) != des_stream.get(key):
            diffs.append(f"streamSettings.{key}")
    cur_settings = dict(current.get("settings") or {})
    cur_settings.pop("clients", None)
    des_settings = dict(desired.get("settings") or {})
    des_settings.pop("clients", None)
    for key in des_settings:
        if cur_settings.get(key) != des_settings.get(key):
            diffs.append(f"settings.{key}")
    return diffs


def merge_inbound_for_update(current: dict, desired: dict) -> dict:
    """Объект для inbounds/update: желаемые поля + текущие клиенты (их ведёт API клиентов)."""
    merged = copy.deepcopy(desired)
    merged["id"] = current.get("id")
    cur_clients = (current.get("settings") or {}).get("clients") or []
    merged.setdefault("settings", {})["clients"] = cur_clients
    for key in ("up", "down", "total", "expiryTime"):
        if key in current:
            merged[key] = current[key]
    return merged
