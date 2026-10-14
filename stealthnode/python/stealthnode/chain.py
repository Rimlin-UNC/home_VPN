"""Связка серверов: российский «мост» (вход для клиентов) → зарубежный «выход».

Зачем (docs/RELAY.md): с 2026 года ТСПУ «замораживает» прямые сессии пользователей из РФ к
зарубежным хостингам (после 15–20 КБ данных пакеты перестают доходить), а иногда IP хостинга
недоступен целиком. Внутрироссийский трафик и обмен «сервер–сервер» фильтруются гораздо мягче.
Поэтому клиенты подключаются к серверу в РФ, а он передаёт трафик на зарубежный сервер по
VLESS + XHTTP + REALITY (несколько пользовательских соединений идут в общих HTTP/2-соединениях).

Выход (зарубежный сервер со StealthNode):
  * отдельный инбаунд ``TAG_BRIDGE_IN`` (VLESS + XHTTP stream-one + REALITY) на ``SN_EXIT_PORT``;
    в UFW он открыт только для IP моста — сканеры и ТСПУ его не видят;
  * один клиент ``BRIDGE_CLIENT`` без лимитов — учётная запись моста; к профилям пользователей
    он не привязан и в подписки не попадает;
  * правило маршрутизации ``TAG_BRIDGE_IN → direct``.
Мост (сервер в РФ со StealthNode, теми же пользователями и ключами — перенос через --restore):
  * исходящий ``TAG_EXIT`` (VLESS по ссылке выхода) первым в списке — он используется по умолчанию;
  * российские сайты (.ru/.su/.рф, крупные сервисы, geoip:ru) — напрямую с моста: банки и госуслуги
    видят российский IP, а зарубежный канал не тратится (отключается ``SN_BRIDGE_RU_DIRECT=0``);
  * DNS только для этого прямого трафика — системный резолвер моста; домены остальных сайтов
    уходят на выход неразрешёнными (без утечки DNS в РФ, маршрутизация ``AsIs``);
  * собственный трафик панели (Telegram-бот, проверки версий) — через выход (``panelOutbound``).
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import time
import urllib.parse
from pathlib import Path

from . import links
from .config import Settings
from .payloads import SNIFFING, client_record, inbound_diff, merge_inbound_for_update, reality_settings
from .util import run, which
from .xui import XuiClient, XuiError

TAG_BRIDGE_IN = "sn-bridge-in"  # инбаунд на выходе (трафик от моста)
TAG_EXIT = "sn-exit"  # исходящий на мосту (к выходу)
BRIDGE_CLIENT = "sn-bridge"  # учётная запись моста на выходе
RULE_BRIDGE_IN = "sn-bridge-in"
RULE_RU_DIRECT = "sn-ru-direct"
OUR_RULES = (RULE_BRIDGE_IN, RULE_RU_DIRECT)
UFW_COMMENT = "StealthNode exit for bridge"
F2B_JAIL_FILE = Path("/etc/fail2ban/jail.d/stealthnode.local")

# Российские сайты, которые мост отправляет напрямую. Только суффиксы доменов (domain:) и geoip:ru —
# без geosite-списков: их наличие зависит от сборки geo-файлов, а ошибка в имени списка не даёт
# Xray запуститься.
RU_DIRECT_DOMAINS = [
    "domain:ru",
    "domain:su",
    "domain:xn--p1ai",  # .рф
    "domain:vk.com",
    "domain:vk.me",
    "domain:vkuser.net",
    "domain:userapi.com",
    "domain:mycdn.me",
    "domain:yandex.net",
    "domain:yandex.com",
    "domain:yastatic.net",
    "domain:yandexcloud.net",
    "domain:sberbank.com",
]
RU_DIRECT_IPS = ["geoip:ru"]
BRIDGE_DNS_SERVERS = ["localhost", "tcp+local://127.0.2.1:53"]


class ChainError(RuntimeError):
    pass


# --- выход: инбаунд, учётная запись моста, ссылка ------------------------------------------


def exit_inbound(s: Settings) -> dict:
    """Инбаунд выхода: как основной XHTTP-профиль, но свой порт, путь и адрес-IP в ссылке."""
    return {
        "remark": "SN-EXIT-for-bridge",
        "enable": True,
        "listen": "",
        "port": s.int("SN_EXIT_PORT"),
        "protocol": "vless",
        "tag": TAG_BRIDGE_IN,
        "expiryTime": 0,
        "total": 0,
        "trafficReset": "never",
        "subSortIndex": 99,
        # Домен указывает на мост, поэтому мост подключается к выходу по IP.
        "shareAddrStrategy": "custom",
        "shareAddr": s.get("SN_PUBLIC_IP") or s.domain,
        "sniffing": dict(SNIFFING),
        "settings": {"clients": [], "decryption": "none", "encryption": "none", "fallbacks": []},
        "streamSettings": {
            "network": "xhttp",
            "security": "reality",
            "externalProxy": [],
            "realitySettings": reality_settings(s),
            "xhttpSettings": {"path": "/" + s.get("SN_EXIT_PATH"), "host": "", "headers": {}, "mode": "stream-one"},
        },
    }


def bridge_client(existing_uuid: str | None = None) -> dict:
    return client_record(
        BRIDGE_CLIENT, limit_gb=0, limit_ip=0, monthly_reset=False, client_uuid=existing_uuid,
        comment="мост StealthNode (вход в РФ); не удалять",
    )


def exit_link(s: Settings, client_uuid: str) -> str:
    """Ссылка для моста (``install.sh --exit-link`` / ``stealthnode bridge set``)."""
    host = s.get("SN_PUBLIC_IP") or s.domain
    if ":" in host:  # IPv6
        host = f"[{host}]"
    params = {
        "type": "xhttp",
        "encryption": "none",
        "security": "reality",
        "pbk": s.get("SN_REALITY_PUBLIC_KEY"),
        "fp": s.get("SN_FINGERPRINT") or "firefox",
        "sni": s.get("SN_REALITY_SNI"),
        "sid": s.get("SN_REALITY_SHORT_ID"),
        "spx": "/",
        "path": "/" + s.get("SN_EXIT_PATH"),
        "mode": "stream-one",
    }
    return f"vless://{client_uuid}@{host}:{s.int('SN_EXIT_PORT')}?{urllib.parse.urlencode(params)}#SN-EXIT"


def find_inbound(xui: XuiClient, tag: str) -> dict | None:
    return next((i for i in xui.list_inbounds() if i.get("tag") == tag), None)


def bridge_client_uuid(xui: XuiClient) -> str | None:
    obj = xui.get_client(BRIDGE_CLIENT)
    if not obj:
        return None
    rec = obj.get("client", obj)
    return rec.get("uuid") or rec.get("id") or None


def _transport(inb: dict) -> str:
    return "udp" if inb.get("protocol") in ("hysteria", "wireguard", "tuic", "amneziawg") else "tcp"


def sync_exit_role(s: Settings, xui: XuiClient) -> list[str]:
    """Инбаунд выхода и учётная запись моста есть ⇔ сервер служит выходом. Возвращает изменения."""
    changes: list[str] = []
    inb = find_inbound(xui, TAG_BRIDGE_IN)
    if not s.is_exit:
        # Например, архив выхода восстановлен на сам мост, или режим выхода выключен.
        if xui.get_client(BRIDGE_CLIENT):
            xui.delete_client(BRIDGE_CLIENT)
            changes.append("удалена учётная запись моста")
        if inb is not None:
            xui.delete_inbound(int(inb["id"]))
            changes.append("удалён инбаунд выхода")
        return changes
    want = exit_inbound(s)
    for other in xui.list_inbounds():
        if other.get("tag") != TAG_BRIDGE_IN and int(other.get("port", 0)) == want["port"] and _transport(other) == "tcp":
            raise XuiError(f"порт выхода {want['port']}/tcp занят инбаундом {other.get('remark') or other.get('tag')!r}")
    if inb is None:
        xui.add_inbound(want)
        inb = find_inbound(xui, TAG_BRIDGE_IN)
        if inb is None:
            raise XuiError("панель не сохранила инбаунд выхода")
        changes.append(f"создан инбаунд выхода для моста (порт {want['port']})")
    else:
        diffs = inbound_diff(inb, want)
        if diffs:
            xui.update_inbound(int(inb["id"]), merge_inbound_for_update(inb, want))
            changes.append("инбаунд выхода исправлен: " + ", ".join(diffs))
    obj = xui.get_client(BRIDGE_CLIENT)
    if not obj:
        xui.add_client(bridge_client(), [int(inb["id"])])
        changes.append("создана учётная запись моста")
    else:
        rec = obj.get("client", obj)
        have = [int(i) for i in (obj.get("inboundIds") or rec.get("inboundIds") or [])]
        if int(inb["id"]) not in have:
            xui.attach_client(BRIDGE_CLIENT, [int(inb["id"])])
            changes.append("учётная запись моста привязана к инбаунду выхода")
    return changes


# --- шаблон Xray ----------------------------------------------------------------------------


def bridge_outbound(link_text: str) -> dict:
    link = links.parse(link_text)
    if link.scheme != "vless" or link.params.get("security") != "reality":
        raise ChainError("ссылка выхода: нужна vless:// с security=reality")
    return links.xray_outbound(link, TAG_EXIT)


def patch_template_chain(tpl: dict, s: Settings) -> None:
    """Привести шаблон Xray к роли сервера (на месте). Чужие правила и исходящие не трогаются."""
    outbounds = tpl.setdefault("outbounds", [])
    outbounds[:] = [o for o in outbounds if o.get("tag") != TAG_EXIT]
    routing = tpl.setdefault("routing", {})
    rules = [r for r in routing.get("rules", []) if r.get("ruleTag") not in OUR_RULES]
    if s.is_exit:
        # Трафик моста уходит в интернет (и никогда — обратно в исходящий к выходу: защита от петли).
        rules.append({"type": "field", "ruleTag": RULE_BRIDGE_IN, "inboundTag": [TAG_BRIDGE_IN], "outboundTag": "direct"})
    if s.is_bridge:
        # Первый исходящий — исходящий по умолчанию: всё, что не попало под правила, идёт на выход.
        outbounds.insert(0, bridge_outbound(s.get("SN_BRIDGE_EXIT_LINK")))
        if s.ru_direct:
            rules.append({"type": "field", "ruleTag": RULE_RU_DIRECT, "domain": list(RU_DIRECT_DOMAINS),
                          "ip": list(RU_DIRECT_IPS), "outboundTag": "direct"})
        dns = tpl.get("dns")
        if isinstance(dns, dict):
            dns["servers"] = list(BRIDGE_DNS_SERVERS)
    routing["rules"] = rules
    routing.setdefault("domainStrategy", "AsIs")


# --- файрвол и fail2ban на выходе -------------------------------------------------------------


def _ufw_rule(bridge_ip: str, port: int) -> list[str]:
    return ["proto", "tcp", "from", bridge_ip, "to", "any", "port", str(port)]


def ufw_allow_bridge(bridge_ip: str, port: int) -> bool:
    if not which("ufw"):
        return False
    proc = run(["ufw", "allow", *_ufw_rule(bridge_ip, port), "comment", UFW_COMMENT], check=False, timeout=30)
    return proc.returncode == 0


def ufw_delete_bridge(bridge_ip: str, port: int) -> None:
    if which("ufw") and bridge_ip and port:
        run(["ufw", "delete", "allow", *_ufw_rule(bridge_ip, port)], check=False, timeout=30)


def ufw_has_bridge_rule(bridge_ip: str, port: int) -> bool | None:
    if not which("ufw"):
        return None
    out = run(["ufw", "status"], check=False, timeout=30).stdout
    return any(re.search(rf"^{port}/tcp\s+ALLOW(?: IN)?\s+{re.escape(bridge_ip)}\b", line) for line in out.splitlines())


def f2b_set_ignore(add: str | None = None, remove: str | None = None, jail_file: Path | None = None) -> bool:
    """Добавить/убрать IP в ignoreip нашего jail-файла и перечитать fail2ban. True — файл изменён."""
    jail_file = jail_file or F2B_JAIL_FILE
    if not jail_file.is_file():
        return False
    text = jail_file.read_text(encoding="utf-8")
    m = re.search(r"^ignoreip\s*=\s*(.*)$", text, re.M)
    if not m:
        return False
    items = m.group(1).split()
    if remove and remove != add:
        items = [i for i in items if i != remove]
    if add and add not in items:
        items.append(add)
    new_line = "ignoreip = " + " ".join(items)
    if new_line == m.group(0):
        return False
    jail_file.write_text(text[: m.start()] + new_line + text[m.end():], encoding="utf-8")
    if which("fail2ban-client"):
        run(["fail2ban-client", "reload"], check=False, timeout=60)
    return True


# --- проверки звена мост → выход -------------------------------------------------------------


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def probe_exit(link_text: str, timeout: float = 8, cafile: str | None = None) -> dict:
    """С моста: TCP до выхода и REALITY-маскировка (без ключа выход должен отдать настоящий
    сертификат сайта-цели). Так видно, что звено через границу не режется и не подменяется."""
    link = links.parse(link_text)
    sni = link.params.get("sni", "")
    result: dict = {"host": link.host, "port": link.port, "sni": sni}
    t0 = time.monotonic()
    try:
        raw = socket.create_connection((link.host, link.port), timeout=timeout)
    except OSError as exc:
        result["error"] = f"TCP: {exc}"
        return result
    result["tcp_ms"] = int((time.monotonic() - t0) * 1000)
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    try:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            cert = tls.getpeercert() or {}
            result["tls"] = tls.version()
            subject = dict(item[0] for item in cert.get("subject", ()))
            result["cert_cn"] = subject.get("commonName", "")
    except ssl.SSLCertVerificationError as exc:
        result["error"] = f"сертификат не прошёл проверку ({exc.verify_message}) — подмена на пути?"
    except OSError as exc:
        result["error"] = f"TLS: {exc}"
    finally:
        raw.close()
    return result
