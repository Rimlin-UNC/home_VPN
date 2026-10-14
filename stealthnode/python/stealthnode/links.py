"""Разбор ссылок vless:// и hysteria2:// и сборка из них клиентских конфигов.

Используется в ``stealthnode doctor --e2e`` (реальное подключение с самого
сервера через бинарник Xray из комплекта 3x-ui) и в тестах. Заодно это
проверка, что ссылки из подписки содержат всё, что требует ТЗ
(mode=stream-one, fp=firefox, flow только у TCP, obfs=salamander и т.д.).
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, field


class LinkError(ValueError):
    pass


@dataclass
class ShareLink:
    scheme: str
    user: str
    host: str
    port: int
    params: dict[str, str] = field(default_factory=dict)
    remark: str = ""

    @property
    def kind(self) -> str:
        """Короткое имя профиля: xhttp / vision / hysteria2 / другое."""
        if self.scheme == "hysteria2":
            return "hysteria2"
        net = self.params.get("type", "tcp")
        if net == "xhttp":
            return "xhttp"
        if net in ("tcp", "raw") and self.params.get("flow", "").startswith("xtls-rprx-vision"):
            return "vision"
        return f"vless-{net}"

    def with_address(self, host: str) -> ShareLink:
        return ShareLink(self.scheme, self.user, host, self.port, dict(self.params), self.remark)


def parse(link: str) -> ShareLink:
    link = link.strip()
    parts = urllib.parse.urlsplit(link)
    scheme = parts.scheme.lower()
    if scheme == "hy2":
        scheme = "hysteria2"
    if scheme not in ("vless", "hysteria2"):
        raise LinkError(f"неподдерживаемая схема: {parts.scheme!r}")
    if not parts.hostname:
        raise LinkError("в ссылке нет адреса сервера")
    try:
        port = parts.port
    except ValueError as exc:
        raise LinkError(f"некорректный порт: {exc}") from exc
    if not port:
        raise LinkError("в ссылке нет порта")
    user = urllib.parse.unquote(parts.username or "")
    if parts.password:
        # hysteria2://user:pass@ — официальный формат auth "user:pass"
        user = f"{user}:{urllib.parse.unquote(parts.password)}"
    if not user:
        raise LinkError("в ссылке нет идентификатора пользователя")
    params = {k: v[0] for k, v in urllib.parse.parse_qs(parts.query, keep_blank_values=True).items()}
    return ShareLink(scheme, user, parts.hostname, port, params, urllib.parse.unquote(parts.fragment))


def _xhttp_settings(p: dict[str, str]) -> dict:
    settings: dict = {"path": p.get("path", "/"), "mode": p.get("mode", "auto")}
    if p.get("host"):
        settings["host"] = p["host"]
    if p.get("extra"):
        try:
            extra = json.loads(p["extra"])
        except json.JSONDecodeError as exc:
            raise LinkError(f"параметр extra не JSON: {exc}") from exc
        if isinstance(extra, dict):
            settings["extra"] = extra
    return settings


def _vless_outbound(link: ShareLink, tag: str) -> dict:
    p = link.params
    network = p.get("type", "tcp")
    if network == "raw":
        network = "tcp"
    security = p.get("security", "none")
    stream: dict = {"network": network, "security": security}
    if security == "reality":
        stream["realitySettings"] = {
            "serverName": p.get("sni", ""),
            "fingerprint": p.get("fp", "firefox"),
            "publicKey": p.get("pbk", ""),
            "shortId": p.get("sid", ""),
            "spiderX": p.get("spx", "/"),
        }
    elif security == "tls":
        tls = {"serverName": p.get("sni", ""), "fingerprint": p.get("fp", "")}
        if p.get("alpn"):
            tls["alpn"] = p["alpn"].split(",")
        stream["tlsSettings"] = tls
    if network == "xhttp":
        stream["xhttpSettings"] = _xhttp_settings(p)
    elif network == "tcp":
        stream["tcpSettings"] = {"header": {"type": p.get("headerType", "none") or "none"}}
    user = {"address": link.host, "port": link.port, "id": link.user, "encryption": p.get("encryption", "none")}
    if p.get("flow"):
        user["flow"] = p["flow"]
    return {"protocol": "vless", "tag": tag, "settings": user, "streamSettings": stream}


def _hysteria_outbound(link: ShareLink, tag: str, ca_file: str | None = None) -> dict:
    p = link.params
    tls: dict = {"serverName": p.get("sni", "") or link.host, "alpn": (p.get("alpn") or "h3").split(",")}
    if p.get("pinSHA256"):
        tls["pinnedPeerCertSha256"] = p["pinSHA256"]
    if ca_file:
        tls["certificates"] = [{"usage": "verify", "certificateFile": ca_file}]
    stream: dict = {
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": tls,
        "hysteriaSettings": {"version": 2, "auth": link.user},
    }
    obfs = p.get("obfs", "")
    if obfs:
        if obfs != "salamander":
            raise LinkError(f"неподдерживаемый obfs: {obfs}")
        stream["finalmask"] = {"udp": [{"type": "salamander", "settings": {"password": p.get("obfs-password", "")}}]}
    return {
        "protocol": "hysteria",
        "tag": tag,
        "settings": {"version": 2, "address": link.host, "port": link.port},
        "streamSettings": stream,
    }


def xray_outbound(link: ShareLink, tag: str = "proxy", ca_file: str | None = None) -> dict:
    if link.scheme == "vless":
        return _vless_outbound(link, tag)
    return _hysteria_outbound(link, tag, ca_file)


def xray_client_config(link: ShareLink, socks_port: int, *, ca_file: str | None = None, loglevel: str = "warning") -> dict:
    """Минимальный клиентский конфиг Xray: SOCKS на 127.0.0.1 → прокси по ссылке."""
    return {
        "log": {"loglevel": loglevel},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [xray_outbound(link, "proxy", ca_file), {"protocol": "freedom", "tag": "direct"}],
    }


def hysteria_client_config(link: ShareLink, socks_port: int, *, ca_file: str | None = None) -> dict:
    """Конфиг официального клиента Hysteria2 (проверка совместимости ссылок)."""
    if link.scheme != "hysteria2":
        raise LinkError("нужна ссылка hysteria2://")
    p = link.params
    tls: dict = {"sni": p.get("sni", "") or link.host, "insecure": p.get("insecure") == "1"}
    if p.get("pinSHA256"):
        tls["pinSHA256"] = p["pinSHA256"]
    if ca_file:
        tls["ca"] = ca_file
    cfg: dict = {
        "server": f"{link.host}:{link.port}",
        "auth": link.user,
        "tls": tls,
        "socks5": {"listen": f"127.0.0.1:{socks_port}"},
    }
    if p.get("obfs") == "salamander":
        cfg["obfs"] = {"type": "salamander", "salamander": {"password": p.get("obfs-password", "")}}
    return cfg


# --- Проверка соответствия ссылок требованиям ТЗ -------------------------------


def audit(link: ShareLink, expected_fp: str = "firefox") -> list[str]:
    """Список нарушений требований ТЗ для ссылки (пустой — всё хорошо)."""
    problems = []
    p = link.params
    kind = link.kind
    if link.scheme == "vless":
        if p.get("security") != "reality":
            problems.append("security должен быть reality")
        if p.get("fp") != expected_fp:
            problems.append(f"fp={p.get('fp')!r}, требуется {expected_fp}")
        for key in ("pbk", "sid", "sni"):
            if not p.get(key):
                problems.append(f"нет параметра {key}")
        if kind == "xhttp":
            if p.get("mode") != "stream-one":
                problems.append(f"mode={p.get('mode')!r}, требуется stream-one")
            if p.get("flow"):
                problems.append("у XHTTP не должно быть flow")
            extra = p.get("extra", "")
            for bad in ("scMaxEachPostBytes", "scMinPostsIntervalMs"):
                if bad in extra:
                    problems.append(f"в extra есть {bad} (детектируется ТСПУ)")
        elif kind != "vision":
            problems.append(f"неожиданный профиль VLESS: {kind}")
    else:
        if p.get("obfs") != "salamander" or not p.get("obfs-password"):
            problems.append("нет обфускации salamander")
        if p.get("insecure") == "1":
            problems.append("insecure=1 (уязвимо к MITM, а Xray >= 26 его не поддерживает)")
        if not p.get("sni"):
            problems.append("нет sni")
    return problems
