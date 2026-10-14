"""``stealthnode doctor`` — проверка сервера по разделу 8 ТЗ (в исправленном виде).

Отличия от исходных тестов ТЗ (см. docs/TESTING.md):
* ``curl -k https://vpn.shprv.ru`` на 443 проверял бы REALITY (там Xray), а не панель —
  панель проверяется на её собственном порту с проверкой сертификата;
* «Reality handshake» проверяется двумя способами: маскировка (без ключа сервер
  отдаёт настоящий сертификат SNI) и реальное подключение клиентом Xray (``--e2e``).
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import ssl
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from . import config, links, users
from .config import Settings
from .util import Console, human_bytes, run, which
from .xui import XuiClient, XuiError

OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"


@dataclass
class Check:
    status: str
    title: str
    detail: str = ""


class Report:
    def __init__(self, console: Console):
        self.console = console
        self.items: list[Check] = []

    def add(self, status: str, title: str, detail: str = "") -> None:
        self.items.append(Check(status, title, detail))
        text = f"{title}" + (f" — {detail}" if detail else "")
        {OK: self.console.ok, WARN: self.console.warn, FAIL: self.console.fail}.get(status, self.console.info)(text)

    @property
    def failed(self) -> int:
        return sum(1 for i in self.items if i.status == FAIL)

    @property
    def warned(self) -> int:
        return sum(1 for i in self.items if i.status == WARN)


def _sh(cmd: list[str], timeout: float = 20) -> tuple[int, str]:
    try:
        p = run(cmd, check=False, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)


# --- системные проверки ---------------------------------------------------------


def check_services(r: Report) -> None:
    r.console.header("Службы")
    for unit, title in (
        ("x-ui", "панель 3x-ui (+ ядро Xray)"),
        ("caddy", "Caddy (HTTPS для панели)"),
        ("fail2ban", "fail2ban"),
    ):
        code, out = _sh(["systemctl", "is-active", unit])
        r.add(OK if out.strip() == "active" else FAIL, f"{unit}: {title}", out.strip())
    code_s, out_s = _sh(["systemctl", "is-active", "dnscrypt-proxy.socket"])
    code_d, out_d = _sh(["systemctl", "is-active", "dnscrypt-proxy"])
    dns_ok = "active" in (out_s.strip(), out_d.strip())
    r.add(OK if dns_ok else FAIL, "dnscrypt-proxy", f"socket={out_s.strip()}, service={out_d.strip()}")
    code, out = _sh(["pgrep", "-f", "bin/xray-linux"])
    r.add(OK if code == 0 else FAIL, "процесс Xray запущен", "" if code == 0 else "не найден")
    code, out = _sh(["ufw", "status"])
    r.add(OK if "Status: active" in out else FAIL, "UFW активен")


def _listening() -> list[tuple[str, str]]:
    """[(proto, local_addr:port)] по выводу ss."""
    code, out = _sh(["ss", "-Hlntu"])
    res = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            res.append((parts[0], parts[4]))
    return res


def _port_of(addr: str) -> int:
    try:
        return int(addr.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return -1


def _host_of(addr: str) -> str:
    return addr.rsplit(":", 1)[0].strip("[]").split("%")[0]


def check_ports(r: Report, s: Settings) -> None:
    r.console.header("Порты")
    sockets = _listening()

    def listening(proto: str, port: int, public: bool | None = None) -> bool:
        for p, addr in sockets:
            if not p.startswith(proto) or _port_of(addr) != port:
                continue
            host = _host_of(addr)
            is_public = host in ("0.0.0.0", "*", "::", "")
            if public is None or public == is_public:
                return True
        return False

    expect = [
        ("tcp", s.int("SN_XHTTP_PORT"), "VLESS+XHTTP+REALITY"),
        ("tcp", s.int("SN_VISION_PORT"), "VLESS+TCP+REALITY+Vision"),
        ("udp", s.int("SN_HY2_PORT"), "Hysteria2"),
        ("tcp", s.int("SN_PANEL_PORT"), "HTTPS панели (Caddy)"),
    ]
    for proto, port, title in expect:
        r.add(OK if listening(proto, port, True) else FAIL, f"{port}/{proto} слушается: {title}")
    for port, title in ((s.int("SN_XUI_PORT"), "панель 3x-ui"), (s.int("SN_SUB_PORT"), "сервер подписки")):
        if listening("tcp", port, True):
            r.add(FAIL, f"{port}/tcp ({title}) доступен извне", "должен слушать только 127.0.0.1")
        elif listening("tcp", port, False):
            r.add(OK, f"{port}/tcp ({title}) — только локально")
        else:
            r.add(FAIL, f"{port}/tcp ({title}) не слушается")


def check_firewall(r: Report, s: Settings) -> None:
    r.console.header("Файрвол")
    code, out = _sh(["ufw", "status", "verbose"])
    if code != 0:
        r.add(FAIL, "ufw status", out.strip()[:200])
        return
    r.add(OK if "deny (incoming)" in out else FAIL, "по умолчанию входящие запрещены")
    rules = {
        f"{s.get('SN_SSH_PORT') or '22'}/tcp": "SSH",
        "80/tcp": "ACME HTTP-01",
        f"{s.get('SN_XHTTP_PORT')}/tcp": "XHTTP",
        f"{s.get('SN_VISION_PORT')}/tcp": "Vision",
        f"{s.get('SN_HY2_PORT')}/udp": "Hysteria2",
        f"{s.get('SN_PANEL_PORT')}/tcp": "панель",
    }
    for rule, title in rules.items():
        r.add(OK if rule in out else FAIL, f"правило {rule} ({title})")
    for port in (s.get("SN_XUI_PORT"), s.get("SN_SUB_PORT")):
        if f"{port}/tcp" in out or f"{port} " in out:
            r.add(FAIL, f"порт {port} открыт в UFW", "внутренний порт не должен быть открыт")


def check_kernel(r: Report) -> None:
    r.console.header("Ядро и система")
    _, cc = _sh(["sysctl", "-n", "net.ipv4.tcp_congestion_control"])
    _, qd = _sh(["sysctl", "-n", "net.core.default_qdisc"])
    r.add(OK if cc.strip() == "bbr" else FAIL, "TCP BBR", cc.strip())
    r.add(OK if qd.strip() == "fq" else WARN, "очередь fq", qd.strip())
    _, ntp = _sh(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    r.add(OK if ntp.strip() == "yes" else WARN, "время синхронизировано (важно для REALITY)", ntp.strip())
    _, ua = _sh(["systemctl", "is-enabled", "unattended-upgrades"])
    auto = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    auto_ok = auto.is_file() and 'Unattended-Upgrade "1"' in auto.read_text()
    r.add(OK if ua.strip() == "enabled" and auto_ok else WARN, "автообновления безопасности", ua.strip())


def check_fail2ban(r: Report) -> None:
    r.console.header("fail2ban")
    code, out = _sh(["fail2ban-client", "status"])
    if code != 0:
        r.add(FAIL, "fail2ban-client status", out.strip()[:200])
        return
    for jail, title in (("sshd", "SSH: 3 попытки → бан 24 ч"), ("stealthnode-panel", "перебор пароля панели"), ("3x-ipl", "лимит IP 3x-ui")):
        r.add(OK if jail in out else (WARN if jail == "3x-ipl" else FAIL), f"jail {jail}", title)


def _mode(path: Path) -> int | None:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        return None


def check_secrets(r: Report) -> None:
    r.console.header("Секреты")
    root = config.sn_root()
    for path, want in (
        (config.env_path(), 0o600),
        (config.credentials_path(), 0o600),
        (root / "hysteria" / "server.key", 0o600),
        (Path("/etc/x-ui/install-result.env"), 0o600),
    ):
        mode = _mode(path)
        if mode is None:
            r.add(WARN, f"{path}", "нет файла")
        else:
            r.add(OK if mode & 0o077 == 0 else FAIL, f"{path}", f"права {oct(mode)}")
    for path in (root / "users", root / "xray" / "share", root / "backups"):
        mode = _mode(path)
        if mode is not None:
            r.add(OK if mode & 0o077 == 0 else FAIL, f"{path}/", f"права {oct(mode)}")


# --- сеть и TLS --------------------------------------------------------------------


def https_request(
    ip: str, port: int, server_name: str, path: str, *, verify: bool, user_agent: str = "stealthnode-doctor",
    timeout: float = 10,
) -> tuple[int, bytes, dict]:
    """HTTPS-запрос к ip:port с SNI/Host = server_name (аналог curl --resolve)."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((ip, port), timeout=timeout)
    try:
        tls = ctx.wrap_socket(raw, server_hostname=server_name)
    except BaseException:
        raw.close()
        raise
    conn = http.client.HTTPConnection(server_name, port, timeout=timeout)
    conn.sock = tls
    try:
        cert = tls.getpeercert() if verify else {}
        conn.request("GET", path, headers={"Host": f"{server_name}:{port}", "User-Agent": user_agent})
        resp = conn.getresponse()
        body = resp.read(1024 * 1024)
        return resp.status, body, cert or {}
    finally:
        conn.close()


def check_panel(r: Report, s: Settings) -> None:
    r.console.header("Панель и подписка (HTTPS через Caddy)")
    verify = s.get("SN_TLS_MODE") == "acme"
    domain, port = s.domain, s.int("SN_PANEL_PORT")
    try:
        status, _, cert = https_request("127.0.0.1", port, domain, f"/{s.get('SN_PANEL_PATH')}/", verify=verify)
        days = ""
        if cert.get("notAfter"):
            left = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
            days = f", сертификат ещё {left:.0f} дн."
        r.add(OK if status == 200 else FAIL, f"https://{domain}:{port}/<путь панели>/", f"HTTP {status}{days}")
        if not verify:
            r.add(WARN, "сертификат панели", "режим tls internal (самоподписанный CA Caddy)")
    except ssl.SSLCertVerificationError as exc:
        r.add(FAIL, "сертификат панели не прошёл проверку", f"{exc.verify_message} — DNS/ACME ещё не готовы?")
    except OSError as exc:
        r.add(FAIL, "панель по HTTPS недоступна", str(exc))
    try:
        status, _, _ = https_request("127.0.0.1", port, domain, "/", verify=False)
        r.add(OK if status == 404 else WARN, "корень сайта не раскрывает панель", f"HTTP {status}")
    except OSError as exc:
        r.add(WARN, "проверка корня сайта", str(exc))


def check_subscription(r: Report, s: Settings, xui: XuiClient) -> list[str]:
    owner = s.get("SN_OWNER_NAME") or "owner"
    client = users.find_user(xui, owner)
    if not client:
        r.add(FAIL, f"пользователь-владелец {owner!r}", "не найден в панели")
        return []
    path = f"/{s.get('SN_SUB_PATH')}/{client.get('subId')}"
    verify = s.get("SN_TLS_MODE") == "acme"
    try:
        status, body, _ = https_request(
            "127.0.0.1", s.int("SN_PANEL_PORT"), s.domain, path, verify=verify, user_agent="v2rayNG/2.0"
        )
    except OSError as exc:
        r.add(FAIL, "подписка недоступна", str(exc))
        return []
    if status != 200:
        r.add(FAIL, "подписка", f"HTTP {status}")
        return []
    try:
        text = base64.b64decode(body + b"=" * (-len(body) % 4)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        text = body.decode("utf-8", "replace")
    raw_links = [ln.strip() for ln in text.splitlines() if "://" in ln]
    kinds = sorted({links.parse(x).kind for x in raw_links if x.startswith(("vless://", "hysteria2://", "hy2://"))})
    ok = {"xhttp", "vision", "hysteria2"} <= set(kinds)
    r.add(OK if ok else FAIL, "подписка владельца отдаёт 3 профиля", ", ".join(kinds) or "пусто")
    for raw in raw_links:
        try:
            link = links.parse(raw)
        except links.LinkError as exc:
            r.add(FAIL, "ссылка не разбирается", str(exc))
            continue
        problems = links.audit(link, s.get("SN_FINGERPRINT") or "firefox")
        r.add(OK if not problems else FAIL, f"ссылка {link.kind} соответствует ТЗ", "; ".join(problems))
    return raw_links


def check_reality_camouflage(r: Report, s: Settings) -> None:
    r.console.header("REALITY: маскировка")
    sni = s.get("SN_REALITY_SNI")
    for port in (s.int("SN_XHTTP_PORT"), s.int("SN_VISION_PORT")):
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
                with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                    ver = tls.version()
                    cert = tls.getpeercert()
            subject = dict(x[0] for x in cert.get("subject", ()))
            r.add(
                OK,
                f"порт {port}: без ключа сервер выглядит как {sni}",
                f"{ver}, настоящий сертификат CN={subject.get('commonName', '?')}",
            )
        except ssl.SSLCertVerificationError as exc:
            r.add(FAIL, f"порт {port}: сертификат не совпадает с {sni}", exc.verify_message)
        except OSError as exc:
            r.add(FAIL, f"порт {port}: TLS-рукопожатие не удалось", str(exc))


def check_reality_target(r: Report, s: Settings, xui: XuiClient | None) -> None:
    target = s.get("SN_REALITY_TARGET")
    sni = s.get("SN_REALITY_SNI")
    if xui is not None:
        try:
            res = xui.scan_reality_target(target, sni)
            detail = (
                f"TLS {res.get('tlsVersion')}, ALPN {res.get('alpn') or '-'}, группа {res.get('curveID') or '-'}, "
                f"сертификат {'ok' if res.get('certValid') else 'НЕ валиден'}, {res.get('latencyMs')} мс"
            )
            r.add(OK if res.get("feasible") else FAIL, f"цель REALITY {target} подходит", detail + (f" ({res.get('reason')})" if res.get("reason") else ""))
            return
        except XuiError as exc:
            r.add(WARN, "сканер REALITY 3x-ui недоступен", str(exc))
    host, _, port = target.rpartition(":")
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["h2"])
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=10) as raw, ctx.wrap_socket(raw, server_hostname=sni) as tls:
            alpn = tls.selected_alpn_protocol()
            ver = tls.version()
        ms = int((time.monotonic() - t0) * 1000)
        r.add(OK if alpn == "h2" else WARN, f"цель REALITY {target}", f"{ver}, ALPN {alpn}, {ms} мс")
    except OSError as exc:
        r.add(FAIL, f"цель REALITY {target} недоступна с сервера", str(exc))


def check_dns(r: Report, s: Settings) -> None:
    r.console.header("DNS")
    if which("dig"):
        code, out = _sh(["dig", "+short", "+time=3", "+tries=2", "@127.0.2.1", "example.com", "A"])
        ok = code == 0 and any(c.isdigit() for c in out)
        r.add(OK if ok else FAIL, "dnscrypt-proxy (127.0.2.1) отвечает", out.strip().splitlines()[0] if out.strip() else "нет ответа")
    try:
        addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(s.domain, None, socket.AF_INET)})
    except socket.gaierror as exc:
        r.add(WARN, f"A-запись {s.domain}", f"не разрешается: {exc}")
        return
    ip = s.get("SN_PUBLIC_IP")
    if ip and ip in addrs:
        r.add(OK, f"A-запись {s.domain} → {ip}")
    else:
        r.add(WARN, f"A-запись {s.domain}", f"указывает на {', '.join(addrs)}, а IP сервера {ip or '?'}")


def check_users(r: Report, xui: XuiClient) -> None:
    r.console.header("Пользователи")
    try:
        online = set(xui.onlines())
    except XuiError:
        online = set()
    lst = users.list_users(xui)
    for c in lst:
        r.console.line("  " + users.describe(c, online))
    r.add(OK if lst else FAIL, "пользователи StealthNode", f"{len(lst)} шт.")


# --- E2E через настоящий клиент Xray ------------------------------------------------


def _wait_port(port: int, timeout: float = 10) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def e2e_link(link: links.ShareLink, xray: Path, *, url: str, speed_url: str | None = None) -> tuple[bool, str]:
    """Поднять клиент Xray с этой ссылкой (адрес → 127.0.0.1) и сходить в интернет через SOCKS."""
    port = _free_port()
    cfg = links.xray_client_config(link.with_address("127.0.0.1"), port)
    with tempfile.TemporaryDirectory(prefix="sn-e2e-") as tmp:
        cfg_path = Path(tmp) / "client.json"
        cfg_path.write_text(json.dumps(cfg))
        proc = subprocess.Popen(
            [str(xray), "run", "-c", str(cfg_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        try:
            if not _wait_port(port):
                proc.terminate()
                out = proc.communicate(timeout=5)[0]
                return False, "клиент Xray не запустился: " + out.strip()[-300:]
            code, out = _sh(
                ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{time_total}", "--max-time", "20",
                 "--socks5-hostname", f"127.0.0.1:{port}", url],
                timeout=30,
            )
            if code != 0 or not out.strip().startswith(("200", "204")):
                return False, f"запрос через туннель не прошёл: {out.strip()[:200]}"
            detail = f"HTTP {out.split()[0]} за {float(out.split()[1]):.2f} с"
            if speed_url:
                code, sp = _sh(
                    ["curl", "-sS", "-o", "/dev/null", "-w", "%{speed_download}", "--max-time", "30",
                     "--socks5-hostname", f"127.0.0.1:{port}", speed_url],
                    timeout=40,
                )
                if code == 0:
                    mbit = float(sp.strip() or 0) * 8 / 1e6
                    detail += f", скорость ~{mbit:.0f} Мбит/с (с самого сервера)"
            return True, detail
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()


def check_e2e(r: Report, s: Settings, xui: XuiClient, speed: bool) -> None:
    r.console.header("E2E: реальное подключение клиентом Xray")
    xray = config.xray_bin()
    if not xray:
        r.add(FAIL, "бинарник Xray из 3x-ui не найден")
        return
    owner = s.get("SN_OWNER_NAME") or "owner"
    try:
        raw_links = xui.client_links(owner)
    except XuiError as exc:
        r.add(FAIL, "не удалось получить ссылки владельца", str(exc))
        return
    url = os.environ.get("SN_E2E_URL", "https://www.gstatic.com/generate_204")
    speed_url = "https://speed.cloudflare.com/__down?bytes=20000000" if speed else None
    for raw in raw_links:
        try:
            link = links.parse(raw)
        except links.LinkError as exc:
            r.add(FAIL, "ссылка не разбирается", str(exc))
            continue
        ok, detail = e2e_link(link, xray, url=url, speed_url=speed_url)
        r.add(OK if ok else FAIL, f"туннель {link.kind} работает", detail)


# --- точка входа ----------------------------------------------------------------------


def run_doctor(s: Settings, console: Console, *, e2e: bool = False, speed: bool = False) -> int:
    r = Report(console)
    console.header(f"StealthNode doctor — {s.domain}")
    check_services(r)
    check_ports(r, s)
    check_firewall(r, s)
    check_kernel(r)
    check_fail2ban(r)
    check_dns(r, s)
    check_panel(r, s)
    xui = None
    try:
        xui = XuiClient(s.xui_api_base, s.get("SN_XUI_API_TOKEN"))
        xui.server_status()
    except XuiError as exc:
        r.add(FAIL, "API панели", str(exc))
        xui = None
    check_reality_camouflage(r, s)
    check_reality_target(r, s, xui)
    if xui:
        console.header("Подписка")
        check_subscription(r, s, xui)
        check_users(r, xui)
        if e2e:
            check_e2e(r, s, xui, speed)
    check_secrets(r)
    console.header("Итог")
    total = len(r.items)
    if r.failed:
        console.fail(f"проблем: {r.failed}, предупреждений: {r.warned}, проверок: {total}")
        return 1
    console.ok(f"всё в порядке (предупреждений: {r.warned}, проверок: {total})")
    return 0


def traffic_summary(xui: XuiClient) -> str:
    lines = []
    for c in users.list_users(xui):
        t = c.get("traffic") or {}
        lines.append(f"{c.get('email')}: {human_bytes(int(t.get('up', 0)) + int(t.get('down', 0)))}")
    return "\n".join(lines)
