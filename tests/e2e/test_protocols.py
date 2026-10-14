"""Локальный E2E протоколов: настоящий Xray 26.10.10 как сервер и как клиент.

Сервер получает ровно те инбаунды, которые StealthNode отдаёт в 3x-ui
(stealthnode.payloads), клиенты — ровно те ссылки, которые генерирует 3x-ui
(формат повторён в tests/unit/fake_xui.py). Цель REALITY — локальный TLS 1.3
сервер, «интернет» — локальный HTTP-сервер.

Что проверяется:
* VLESS + XHTTP(stream-one) + REALITY, fp=firefox — работает;
* VLESS + TCP + REALITY + Vision — работает;
* Hysteria2 + Salamander, self-signed + pinSHA256 — Xray-клиент и официальный
  клиент Hysteria2 подключаются; без пароля obfs — нет;
* REALITY в Xray >= 26.9.8 отвергает отпечаток без X25519MLKEM768 (ios) — это
  основание для выбора fp=firefox в docs/TZ-REVIEW.md.

Запуск: нужен модуль ``xray`` (pip install xray-core==1.8.26.13, Python 3.11)
или переменная XRAY_BIN; для Hysteria2-клиента — ``hysteria2`` (pip).
"""

from __future__ import annotations

import http.server
import importlib.util
import json
import os
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "stealthnode" / "python"))
sys.path.insert(0, str(ROOT / "tests" / "unit"))

from fake_xui import FakeXuiState  # noqa: E402
from stealthnode import certs, config, links, payloads  # noqa: E402

HAVE_XRAY = bool(os.environ.get("XRAY_BIN")) or importlib.util.find_spec("xray") is not None
HAVE_HY = importlib.util.find_spec("hysteria2") is not None
pytestmark = pytest.mark.skipif(not HAVE_XRAY, reason="нет Xray (XRAY_BIN или pip xray-core)")

RUNNER = Path(__file__).with_name("run_core.py")


def free_port(kind=socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def free_tcp_udp_port() -> int:
    """Порт, свободный и для TCP, и для UDP (XHTTP и Hysteria2 на одном номере, как 443)."""
    for _ in range(50):
        p = free_port()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
                u.bind(("127.0.0.1", p))
            return p
        except OSError:
            continue
    raise RuntimeError("нет свободного порта")


def wait_port(port: int, timeout: float = 15) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.1)
    return False


class Proc:
    def __init__(self, kind: str, cfg: dict, tmp: Path, name: str):
        self.path = tmp / f"{name}.json"
        self.path.write_text(json.dumps(cfg, indent=1))
        self.log = tmp / f"{name}.log"
        self.p = subprocess.Popen(
            [sys.executable, str(RUNNER), kind, str(self.path)], stdout=self.log.open("w"), stderr=subprocess.STDOUT
        )

    def stop(self) -> str:
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(5)
            except subprocess.TimeoutExpired:
                self.p.kill()
        return self.log.read_text(errors="replace")


# --- окружение: цель REALITY и «интернет» ---------------------------------------------


class _Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"stealthnode-e2e-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _TLSTarget(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, ctx):
        self.ctx = ctx
        super().__init__(addr, _TLSHandler)


class _TLSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with self.server.ctx.wrap_socket(self.request, server_side=True) as tls:
                tls.settimeout(5)
                tls.recv(1024)
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except (OSError, ssl.SSLError):
            pass


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("e2e")
    os.environ["SN_ROOT"] = str(tmp / "opt")
    # Цель REALITY: TLS 1.3 + h2, сертификат на reality.test.
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
         "-subj", "/CN=reality.test", "-addext", "subjectAltName=DNS:reality.test",
         "-keyout", str(tmp / "t.key"), "-out", str(tmp / "t.crt")],
        check=True, capture_output=True,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(tmp / "t.crt", tmp / "t.key")
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    target = _TLSTarget(("127.0.0.1", 0), ctx)
    threading.Thread(target=target.serve_forever, daemon=True).start()
    web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=web.serve_forever, daemon=True).start()

    port443 = free_tcp_udp_port()
    values = config.fill_defaults(
        {
            "SN_DOMAIN": "vpn.test",
            "SN_REALITY_SNI": "reality.test",
            "SN_REALITY_TARGET": f"127.0.0.1:{target.server_address[1]}",
            "SN_XHTTP_PORT": str(port443),
            "SN_HY2_PORT": str(port443),
            "SN_VISION_PORT": str(free_port()),
            "SN_PANEL_PORT": str(free_port()),
            "SN_XUI_PORT": str(free_port()),
            "SN_SUB_PORT": str(free_port()),
        },
        "2.0.0",
    )
    s = config.Settings(values)
    assert s.validate() == []
    cert = certs.ensure_hy2_cert(s)
    assert cert.mode == "selfsigned" and cert.pin_sha256

    # «Панель»: те же инбаунды и клиент, что создаёт provision.
    state = FakeXuiState()
    for i, (_tag, inb) in enumerate(payloads.desired_inbounds(s, cert.cert_file, cert.key_file, cert.pin_sha256).items(), 1):
        inb = json.loads(json.dumps(inb))
        inb["id"] = i
        state.inbounds.append(inb)
    client = payloads.client_record("owner")
    client["inboundIds"] = [1, 2, 3]
    client["_rec_id"] = 1
    state.clients["owner"] = client
    server_cfg = state.xray_config()
    for inb in server_cfg["inbounds"]:
        inb["listen"] = "127.0.0.1"
    # Xray 26 по умолчанию не пускает VLESS/Hysteria-клиентов в приватные сети (finalRules);
    # «интернет» в тесте — 127.0.0.1, поэтому явно разрешаем.
    server_cfg["outbounds"] = [{"protocol": "freedom", "tag": "direct", "settings": {"finalRules": [{"action": "allow"}]}}]
    server_cfg["log"] = {"loglevel": "debug"}
    server_cfg.pop("routing", None)
    server = Proc("xray", server_cfg, tmp, "server")
    assert wait_port(port443), server.stop()
    raw_links = {links.parse(state.link(inb, "owner", "127.0.0.1")).kind: state.link(inb, "owner", "127.0.0.1") for inb in state.inbounds}
    yield {"tmp": tmp, "links": raw_links, "web": f"http://127.0.0.1:{web.server_address[1]}/", "server": server}
    log = server.stop()
    target.shutdown()
    web.shutdown()
    print(log[-3000:])


def curl_via_socks(socks_port: int, url: str, timeout: int = 15) -> tuple[int, str]:
    p = subprocess.run(
        ["curl", "-sS", "--max-time", str(timeout), "--socks5-hostname", f"127.0.0.1:{socks_port}", url],
        capture_output=True, text=True,
    )
    return p.returncode, (p.stdout or p.stderr).strip()


def run_client(env, link: links.ShareLink, name: str, core: str = "xray") -> tuple[int, str, str]:
    port = free_port()
    if core == "xray":
        cfg = links.xray_client_config(link, port, loglevel="debug")
    else:
        cfg = links.hysteria_client_config(link, port)
    proc = Proc(core, cfg, env["tmp"], name)
    try:
        if not wait_port(port):
            return 99, "клиент не поднял SOCKS", proc.stop()
        code, out = curl_via_socks(port, env["web"])
        return code, out, ""
    finally:
        log = proc.stop()
        if os.environ.get("E2E_VERBOSE"):
            print(log[-2000:])


@pytest.mark.parametrize("kind", ["xhttp", "vision", "hysteria2"])
def test_profile_works_with_xray_client(env, kind):
    link = links.parse(env["links"][kind])
    assert links.audit(link) == [], links.audit(link)
    code, out, log = run_client(env, link, f"client-{kind}")
    assert code == 0 and out == "stealthnode-e2e-ok", f"{kind}: {out}\n{log}"


@pytest.mark.skipif(not HAVE_HY, reason="нет pip-пакета hysteria2")
def test_hysteria2_official_client_pin_needs_insecure(env):
    """Официальный клиент Hysteria2: pinSHA256 — ДОПОЛНИТЕЛЬНАЯ проверка, CA он проверяет всё равно.

    Поэтому self-signed режим (до получения Let's Encrypt) рассчитан на Xray-клиенты
    (v2rayNG, v2rayN, Happ), а официальному клиенту нужен insecure=1 + pinSHA256
    (MITM всё равно невозможен — отпечаток сверяется).
    """
    link = links.parse(env["links"]["hysteria2"])
    assert link.params.get("pinSHA256")
    code, out, log = run_client(env, link, "client-hy-official-pin", core="hysteria")
    assert code != 0 and "unknown authority" in log, f"{out}\n{log}"
    link.params["insecure"] = "1"
    code, out, log = run_client(env, link, "client-hy-official-pin-insecure", core="hysteria")
    assert code == 0 and out == "stealthnode-e2e-ok", f"{out}\n{log}"
    link.params["pinSHA256"] = "00" * 32
    code, out, log = run_client(env, link, "client-hy-official-badpin", core="hysteria")
    assert code != 0, "чужой отпечаток должен отвергаться даже с insecure=1"


def test_hysteria2_wrong_obfs_password_fails(env):
    raw = env["links"]["hysteria2"]
    link = links.parse(raw)
    link.params["obfs-password"] = "wrong-password-123456"
    code, out, _ = run_client(env, link, "client-hy-wrong")
    assert code != 0, out


def test_reality_rejects_fingerprint_without_mlkem(env):
    """Xray >= 26.9.8: ClientHello без X25519MLKEM768 (ios = iOS_14) не проходит REALITY."""
    link = links.parse(env["links"]["vision"])
    link.params["fp"] = "ios"
    code, out, _ = run_client(env, link, "client-ios-fp")
    assert code != 0, f"ожидался отказ, получено: {out}"


def test_reality_chrome_fingerprint_still_works(env):
    """Chrome (с MLKEM) проходит REALITY — но его режет ТСПУ, поэтому в ссылках firefox."""
    link = links.parse(env["links"]["xhttp"])
    link.params["fp"] = "chrome"
    code, out, log = run_client(env, link, "client-chrome-fp")
    assert code == 0 and out == "stealthnode-e2e-ok", f"{out}\n{log}"


def test_wrong_short_id_is_camouflaged(env):
    """Неверный shortId: REALITY не пускает (трафик уходит к цели, туннеля нет)."""
    link = links.parse(env["links"]["vision"])
    link.params["sid"] = "0123456789abcdef"
    code, out, _ = run_client(env, link, "client-bad-sid")
    assert code != 0, out


# --- Режим Let's Encrypt: сертификат от доверенного CA, без pin -----------------------


@pytest.fixture(scope="module")
def env_ca(env):
    tmp = env["tmp"] / "ca"
    tmp.mkdir()

    def ossl(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True)

    ossl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
         "-subj", "/CN=StealthNode Test CA", "-keyout", str(tmp / "ca.key"), "-out", str(tmp / "ca.crt"))
    ossl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/CN=vpn.test",
         "-keyout", str(tmp / "srv.key"), "-out", str(tmp / "srv.csr"))
    (tmp / "ext.cnf").write_text("subjectAltName=DNS:vpn.test\n")
    ossl("x509", "-req", "-in", str(tmp / "srv.csr"), "-CA", str(tmp / "ca.crt"), "-CAkey", str(tmp / "ca.key"),
         "-CAcreateserial", "-days", "2", "-extfile", str(tmp / "ext.cnf"), "-out", str(tmp / "srv.crt"))
    port = free_tcp_udp_port()
    values = config.fill_defaults({"SN_DOMAIN": "vpn.test", "SN_HY2_PORT": str(port), "SN_PANEL_PORT": str(free_port()),
                                   "SN_XUI_PORT": str(free_port()), "SN_SUB_PORT": str(free_port())}, "2.0.0")
    s = config.Settings(values)
    state = FakeXuiState()
    inb = payloads.inbound_hy2(s, str(tmp / "srv.crt"), str(tmp / "srv.key"), pin_sha256=None)
    inb["id"] = 1
    state.inbounds.append(inb)
    client = payloads.client_record("owner")
    client.update(inboundIds=[1], _rec_id=1)
    state.clients["owner"] = client
    cfg = state.xray_config()
    cfg["inbounds"][0]["listen"] = "127.0.0.1"
    cfg["outbounds"] = [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
    cfg.pop("routing", None)
    server = Proc("xray", cfg, tmp, "server-ca")
    time.sleep(1.5)
    link = state.link(inb, "owner", "127.0.0.1")
    yield {"tmp": tmp, "link": link, "ca": str(tmp / "ca.crt"), "web": env["web"]}
    server.stop()


def test_ca_mode_link_has_no_pin_and_no_insecure(env_ca):
    link = links.parse(env_ca["link"])
    assert "pinSHA256" not in link.params and "insecure" not in link.params
    assert links.audit(link) == []


def test_ca_mode_xray_client(env_ca):
    link = links.parse(env_ca["link"])
    port = free_port()
    proc = Proc("xray", links.xray_client_config(link, port, ca_file=env_ca["ca"]), env_ca["tmp"], "cli-ca-xray")
    try:
        assert wait_port(port)
        code, out = curl_via_socks(port, env_ca["web"])
    finally:
        log = proc.stop()
    assert code == 0 and out == "stealthnode-e2e-ok", f"{out}\n{log}"


@pytest.mark.skipif(not HAVE_HY, reason="нет pip-пакета hysteria2")
def test_ca_mode_official_client(env_ca):
    link = links.parse(env_ca["link"])
    port = free_port()
    proc = Proc("hysteria", links.hysteria_client_config(link, port, ca_file=env_ca["ca"]), env_ca["tmp"], "cli-ca-hy")
    try:
        assert wait_port(port), proc.stop()
        code, out = curl_via_socks(port, env_ca["web"])
    finally:
        log = proc.stop()
    assert code == 0 and out == "stealthnode-e2e-ok", f"{out}\n{log}"
