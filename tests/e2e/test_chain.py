"""Локальный E2E связки «мост в РФ → выход за рубежом» на настоящем Xray 26.10.10.

Три процесса Xray: клиент → мост → выход. Конфиги моста и выхода строит код StealthNode
(payloads/chain → шаблон 3x-ui → итоговый конфиг, как его собирает панель; см. fake_xui.py).
«Интернет» — локальный HTTP-сервер, который отвечает IP-адресом подключившегося. Исходящий
direct у моста привязан к 127.0.0.3, у выхода — к 127.0.0.4, поэтому по ответу видно, через
какой сервер трафик вышел в интернет.

Проверяется:
* все три профиля (XHTTP, Vision, Hysteria2) через мост выходят в интернет с выхода;
* российские сайты (.ru) мост отправляет напрямую — с IP моста;
* звено мост → выход — VLESS + XHTTP(stream-one) + REALITY с fp=firefox (ссылка stealthnode exit link);
* без выхода зарубежные сайты недоступны, а российские продолжают работать.

geoip:ru в правиле моста здесь убран: в сборке Xray с PyPI нет geo-файлов. С настоящей 3x-ui
(у неё geoip.dat есть) правило целиком проверяет CI (шаг «Связка мост → выход»).
"""

from __future__ import annotations

import copy
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
from stealthnode import certs, chain, config, links, payloads  # noqa: E402

HAVE_XRAY = bool(os.environ.get("XRAY_BIN")) or importlib.util.find_spec("xray") is not None
pytestmark = pytest.mark.skipif(not HAVE_XRAY, reason="нет Xray (XRAY_BIN или pip xray-core)")
RUNNER = Path(__file__).with_name("run_core.py")
BRIDGE_SRC, EXIT_SRC = "127.0.0.3", "127.0.0.4"
HOSTS = {"echo.test": "127.0.0.1", "echo.ru": "127.0.0.1"}


def free_port(kind=socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def free_tcp_udp_port() -> int:
    for _ in range(50):
        port = free_port()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            try:
                u.bind(("127.0.0.1", port))
            except OSError:
                continue
        return port
    raise RuntimeError("нет свободного порта TCP+UDP")


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
    def __init__(self, cfg: dict, tmp: Path, name: str):
        self.path = tmp / f"{name}.json"
        self.path.write_text(json.dumps(cfg, indent=1))
        self.log = tmp / f"{name}.log"
        self.p = subprocess.Popen([sys.executable, str(RUNNER), "xray", str(self.path)],
                                  stdout=self.log.open("w"), stderr=subprocess.STDOUT)

    def stop(self) -> str:
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(5)
            except subprocess.TimeoutExpired:
                self.p.kill()
        return self.log.read_text(errors="replace")


class _WhoAmI(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = self.client_address[0].encode()
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
        except (OSError, ssl.SSLError):
            pass


def finalize(state: FakeXuiState, src: str) -> dict:
    """Итоговый конфиг, как его соберёт 3x-ui, + тестовые замены: локальные адреса и DNS-подмены."""
    cfg = state.xray_config()
    for inb in cfg["inbounds"]:
        inb["listen"] = "127.0.0.1"
    for out in cfg["outbounds"]:
        if out.get("tag") == "direct":
            # «Интернет» — 127.0.0.1 (Xray 26 по умолчанию запрещает приватные адреса), источник — свой.
            out["settings"] = {"domainStrategy": "UseIPv4", "finalRules": [{"action": "allow"}]}
            out["sendThrough"] = src
    for rule in cfg.get("routing", {}).get("rules", []):
        rule.pop("ip", None) if rule.get("ruleTag") == chain.RULE_RU_DIRECT else None
    cfg["dns"] = {"hosts": dict(HOSTS), "servers": ["localhost"]}
    cfg["log"] = {"loglevel": "debug"}
    return cfg


@pytest.fixture(scope="module")
def chain_env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("chain")
    os.environ["SN_ROOT"] = str(tmp / "opt")
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
    web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _WhoAmI)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    reality = {"SN_REALITY_SNI": "reality.test", "SN_REALITY_TARGET": f"127.0.0.1:{target.server_address[1]}"}

    # --- выход: инбаунд для моста + учётная запись моста, как их создаёт provision ---
    s_exit = config.Settings(config.fill_defaults(
        {"SN_DOMAIN": "vpn.test", "SN_PUBLIC_IP": "127.0.0.1", "SN_EXIT_BRIDGE_IP": "127.0.0.2",
         "SN_EXIT_PORT": str(free_port()), **reality}, "2.1.0"))
    assert s_exit.validate() == [], s_exit.validate()
    st_exit = FakeXuiState()
    inb = copy.deepcopy(chain.exit_inbound(s_exit))
    inb["id"] = 1
    st_exit.inbounds.append(inb)
    bridge_rec = chain.bridge_client()
    bridge_rec.update(inboundIds=[1], _rec_id=1)
    st_exit.clients[chain.BRIDGE_CLIENT] = bridge_rec
    st_exit.template, _ = payloads.patch_xray_template(st_exit.template, s_exit)
    exit_link = chain.exit_link(s_exit, bridge_rec["id"])
    assert links.audit(links.parse(exit_link)) == []

    # --- мост: профили пользователей + исходящий на выход по ссылке ---
    port443 = free_tcp_udp_port()
    s_bridge = config.Settings(config.fill_defaults(
        {"SN_DOMAIN": "vpn.test", "SN_PUBLIC_IP": "127.0.0.2", "SN_BRIDGE_EXIT_LINK": exit_link,
         "SN_XHTTP_PORT": str(port443), "SN_HY2_PORT": str(port443), "SN_VISION_PORT": str(free_port()),
         "SN_PANEL_PORT": str(free_port()), "SN_XUI_PORT": str(free_port()), "SN_SUB_PORT": str(free_port()),
         **reality}, "2.1.0"))
    assert s_bridge.validate() == [], s_bridge.validate()
    cert = certs.ensure_hy2_cert(s_bridge)
    st_bridge = FakeXuiState()
    for i, (_tag, desired) in enumerate(payloads.desired_inbounds(s_bridge, cert.cert_file, cert.key_file,
                                                                  cert.pin_sha256).items(), 1):
        desired = copy.deepcopy(desired)
        desired["id"] = i
        st_bridge.inbounds.append(desired)
    owner = payloads.client_record("owner")
    owner.update(inboundIds=[1, 2, 3], _rec_id=1)
    st_bridge.clients["owner"] = owner
    st_bridge.template, _ = payloads.patch_xray_template(st_bridge.template, s_bridge)
    assert st_bridge.template["outbounds"][0]["tag"] == chain.TAG_EXIT

    exit_cfg = finalize(st_exit, EXIT_SRC)
    bridge_cfg = finalize(st_bridge, BRIDGE_SRC)
    exit_proc = Proc(exit_cfg, tmp, "exit")
    assert wait_port(s_exit.int("SN_EXIT_PORT")), exit_proc.stop()
    bridge_proc = Proc(bridge_cfg, tmp, "bridge")
    assert wait_port(port443), bridge_proc.stop()
    user_links = {links.parse(lk).kind: lk for lk in (st_bridge.link(i, "owner", "127.0.0.1") for i in st_bridge.inbounds)}
    yield {"tmp": tmp, "links": user_links, "web": web.server_address[1], "exit": exit_proc, "bridge": bridge_proc}
    print("--- bridge ---\n" + bridge_proc.stop()[-2500:])
    print("--- exit ---\n" + exit_proc.stop()[-2500:])
    target.shutdown()
    web.shutdown()


def whoami_via(env, kind: str, host: str) -> tuple[int, str]:
    port = free_port()
    cfg = links.xray_client_config(links.parse(env["links"][kind]), port, loglevel="debug")
    proc = Proc(cfg, env["tmp"], f"client-{kind}-{host}")
    try:
        if not wait_port(port):
            return 99, proc.stop()[-500:]
        p = subprocess.run(["curl", "-sS", "--max-time", "15", "--socks5-hostname", f"127.0.0.1:{port}",
                            f"http://{host}:{env['web']}/"], capture_output=True, text=True)
        return p.returncode, (p.stdout or p.stderr).strip()
    finally:
        proc.stop()


@pytest.mark.parametrize("kind", ["xhttp", "vision", "hysteria2"])
def test_foreign_sites_exit_through_the_exit_server(chain_env, kind):
    code, out = whoami_via(chain_env, kind, "echo.test")
    assert code == 0 and out == EXIT_SRC, out


def test_russian_sites_go_direct_from_the_bridge(chain_env):
    code, out = whoami_via(chain_env, "xhttp", "echo.ru")
    assert code == 0 and out == BRIDGE_SRC, out


def test_without_exit_foreign_fails_but_russian_still_works(chain_env):
    chain_env["exit"].stop()
    code, _ = whoami_via(chain_env, "xhttp", "echo.test")
    assert code != 0
    code, out = whoami_via(chain_env, "vision", "echo.ru")
    assert code == 0 and out == BRIDGE_SRC, out
