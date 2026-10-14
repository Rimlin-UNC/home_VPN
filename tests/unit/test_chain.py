"""Связка «мост в РФ → выход за рубежом»: инбаунд выхода, ссылка, шаблон Xray, provision, CLI."""

from __future__ import annotations

import io
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from fake_xui import FakeXuiServer
from stealthnode import chain, cli, config, links, payloads, provision, users
from stealthnode.util import Console

EXIT_IP = "95.182.99.147"
BRIDGE_IP = "31.59.126.178"


def quiet() -> Console:
    return Console(io.StringIO(), color=False)


def exit_settings(**extra) -> config.Settings:
    values = config.fill_defaults(
        {"SN_DOMAIN": "vpn.example.test", "SN_PUBLIC_IP": EXIT_IP, "SN_EXIT_BRIDGE_IP": BRIDGE_IP, **extra}, "2.1.0"
    )
    s = config.Settings(values)
    assert s.validate() == [], s.validate()
    return s


def make_exit_link(uuid: str = "11111111-2222-4333-8444-555555555555") -> str:
    return chain.exit_link(exit_settings(), uuid)


@pytest.fixture
def fake(settings):
    with FakeXuiServer(settings.get("SN_PANEL_PATH")) as srv:
        settings.values["SN_XUI_PORT"] = str(srv.port)
        config.save_settings(settings)
        yield srv


@pytest.fixture
def installed(settings, fake):
    """Панель уже настроена установщиком (иначе первый provision перезапускает x-ui через systemctl)."""
    provision.provision(settings, provision.client_from_settings(settings), quiet(), restart_panel_if_needed=False)
    return fake


def client_for(s):
    return provision.client_from_settings(s)


# --- выход ---------------------------------------------------------------------------------


def test_exit_settings_generate_port_and_path_only_for_exit():
    plain = config.fill_defaults({"SN_DOMAIN": "vpn.example.test"}, "2.1.0")
    assert "SN_EXIT_PORT" not in plain and "SN_EXIT_PATH" not in plain
    s = exit_settings()
    lo, hi = config.EXIT_PORT_RANGE
    assert lo <= s.int("SN_EXIT_PORT") <= hi and len(s.get("SN_EXIT_PATH")) == 16
    assert s.is_exit and not s.is_bridge


def test_exit_inbound_mirrors_main_reality_but_own_port_and_ip():
    s = exit_settings()
    inb = chain.exit_inbound(s)
    main = payloads.inbound_xhttp(s)
    assert inb["tag"] == chain.TAG_BRIDGE_IN and inb["port"] == s.int("SN_EXIT_PORT")
    assert inb["shareAddr"] == EXIT_IP  # домен указывает на мост — выход адресуется по IP
    st = inb["streamSettings"]
    assert st["network"] == "xhttp" and st["xhttpSettings"]["mode"] == "stream-one"
    assert st["xhttpSettings"]["path"] == "/" + s.get("SN_EXIT_PATH") != main["streamSettings"]["xhttpSettings"]["path"]
    assert st["realitySettings"] == main["streamSettings"]["realitySettings"]
    assert chain.TAG_BRIDGE_IN not in config.ALL_TAGS  # пользователи к нему не привязываются


def test_exit_link_roundtrip_and_audit():
    s = exit_settings()
    link = links.parse(chain.exit_link(s, "11111111-2222-4333-8444-555555555555"))
    assert link.kind == "xhttp" and link.host == EXIT_IP and link.port == s.int("SN_EXIT_PORT")
    assert link.params["pbk"] == s.get("SN_REALITY_PUBLIC_KEY") and link.params["sid"] == s.get("SN_REALITY_SHORT_ID")
    assert link.params["path"] == "/" + s.get("SN_EXIT_PATH")
    assert links.audit(link) == []  # stream-one, fp=firefox, без flow — как требует ТЗ
    out = chain.bridge_outbound(chain.exit_link(s, "11111111-2222-4333-8444-555555555555"))
    assert out["tag"] == chain.TAG_EXIT and out["settings"]["address"] == EXIT_IP
    assert out["streamSettings"]["xhttpSettings"]["mode"] == "stream-one"
    assert out["streamSettings"]["realitySettings"]["fingerprint"] == "firefox"


def test_exit_link_ipv6_host_in_brackets():
    s = exit_settings(SN_PUBLIC_IP="2001:db8::7")
    assert "@[2001:db8::7]:" in chain.exit_link(s, "11111111-2222-4333-8444-555555555555")


# --- шаблон Xray ------------------------------------------------------------------------------

BASE_TEMPLATE = {
    "dns": {"servers": ["x"]},
    "outbounds": [
        {"protocol": "freedom", "tag": "direct", "settings": {}},
        {"protocol": "blackhole", "tag": "blocked", "settings": {}},
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
            {"type": "field", "domain": ["full:my.example"], "outboundTag": "blocked"},  # своё правило владельца
        ],
    },
}


def bridge(settings, **extra) -> config.Settings:
    s = config.Settings(dict(settings.values, SN_PUBLIC_IP=BRIDGE_IP, SN_BRIDGE_EXIT_LINK=make_exit_link(), **extra))
    assert s.validate() == [], s.validate()
    return s


def test_template_bridge_role(settings):
    s = bridge(settings)
    tpl, changed = payloads.patch_xray_template(BASE_TEMPLATE, s)
    assert changed
    assert tpl["outbounds"][0]["tag"] == chain.TAG_EXIT  # первый исходящий — по умолчанию
    assert [o["tag"] for o in tpl["outbounds"]] == [chain.TAG_EXIT, "direct", "blocked"]
    rules = tpl["routing"]["rules"]
    assert rules[:3] == BASE_TEMPLATE["routing"]["rules"]  # api, блокировки и правила владельца — на месте
    ru = rules[-1]
    assert ru["ruleTag"] == chain.RULE_RU_DIRECT and ru["outboundTag"] == "direct"
    assert "domain:ru" in ru["domain"] and "domain:xn--p1ai" in ru["domain"] and ru["ip"] == ["geoip:ru"]
    assert not any(d.startswith("geosite:") for d in ru["domain"])  # без зависимости от geo-списков
    assert tpl["dns"]["servers"][0] == "localhost"  # DNS только для прямого трафика — резолвер моста
    assert tpl["routing"]["domainStrategy"] == "AsIs"  # остальные домены уходят на выход неразрешёнными
    # Идемпотентность.
    again, changed2 = payloads.patch_xray_template(tpl, s)
    assert not changed2 and again == tpl
    # Российские сайты через выход.
    s.values["SN_BRIDGE_RU_DIRECT"] = "0"
    no_ru, _ = payloads.patch_xray_template(tpl, s)
    assert not any(r.get("ruleTag") == chain.RULE_RU_DIRECT for r in no_ru["routing"]["rules"])
    # Мост выключен — всё наше убрано, DNS прежний.
    s.values.pop("SN_BRIDGE_EXIT_LINK")
    off, _ = payloads.patch_xray_template(tpl, s)
    assert [o["tag"] for o in off["outbounds"]] == ["direct", "blocked"]
    assert off["routing"]["rules"] == BASE_TEMPLATE["routing"]["rules"]
    assert off["dns"]["servers"][0] == "tcp+local://127.0.2.1:53"


def test_template_exit_role_routes_bridge_traffic_direct():
    s = exit_settings()
    tpl, _ = payloads.patch_xray_template(BASE_TEMPLATE, s)
    rule = tpl["routing"]["rules"][-1]
    assert rule == {"type": "field", "ruleTag": chain.RULE_BRIDGE_IN, "inboundTag": [chain.TAG_BRIDGE_IN],
                    "outboundTag": "direct"}
    assert tpl["outbounds"][0]["tag"] == "direct"


# --- проверки параметров ---------------------------------------------------------------------


def test_chain_validation(settings):
    s = config.Settings(dict(settings.values, SN_EXIT_BRIDGE_IP="not-an-ip", SN_EXIT_PORT="443", SN_EXIT_PATH="x"))
    errs = " ".join(s.validate())
    assert "SN_EXIT_BRIDGE_IP" in errs and "SN_EXIT_PORT" in errs and "SN_EXIT_PATH" in errs
    own = chain.exit_link(config.Settings(dict(exit_settings().values, SN_PUBLIC_IP=settings.get("SN_PUBLIC_IP"))),
                          "11111111-2222-4333-8444-555555555555")
    s = config.Settings(dict(settings.values, SN_BRIDGE_EXIT_LINK=own))
    assert any("этот же сервер" in e for e in s.validate())
    s = config.Settings(dict(settings.values, SN_BRIDGE_EXIT_LINK="vless://u@1.2.3.4:443?security=tls&type=tcp"))
    assert any("reality" in e for e in s.validate())


# --- provision против фейковой 3x-ui ----------------------------------------------------------


def test_provision_exit_role_and_disable(settings, fake):
    s = config.Settings(dict(settings.values, SN_EXIT_BRIDGE_IP=BRIDGE_IP))
    s.values = config.fill_defaults(s.values, "2.1.0")
    xui = client_for(s)
    provision.provision(s, xui, quiet(), restart_panel_if_needed=False)
    st = fake.state
    exit_in = next(i for i in st.inbounds if i["tag"] == chain.TAG_BRIDGE_IN)
    assert exit_in["port"] == s.int("SN_EXIT_PORT")
    bridge_client = st.clients[chain.BRIDGE_CLIENT]
    assert bridge_client["inboundIds"] == [exit_in["id"]]
    assert bridge_client["totalGB"] == 0 and bridge_client["limitIp"] == 0
    assert chain.BRIDGE_CLIENT not in {c["email"] for c in users.list_users(xui)}  # не «пользователь»
    owner = st.clients["owner"]
    assert exit_in["id"] not in owner["inboundIds"]  # пользователи к выходу не привязаны
    assert any(r.get("ruleTag") == chain.RULE_BRIDGE_IN for r in st.template["routing"]["rules"])
    # Повтор ничего не меняет и не перезапускает Xray.
    restarts = st.xray_restarts
    res = provision.provision(s, xui, quiet(), restart_panel_if_needed=False)
    assert not res.updated_inbounds and not res.template_changed and st.xray_restarts == restarts
    # Ссылка выхода совпадает с учётной записью моста.
    link = links.parse(chain.exit_link(s, chain.bridge_client_uuid(xui)))
    assert link.user == bridge_client["id"]
    # Выключение: инбаунд, учётная запись и правило удаляются.
    for key in ("SN_EXIT_BRIDGE_IP", "SN_EXIT_PORT", "SN_EXIT_PATH"):
        s.values.pop(key)
    provision.provision(s, xui, quiet(), restart_panel_if_needed=False)
    assert chain.TAG_BRIDGE_IN not in {i["tag"] for i in st.inbounds}
    assert chain.BRIDGE_CLIENT not in st.clients
    assert not any(r.get("ruleTag") == chain.RULE_BRIDGE_IN for r in st.template["routing"]["rules"])


def test_provision_bridge_role_sets_default_outbound_and_panel_egress(settings, fake):
    s = bridge(settings)
    xui = client_for(s)
    provision.provision(s, xui, quiet(), restart_panel_if_needed=False)
    st = fake.state
    assert st.template["outbounds"][0]["tag"] == chain.TAG_EXIT
    assert st.settings["panelOutbound"] == chain.TAG_EXIT  # Telegram-бот панели — через выход
    cfg = st.xray_config()
    assert cfg["outbounds"][0]["settings"]["address"] == EXIT_IP
    s.values.pop("SN_BRIDGE_EXIT_LINK")
    provision.provision(s, xui, quiet(), restart_panel_if_needed=False)
    assert st.template["outbounds"][0]["tag"] == "direct" and st.settings["panelOutbound"] == ""


def test_exit_archive_restored_on_bridge_drops_exit_role(sn_root, capsys):
    """Архив выхода (с ролью «выход для моста X») восстановлен на сам мост X: роль снимается."""
    values = exit_settings().values
    config.save_settings(config.Settings(values))
    assert cli.main(["env", "init", "SN_DOMAIN=vpn.example.test", f"SN_PUBLIC_IP={BRIDGE_IP}",
                     f"SN_BRIDGE_EXIT_LINK={make_exit_link()}"]) == 0
    s = config.load_settings()
    assert not s.is_exit and s.is_bridge
    assert "SN_EXIT_PORT" not in s.values
    assert "роль «выход» из архива снята" in capsys.readouterr().out


# --- CLI: exit enable / link / disable, bridge set / off ----------------------------------------

FAKE_TOOL = """#!/bin/sh
echo "$(basename "$0") $*" >> "{log}"
[ "$1" = status ] && [ "$(basename "$0")" = ufw ] && printf '%s\\n' "$UFW_STATUS"
exit 0
"""


@pytest.fixture
def tools(tmp_path, monkeypatch):
    """Фейковые ufw и fail2ban-client (журнал вызовов) и jail-файл fail2ban."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "tools.log"
    for name in ("ufw", "fail2ban-client"):
        f = bindir / name
        f.write_text(FAKE_TOOL.format(log=log))
        f.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    jail = tmp_path / "stealthnode.local"
    jail.write_text("[DEFAULT]\nbanaction = iptables-multiport\nignoreip = 127.0.0.1/8 ::1\n\n[sshd]\nenabled = true\n")
    monkeypatch.setattr(chain, "F2B_JAIL_FILE", jail)
    monkeypatch.setattr(config, "XUI_DB", tmp_path / "no-x-ui.db")
    return log, jail


def test_cli_exit_enable_link_status_disable(settings, installed, tools, capsys, monkeypatch):
    log, jail = tools
    assert cli.main(["exit", "enable", BRIDGE_IP]) == 0
    out = capsys.readouterr().out
    s = config.load_settings()
    port = s.int("SN_EXIT_PORT")
    assert f"ufw allow proto tcp from {BRIDGE_IP} to any port {port} comment {chain.UFW_COMMENT}" in log.read_text()
    assert f"ignoreip = 127.0.0.1/8 ::1 {BRIDGE_IP}" in jail.read_text()
    assert "fail2ban-client reload" in log.read_text()
    assert "--exit-link 'vless://" in out and "--restore /root/stealthnode-" in out
    assert list((config.sn_root() / "backups").glob("stealthnode-*.tar.gz"))
    assert cli.main(["exit", "link"]) == 0
    link = capsys.readouterr().out.strip()
    assert link.startswith("vless://") and f"@{settings.get('SN_PUBLIC_IP')}:{port}?" in link
    monkeypatch.setenv("UFW_STATUS", f"{port}/tcp                  ALLOW       {BRIDGE_IP}")
    assert cli.main(["exit", "status"]) == 0
    status = capsys.readouterr().out
    assert "только для" in status and "↑ 1024 Б, ↓ 4096 Б" in status
    # Смена моста: старое правило UFW удаляется, IP в ignoreip заменяется.
    assert cli.main(["exit", "enable", "198.51.100.20"]) == 0
    text = log.read_text()
    assert f"ufw delete allow proto tcp from {BRIDGE_IP} to any port {port}" in text
    assert "ignoreip = 127.0.0.1/8 ::1 198.51.100.20" in jail.read_text()
    assert cli.main(["exit", "disable"]) == 0
    assert "SN_EXIT_BRIDGE_IP" not in config.load_settings().values
    assert "ignoreip = 127.0.0.1/8 ::1\n" in jail.read_text()
    assert cli.main(["exit", "enable", settings.get("SN_PUBLIC_IP")]) == 2  # свой IP — ошибка


def test_cli_bridge_set_refuses_unreachable_exit_then_force_and_off(settings, installed, monkeypatch, capsys):
    link = make_exit_link()
    monkeypatch.setattr(chain, "probe_exit", lambda *a, **k: {"host": EXIT_IP, "port": 1, "sni": "max.ru",
                                                               "error": "TCP: timed out"})
    assert cli.main(["bridge", "set", link]) == 1
    assert not config.load_settings().is_bridge  # без рабочего выхода ничего не меняем
    assert "ничего не изменено" in capsys.readouterr().out
    ok = {"host": EXIT_IP, "port": 1, "sni": "max.ru", "tcp_ms": 40, "tls": "TLSv1.3", "cert_cn": "*.max.ru"}
    monkeypatch.setattr(chain, "probe_exit", lambda *a, **k: ok)
    assert cli.main(["bridge", "set", link, "--no-ru-direct"]) == 0
    s = config.load_settings()
    assert s.is_bridge and not s.ru_direct
    assert installed.state.template["outbounds"][0]["tag"] == chain.TAG_EXIT
    assert cli.main(["bridge", "status"]) == 0
    assert cli.main(["bridge", "off"]) == 0
    assert not config.load_settings().is_bridge
    assert installed.state.template["outbounds"][0]["tag"] == "direct"


def test_f2b_set_ignore_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    jail = tmp_path / "j.local"
    jail.write_text("[DEFAULT]\nignoreip = 127.0.0.1/8 ::1\n")
    assert chain.f2b_set_ignore(add="203.0.113.5", jail_file=jail)
    assert not chain.f2b_set_ignore(add="203.0.113.5", jail_file=jail)
    assert chain.f2b_set_ignore(remove="203.0.113.5", jail_file=jail)
    assert jail.read_text() == "[DEFAULT]\nignoreip = 127.0.0.1/8 ::1\n"
    assert not chain.f2b_set_ignore(add="1.2.3.4", jail_file=tmp_path / "missing")


# --- проверка звена мост → выход ---------------------------------------------------------------


def _tls_server(tmp_path: Path, cn: str):
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
         "-subj", f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn}",
         "-keyout", str(tmp_path / "k.pem"), "-out", str(tmp_path / "c.pem")],
        check=True, capture_output=True,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    return srv, str(tmp_path / "c.pem")


def test_probe_exit_reports_camouflage_and_failures(tmp_path):
    srv, ca = _tls_server(tmp_path, "max.test")
    port = srv.getsockname()[1]
    link = f"vless://u@127.0.0.1:{port}?type=xhttp&security=reality&sni=max.test&pbk=x&sid=ab&fp=firefox"
    ok = chain.probe_exit(link, cafile=ca)
    assert ok.get("error") is None and ok["tls"] == "TLSv1.3" and ok["cert_cn"] == "max.test"
    bad = chain.probe_exit(link.replace("sni=max.test", "sni=other.test"), cafile=ca)
    assert "подмена" in bad["error"]
    srv.close()
    with socket.socket() as tmp:  # порт, на котором никто не слушает
        tmp.bind(("127.0.0.1", 0))
        closed_port = tmp.getsockname()[1]
    closed = chain.probe_exit(f"vless://u@127.0.0.1:{closed_port}?type=xhttp&security=reality&sni=max.test", timeout=2)
    assert closed["error"].startswith("TCP")
