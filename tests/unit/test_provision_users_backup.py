"""Провижининг и пользователи против фейкового API 3x-ui; резервные копии; CLI."""

from __future__ import annotations

import sqlite3
import stat
import tarfile

import pytest

from fake_xui import FakeXuiServer
from stealthnode import backup, cli, config, links, provision, users
from stealthnode.util import Console
from stealthnode.xui import XuiClient, XuiError


@pytest.fixture
def fake(settings):
    with FakeXuiServer(settings.get("SN_PANEL_PATH")) as srv:
        settings.values["SN_XUI_PORT"] = str(srv.port)
        config.save_settings(settings)
        yield srv


def client_for(settings):
    return XuiClient(settings.xui_api_base, settings.get("SN_XUI_API_TOKEN"))


def quiet():
    import io

    return Console(io.StringIO(), color=False)


def test_bad_token_is_reported(settings, fake):
    bad = XuiClient(settings.xui_api_base, "wrong")
    with pytest.raises(XuiError, match="401"):
        bad.list_inbounds()


def test_provision_creates_everything_and_is_idempotent(settings, fake):
    xui = client_for(settings)
    res = provision.provision(settings, xui, quiet(), extra_users=[("mama", 50, 2)], restart_panel_if_needed=False)
    st = fake.state
    assert sorted(res.created_inbounds) == sorted(config.ALL_TAGS)
    assert sorted(res.created_users) == ["mama", "owner"]
    assert res.cert is not None and res.cert.mode == "selfsigned" and res.cert.pin_sha256
    key = config.sn_root() / "hysteria" / "server.key"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert st.settings["subListen"] == "127.0.0.1" and st.settings["tgLang"] == "ru-RU"
    assert st.template["dns"]["servers"][0] == "tcp+local://127.0.2.1:53"
    ids = {i["id"] for i in st.inbounds}
    assert all(set(c["inboundIds"]) == ids for c in st.clients.values())
    assert st.clients["mama"]["totalGB"] == 50 * 1024**3 and st.clients["mama"]["limitIp"] == 2
    assert st.xray_restarts == 1

    # Итоговый «конфиг Xray»: flow только на TCP/Vision.
    cfg = st.xray_config()
    by_tag = {i["tag"]: i for i in cfg["inbounds"]}
    assert all("flow" not in c for c in by_tag[config.TAG_XHTTP]["settings"]["clients"])
    assert all(c["flow"] == "xtls-rprx-vision" for c in by_tag[config.TAG_VISION]["settings"]["clients"])

    # Повторный запуск: ничего не создаётся и не меняется.
    calls_before = len(st.calls)
    res2 = provision.provision(settings, xui, quiet(), extra_users=[("mama", 50, 2)], restart_panel_if_needed=False)
    assert res2.created_inbounds == [] and res2.updated_inbounds == [] and res2.created_users == []
    assert res2.settings_changed == [] and not res2.template_changed
    assert st.xray_restarts == 1  # повторный запуск не рвёт соединения пользователей
    writes = [c for c in st.calls[calls_before:] if c[0] == "POST" and not c[1].startswith(("setting/all", "xray/", "server/"))]
    assert writes == []


def test_provision_repairs_drift(settings, fake):
    xui = client_for(settings)
    provision.provision(settings, xui, quiet(), restart_panel_if_needed=False)
    inb = next(i for i in fake.state.inbounds if i["tag"] == config.TAG_XHTTP)
    inb["streamSettings"]["xhttpSettings"]["mode"] = "auto"
    inb["streamSettings"]["xhttpSettings"]["scMinPostsIntervalMs"] = 30
    res = provision.provision(settings, xui, quiet(), restart_panel_if_needed=False)
    assert res.updated_inbounds == [config.TAG_XHTTP]
    fixed = next(i for i in fake.state.inbounds if i["tag"] == config.TAG_XHTTP)
    assert fixed["streamSettings"]["xhttpSettings"]["mode"] == "stream-one"
    assert "scMinPostsIntervalMs" not in fixed["streamSettings"]["xhttpSettings"]
    assert fixed["settings"]["clients"] == inb["settings"]["clients"]


def test_port_conflict_with_foreign_inbound(settings, fake):
    fake.state.inbounds.append({"id": 99, "tag": "other", "remark": "чужой", "port": 8443, "protocol": "vless",
                                "settings": {"clients": []}, "streamSettings": {"network": "tcp"}})
    fake.state.next_inbound_id = 100
    with pytest.raises(XuiError, match="8443"):
        provision.provision(settings, client_for(settings), quiet(), restart_panel_if_needed=False)


def test_users_lifecycle_and_files(settings, fake):
    xui = client_for(settings)
    provision.provision(settings, xui, quiet(), restart_panel_if_needed=False)
    users.add_user(xui, "papa", limit_gb=30, ip_limit=1)
    with pytest.raises(ValueError):
        users.add_user(xui, "papa", limit_gb=30, ip_limit=1)
    with pytest.raises(ValueError):
        users.validate_name("Мама с пробелом")
    users.set_limits(xui, "papa", limit_gb=10, ip_limit=3)
    c = users.find_user(xui, "papa")
    assert c["totalGB"] == 10 * 1024**3 and c["limitIp"] == 3 and c["trafficReset"] == "monthly"
    assert c["uuid"]  # учётные данные не потерялись при обновлении
    users.write_all(xui, settings)
    d = config.sn_root() / "users" / "papa"
    text = (d / "links.txt").read_text()
    assert settings.sub_base_url in text and "vless://" in text and "hysteria2://" in text
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert stat.S_IMODE((d / "links.txt").stat().st_mode) == 0o600
    for raw in xui.client_links("papa"):
        assert links.audit(links.parse(raw)) == []
    admin = (config.sn_root() / "xray" / "share" / "admin-links.txt").read_text()
    assert "owner" in admin and "papa" in admin
    users.delete_user(xui, "papa")
    assert users.find_user(xui, "papa") is None and not d.exists()


def test_cert_sync_switches_to_acme(settings, fake, tmp_path, monkeypatch):
    xui = client_for(settings)
    provision.provision(settings, xui, quiet(), restart_panel_if_needed=False)
    hy = next(i for i in fake.state.inbounds if i["tag"] == config.TAG_HY2)
    assert hy["streamSettings"]["tlsSettings"]["settings"]["pinnedPeerCertSha256"]
    # Имитируем сертификат Let's Encrypt, полученный Caddy.
    data = tmp_path / "caddy"
    d = data / "certificates" / "acme-v02.api.letsencrypt.org-directory" / settings.domain
    d.mkdir(parents=True)
    src = config.sn_root() / "hysteria" / "selfsigned.crt"
    (d / f"{settings.domain}.crt").write_bytes(src.read_bytes().replace(b"\n", b"\n"))
    (d / f"{settings.domain}.key").write_bytes((config.sn_root() / "hysteria" / "selfsigned.key").read_bytes())
    monkeypatch.setattr(config, "CADDY_DATA", data)
    assert provision.cert_sync(settings, xui, quiet()) is True
    hy = next(i for i in fake.state.inbounds if i["tag"] == config.TAG_HY2)
    assert "pinnedPeerCertSha256" not in hy["streamSettings"]["tlsSettings"]["settings"]
    assert config.load_settings().get("SN_HY2_CERT_MODE") == "acme"
    assert provision.cert_sync(config.load_settings(), xui, quiet()) is False


def test_backup_and_restore(settings, tmp_path, monkeypatch):
    db = tmp_path / "x-ui.db"
    with sqlite3.connect(db) as con:
        con.execute("create table t(x)")
        con.execute("insert into t values (42)")
    monkeypatch.setattr(config, "XUI_DB", db)
    (config.sn_root() / "users" / "mama").mkdir(parents=True)
    (config.sn_root() / "users" / "mama" / "links.txt").write_text("vless://...")
    archive = backup.make_backup(keep=2, settings=settings)
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    with tarfile.open(archive) as tar:
        names = tar.getnames()
    assert {"MANIFEST.json", "stealthnode/.env", "x-ui/x-ui.db", "stealthnode/users/mama/links.txt"} <= set(names)
    # Ротация: хранится не больше keep архивов.
    for i in range(3):
        (archive.parent / f"stealthnode-2000010{i}-000000.tar.gz").write_bytes(b"old")
    backup.prune(2)
    assert len(list(archive.parent.glob(backup.BACKUP_GLOB))) == 2
    # Восстановление на «чистый» сервер (без БД, чтобы не трогать systemctl).
    config.env_path().unlink()
    restored = backup.restore(archive, db=False)
    assert str(config.env_path()) in restored
    assert config.load_settings().values == settings.values


def test_restore_rejects_path_traversal(sn_root, tmp_path):
    evil = tmp_path / "evil.tar.gz"
    with tarfile.open(evil, "w:gz") as tar:
        p = tmp_path / "x"
        p.write_text("x")
        tar.add(p, arcname="../../etc/passwd")
    with pytest.raises(ValueError):
        backup.restore(evil)


def test_cli_parse_user_spec():
    assert cli.parse_user_spec("mama", 50, 2) == ("mama", 50, 2)
    assert cli.parse_user_spec("papa:30", 50, 2) == ("papa", 30, 2)
    assert cli.parse_user_spec("kid:10:1", 50, 2) == ("kid", 10, 1)
    with pytest.raises(ValueError):
        cli.parse_user_spec("a:b:c:d", 50, 2)


def test_cli_env_init_and_check(sn_root, capsys):
    assert cli.main(["env", "init", "SN_DOMAIN=vpn.example.test", "SN_REALITY_SNI=yandex.ru"]) == 0
    s = config.load_settings()
    assert s.get("SN_REALITY_TARGET") == "yandex.ru:443" and s.get("SN_FINGERPRINT") == "firefox"
    assert stat.S_IMODE(config.env_path().stat().st_mode) == 0o600
    # Повтор с теми же параметрами не меняет секреты.
    before = dict(s.values)
    assert cli.main(["env", "init", "SN_DOMAIN=vpn.example.test"]) == 0
    assert config.load_settings().values == before
    assert cli.main(["env", "check"]) == 0
    assert cli.main(["env", "init", "BAD=1"]) == 2
    assert cli.main(["env", "set", "SN_FINGERPRINT=ios"]) == 0
    assert cli.main(["env", "check"]) == 1
