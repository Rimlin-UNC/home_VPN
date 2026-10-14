"""Пароль панели: сверка .env с bcrypt-хешем 3x-ui, смена через x-ui, снятие банов fail2ban.

Регрессия 2.0.1: после смены пароля в веб-интерфейсе повторный install.sh возвращал
пароль из .env, а credentials-файл показывал устаревший пароль — «после смены пароля
не могу зайти».
"""

from __future__ import annotations

import ctypes
import io
import sqlite3
import stat
import sys
from pathlib import Path

import pytest

from fake_xui import FakeXuiServer
from stealthnode import cli, config, panelauth
from stealthnode.util import Console

# Вектор из golang.org/x/crypto/bcrypt (bcrypt_test.go): так хеширует пароли 3x-ui.
GO_HASH = "$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga"

needs_libcrypt = pytest.mark.skipif(panelauth._crypt_fn() is None, reason="нет libcrypt с bcrypt")


def bcrypt_hash(password: str) -> str:
    """bcrypt-хеш через системную libxcrypt (cost 4 — быстро для тестов)."""
    lib = ctypes.CDLL("libcrypt.so.1")
    lib.crypt_gensalt.restype = ctypes.c_char_p
    lib.crypt_gensalt.argtypes = [ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_int]
    lib.crypt.restype = ctypes.c_char_p
    lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    return lib.crypt(password.encode(), lib.crypt_gensalt(b"$2b$", 4, None, 0)).decode()


def make_panel_db(path: Path, username: str | None, password: str = "", *, two_factor: bool = False) -> Path:
    """Минимальная БД 3x-ui: таблицы users и settings, как их создаёт gorm."""
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, "
                   "login_epoch INTEGER DEFAULT 0)")
        db.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, value TEXT)")
        if username is not None:
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, bcrypt_hash(password)))
        db.execute("INSERT INTO settings (key, value) VALUES ('twoFactorEnable', ?)", ("true" if two_factor else "false",))
    return path


FAKE_XUI = r'''#!{python}
"""Фейковый x-ui: «setting -username U -password P [-resetTwoFactor=true]» пишет bcrypt в БД."""
import ctypes, os, sqlite3, sys
args = sys.argv[1:]
log = os.environ.get("FAKE_XUI_LOG")
if log:
    with open(log, "a") as fh:
        fh.write(" ".join(args) + "\n")
opts = dict(zip(args[1::2], args[2::2]))
if os.environ.get("FAKE_XUI_MODE") == "silent-fail":
    # Как настоящий x-ui: ошибку печатает, но код возврата 0.
    print("Failed to update username and password: boom " + opts.get("-password", ""))
    sys.exit(0)
lib = ctypes.CDLL("libcrypt.so.1")
lib.crypt_gensalt.restype = ctypes.c_char_p
lib.crypt_gensalt.argtypes = [ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_int]
lib.crypt.restype = ctypes.c_char_p
lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
h = lib.crypt(opts["-password"].encode(), lib.crypt_gensalt(b"$2b$", 4, None, 0)).decode()
with sqlite3.connect(os.environ["FAKE_XUI_DB"]) as db:
    db.execute("UPDATE users SET username=?, password=?, login_epoch=login_epoch+1 WHERE id=(SELECT MIN(id) FROM users)",
               (opts["-username"], h))
    if "-resetTwoFactor=true" in args:
        db.execute("UPDATE settings SET value='false' WHERE key='twoFactorEnable'")
print("Username and password updated successfully")
'''


@pytest.fixture
def panel(tmp_path, monkeypatch, settings):
    """БД панели с паролем из .env + фейковый бинарник x-ui."""
    db = make_panel_db(tmp_path / "x-ui.db", settings.get("SN_XUI_USERNAME"), settings.get("SN_XUI_PASSWORD"))
    xui_bin = tmp_path / "x-ui"
    xui_bin.write_text(FAKE_XUI.replace("{python}", sys.executable))
    xui_bin.chmod(0o755)
    monkeypatch.setattr(config, "XUI_DB", db)
    monkeypatch.setattr(config, "XUI_BIN", xui_bin)
    monkeypatch.setenv("FAKE_XUI_DB", str(db))
    monkeypatch.setenv("FAKE_XUI_LOG", str(tmp_path / "x-ui.calls"))
    return db


def set_db_password(db: Path, username: str, password: str) -> None:
    """Смена пароля «в веб-интерфейсе»."""
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE users SET username=?, password=?, login_epoch=login_epoch+1", (username, bcrypt_hash(password)))


def quiet() -> Console:
    return Console(io.StringIO(), color=False)


# --- bcrypt -----------------------------------------------------------------------------


@needs_libcrypt
def test_bcrypt_matches_go_vector():
    assert panelauth.bcrypt_check("allmine", GO_HASH) is True
    assert panelauth.bcrypt_check("allminE", GO_HASH) is False
    assert panelauth.bcrypt_check("allmine\0x", GO_HASH) is False


@needs_libcrypt
def test_bcrypt_unicode_and_special_characters():
    for pw in ("Пароль-мамы-2026", "a'b\"c$d`e\\f g", "x" * 72):
        h = bcrypt_hash(pw)
        assert panelauth.bcrypt_check(pw, h) is True
        assert panelauth.bcrypt_check(pw[:-1] + "!", h) is False
    # bcrypt учитывает только первые 72 байта (как и Go в 3x-ui) — поэтому длиннее не пускаем.
    assert panelauth.bcrypt_check("x" * 72 + "!", bcrypt_hash("x" * 72)) is True


def test_bcrypt_unknown_formats_are_not_guessed():
    assert panelauth.bcrypt_check("admin", "admin") is None  # открытый текст — не bcrypt
    assert panelauth.bcrypt_check("x", "") is None
    assert panelauth.bcrypt_check("x", "$2a$10$short") is None


# --- состояние .env относительно панели ------------------------------------------------------


@needs_libcrypt
def test_env_state_all_cases(settings, tmp_path):
    user, pw = settings.get("SN_XUI_USERNAME"), settings.get("SN_XUI_PASSWORD")
    state = lambda db: panelauth.env_state(settings, panelauth.read_admin(db))  # noqa: E731
    assert state(make_panel_db(tmp_path / "match.db", user, pw)) == panelauth.MATCH
    assert state(make_panel_db(tmp_path / "pw.db", user, "Новый-пароль-из-UI")) == panelauth.CHANGED
    assert state(make_panel_db(tmp_path / "user.db", "mylogin", pw)) == panelauth.CHANGED
    assert state(make_panel_db(tmp_path / "default.db", "admin", "admin")) == panelauth.DEFAULT
    assert state(make_panel_db(tmp_path / "empty.db", None)) == panelauth.MISSING
    assert panelauth.env_state(settings, panelauth.read_admin(tmp_path / "nope.db")) == panelauth.UNKNOWN


@needs_libcrypt
def test_read_admin_first_user_and_two_factor(tmp_path):
    db = make_panel_db(tmp_path / "x.db", "first", "password-1", two_factor=True)
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO users (username, password) VALUES ('second', 'x')")
    admin = panelauth.read_admin(db)
    assert admin.username == "first" and admin.two_factor is True
    (tmp_path / "broken.db").write_text("not a database")
    assert panelauth.read_admin(tmp_path / "broken.db") is None


# --- смена пароля -------------------------------------------------------------------------


def test_password_rules():
    panelauth.validate_password("12345678")
    for bad in ("1234567", "x" * 73, "Ж" * 37, "line\nbreak1"):
        with pytest.raises(ValueError):
            panelauth.validate_password(bad)
    for bad in ("", "with space", "x" * 65):
        with pytest.raises(ValueError):
            panelauth.validate_username(bad)


@needs_libcrypt
def test_set_admin_verifies_by_database(panel, monkeypatch):
    panelauth.set_admin("owner2", "Новый пароль 2026", reset_2fa=True)
    admin = panelauth.read_admin()
    assert admin.username == "owner2" and panelauth.bcrypt_check("Новый пароль 2026", admin.password_hash)
    assert "-resetTwoFactor=true" in (panel.parent / "x-ui.calls").read_text()
    # x-ui «молча» не применил пароль (код 0): ошибка, и пароль не утекает в сообщение.
    monkeypatch.setenv("FAKE_XUI_MODE", "silent-fail")
    with pytest.raises(panelauth.PanelAuthError) as err:
        panelauth.set_admin("owner2", "ещё-один-пароль")
    assert "ещё-один-пароль" not in str(err.value) and "***" in str(err.value)


# --- CLI ------------------------------------------------------------------------------------


@pytest.fixture
def fake(settings):
    with FakeXuiServer(settings.get("SN_PANEL_PATH")) as srv:
        settings.values["SN_XUI_PORT"] = str(srv.port)
        config.save_settings(settings)
        yield srv


@needs_libcrypt
def test_cli_password_changed_in_ui_then_recovered(settings, panel, fake, capsys):
    """Сценарий из жалобы: пароль сменили в веб-интерфейсе → доступ восстанавливается одной командой."""
    old_pw = settings.get("SN_XUI_PASSWORD")
    assert cli.main(["panel-password", "--state"]) == 0
    assert capsys.readouterr().out.strip() == panelauth.MATCH

    set_db_password(panel, settings.get("SN_XUI_USERNAME"), "Сменил-в-панели-1")
    assert cli.main(["panel-password", "--state"]) == 0
    assert capsys.readouterr().out.strip() == panelauth.CHANGED
    assert cli.main(["panel-password", "--check"]) == 0
    assert "изменены в веб-интерфейсе" in capsys.readouterr().out

    # Файл учётных данных больше не показывает устаревший пароль как действующий.
    assert cli.main(["credentials"]) == 0
    text = config.credentials_path().read_text()
    assert old_pw not in text and "изменён в веб-интерфейсе" in text and "stealthnode panel-password" in text

    # Восстановление: новый пароль применён в панели, сохранён в .env и в файле.
    assert cli.main(["panel-password", "--password", "Восстановлен-2026", "--no-restart"]) == 0
    out = capsys.readouterr().out
    assert "Восстановлен-2026" not in out  # свой пароль на экран не печатаем
    s = config.load_settings()
    assert s.get("SN_XUI_PASSWORD") == "Восстановлен-2026"
    assert panelauth.env_state(s, panelauth.read_admin()) == panelauth.MATCH
    text = config.credentials_path().read_text()
    assert "Пароль:  Восстановлен-2026" in text
    assert stat.S_IMODE(config.credentials_path().stat().st_mode) == 0o600


@needs_libcrypt
def test_cli_random_password_is_shown_once(settings, panel, fake, capsys):
    assert cli.main(["panel-password", "--random", "--username", "boss", "--no-restart"]) == 0
    out = capsys.readouterr().out
    s = config.load_settings()
    assert s.get("SN_XUI_USERNAME") == "boss" and len(s.get("SN_XUI_PASSWORD")) == 24
    assert f"Пароль: {s.get('SN_XUI_PASSWORD')}" in out
    assert panelauth.env_state(s, panelauth.read_admin()) == panelauth.MATCH


@needs_libcrypt
def test_cli_default_admin_is_reported(settings, panel, capsys):
    set_db_password(panel, "admin", "admin")
    assert cli.main(["panel-password", "--check"]) == 1
    assert cli.main(["info", "--secrets"]) == 0
    assert "НЕБЕЗОПАСНО" in capsys.readouterr().out


def test_cli_env_set_refuses_panel_credentials(settings, capsys):
    assert cli.main(["env", "set", "SN_XUI_PASSWORD=new-password-123"]) == 2
    assert "stealthnode panel-password" in capsys.readouterr().out
    assert config.load_settings().get("SN_XUI_PASSWORD") == settings.get("SN_XUI_PASSWORD")


def test_admin_ip_setting_validation(settings):
    s = config.Settings(dict(settings.values, SN_ADMIN_IP="203.0.113.7, 2001:db8::/64"))
    assert s.validate() == [] and config.admin_ips(s.get("SN_ADMIN_IP")) == ["203.0.113.7", "2001:db8::/64"]
    s.values["SN_ADMIN_IP"] = "1.2.3.999"
    assert any("SN_ADMIN_IP" in e for e in s.validate())
    s.values["SN_ADMIN_IP"] = ""
    s.values["SN_XUI_PASSWORD"] = "short-10ch"
    assert s.validate() == [] and any("пароль панели" in w for w in s.warnings())


# --- fail2ban -------------------------------------------------------------------------------

FAKE_F2B = r'''#!/bin/sh
# Фейковый fail2ban-client: статус jail из переменных, вызовы unban — в журнал.
case "$1" in
    status)
        case "$2" in
            stealthnode-panel) printf 'Status for the jail: %s\n`- Actions\n   `- Banned IP list:\t%s\n' "$2" "$PANEL_BANS" ;;
            recidive) printf 'Status for the jail: %s\n`- Actions\n   `- Banned IP list:\t%s\n' "$2" "$RECIDIVE_BANS" ;;
            sshd) printf 'Status for the jail: sshd\n`- Actions\n   `- Banned IP list:\t\n' ;;
            *) echo "Sorry but the jail '$2' does not exist" >&2; exit 255 ;;
        esac ;;
    unban) shift; echo "unban $*" >> "$F2B_LOG"; echo "$#" ;;
    *) exit 1 ;;
esac
'''


@pytest.fixture
def fake_f2b(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "fail2ban-client"
    script.write_text(FAKE_F2B)
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    monkeypatch.setenv("F2B_LOG", str(tmp_path / "f2b.calls"))
    return tmp_path / "f2b.calls"


def test_unban_panel_lockouts_only_panel_related(fake_f2b, tmp_path, monkeypatch):
    log = tmp_path / "fail2ban.log"
    log.write_text(
        "2026-10-14 12:00:00,001 fail2ban.actions [1]: NOTICE  [stealthnode-panel] Ban 192.0.2.10\n"
        "2026-10-14 12:05:00,001 fail2ban.actions [1]: NOTICE  [sshd] Ban 198.51.100.66\n"
        "2026-10-14 13:00:00,001 fail2ban.actions [1]: NOTICE  [stealthnode-panel] Restore Ban 2001:db8::7\n"
    )
    monkeypatch.setenv("PANEL_BANS", "203.0.113.5")
    monkeypatch.setenv("RECIDIVE_BANS", "192.0.2.10 198.51.100.66 2001:db8::7")
    assert panelauth.banned_ips("sshd") == []
    assert panelauth.banned_ips("nope") is None
    got = panelauth.unban_panel_lockouts(log_paths=(log,))
    # Бан панели + recidive для IP, которых банила панель; чужой SSH-нарушитель остаётся в recidive.
    assert got == ["192.0.2.10", "2001:db8::7", "203.0.113.5"]
    assert fake_f2b.read_text().split() == ["unban", "192.0.2.10", "2001:db8::7", "203.0.113.5"]


def test_cli_unban(fake_f2b, settings, monkeypatch, capsys):
    monkeypatch.setenv("PANEL_BANS", "192.0.2.10")
    monkeypatch.setenv("RECIDIVE_BANS", "")
    assert cli.main(["unban"]) == 0
    out = capsys.readouterr().out
    assert "stealthnode-panel" in out and "192.0.2.10" in out
    assert cli.main(["unban", "192.0.2.10"]) == 0
    assert cli.main(["unban", "not-an-ip"]) == 1
    assert cli.main(["unban", "--all"]) == 0
    assert fake_f2b.read_text().splitlines() == ["unban 192.0.2.10", "unban --all"]
