"""Учётная запись администратора панели 3x-ui: проверка, смена пароля, снятие блокировок.

Пароль панели хранится в БД 3x-ui (bcrypt), и владелец вправе сменить его в веб-интерфейсе.
StealthNode работает с панелью по API-токену, пароль ему не нужен. Отсюда правила:

* установщик задаёт логин/пароль из .env только чистой панели (или стандартным admin/admin);
  пароль, изменённый в веб-интерфейсе, повторный запуск install.sh не трогает;
* пароль из .env показывается, только пока он действительно подходит;
* восстановление доступа — одна команда: ``stealthnode panel-password``.

Пароль сверяется с хешем в БД через системную libcrypt (bcrypt), без попытки входа:
так не появляются записи «failed login», не срабатывают лимит 3x-ui и fail2ban,
а Telegram-бот панели не шлёт уведомлений о входе.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hmac
import ipaddress
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from . import config
from .config import Settings
from .util import run, which

# Состояние логина/пароля из .env относительно панели.
MATCH = "match"  # подходят
CHANGED = "changed"  # владелец сменил логин или пароль в веб-интерфейсе
DEFAULT = "default"  # стандартные admin/admin
MISSING = "missing"  # в БД нет администратора
UNKNOWN = "unknown"  # нет БД или libcrypt — сверить нечем

STATE_TEXT = {
    MATCH: "логин и пароль из .env действуют",
    CHANGED: "логин/пароль изменены в веб-интерфейсе панели (в .env остались исходные)",
    DEFAULT: "стандартные admin/admin — небезопасно",
    MISSING: "в панели нет администратора",
    UNKNOWN: "не удалось сверить (нет доступа к БД панели или к libcrypt)",
}

PASSWORD_MIN = config.PANEL_PASSWORD_MIN
PASSWORD_RECOMMENDED = config.PANEL_PASSWORD_RECOMMENDED
BCRYPT_MAX_BYTES = 72  # bcrypt (Go x/crypto) не принимает пароли длиннее

# Встроенный лимит входа 3x-ui v3 (internal/web/controller/login_limiter.go).
LIMITER_FAILURES, LIMITER_WINDOW_MIN, LIMITER_COOLDOWN_MIN = 5, 5, 15

PANEL_JAIL = "stealthnode-panel"
REPORT_JAILS = ("sshd", PANEL_JAIL, "recidive", "3x-ipl")
F2B_LOGS = (Path("/var/log/fail2ban.log"), Path("/var/log/fail2ban.log.1"))

_BCRYPT_RE = re.compile(r"^\$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}$")
_USERNAME_RE = re.compile(r"^[^\s\x00-\x1f\x7f]{1,64}$")


class PanelAuthError(RuntimeError):
    pass


@dataclass
class PanelAdmin:
    username: str
    password_hash: str
    two_factor: bool = False


# --- чтение БД панели ------------------------------------------------------------------


def read_admin(db_path: Path | str | None = None) -> PanelAdmin | None:
    """Администратор панели — первый пользователь, как его выбирает сама 3x-ui (GetFirstUser).

    Только чтение. ``None`` — БД нет или прочитать её не удалось.
    """
    path = Path(db_path) if db_path else config.XUI_DB
    if not path.is_file():
        return None
    try:
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=10)) as db:
            row = db.execute("SELECT username, password FROM users ORDER BY id LIMIT 1").fetchone()
            try:
                tfa = db.execute(
                    "SELECT value FROM settings WHERE key = 'twoFactorEnable' ORDER BY id LIMIT 1"
                ).fetchone()
            except sqlite3.Error:
                tfa = None
    except sqlite3.Error:
        return None
    if row is None:
        return PanelAdmin("", "")
    two_factor = bool(tfa) and str(tfa[0]).strip().lower() == "true"
    return PanelAdmin(str(row[0] or ""), str(row[1] or ""), two_factor)


# --- bcrypt через системную libcrypt (libxcrypt есть в любой Ubuntu) ----------------------

_crypt = None


def _crypt_fn():
    global _crypt
    if _crypt is None:
        try:
            lib = ctypes.CDLL(ctypes.util.find_library("crypt") or "libcrypt.so.1")
            fn = lib.crypt
            fn.restype = ctypes.c_char_p
            fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            _crypt = fn
        except (OSError, AttributeError):
            _crypt = False
    return _crypt or None


def can_verify(password_hash: str) -> bool:
    return bool(_BCRYPT_RE.match(password_hash or "")) and _crypt_fn() is not None


def bcrypt_check(password: str, password_hash: str) -> bool | None:
    """Пароль против bcrypt-хеша 3x-ui (``$2a$``, Go x/crypto). ``None`` — проверить нечем."""
    if not can_verify(password_hash):
        return None
    raw = password.encode("utf-8")
    if b"\0" in raw:
        return False
    out = _crypt_fn()(raw, password_hash.encode("ascii"))
    if not out or out.startswith(b"*"):  # libxcrypt сообщает об ошибке строкой «*0»/«*1»
        return None
    return hmac.compare_digest(out, password_hash.encode("ascii"))


def env_state(s: Settings, admin: PanelAdmin | None) -> str:
    """Подходят ли логин и пароль из .env к панели (см. константы MATCH…UNKNOWN)."""
    if admin is None:
        return UNKNOWN
    if not admin.username or not admin.password_hash:
        return MISSING
    if not can_verify(admin.password_hash):
        return UNKNOWN
    if admin.username == s.get("SN_XUI_USERNAME") and bcrypt_check(s.get("SN_XUI_PASSWORD"), admin.password_hash):
        return MATCH
    if admin.username == "admin" and bcrypt_check("admin", admin.password_hash):
        return DEFAULT
    return CHANGED


def current_state(s: Settings) -> tuple[str, PanelAdmin | None]:
    admin = read_admin()
    return env_state(s, admin), admin


# --- смена логина/пароля -----------------------------------------------------------------


def validate_username(name: str) -> str:
    if not _USERNAME_RE.match(name or ""):
        raise ValueError("логин панели: 1-64 символа без пробелов")
    return name


def validate_password(password: str) -> str:
    if len(password) < PASSWORD_MIN:
        raise ValueError(f"пароль панели: минимум {PASSWORD_MIN} символов")
    if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        raise ValueError(f"пароль панели: максимум {BCRYPT_MAX_BYTES} байт (ограничение bcrypt)")
    if any(ch in password for ch in "\r\n\x00"):
        raise ValueError("пароль панели не может содержать перевод строки")
    return password


def _tail(text: str, secret: str = "") -> str:
    if secret:
        text = text.replace(secret, "***")
    return " ".join(text.split())[-300:]


def set_admin(username: str, password: str, *, reset_2fa: bool = False, xui_bin: Path | None = None) -> None:
    """Задать логин/пароль штатной командой ``x-ui setting`` и проверить результат по БД.

    ``x-ui setting`` завершается с кодом 0 даже при ошибке, поэтому истина — хеш в БД.
    Смена увеличивает login_epoch: все открытые сессии панели завершаются.
    """
    validate_username(username)
    validate_password(password)
    binary = Path(xui_bin) if xui_bin else config.XUI_BIN
    if not binary.is_file():
        raise PanelAuthError(f"не найден {binary} — панель 3x-ui не установлена")
    # Пароль на секунду виден в списке процессов root-сервера — так же делает меню x-ui.
    cmd = [str(binary), "setting", "-username", username, "-password", password]
    if reset_2fa:
        cmd.append("-resetTwoFactor=true")
    proc = run(cmd, check=False, timeout=90)
    out = (proc.stdout or "") + (proc.stderr or "")
    admin = read_admin()
    if admin is not None and can_verify(admin.password_hash):
        if admin.username != username or not bcrypt_check(password, admin.password_hash):
            raise PanelAuthError("панель не приняла новый логин/пароль: " + _tail(out, password))
        return
    if proc.returncode != 0 or "updated successfully" not in out:
        raise PanelAuthError("x-ui setting: " + _tail(out, password))


# --- fail2ban ------------------------------------------------------------------------------


def f2b_available() -> bool:
    return which("fail2ban-client") is not None


def banned_ips(jail: str) -> list[str] | None:
    """IP в бане у jail; ``None`` — jail не запущен или fail2ban недоступен."""
    proc = run(["fail2ban-client", "status", jail], check=False, timeout=20)
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        if "Banned IP list:" in line:
            return line.split("Banned IP list:", 1)[1].split()
    return []


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ValueError(f"некорректный IP-адрес: {value!r}") from None


def unban(ips: list[str]) -> None:
    """Снять бан с IP во всех jail и в базе fail2ban."""
    if not ips:
        return
    proc = run(["fail2ban-client", "unban", *ips], check=False, timeout=30)
    if proc.returncode != 0:
        raise PanelAuthError("fail2ban-client unban: " + _tail(proc.stdout + proc.stderr))


def unban_all() -> None:
    proc = run(["fail2ban-client", "unban", "--all"], check=False, timeout=30)
    if proc.returncode != 0:
        raise PanelAuthError("fail2ban-client unban --all: " + _tail(proc.stdout + proc.stderr))


def panel_ban_history(log_paths: tuple[Path, ...] = F2B_LOGS) -> set[str]:
    """IP, которые банил jail панели (по журналу fail2ban) — чтобы снять и их бан в recidive."""
    pattern = re.compile(rf"\[{re.escape(PANEL_JAIL)}\]\s+(?:Restore\s+)?Ban\s+(\S+)")
    found: set[str] = set()
    for path in log_paths:
        try:
            found.update(pattern.findall(path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return found


def unban_panel_lockouts(log_paths: tuple[Path, ...] = F2B_LOGS) -> list[str]:
    """Снять баны, из-за которых не открывается панель: jail панели и recidive для тех же IP."""
    if not f2b_available():
        return []
    ips = set(banned_ips(PANEL_JAIL) or [])
    ips |= set(banned_ips("recidive") or []) & panel_ban_history(log_paths)
    found = sorted(ips)
    unban(found)
    return found
