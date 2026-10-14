"""Командная строка ``stealthnode``.

Примеры:
    stealthnode doctor --e2e          # проверка сервера + реальное подключение
    stealthnode user add mama         # 50 ГБ/мес, 2 IP (значения по умолчанию из .env)
    stealthnode user show mama --qr   # ссылки и QR-код подписки в терминале
    stealthnode backup                # архив в /opt/stealthnode/backups
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import subprocess
import sys
import time

from . import __version__, backup, config, doctor, panelauth, provision, users
from .config import Settings
from .panelauth import PanelAuthError
from .util import Console, atomic_write, rand_str
from .xui import XuiError

# Логин/пароль панели меняются только вместе с панелью (stealthnode panel-password),
# иначе .env и учётные данные разойдутся с настоящим паролем.
PANEL_CRED_KEYS = ("SN_XUI_USERNAME", "SN_XUI_PASSWORD")


def _settings_or_die(console: Console) -> Settings:
    s = config.load_settings()
    if not s.values:
        console.fail(f"нет файла {config.env_path()} — StealthNode не установлен (запустите install.sh)")
        sys.exit(2)
    return s


def _client(s: Settings):
    return provision.client_from_settings(s)


def parse_user_spec(spec: str, default_gb: float, default_ip: int) -> tuple[str, float, int]:
    """``имя[:ГБ[:IP]]`` → (имя, ГБ, IP). ГБ=0 — без лимита."""
    parts = spec.split(":")
    if not 1 <= len(parts) <= 3:
        raise ValueError(f"формат пользователя: имя[:ГБ[:IP]], получено {spec!r}")
    name = users.validate_name(parts[0])
    gb = float(parts[1]) if len(parts) > 1 and parts[1] != "" else default_gb
    ip = int(parts[2]) if len(parts) > 2 and parts[2] != "" else default_ip
    if gb < 0 or ip < 0:
        raise ValueError("лимиты не могут быть отрицательными")
    return name, gb, ip


# --- env ---------------------------------------------------------------------------


def cmd_env(args, console: Console) -> int:
    path = config.env_path()
    current = config.load_settings().values
    if args.action == "init":
        overrides = {}
        for item in args.pairs:
            key, sep, value = item.partition("=")
            if not sep or not re.match(r"^SN_[A-Z0-9_]+$", key):
                console.fail(f"ожидается SN_KEY=VALUE, получено {item!r}")
                return 2
            overrides[key] = value
        merged = dict(current)
        # Явно переданные параметры установщика имеют приоритет над сохранёнными.
        merged.update({k: v for k, v in overrides.items() if v != ""})
        filled = config.fill_defaults(merged, __version__)
        s = Settings(filled)
        errors = s.validate()
        if errors:
            for e in errors:
                console.fail(e)
            return 1
        config.save_settings(s)
        for w in s.warnings():
            console.warn(w)
        console.ok(f"параметры сохранены: {path} (600)")
        return 0
    if args.action == "get":
        for key in args.pairs:
            print(current.get(key, ""))
        return 0
    if args.action == "set":
        for item in args.pairs:
            key, sep, value = item.partition("=")
            if not sep or not re.match(r"^SN_[A-Z0-9_]+$", key):
                console.fail(f"ожидается SN_KEY=VALUE, получено {item!r}")
                return 2
            if key in PANEL_CRED_KEYS:
                console.fail(f"{key} в .env не меняет пароль панели — используйте: stealthnode panel-password")
                return 2
            current[key] = value
        config.save_settings(Settings(current))
        return 0
    if args.action == "check":
        s = Settings(current)
        errors = s.validate()
        for e in errors:
            console.fail(e)
        for w in s.warnings():
            console.warn(w)
        if not errors:
            console.ok("параметры корректны")
        return 1 if errors else 0
    return 2


# --- provision / info / links ---------------------------------------------------------


def cmd_provision(args, console: Console) -> int:
    s = _settings_or_die(console)
    extra = [parse_user_spec(u, s.int("SN_DEFAULT_LIMIT_GB", 50), s.int("SN_DEFAULT_IP_LIMIT", 2)) for u in args.user or []]
    xui = _client(s)
    provision.wait_for_api(xui, timeout=args.wait)
    provision.provision(s, xui, console, extra_users=extra)
    path = provision.export_xray_config(xui)
    console.ok(f"конфиг Xray (справочно) сохранён: {path}")
    users.write_all(xui, s, console)
    write_credentials(s, xui, console)
    return 0


def panel_login_view(s: Settings) -> tuple[str, str, str]:
    """(логин, пароль, пояснение) для показа владельцу — с учётом смены пароля в веб-интерфейсе."""
    state, admin = panelauth.current_state(s)
    login, password, note = s.get("SN_XUI_USERNAME"), s.get("SN_XUI_PASSWORD"), ""
    if state == panelauth.CHANGED:
        login = admin.username if admin else login
        password = "изменён в веб-интерфейсе панели (StealthNode его не хранит)"
        note = "Забыли новый пароль: sudo stealthnode panel-password"
    elif state == panelauth.DEFAULT:
        login, password = "admin", "admin"
        note = "НЕБЕЗОПАСНО: стандартный пароль — выполните sudo stealthnode panel-password"
    elif state == panelauth.MISSING:
        note = "В панели нет администратора — выполните sudo stealthnode panel-password"
    elif state == panelauth.UNKNOWN:
        note = "Если меняли пароль в веб-интерфейсе — действует новый"
    if admin and admin.two_factor:
        note = (note + "; " if note else "") + "включена 2FA: нужен код из приложения"
    return login, password, note


def write_credentials(s: Settings, xui, console: Console | None = None) -> None:
    owner = s.get("SN_OWNER_NAME") or "owner"
    client = None
    if xui:
        try:
            client = users.find_user(xui, owner)
        except XuiError:
            client = None
    sub = users.sub_url(s, client) if client else "(нет владельца или панель недоступна: stealthnode credentials)"
    login, password, note = panel_login_view(s)
    note_line = f"{note}\n" if note else ""
    text = f"""StealthNode {__version__} — учётные данные (СЕКРЕТНО, права 600)
Обновлено: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}

== Панель 3X-UI ==
Адрес:   {s.panel_url}
Логин:   {login}
Пароль:  {password}
{note_line}(язык интерфейса: выберите «Русский» на странице входа; включите 2FA в настройках)

== Не пускает в панель / забыли пароль ==
sudo stealthnode panel-password   новый пароль + снятие блокировок (лимит 3x-ui и fail2ban)
После {panelauth.LIMITER_FAILURES} неверных попыток за {panelauth.LIMITER_WINDOW_MIN} минут 3x-ui на \
{panelauth.LIMITER_COOLDOWN_MIN} минут блокирует вход
и отвечает «неверный логин или пароль» даже на правильный — подождите или выполните команду выше.

== Подписка владельца ({owner}) ==
{sub}

== Протоколы ==
VLESS + XHTTP + REALITY      {s.get('SN_XHTTP_PORT')}/tcp   mode=stream-one, fp={s.get('SN_FINGERPRINT')}
VLESS + TCP + REALITY Vision {s.get('SN_VISION_PORT')}/tcp  (iOS)
Hysteria2 + Salamander       {s.get('SN_HY2_PORT')}/udp
REALITY: SNI {s.get('SN_REALITY_SNI')}, target {s.get('SN_REALITY_TARGET')}
REALITY publicKey: {s.get('SN_REALITY_PUBLIC_KEY')}
REALITY shortId:   {s.get('SN_REALITY_SHORT_ID')}
Hysteria2 obfs (salamander) password: {s.get('SN_HY2_OBFS_PASSWORD')}
Сертификат Hysteria2: {s.get('SN_HY2_CERT_MODE')}

== Файлы ==
Параметры и секреты:  {config.env_path()}
Ссылки администратора: {config.sn_root() / 'xray/share/admin-links.txt'}
Профили пользователей: {config.sn_root() / 'users'}/<имя>/
Резервные копии:       {config.sn_root() / 'backups'}/

== Команды ==
stealthnode doctor --e2e          проверка всего сервера
stealthnode user add mama         новый пользователь ({s.get('SN_DEFAULT_LIMIT_GB')} ГБ/мес, IP: {s.get('SN_DEFAULT_IP_LIMIT')})
stealthnode user show mama --qr   ссылки и QR-код
stealthnode backup                резервная копия
"""
    atomic_write(config.credentials_path(), text, mode=0o600)
    if console:
        console.ok(f"учётные данные: {config.credentials_path()} (600)")


def cmd_info(args, console: Console) -> int:
    s = _settings_or_die(console)
    console.header("StealthNode")
    console.line(f"Версия:     {__version__}")
    console.line(f"Домен:      {s.domain} (IP {s.get('SN_PUBLIC_IP') or '?'})")
    console.line(f"Панель:     {s.panel_url}")
    console.line(f"Подписки:   {s.sub_base_url}<subId>")
    console.line(
        f"Порты:      XHTTP {s.get('SN_XHTTP_PORT')}/tcp, Vision {s.get('SN_VISION_PORT')}/tcp, "
        f"Hysteria2 {s.get('SN_HY2_PORT')}/udp, панель {s.get('SN_PANEL_PORT')}/tcp, SSH {s.get('SN_SSH_PORT')}/tcp"
    )
    console.line(f"REALITY:    SNI {s.get('SN_REALITY_SNI')}, fp {s.get('SN_FINGERPRINT')}")
    console.line(f"Сертификат Hysteria2: {s.get('SN_HY2_CERT_MODE')}")
    if args.secrets:
        login, password, note = panel_login_view(s)
        console.line(f"Логин/пароль панели: {login} / {password}")
        if note:
            console.line(f"            {note}")
    else:
        console.line(f"Учётные данные: {config.credentials_path()} (или stealthnode info --secrets)")
    try:
        xui = _client(s)
        console.line(f"Xray:       {xui.xray_version()}")
    except XuiError as exc:
        console.warn(f"API панели недоступен: {exc}")
    return 0


def cmd_links(args, console: Console) -> int:
    s = _settings_or_die(console)
    xui = _client(s)
    users.write_all(xui, s, console)
    write_credentials(s, xui, console)
    return 0


# --- users -----------------------------------------------------------------------------


def cmd_user(args, console: Console) -> int:
    s = _settings_or_die(console)
    xui = _client(s)
    if args.action == "list":
        try:
            online = set(xui.onlines())
        except XuiError:
            online = set()
        lst = users.list_users(xui)
        if not lst:
            console.warn("пользователей нет")
        for c in lst:
            console.line(users.describe(c, online))
        return 0
    if args.action == "add":
        gb = 0 if args.unlimited else (args.gb if args.gb is not None else s.int("SN_DEFAULT_LIMIT_GB", 50))
        ip = 0 if args.unlimited else (args.ip if args.ip is not None else s.int("SN_DEFAULT_IP_LIMIT", 2))
        # 3x-ui v3 добавляет клиента в работающий Xray через его API — без перезапуска ядра.
        client = users.add_user(
            xui, args.name, limit_gb=gb, ip_limit=ip, monthly=not args.no_reset, days=args.days, comment=args.comment
        )
        console.ok(f"пользователь {client['email']} создан: {gb:g} ГБ{' в месяц' if gb and not args.no_reset else ''}, IP-лимит {ip or '∞'}")
        created = users.find_user(xui, client["email"]) or client
        d = users.write_user_files(xui, s, created)
        users.write_admin_links(xui, s)
        console.line(f"Подписка: {users.sub_url(s, created)}")
        console.line(f"Файлы и QR: {d}")
        return 0
    if args.action == "del":
        if not args.yes:
            console.fail("удаление необратимо: повторите с --yes")
            return 2
        users.delete_user(xui, args.name)
        users.write_admin_links(xui, s)
        console.ok(f"пользователь {args.name} удалён")
        return 0
    if args.action == "show":
        c = users.find_user(xui, args.name)
        if not c:
            console.fail(f"пользователь {args.name!r} не найден")
            return 1
        console.line(users.describe(c))
        url = users.sub_url(s, c)
        console.line(f"\nПодписка: {url}\n")
        for raw in xui.client_links(args.name):
            console.line(raw + "\n")
        if args.qr:
            console.line(users.qr_terminal(url))
        return 0
    if args.action == "reset":
        xui.reset_client_traffic(args.name)
        console.ok(f"трафик пользователя {args.name} обнулён")
        return 0
    if args.action == "limit":
        users.set_limits(xui, args.name, limit_gb=args.gb, ip_limit=args.ip)
        console.ok(f"лимиты пользователя {args.name} обновлены")
        return 0
    return 2


# --- обслуживание ---------------------------------------------------------------------


def cmd_doctor(args, console: Console) -> int:
    s = _settings_or_die(console)
    return doctor.run_doctor(s, console, e2e=args.e2e, speed=args.speed)


def cmd_cert_sync(args, console: Console) -> int:
    s = _settings_or_die(console)
    provision.cert_sync(s, _client(s), console)
    return 0


def cmd_sni_check(args, console: Console) -> int:
    s = _settings_or_die(console)
    xui = _client(s)
    targets = args.domains or [s.get("SN_REALITY_SNI"), "max.ru", "yandex.ru", "ya.ru", "vk.com", "www.wp.pl"]
    seen = []
    for t in targets:
        if t and t not in seen:
            seen.append(t)
    console.header("Проверка кандидатов SNI для REALITY (с этого сервера)")
    rows = []
    for host in seen:
        try:
            res = xui.scan_reality_target(f"{host}:443", host)
        except XuiError as exc:
            console.fail(f"{host}: {exc}")
            continue
        rows.append((res.get("feasible", False), res.get("latencyMs", 99999), host, res))
    rows.sort(key=lambda r: (not r[0], r[1]))
    for feasible, latency, host, res in rows:
        text = (
            f"{host:<20} TLS {res.get('tlsVersion', '?'):<4} ALPN {res.get('alpn') or '-':<9} "
            f"{res.get('curveID') or '-':<16} {latency} мс {res.get('reason') or ''}"
        )
        (console.ok if feasible else console.warn)(text)
    console.line("\nПодходит: TLS 1.3 + h2 + X25519/X25519MLKEM768 + валидный сертификат. Меньше задержка — лучше.")
    console.line("Сменить SNI: stealthnode sni-set <домен> (пользователям нужно обновить подписку).")
    return 0


def cmd_sni_set(args, console: Console) -> int:
    s = _settings_or_die(console)
    sni = args.domain.strip().lower()
    if not config.is_valid_domain(sni):
        console.fail(f"некорректный домен: {sni!r}")
        return 2
    s.values["SN_REALITY_SNI"] = sni
    s.values["SN_REALITY_TARGET"] = args.target or f"{sni}:443"
    errors = s.validate()
    if errors:
        for e in errors:
            console.fail(e)
        return 1
    config.save_settings(s)
    xui = _client(s)
    provision.provision(s, xui, console)
    users.write_all(xui, s, console)
    write_credentials(s, xui, console)
    console.warn("SNI изменён: пользователям нужно обновить подписку в клиенте")
    return 0


def cmd_export(args, console: Console) -> int:
    s = _settings_or_die(console)
    console.ok(f"сохранено: {provision.export_xray_config(_client(s))}")
    return 0


def cmd_backup(args, console: Console) -> int:
    s = config.load_settings()
    path = backup.make_backup(keep=args.keep, settings=s)
    console.ok(f"резервная копия: {path}")
    return 0


def cmd_restore(args, console: Console) -> int:
    env = not args.db_only
    files = not (args.env_only or args.db_only)
    db = not args.env_only
    restored = backup.restore(args.archive, env=env, files=files, db=db)
    for item in restored:
        console.ok(f"восстановлено: {item}")
    if db and str(config.XUI_DB) in restored:
        # Панель перезапущена с восстановленной БД — дождаться её и ядра Xray.
        s = config.load_settings()
        if s.get("SN_XUI_API_TOKEN"):
            try:
                provision.wait_for_api(_client(s), timeout=90)
                doctor.wait_xray_process(timeout=30)
                console.ok("панель и Xray снова работают")
            except XuiError as exc:
                console.warn(f"панель пока не отвечает: {exc}")
    return 0


def cmd_credentials(args, console: Console) -> int:
    s = _settings_or_die(console)
    try:
        xui = _client(s)
    except XuiError:
        xui = None
    write_credentials(s, xui, console)
    return 0


def cmd_token(args, console: Console) -> int:
    """Перевыпустить API-токен StealthNode и сохранить в .env."""
    s = _settings_or_die(console)
    proc = subprocess.run(
        [str(config.XUI_BIN), "setting", "-tokenName", "stealthnode", "-tokenScope", "admin", "-getApiToken"],
        capture_output=True, text=True, timeout=60, check=False,
    )
    match = re.search(r"apiToken:\s*(\S+)", proc.stdout)
    if not match:
        console.fail("не удалось получить токен: " + (proc.stdout + proc.stderr).strip()[-300:])
        return 1
    s.values["SN_XUI_API_TOKEN"] = match.group(1)
    config.save_settings(s)
    console.ok("API-токен перевыпущен и сохранён в .env")
    return 0


def _ask_password(console: Console) -> str:
    """Спросить новый пароль дважды; пустой ввод — сгенерировать случайный."""
    first = getpass.getpass("Новый пароль панели (Enter — сгенерировать случайный): ")
    if not first:
        return ""
    if getpass.getpass("Повторите пароль: ") != first:
        raise ValueError("пароли не совпадают — ничего не изменено")
    return first


def _restart_panel(s: Settings, console: Console) -> bool:
    """Перезапуск x-ui: обнуляет встроенный лимит неудачных входов (он хранится в памяти)."""
    proc = subprocess.run(["systemctl", "restart", "x-ui"], capture_output=True, text=True, timeout=120, check=False)
    if proc.returncode != 0:
        console.warn("systemctl restart x-ui: " + (proc.stdout + proc.stderr).strip()[-300:])
        return False
    try:
        provision.wait_for_api(_client(s), timeout=90)
    except XuiError as exc:
        console.warn(f"панель после перезапуска пока не отвечает: {exc}")
        return False
    doctor.wait_xray_process(timeout=30)
    return True


def cmd_panel_password(args, console: Console) -> int:
    """Сменить или восстановить логин/пароль панели 3x-ui и снять блокировки входа."""
    s = _settings_or_die(console)
    state, admin = panelauth.current_state(s)
    if args.state:  # для install.sh: одно слово
        print(state)
        return 0
    if args.check:
        console.line(f"Панель:  {s.panel_url}")
        console.line(f"Логин в панели: {admin.username if admin and admin.username else '?'}")
        (console.ok if state in (panelauth.MATCH, panelauth.CHANGED) else console.warn)(panelauth.STATE_TEXT[state])
        if admin and admin.two_factor:
            console.info("включена 2FA: при входе нужен код из приложения")
        if panelauth.f2b_available():
            banned = panelauth.banned_ips(panelauth.PANEL_JAIL)
            if banned:
                console.warn(f"fail2ban: в бане панели {len(banned)} IP: {' '.join(banned)} (снять: stealthnode unban <IP>)")
        return {panelauth.MATCH: 0, panelauth.CHANGED: 0, panelauth.UNKNOWN: 3}.get(state, 1)

    username = args.username or (admin.username if admin and admin.username else s.get("SN_XUI_USERNAME"))
    panelauth.validate_username(username)
    generated = False
    if args.password is not None:
        password = args.password
    elif args.random or not sys.stdin.isatty():
        password = ""
    else:
        password = _ask_password(console)
    if not password:
        password, generated = rand_str(24), True
    panelauth.validate_password(password)

    panelauth.set_admin(username, password, reset_2fa=args.reset_2fa)
    s.values["SN_XUI_USERNAME"], s.values["SN_XUI_PASSWORD"] = username, password
    config.save_settings(s)
    console.ok("логин/пароль панели изменены; открытые сессии панели завершены")
    console.line(f"       Адрес:  {s.panel_url}")
    console.line(f"       Логин:  {username}")
    if generated:
        console.line(f"       Пароль: {password}")
    if args.reset_2fa:
        console.ok("двухфакторная аутентификация (2FA) отключена")
    elif admin and admin.two_factor:
        console.info("в панели включена 2FA: код из приложения по-прежнему нужен (потеряли — добавьте --reset-2fa)")

    if args.no_restart:
        console.info(
            f"панель не перезапускалась: если недавно было {panelauth.LIMITER_FAILURES}+ неверных попыток, "
            f"вход может быть заблокирован ещё до {panelauth.LIMITER_COOLDOWN_MIN} минут"
        )
    elif _restart_panel(s, console):
        console.ok("панель перезапущена: лимит неудачных входов 3x-ui сброшен (VPN переподключился за секунды)")
    try:
        unbanned = panelauth.unban_panel_lockouts()
    except PanelAuthError as exc:
        console.warn(str(exc))
        unbanned = []
    if unbanned:
        console.ok(f"fail2ban: сняты баны входа в панель: {' '.join(unbanned)}")
    try:
        xui = _client(s)
    except XuiError:
        xui = None
    write_credentials(s, xui, console)
    return 0


def cmd_unban(args, console: Console) -> int:
    """Показать или снять баны fail2ban (SSH, панель, recidive, лимит IP 3x-ui)."""
    if not panelauth.f2b_available():
        console.fail("fail2ban не установлен")
        return 1
    if args.all:
        panelauth.unban_all()
        console.ok("сняты все баны fail2ban")
        return 0
    if args.ips:
        ips = [panelauth.validate_ip(ip) for ip in args.ips]
        panelauth.unban(ips)
        console.ok(f"сняты баны: {' '.join(ips)}")
        console.info(
            f"если панель всё ещё отвечает «неверный логин или пароль» на верный пароль — это лимит 3x-ui "
            f"({panelauth.LIMITER_COOLDOWN_MIN} мин); сбросить сразу: stealthnode panel-password"
        )
        return 0
    console.header("Баны fail2ban")
    for jail in panelauth.REPORT_JAILS:
        banned = panelauth.banned_ips(jail)
        if banned is None:
            continue
        console.line(f"{jail:<18} {len(banned):>3}  {' '.join(banned) or '-'}")
    console.line("\nСнять: stealthnode unban <IP> [<IP>…] | все: stealthnode unban --all")
    console.line("Свой IP навсегда в исключения: sudo bash install.sh --admin-ip <IP> (запоминается)")
    return 0


def cmd_version(args, console: Console) -> int:
    print(__version__)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="stealthnode", description="StealthNode: обслуживание личного VPN (3x-ui/Xray)")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    e = sub.add_parser("env", help="параметры установки (.env)")
    e.add_argument("action", choices=["init", "get", "set", "check"])
    e.add_argument("pairs", nargs="*")
    e.set_defaults(func=cmd_env)

    pr = sub.add_parser("provision", help="настроить панель: инбаунды, настройки, пользователи")
    pr.add_argument("--user", action="append", metavar="ИМЯ[:ГБ[:IP]]", help="добавить пользователя (можно несколько)")
    pr.add_argument("--wait", type=float, default=120, help="сколько ждать API панели, с")
    pr.set_defaults(func=cmd_provision)

    i = sub.add_parser("info", help="сводка по установке")
    i.add_argument("--secrets", action="store_true", help="показать логин/пароль панели")
    i.set_defaults(func=cmd_info)

    d = sub.add_parser("doctor", help="проверка сервера (раздел 8 ТЗ)")
    d.add_argument("--e2e", action="store_true", help="реальное подключение по каждому профилю")
    d.add_argument("--speed", action="store_true", help="замер скорости через туннель (с --e2e)")
    d.set_defaults(func=cmd_doctor)

    u = sub.add_parser("user", help="пользователи")
    usub = u.add_subparsers(dest="action", required=True)
    usub.add_parser("list", help="список с трафиком")
    ua = usub.add_parser("add", help="добавить")
    ua.add_argument("name")
    ua.add_argument("--gb", type=float, help="лимит ГБ в месяц (по умолчанию SN_DEFAULT_LIMIT_GB)")
    ua.add_argument("--ip", type=int, help="лимит одновременных IP (по умолчанию SN_DEFAULT_IP_LIMIT)")
    ua.add_argument("--unlimited", action="store_true", help="без лимитов")
    ua.add_argument("--days", type=int, default=0, help="срок действия в днях (0 — бессрочно)")
    ua.add_argument("--no-reset", action="store_true", help="не сбрасывать трафик ежемесячно")
    ua.add_argument("--comment", default="")
    ud = usub.add_parser("del", help="удалить")
    ud.add_argument("name")
    ud.add_argument("--yes", action="store_true")
    us = usub.add_parser("show", help="ссылки пользователя")
    us.add_argument("name")
    us.add_argument("--qr", action="store_true", help="QR-код подписки в терминале")
    ur = usub.add_parser("reset", help="обнулить трафик")
    ur.add_argument("name")
    ul = usub.add_parser("limit", help="изменить лимиты")
    ul.add_argument("name")
    ul.add_argument("--gb", type=float)
    ul.add_argument("--ip", type=int)
    u.set_defaults(func=cmd_user)

    sub.add_parser("links", help="пересоздать файлы ссылок и QR").set_defaults(func=cmd_links)
    sub.add_parser("cert-sync", help="синхронизировать сертификат Hysteria2 с Caddy").set_defaults(func=cmd_cert_sync)

    sc = sub.add_parser("sni-check", help="проверить кандидатов SNI для REALITY")
    sc.add_argument("domains", nargs="*")
    sc.set_defaults(func=cmd_sni_check)

    ss = sub.add_parser("sni-set", help="сменить SNI/цель REALITY")
    ss.add_argument("domain")
    ss.add_argument("--target", help="host:port цели (по умолчанию <домен>:443)")
    ss.set_defaults(func=cmd_sni_set)

    sub.add_parser("export-config", help="сохранить работающий конфиг Xray").set_defaults(func=cmd_export)

    b = sub.add_parser("backup", help="резервная копия")
    b.add_argument("--keep", type=int, default=14, help="сколько последних копий хранить")
    b.set_defaults(func=cmd_backup)

    r = sub.add_parser("restore", help="восстановить из резервной копии")
    r.add_argument("archive")
    g = r.add_mutually_exclusive_group()
    g.add_argument("--env-only", action="store_true")
    g.add_argument("--db-only", action="store_true")
    r.set_defaults(func=cmd_restore)

    pp = sub.add_parser(
        "panel-password",
        help="сменить/восстановить пароль панели и снять блокировки входа",
        description="Новый логин/пароль панели 3x-ui: применяется в панели, сохраняется в .env и файле учётных "
        "данных; панель перезапускается (сброс лимита неудачных входов), снимаются баны fail2ban для панели.",
    )
    pp.add_argument("--password", help="новый пароль (по умолчанию спросит; Enter — случайный)")
    pp.add_argument("--random", action="store_true", help="сгенерировать случайный пароль, не спрашивая")
    pp.add_argument("--username", help="новый логин (по умолчанию текущий логин панели)")
    pp.add_argument("--reset-2fa", action="store_true", help="отключить 2FA (если потерян доступ к приложению)")
    pp.add_argument("--no-restart", action="store_true", help="не перезапускать панель")
    pp.add_argument("--check", action="store_true", help="только проверить: подходит ли пароль из .env")
    pp.add_argument("--state", action="store_true", help=argparse.SUPPRESS)
    pp.set_defaults(func=cmd_panel_password)

    ub = sub.add_parser("unban", help="показать/снять баны fail2ban")
    ub.add_argument("ips", nargs="*", metavar="IP")
    ub.add_argument("--all", action="store_true", help="снять все баны")
    ub.set_defaults(func=cmd_unban)

    sub.add_parser("credentials", help=f"обновить {config.credentials_path()}").set_defaults(func=cmd_credentials)
    sub.add_parser("token-rotate", help="перевыпустить API-токен панели").set_defaults(func=cmd_token)
    sub.add_parser("version", help="версия").set_defaults(func=cmd_version)
    return p


def main(argv: list[str] | None = None) -> int:
    console = Console()
    parser = build_parser()
    args = parser.parse_args(argv)
    if os.geteuid() != 0 and args.command not in ("version",) and not os.environ.get("SN_ALLOW_NONROOT"):
        console.fail("нужны права root: sudo stealthnode ...")
        return 2
    try:
        return int(args.func(args, console) or 0)
    except (XuiError, PanelAuthError, ValueError, OSError, json.JSONDecodeError) as exc:
        console.fail(str(exc))
        return 1
    except KeyboardInterrupt:
        return 130
