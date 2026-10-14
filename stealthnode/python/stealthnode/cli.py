"""Командная строка ``stealthnode``.

Примеры:
    stealthnode doctor --e2e          # проверка сервера + реальное подключение
    stealthnode user add mama         # 50 ГБ/мес, 2 IP (значения по умолчанию из .env)
    stealthnode user show mama --qr   # ссылки и QR-код подписки в терминале
    stealthnode backup                # архив в /opt/stealthnode/backups
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time

from . import __version__, backup, config, doctor, provision, users
from .config import Settings
from .util import Console, atomic_write
from .xui import XuiError


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


def write_credentials(s: Settings, xui, console: Console | None = None) -> None:
    owner = s.get("SN_OWNER_NAME") or "owner"
    client = users.find_user(xui, owner) if xui else None
    sub = users.sub_url(s, client) if client else "(нет владельца)"
    text = f"""StealthNode {__version__} — учётные данные (СЕКРЕТНО, права 600)
Обновлено: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}

== Панель 3X-UI ==
Адрес:   {s.panel_url}
Логин:   {s.get('SN_XUI_USERNAME')}
Пароль:  {s.get('SN_XUI_PASSWORD')}
(язык интерфейса: выберите «Русский» на странице входа; включите 2FA в настройках)

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
        console.line(f"Логин/пароль панели: {s.get('SN_XUI_USERNAME')} / {s.get('SN_XUI_PASSWORD')}")
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
    for item in backup.restore(args.archive, env=env, files=files, db=db):
        console.ok(f"восстановлено: {item}")
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
    except (XuiError, ValueError, OSError, json.JSONDecodeError) as exc:
        console.fail(str(exc))
        return 1
    except KeyboardInterrupt:
        return 130
