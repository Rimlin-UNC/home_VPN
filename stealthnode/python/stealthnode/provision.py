"""Идемпотентная настройка панели 3x-ui под схему StealthNode.

Повторный запуск безопасен: создаётся только недостающее, расхождения в
управляемых полях исправляются, пользователи и их трафик не трогаются.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field

from . import certs, config, users
from .config import ALL_TAGS, Settings
from .payloads import apply_settings_patch, desired_inbounds, inbound_diff, merge_inbound_for_update, patch_xray_template, settings_patch
from .util import Console, atomic_write
from .xui import XuiClient, XuiError


@dataclass
class ProvisionResult:
    created_inbounds: list[str] = field(default_factory=list)
    updated_inbounds: list[str] = field(default_factory=list)
    settings_changed: list[str] = field(default_factory=list)
    template_changed: bool = False
    created_users: list[str] = field(default_factory=list)
    cert: certs.CertState | None = None
    panel_restarted: bool = False


def client_from_settings(s: Settings, timeout: float = 30.0) -> XuiClient:
    return XuiClient(s.xui_api_base, s.get("SN_XUI_API_TOKEN"), timeout=timeout)


def wait_for_api(xui: XuiClient, timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            xui.server_status()
            return
        except XuiError as exc:
            last = exc
            time.sleep(2)
    raise XuiError(f"панель не ответила за {int(timeout)} с: {last}")


def restart_panel(xui: XuiClient) -> None:
    subprocess.run(["systemctl", "restart", "x-ui"], check=True, timeout=120)
    time.sleep(3)
    wait_for_api(xui)


def check_port_conflicts(existing: list[dict], desired: dict[str, dict]) -> list[str]:
    """Чужие инбаунды на наших портах (с учётом TCP/UDP) — ошибка, а не тихая перезапись."""
    def transport(inb: dict) -> str:
        return "udp" if inb.get("protocol") in ("hysteria", "wireguard", "tuic", "amneziawg") else "tcp"

    problems = []
    for tag, want in desired.items():
        for inb in existing:
            if inb.get("tag") in ALL_TAGS:
                continue
            if int(inb.get("port", 0)) == int(want["port"]) and transport(inb) == transport(want):
                problems.append(
                    f"порт {want['port']}/{transport(want)} нужен для {tag}, но занят инбаундом "
                    f"{inb.get('remark') or inb.get('tag')!r} (id {inb.get('id')})"
                )
    return problems


def provision(
    s: Settings,
    xui: XuiClient,
    console: Console | None = None,
    *,
    extra_users: list[tuple[str, float, int]] | None = None,
    restart_panel_if_needed: bool = True,
) -> ProvisionResult:
    console = console or Console()
    res = ProvisionResult()
    errors = s.validate()
    if errors:
        raise ValueError("ошибки конфигурации:\n  " + "\n  ".join(errors))

    # 1. Общие настройки панели (подписка за Caddy, часовой пояс, язык бота).
    current = xui.get_settings()
    new_settings, changed = apply_settings_patch(current, settings_patch(s))
    if changed:
        xui.update_settings(new_settings)
        res.settings_changed = changed
        console.ok("настройки панели обновлены: " + ", ".join(changed))
    else:
        console.ok("настройки панели уже актуальны")

    # 2. Шаблон Xray: DNS через dnscrypt-proxy, стратегия freedom.
    tpl = xui.get_xray_template()
    new_tpl, tpl_changed = patch_xray_template(tpl, s)
    if tpl_changed:
        xui.update_xray_template(new_tpl)
        res.template_changed = True
        console.ok("шаблон Xray обновлён (DNS → dnscrypt-proxy, резерв DoH)")

    # 3. Сертификат Hysteria2.
    cert = certs.ensure_hy2_cert(s)
    res.cert = cert
    if s.get("SN_HY2_CERT_MODE") != cert.mode:
        s.values["SN_HY2_CERT_MODE"] = cert.mode
        config.save_settings(s)
    if cert.mode == "acme":
        console.ok(f"Hysteria2: сертификат Let's Encrypt ({cert.source})")
    else:
        console.warn("Hysteria2: временно self-signed + pinSHA256 (Let's Encrypt появится после настройки DNS)")

    # 4. Инбаунды.
    existing = xui.list_inbounds()
    desired = desired_inbounds(s, cert.cert_file, cert.key_file, cert.pin_sha256)
    conflicts = check_port_conflicts(existing, desired)
    if conflicts:
        raise XuiError("конфликт портов:\n  " + "\n  ".join(conflicts))
    by_tag = {i.get("tag"): i for i in existing}
    for tag, want in desired.items():
        cur = by_tag.get(tag)
        if cur is None:
            xui.add_inbound(want)
            res.created_inbounds.append(tag)
            console.ok(f"создан инбаунд {tag} (порт {want['port']})")
            continue
        diffs = inbound_diff(cur, want)
        if diffs:
            xui.update_inbound(int(cur["id"]), merge_inbound_for_update(cur, want))
            res.updated_inbounds.append(tag)
            console.ok(f"инбаунд {tag} исправлен: {', '.join(diffs)}")

    # 5. Пользователи: владелец без лимитов + дополнительные из параметров.
    owner = s.get("SN_OWNER_NAME") or "owner"
    _, created = users.ensure_user(xui, owner, limit_gb=0, ip_limit=0, comment="владелец")
    if created:
        res.created_users.append(owner)
        console.ok(f"создан пользователь-владелец {owner!r} (без лимитов)")
    for name, gb, ip in extra_users or []:
        _, created = users.ensure_user(xui, name, limit_gb=gb, ip_limit=ip)
        if created:
            res.created_users.append(name)
            console.ok(f"создан пользователь {name!r}: {gb:g} ГБ/мес, IP-лимит {ip}")
    fixed = users.ensure_attached(xui)
    for email in fixed:
        console.ok(f"пользователь {email} привязан ко всем профилям")

    # 6. Применение: подписка слушает новый адрес только после перезапуска панели.
    need_panel_restart = any(k.startswith("sub") or k == "timeLocation" for k in res.settings_changed)
    if need_panel_restart and restart_panel_if_needed:
        restart_panel(xui)
        res.panel_restarted = True
        console.ok("панель перезапущена (новые параметры подписки)")
    # Пользователей 3x-ui применяет на лету; перезапуск ядра (обрыв всех соединений) —
    # только если менялись инбаунды, шаблон Xray или сертификат.
    if res.created_inbounds or res.updated_inbounds or res.template_changed or cert.changed:
        xui.restart_xray()
        console.ok("Xray перезапущен с актуальной конфигурацией")
    else:
        console.ok("конфигурация Xray не менялась — перезапуск не нужен")
    return res


def export_xray_config(xui: XuiClient) -> str:
    """Сохранить работающий конфиг Xray в /opt/stealthnode/xray/config.json (только для справки)."""
    cfg = xui.xray_config()
    path = config.sn_root() / "xray" / "config.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    atomic_write(path, json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", mode=0o600)
    return str(path)


def cert_sync(s: Settings, xui: XuiClient, console: Console | None = None) -> bool:
    """Синхронизировать сертификат Hysteria2 с Caddy. True — если что-то изменилось."""
    console = console or Console()
    before_mode = s.get("SN_HY2_CERT_MODE")
    cert = certs.ensure_hy2_cert(s)
    inbound = next((i for i in xui.list_inbounds() if i.get("tag") == config.TAG_HY2), None)
    if inbound is None:
        console.warn("инбаунд Hysteria2 не найден — запустите: stealthnode provision")
        return False
    want = desired_inbounds(s, cert.cert_file, cert.key_file, cert.pin_sha256)[config.TAG_HY2]
    diffs = inbound_diff(inbound, want)
    if diffs:
        xui.update_inbound(int(inbound["id"]), merge_inbound_for_update(inbound, want))
    if cert.mode != before_mode:
        s.values["SN_HY2_CERT_MODE"] = cert.mode
        config.save_settings(s)
        console.warn(
            f"Hysteria2: сертификат переключён {before_mode} → {cert.mode}; клиентам нужно обновить подписку"
        )
    if cert.changed or diffs:
        xui.restart_xray()
        console.ok("сертификат Hysteria2 обновлён, Xray перезапущен")
        return True
    console.ok(f"сертификат Hysteria2 актуален ({cert.mode})")
    return False
