#!/usr/bin/env python3
"""Вход в панель 3x-ui так же, как браузер: HTTPS через Caddy, CSRF-токен, cookie-сессия.

Запускается в CI на сервере после установки (параметры берутся из /opt/stealthnode/.env):

  panel_login.py login ЛОГИН ПАРОЛЬ [--source-ip IP] [--expect ok|fail|blocked]
  panel_login.py change СТАРЫЙ_ЛОГИН СТАРЫЙ_ПАРОЛЬ НОВЫЙ_ЛОГИН НОВЫЙ_ПАРОЛЬ

``change`` повторяет то, что делает вкладка «Безопасность» веб-интерфейса
(POST panel/api/setting/updateUser в сессии владельца).
``--source-ip`` — адрес-источник (алиас на lo): так Caddy и 3x-ui видят «чужой» IP,
и можно проверить встроенный лимит 3x-ui и бан fail2ban (127.0.0.1 в исключениях).
``blocked`` — соединение отклонено (бан fail2ban на порту панели).
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import sys
import urllib.parse

sys.path.insert(0, os.environ.get("SN_APP_PY", "/opt/stealthnode/app/python"))

from stealthnode import config  # noqa: E402


class SNIConnection(http.client.HTTPSConnection):
    """HTTPS к ip:port с заданным SNI (аналог curl --resolve) и адресом-источником."""

    def __init__(self, ip: str, port: int, sni: str, source_ip: str | None):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # в CI tls internal; сертификат проверяет doctor
        super().__init__(ip, port, context=ctx, timeout=20, source_address=(source_ip, 0) if source_ip else None)
        self._sni = sni

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._sni)


class Browser:
    def __init__(self, source_ip: str | None = None):
        s = config.load_settings()
        self.domain, self.port = s.domain, s.int("SN_PANEL_PORT")
        self.base = f"/{s.get('SN_PANEL_PATH')}"
        # С алиаса на lo подключаемся к нему же: так пакет гарантированно идёт с этим источником.
        self.ip = source_ip or "127.0.0.1"
        self.source_ip = source_ip
        self.cookies: dict[str, str] = {}
        self.csrf = ""

    def request(self, method: str, path: str, form: dict | None = None) -> tuple[int, dict]:
        conn = SNIConnection(self.ip, self.port, self.domain, self.source_ip)
        headers = {"Host": f"{self.domain}:{self.port}", "Accept": "application/json"}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["X-CSRF-Token"] = self.csrf
        try:
            conn.request(method, self.base + path, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            for header, value in resp.getheaders():
                if header.lower() == "set-cookie":
                    name, _, rest = value.partition("=")
                    self.cookies[name.strip()] = rest.split(";", 1)[0]
        finally:
            conn.close()
        try:
            data = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            data = {"raw": raw[:200].decode(errors="replace")}
        return resp.status, data

    def fetch_csrf(self) -> None:
        status, data = self.request("GET", "/csrf-token")
        if status != 200 or not data.get("success"):
            raise RuntimeError(f"csrf-token: HTTP {status} {data}")
        self.csrf = data["obj"]

    def login(self, username: str, password: str) -> tuple[bool, str]:
        self.fetch_csrf()
        status, data = self.request("POST", "/login", {"username": username, "password": password})
        if status != 200:
            raise RuntimeError(f"login: HTTP {status} {data}")
        return bool(data.get("success")), str(data.get("msg", ""))

    def change_credentials(self, old_user: str, old_pw: str, new_user: str, new_pw: str) -> tuple[bool, str]:
        ok, msg = self.login(old_user, old_pw)
        if not ok:
            return False, f"вход со старым паролем не удался: {msg}"
        self.fetch_csrf()
        form = {"oldUsername": old_user, "oldPassword": old_pw, "newUsername": new_user, "newPassword": new_pw,
                "twoFactorCode": ""}
        status, data = self.request("POST", "/panel/api/setting/updateUser", form)
        return status == 200 and bool(data.get("success")), f"HTTP {status} {data.get('msg', data)}"


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    lg = sub.add_parser("login")
    lg.add_argument("username")
    lg.add_argument("password")
    lg.add_argument("--source-ip")
    lg.add_argument("--expect", choices=["ok", "fail", "blocked"], default="ok")
    ch = sub.add_parser("change")
    ch.add_argument("old_user")
    ch.add_argument("old_password")
    ch.add_argument("new_user")
    ch.add_argument("new_password")
    args = p.parse_args()

    if args.cmd == "change":
        ok, msg = Browser().change_credentials(args.old_user, args.old_password, args.new_user, args.new_password)
        print(f"[{'OK  ' if ok else 'FAIL'}] смена логина/пароля через веб-интерфейс — {msg}")
        return 0 if ok else 1

    where = args.source_ip or "127.0.0.1"
    try:
        ok, msg = Browser(args.source_ip).login(args.username, args.password)
        got = "ok" if ok else "fail"
    except OSError as exc:  # соединение отклонено/сброшено — бан fail2ban
        got, msg = "blocked", f"{type(exc).__name__}: {exc}"
    passed = got == args.expect
    print(f"[{'OK  ' if passed else 'FAIL'}] вход {args.username!r} с {where}: {got} (ожидалось {args.expect}) {msg}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
