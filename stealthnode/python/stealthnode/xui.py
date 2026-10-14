"""Клиент HTTP API панели 3x-ui v3 (только стандартная библиотека).

Аутентификация — API-токен (``Authorization: Bearer``), созданный командой
``x-ui setting -getApiToken``. С токеном CSRF не требуется. Панель слушает
только 127.0.0.1, поэтому запросы идут по HTTP внутри сервера.

Формат ответов панели: ``{"success": bool, "msg": str, "obj": any}``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any



class XuiError(RuntimeError):
    """Ошибка вызова API 3x-ui."""


class XuiClient:
    def __init__(self, base_url: str, token: str, timeout: float = 30.0):
        if not token:
            raise XuiError("не задан API-токен 3x-ui (SN_XUI_API_TOKEN)")
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    # --- транспорт ---------------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        form: dict[str, str] | None = None,
        query: dict[str, str] | None = None,
    ) -> dict:
        url = f"{self.base}/panel/api/{path.lstrip('/')}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "User-Agent": "stealthnode",
        }
        data = None
        if json_body is not None:
            data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif form is not None:
            data = urllib.parse.urlencode(form).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - только 127.0.0.1
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            hint = {
                401: "токен API недействителен (перевыпустите: stealthnode token-rotate)",
                403: "у токена нет прав admin",
                404: "неверный webBasePath или порт панели",
            }.get(exc.code, "")
            raise XuiError(f"{method} {path}: HTTP {exc.code} {hint}".strip()) from exc
        except urllib.error.URLError as exc:
            raise XuiError(f"{method} {path}: панель недоступна ({exc.reason})") from exc
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            raise XuiError(f"{method} {path}: ответ не JSON: {raw[:200]!r}") from exc
        if isinstance(payload, dict) and payload.get("success") is False:
            raise XuiError(f"{method} {path}: {payload.get('msg') or 'ошибка панели'}")
        return payload if isinstance(payload, dict) else {"success": True, "obj": payload}

    def call(self, method: str, path: str, **kwargs) -> Any:
        return self._request(method, path, **kwargs).get("obj")

    # --- инбаунды ----------------------------------------------------------
    @staticmethod
    def normalize_inbound(inb: dict) -> dict:
        """Поля settings/streamSettings/sniffing → dict (панель отдаёт объект или строку)."""
        out = dict(inb)
        for key in ("settings", "streamSettings", "sniffing"):
            val = out.get(key)
            if isinstance(val, str):
                out[key] = json.loads(val) if val.strip() else {}
            elif val is None:
                out[key] = {}
        return out

    def list_inbounds(self) -> list[dict]:
        return [self.normalize_inbound(i) for i in (self.call("GET", "inbounds/list") or [])]

    def add_inbound(self, inbound: dict) -> dict:
        return self.normalize_inbound(self.call("POST", "inbounds/add", json_body=inbound) or {})

    def update_inbound(self, inbound_id: int, inbound: dict) -> dict:
        obj = self.call("POST", f"inbounds/update/{inbound_id}", json_body=inbound)
        return self.normalize_inbound(obj) if isinstance(obj, dict) else {}

    def delete_inbound(self, inbound_id: int) -> None:
        self.call("POST", f"inbounds/del/{inbound_id}")

    # --- клиенты (пользователи) -------------------------------------------
    def list_clients(self) -> list[dict]:
        return list(self.call("GET", "clients/list") or [])

    def get_client(self, email: str) -> dict | None:
        try:
            return self.call("GET", f"clients/get/{urllib.parse.quote(email, safe='')}")
        except XuiError:
            return None

    def add_client(self, client: dict, inbound_ids: list[int]) -> None:
        self.call("POST", "clients/add", json_body={"client": client, "inboundIds": inbound_ids})

    def update_client(self, email: str, client: dict) -> None:
        self.call("POST", f"clients/update/{urllib.parse.quote(email, safe='')}", json_body=client)

    def attach_client(self, email: str, inbound_ids: list[int]) -> None:
        self.call("POST", f"clients/{urllib.parse.quote(email, safe='')}/attach", json_body={"inboundIds": inbound_ids})

    def delete_client(self, email: str) -> None:
        self.call("POST", f"clients/del/{urllib.parse.quote(email, safe='')}")

    def reset_client_traffic(self, email: str) -> None:
        self.call("POST", f"clients/resetTraffic/{urllib.parse.quote(email, safe='')}")

    def client_links(self, email: str) -> list[str]:
        return list(self.call("GET", f"clients/links/{urllib.parse.quote(email, safe='')}") or [])

    def sub_links(self, sub_id: str) -> list[str]:
        return list(self.call("GET", f"clients/subLinks/{urllib.parse.quote(sub_id, safe='')}") or [])

    def client_traffic(self, email: str) -> dict | None:
        try:
            return self.call("GET", f"clients/traffic/{urllib.parse.quote(email, safe='')}")
        except XuiError:
            return None

    def onlines(self) -> list[str]:
        return list(self.call("POST", "clients/onlines") or [])

    # --- настройки панели --------------------------------------------------
    def get_settings(self) -> dict:
        return dict(self.call("POST", "setting/all") or {})

    def update_settings(self, settings: dict) -> None:
        self.call("POST", "setting/update", json_body=settings)

    # --- шаблон Xray ------------------------------------------------------
    def get_xray_template(self) -> dict:
        obj = self.call("POST", "xray/") or {}
        tpl = obj.get("xraySetting") if isinstance(obj, dict) else None
        if isinstance(tpl, str):
            tpl = json.loads(tpl)
        if not isinstance(tpl, dict):
            raise XuiError("xray/: неожиданный формат шаблона")
        return tpl

    def update_xray_template(self, template: dict, outbound_test_url: str = "") -> None:
        form = {"xraySetting": json.dumps(template, ensure_ascii=False, indent=2)}
        if outbound_test_url:
            form["outboundTestUrl"] = outbound_test_url
        self.call("POST", "xray/update", form=form)

    # --- сервер ------------------------------------------------------------
    def restart_xray(self) -> None:
        self.call("POST", "server/restartXrayService")

    def server_status(self) -> dict:
        return dict(self.call("GET", "server/status") or {})

    def xray_config(self) -> dict:
        obj = self.call("GET", "server/getConfigJson")
        if isinstance(obj, str):
            obj = json.loads(obj)
        return obj or {}

    def xray_version(self) -> str:
        obj = self.call("GET", "server/getXrayVersion")
        return obj if isinstance(obj, str) else json.dumps(obj)

    def new_x25519(self) -> tuple[str, str]:
        obj = self.call("GET", "server/getNewX25519Cert") or {}
        return obj["privateKey"], obj["publicKey"]

    def scan_reality_target(self, target: str, sni: str = "") -> dict:
        return dict(self.call("POST", "server/scanRealityTarget", form={"target": target, "sni": sni}) or {})

    def xray_result(self) -> str:
        obj = self.call("GET", "xray/getXrayResult")
        return obj if isinstance(obj, str) else ""
