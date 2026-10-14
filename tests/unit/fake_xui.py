"""Фейковый API 3x-ui v3 для тестов провижининга.

Реализует ровно те эндпоинты, которые использует StealthNode, с поведением,
повторяющим 3x-ui v3.10.0 (проверено по исходникам): клиенты — отдельные записи,
привязка к нескольким инбаундам, flow только для TCP+REALITY, ссылки по
subId/email. Контракт с настоящей панелью дополнительно проверяет CI
(tests/ci/contract_check.py) на реальной установке.
"""

from __future__ import annotations

import copy
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeXuiState:
    def __init__(self, token: str = "test-token"):
        self.token = token
        self.inbounds: list[dict] = []
        self.clients: dict[str, dict] = {}
        self.next_inbound_id = 1
        self.next_client_id = 1
        self.settings = {
            "webListen": "127.0.0.1",
            "webPort": 30000,
            "webBasePath": "/panel/",
            "subEnable": True,
            "subListen": "",
            "subPort": 2096,
            "subPath": "/sub/",
            "subURI": "",
            "subTitle": "",
            "subUpdates": 12,
            "subJsonEnable": False,
            "subClashEnable": False,
            "timeLocation": "Local",
            "tgLang": "en-US",
            "trustedProxyCIDRs": "127.0.0.1/32,::1/128",
            "restartXrayOnClientDisable": True,
            "tgBotToken": "",
        }
        self.template = {
            "log": {"access": "none", "loglevel": "warning"},
            "outbounds": [
                {"protocol": "freedom", "settings": {"finalRules": [{"action": "block", "ip": ["geoip:private"]}]}, "tag": "direct"},
                {"protocol": "blackhole", "settings": {}, "tag": "blocked"},
            ],
            "routing": {"rules": []},
        }
        self.calls: list[tuple[str, str]] = []
        self.xray_restarts = 0

    # --- логика панели ---------------------------------------------------
    def inbound(self, ib_id: int) -> dict:
        for i in self.inbounds:
            if i["id"] == ib_id:
                return i
        raise KeyError(ib_id)

    @staticmethod
    def flow_allowed(inb: dict) -> bool:
        st = inb.get("streamSettings") or {}
        return inb["protocol"] == "vless" and st.get("network") == "tcp" and st.get("security") in ("tls", "reality")

    def client_row(self, email: str) -> dict:
        c = self.clients[email]
        row = {k: v for k, v in c.items() if k not in ("id",)}
        row["uuid"] = c["id"]
        row["id"] = c["_rec_id"]
        row["traffic"] = {"up": 0, "down": 0, "enable": True}
        row.pop("_rec_id", None)
        return row

    def link(self, inb: dict, email: str, host: str) -> str:
        c = self.clients[email]
        st = inb["streamSettings"]
        if inb["protocol"] == "hysteria":
            tls = st["tlsSettings"]
            params = {"security": "tls", "alpn": ",".join(tls.get("alpn", [])), "sni": tls.get("serverName", "")}
            pins = tls.get("settings", {}).get("pinnedPeerCertSha256") or []
            if pins:
                params["pinSHA256"] = ",".join(pins)
            for m in st.get("finalmask", {}).get("udp", []):
                if m["type"] == "salamander":
                    params["obfs"] = "salamander"
                    params["obfs-password"] = m["settings"]["password"]
            q = urllib.parse.urlencode(params)
            return f"hysteria2://{c['auth']}@{host}:{inb['port']}?{q}#{inb['remark']}-{email}"
        rs = st["realitySettings"]
        params = {
            "type": st["network"],
            "encryption": "none",
            "security": "reality",
            "pbk": rs["settings"]["publicKey"],
            "fp": rs["settings"]["fingerprint"],
            "sni": rs["serverNames"][0],
            "sid": rs["shortIds"][0],
            "spx": "/",
        }
        if st["network"] == "xhttp":
            params["path"] = st["xhttpSettings"]["path"]
            params["mode"] = st["xhttpSettings"]["mode"]
        if self.flow_allowed(inb) and c.get("flow"):
            params["flow"] = c["flow"]
        q = urllib.parse.urlencode(params)
        return f"vless://{c['id']}@{host}:{inb['port']}?{q}#{inb['remark']}-{email}"

    def xray_config(self) -> dict:
        inbounds = []
        for inb in self.inbounds:
            clients = []
            for email, c in self.clients.items():
                if inb["id"] not in c["inboundIds"] or not c.get("enable", True):
                    continue
                if inb["protocol"] == "hysteria":
                    clients.append({"email": email, "auth": c["auth"]})
                else:
                    entry = {"email": email, "id": c["id"]}
                    if self.flow_allowed(inb) and c.get("flow"):
                        entry["flow"] = c["flow"]
                    clients.append(entry)
            settings = copy.deepcopy(inb["settings"])
            settings["clients"] = clients
            inbounds.append({"tag": inb["tag"], "port": inb["port"], "protocol": inb["protocol"], "settings": settings,
                             "streamSettings": inb["streamSettings"]})
        cfg = copy.deepcopy(self.template)
        cfg["inbounds"] = inbounds
        return cfg


def make_handler(state: FakeXuiState, base: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # тихо
            pass

        def _send(self, obj, success=True, msg="", code=200):
            body = json.dumps({"success": success, "msg": msg, "obj": obj}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            ctype = self.headers.get("Content-Type", "")
            if "application/json" in ctype:
                return json.loads(raw or b"{}")
            if "x-www-form-urlencoded" in ctype:
                return {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode()).items()}
            return {}

        def _route(self, method):
            path = urllib.parse.urlsplit(self.path).path
            prefix = f"/{base}/panel/api/"
            if not path.startswith(prefix):
                self.send_response(404)
                self.end_headers()
                return
            if self.headers.get("Authorization") != f"Bearer {state.token}":
                self.send_response(401)
                self.end_headers()
                return
            rel = path[len(prefix):]
            state.calls.append((method, rel))
            body = self._body() if method == "POST" else {}
            try:
                self._dispatch(method, rel, body)
            except KeyError as exc:
                self._send(None, False, f"not found: {exc}")

        def _dispatch(self, method, rel, body):
            s = state
            parts = [urllib.parse.unquote(p) for p in rel.split("/")]
            if rel == "server/status":
                return self._send({"xray": {"state": "running"}})
            if rel == "server/restartXrayService":
                s.xray_restarts += 1
                return self._send(None)
            if rel == "server/getConfigJson":
                return self._send(s.xray_config())
            if rel == "server/getXrayVersion":
                return self._send("26.10.10")
            if rel == "inbounds/list":
                return self._send(copy.deepcopy(s.inbounds))
            if rel == "inbounds/add":
                for inb in s.inbounds:
                    if inb["port"] == body["port"] and (inb["protocol"] == "hysteria") == (body["protocol"] == "hysteria"):
                        return self._send(None, False, "port already in use")
                    if inb["tag"] == body["tag"]:
                        return self._send(None, False, "tag already in use")
                inb = copy.deepcopy(body)
                inb["id"] = s.next_inbound_id
                s.next_inbound_id += 1
                inb.setdefault("settings", {}).setdefault("clients", [])
                s.inbounds.append(inb)
                return self._send(copy.deepcopy(inb))
            if parts[:2] == ["inbounds", "update"]:
                inb = s.inbound(int(parts[2]))
                new = copy.deepcopy(body)
                new["id"] = inb["id"]
                s.inbounds[s.inbounds.index(inb)] = new
                return self._send(copy.deepcopy(new))
            if rel == "clients/list":
                return self._send([s.client_row(e) for e in s.clients])
            if parts[:2] == ["clients", "get"]:
                email = parts[2]
                row = s.client_row(email)
                return self._send({"client": row, "inboundIds": row["inboundIds"]})
            if rel == "clients/add":
                c = copy.deepcopy(body["client"])
                if c["email"] in s.clients:
                    return self._send(None, False, "email already in use")
                if any(x["subId"] == c["subId"] for x in s.clients.values()):
                    return self._send(None, False, "subId already in use")
                c["inboundIds"] = list(body["inboundIds"])
                c["_rec_id"] = s.next_client_id
                s.next_client_id += 1
                for ib in c["inboundIds"]:
                    s.inbound(ib)
                s.clients[c["email"]] = c
                return self._send(None)
            if len(parts) == 3 and parts[0] == "clients" and parts[2] == "attach":
                c = s.clients[parts[1]]
                c["inboundIds"] = sorted(set(c["inboundIds"]) | set(body["inboundIds"]))
                return self._send(None)
            if parts[:2] == ["clients", "update"]:
                email = parts[2]
                old = s.clients[email]
                new = copy.deepcopy(body)
                for keep in ("inboundIds", "_rec_id"):
                    new[keep] = old[keep]
                for cred in ("id", "auth", "password"):
                    if not new.get(cred):
                        new[cred] = old.get(cred, "")
                s.clients[email] = new
                return self._send(None)
            if parts[:2] == ["clients", "del"]:
                del s.clients[parts[2]]
                return self._send(None)
            if parts[:2] == ["clients", "resetTraffic"]:
                s.clients[parts[2]]
                return self._send(None)
            if parts[:2] == ["clients", "links"]:
                email = parts[2]
                c = s.clients[email]
                out = []
                for inb in sorted(s.inbounds, key=lambda i: i.get("subSortIndex", 1)):
                    if inb["id"] in c["inboundIds"]:
                        out.append(s.link(inb, email, inb.get("shareAddr") or "127.0.0.1"))
                return self._send(out)
            if rel == "clients/onlines":
                return self._send([])
            if rel == "setting/all":
                return self._send(copy.deepcopy(s.settings))
            if rel == "setting/update":
                s.settings = copy.deepcopy(body)
                return self._send(None)
            if rel == "xray/":
                # Как в 3x-ui v3.10.0: obj — JSON-строка с объектом внутри.
                return self._send(json.dumps({"xraySetting": s.template, "inboundTags": []}))
            if rel == "xray/update":
                s.template = json.loads(body["xraySetting"])
                return self._send(None)
            if rel == "server/scanRealityTarget":
                return self._send({"feasible": True, "tlsVersion": "1.3", "alpn": "h2", "curveID": "X25519MLKEM768", "latencyMs": 42})
            return self._send(None, False, f"unknown endpoint {rel}")

        def do_GET(self):
            self._route("GET")

        def do_POST(self):
            self._route("POST")

    return Handler


class FakeXuiServer:
    def __init__(self, base: str, token: str = "test-token"):
        self.state = FakeXuiState(token)
        self.base = base
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state, base))
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
