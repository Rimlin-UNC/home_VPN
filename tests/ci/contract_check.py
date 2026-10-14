#!/usr/bin/env python3
"""Проверка контракта с настоящей панелью 3x-ui после установки (запускается в CI на сервере).

Проверяет то, что нельзя проверить unit-тестами без 3x-ui:
* инбаунды сохранены панелью ровно так, как требует ТЗ;
* итоговый конфиг Xray (getConfigJson): flow только у TCP/Vision, auth у Hysteria2, DNS;
* у каждого пользователя одна запись на три инбаунда, квоты/сброс/лимит IP;
* ссылки из подписки проходят аудит требований ТЗ.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.environ.get("SN_APP_PY", "/opt/stealthnode/app/python"))

from stealthnode import config, links, users  # noqa: E402
from stealthnode.provision import client_from_settings  # noqa: E402

GIB = 1024**3
failures: list[str] = []


def check(cond: bool, title: str, detail: str = "") -> None:
    mark = "OK  " if cond else "FAIL"
    print(f"[{mark}] {title}" + (f" — {detail}" if detail else ""))
    if not cond:
        failures.append(title)


def main() -> int:
    s = config.load_settings()
    xui = client_from_settings(s)

    inbounds = {i["tag"]: i for i in xui.list_inbounds() if i.get("tag") in config.ALL_TAGS}
    check(set(inbounds) == set(config.ALL_TAGS), "три инбаунда StealthNode", ", ".join(sorted(inbounds)))

    x = inbounds.get(config.TAG_XHTTP, {})
    xs = x.get("streamSettings", {})
    check(x.get("port") == s.int("SN_XHTTP_PORT") and x.get("protocol") == "vless", "XHTTP: vless на нужном порту")
    check(xs.get("network") == "xhttp" and xs.get("security") == "reality", "XHTTP: xhttp + reality")
    xh = xs.get("xhttpSettings", {})
    check(xh.get("mode") == "stream-one", "XHTTP: mode=stream-one", str(xh.get("mode")))
    check(not any(k in json.dumps(xh) for k in ("scMaxEachPostBytes", "scMinPostsIntervalMs")), "XHTTP: нет sc*-полей")
    rs = xs.get("realitySettings", {})
    check(rs.get("settings", {}).get("fingerprint") == "firefox", "REALITY: fp=firefox")
    check(rs.get("serverNames") == [s.get("SN_REALITY_SNI")], "REALITY: serverNames", str(rs.get("serverNames")))

    v = inbounds.get(config.TAG_VISION, {})
    vs = v.get("streamSettings", {})
    check(v.get("port") == s.int("SN_VISION_PORT") and vs.get("network") == "tcp", "Vision: tcp на нужном порту")
    check(
        vs.get("realitySettings", {}).get("privateKey") == rs.get("privateKey")
        and vs.get("realitySettings", {}).get("shortIds") == rs.get("shortIds"),
        "Vision: те же ключи и shortId, что у XHTTP",
    )

    h = inbounds.get(config.TAG_HY2, {})
    hs = h.get("streamSettings", {})
    check(h.get("protocol") == "hysteria" and h.get("port") == s.int("SN_HY2_PORT"), "Hysteria2: на нужном порту")
    masks = hs.get("finalmask", {}).get("udp", [])
    check(any(m.get("type") == "salamander" for m in masks), "Hysteria2: salamander")

    # Итоговый конфиг Xray, который реально запущен.
    cfg = xui.xray_config()
    by_tag = {i.get("tag"): i for i in cfg.get("inbounds", [])}
    for tag in config.ALL_TAGS:
        check(tag in by_tag, f"Xray: инбаунд {tag} запущен")
    xcl = by_tag.get(config.TAG_XHTTP, {}).get("settings", {}).get("clients", [])
    vcl = by_tag.get(config.TAG_VISION, {}).get("settings", {}).get("clients", [])
    hcl = by_tag.get(config.TAG_HY2, {}).get("settings", {}).get("clients", [])
    check(xcl and all(not c.get("flow") for c in xcl), "Xray: у клиентов XHTTP нет flow", f"{len(xcl)} клиентов")
    check(vcl and all(c.get("flow") == "xtls-rprx-vision" for c in vcl), "Xray: у клиентов Vision flow=xtls-rprx-vision")
    check(hcl and all(c.get("auth") for c in hcl), "Xray: у клиентов Hysteria2 есть auth")
    dns = cfg.get("dns", {})
    check("tcp+local://127.0.2.1:53" in json.dumps(dns), "Xray: DNS через dnscrypt-proxy", json.dumps(dns)[:120])

    # Пользователи.
    ids = set(users.sn_inbound_ids(xui).values())
    lst = {c["email"]: c for c in users.list_users(xui)}
    owner = s.get("SN_OWNER_NAME") or "owner"
    check(owner in lst and int(lst[owner].get("totalGB", 0)) == 0, "владелец без лимита трафика")
    for name, c in lst.items():
        check(set(c.get("inboundIds", [])) == ids, f"{name}: привязан ко всем трём профилям")
    if "mama" in lst:
        m = lst["mama"]
        check(int(m.get("totalGB", 0)) == 50 * GIB, "mama: 50 ГиБ", str(m.get("totalGB")))
        check(int(m.get("limitIp", 0)) == 2, "mama: лимит 2 IP", str(m.get("limitIp")))
        check(m.get("trafficReset") == "monthly", "mama: ежемесячный сброс", str(m.get("trafficReset")))

    # Ссылки из панели.
    raw = xui.client_links(owner)
    kinds = sorted(links.parse(r).kind for r in raw)
    check(kinds == ["hysteria2", "vision", "xhttp"], "ссылки владельца: 3 профиля", ", ".join(kinds))
    for r in raw:
        link = links.parse(r)
        problems = links.audit(link)
        check(not problems, f"ссылка {link.kind} соответствует ТЗ", "; ".join(problems))
        check(link.host == s.domain, f"ссылка {link.kind}: адрес = домен", link.host)
        print("      ", r.split("#")[0][:160] + "...")

    print()
    if failures:
        print(f"ПРОВАЛЕНО: {len(failures)}")
        return 1
    print("контракт с 3x-ui соблюдён")
    return 0


if __name__ == "__main__":
    sys.exit(main())
