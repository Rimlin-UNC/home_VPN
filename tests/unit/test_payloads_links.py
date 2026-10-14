"""Генераторы JSON для 3x-ui и разбор/аудит ссылок."""

from __future__ import annotations

import json

import pytest

from stealthnode import config, links, payloads


def test_xhttp_inbound_matches_tz(settings):
    inb = payloads.inbound_xhttp(settings)
    st = inb["streamSettings"]
    assert inb["protocol"] == "vless" and inb["port"] == 443 and inb["tag"] == config.TAG_XHTTP
    assert st["network"] == "xhttp" and st["security"] == "reality"
    assert st["xhttpSettings"]["mode"] == "stream-one"
    assert st["xhttpSettings"]["path"] == "/" + settings.get("SN_XHTTP_PATH")
    dumped = json.dumps(inb)
    for bad in payloads.FORBIDDEN_XHTTP_KEYS:
        assert bad not in dumped
    rs = st["realitySettings"]
    assert rs["settings"]["fingerprint"] == "firefox"
    assert rs["serverNames"] == ["max.ru"] and rs["target"] == "max.ru:443"
    assert rs["privateKey"] == settings.get("SN_REALITY_PRIVATE_KEY")
    assert inb["shareAddrStrategy"] == "custom" and inb["shareAddr"] == "vpn.example.test"
    assert inb["settings"]["decryption"] == "none"


def test_vision_shares_keys_with_xhttp(settings):
    a = payloads.inbound_xhttp(settings)["streamSettings"]["realitySettings"]
    b = payloads.inbound_vision(settings)["streamSettings"]["realitySettings"]
    assert a == b
    v = payloads.inbound_vision(settings)
    assert v["port"] == 8443 and v["streamSettings"]["network"] == "tcp"


def test_hy2_inbound_salamander_and_pin(settings):
    inb = payloads.inbound_hy2(settings, "/c.crt", "/c.key", pin_sha256="AB" * 32)
    st = inb["streamSettings"]
    assert inb["protocol"] == "hysteria" and inb["settings"]["version"] == 2
    assert st["network"] == "hysteria" and st["security"] == "tls"
    assert st["tlsSettings"]["alpn"] == ["h3"]
    assert st["tlsSettings"]["serverName"] == "vpn.example.test"
    assert st["tlsSettings"]["settings"]["pinnedPeerCertSha256"] == ["ab" * 32]
    mask = st["finalmask"]["udp"][0]
    assert mask["type"] == "salamander" and len(mask["settings"]["password"]) >= 16
    no_pin = payloads.inbound_hy2(settings, "/c.crt", "/c.key", None)
    assert "pinnedPeerCertSha256" not in no_pin["streamSettings"]["tlsSettings"]["settings"]


def test_client_record_units_and_reset():
    c = payloads.client_record("mama", limit_gb=50, limit_ip=2)
    assert c["totalGB"] == 50 * 1024**3  # байты!
    assert c["trafficReset"] == "monthly" and c["trafficResetDay"] == 1
    assert c["flow"] == "xtls-rprx-vision" and c["limitIp"] == 2 and c["expiryTime"] == 0
    owner = payloads.client_record("owner", limit_gb=0, limit_ip=0)
    assert owner["totalGB"] == 0 and owner["trafficReset"] == "never"
    assert len(owner["auth"]) >= 16 and owner["subId"]


def test_settings_patch_and_apply(settings):
    patch = payloads.settings_patch(settings)
    assert patch["subListen"] == "127.0.0.1"
    assert patch["subURI"] == settings.sub_base_url
    assert patch["subPath"] == f"/{settings.get('SN_SUB_PATH')}/"
    assert "webListen" not in patch  # меняется только через x-ui setting
    current = {"subListen": "", "subPort": 2096, "tgLang": "en-US", "keep": "me"}
    new, changed = payloads.apply_settings_patch(current, patch)
    assert new["keep"] == "me" and "subListen" in changed and "subPort" not in changed
    again, changed2 = payloads.apply_settings_patch(new, patch)
    assert changed2 == [] and again == new


def test_template_patch_idempotent(settings):
    tpl = {"outbounds": [{"protocol": "freedom", "tag": "direct", "settings": {"finalRules": [1]}}], "log": {}}
    new, changed = payloads.patch_xray_template(tpl, settings)
    assert changed
    assert new["dns"]["servers"][0] == "tcp+local://127.0.2.1:53"
    assert new["outbounds"][0]["settings"]["domainStrategy"] == "UseIPv4"
    assert new["outbounds"][0]["settings"]["finalRules"] == [1]
    assert new["log"]["access"] == "none"
    _, changed_again = payloads.patch_xray_template(new, settings)
    assert not changed_again


def test_inbound_diff_ignores_clients(settings):
    want = payloads.inbound_xhttp(settings)
    cur = json.loads(json.dumps(want))
    cur["id"] = 5
    cur["settings"]["clients"] = [{"email": "x"}]
    assert payloads.inbound_diff(cur, want) == []
    cur["streamSettings"]["xhttpSettings"]["mode"] = "auto"
    cur["port"] = 444
    assert set(payloads.inbound_diff(cur, want)) == {"port", "streamSettings.xhttpSettings"}
    merged = payloads.merge_inbound_for_update(cur, want)
    assert merged["id"] == 5 and merged["settings"]["clients"] == [{"email": "x"}] and merged["port"] == 443


# --- ссылки ------------------------------------------------------------------------

XHTTP = (
    "vless://11111111-2222-4333-8444-555555555555@vpn.example.test:443?type=xhttp&encryption=none&security=reality"
    "&pbk=PUBKEY&fp=firefox&sni=max.ru&sid=abcd&spx=%2Fx&path=%2Fp4th&mode=stream-one#SN-XHTTP-owner"
)
VISION = (
    "vless://11111111-2222-4333-8444-555555555555@vpn.example.test:8443?type=tcp&encryption=none&security=reality"
    "&pbk=PUBKEY&fp=firefox&sni=max.ru&sid=abcd&spx=%2F&flow=xtls-rprx-vision#SN-TCP-iOS-owner"
)
HY2 = "hysteria2://s3cr3t@vpn.example.test:443?security=tls&alpn=h3&sni=vpn.example.test&obfs=salamander&obfs-password=pw#SN-HY2"


def test_parse_and_kinds():
    assert links.parse(XHTTP).kind == "xhttp"
    assert links.parse(VISION).kind == "vision"
    h = links.parse(HY2)
    assert h.kind == "hysteria2" and h.user == "s3cr3t" and h.port == 443
    assert links.parse(HY2.replace("hysteria2://", "hy2://")).scheme == "hysteria2"


@pytest.mark.parametrize("link", [XHTTP, VISION, HY2])
def test_audit_clean_links(link):
    assert links.audit(links.parse(link)) == []


def add_param(link: str, extra: str) -> str:
    base, _, frag = link.partition("#")
    return f"{base}&{extra}#{frag}"


def test_audit_catches_violations():
    bad = links.parse(
        add_param(XHTTP.replace("mode=stream-one", "mode=auto").replace("fp=firefox", "fp=chrome"), "flow=xtls-rprx-vision")
    )
    problems = "\n".join(links.audit(bad))
    assert "stream-one" in problems and "chrome" in problems
    bad_hy = links.parse(add_param(HY2.replace("obfs=salamander&", ""), "insecure=1"))
    problems = "\n".join(links.audit(bad_hy))
    assert "salamander" in problems and "insecure" in problems
    extra = links.parse(add_param(XHTTP, "extra=%7B%22scMinPostsIntervalMs%22%3A30%7D"))
    assert any("scMinPostsIntervalMs" in p for p in links.audit(extra))


def test_xray_client_configs():
    cfg = links.xray_client_config(links.parse(XHTTP).with_address("127.0.0.1"), 10808)
    out = cfg["outbounds"][0]
    assert out["settings"]["address"] == "127.0.0.1" and "flow" not in out["settings"]
    assert out["streamSettings"]["xhttpSettings"] == {"path": "/p4th", "mode": "stream-one"}
    assert out["streamSettings"]["realitySettings"]["fingerprint"] == "firefox"
    v = links.xray_outbound(links.parse(VISION))
    assert v["settings"]["flow"] == "xtls-rprx-vision" and v["streamSettings"]["network"] == "tcp"
    h = links.xray_outbound(links.parse(add_param(HY2, "pinSHA256=" + "ab" * 32)))
    assert h["protocol"] == "hysteria" and h["streamSettings"]["hysteriaSettings"]["auth"] == "s3cr3t"
    assert h["streamSettings"]["finalmask"]["udp"][0]["settings"]["password"] == "pw"
    assert h["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"] == "ab" * 32
    hc = links.hysteria_client_config(links.parse(HY2), 1080)
    assert hc["obfs"]["salamander"]["password"] == "pw" and hc["tls"]["insecure"] is False


@pytest.mark.parametrize("bad", ["http://x", "vless://@host:1", "vless://id@host", "hysteria2://a@:5"])
def test_parse_rejects_bad(bad):
    with pytest.raises(links.LinkError):
        links.parse(bad)
