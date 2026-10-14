"""X25519 (векторы RFC 7748), формат .env, параметры установки."""

from __future__ import annotations

import stat

import pytest

from stealthnode import config, envfile, x25519


# --- X25519 ---------------------------------------------------------------------

def test_rfc7748_section_5_2_vector_1():
    k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    assert x25519.x25519(k, u).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"


def test_rfc7748_section_6_1_diffie_hellman():
    a_priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b_priv = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    base = (9).to_bytes(32, "little")
    a_pub = x25519.x25519(a_priv, base)
    b_pub = x25519.x25519(b_priv, base)
    assert a_pub.hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert b_pub.hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert x25519.x25519(a_priv, b_pub).hex() == shared
    assert x25519.x25519(b_priv, a_pub).hex() == shared


def test_generate_keypair_format_matches_xray():
    priv, pub = x25519.generate_keypair()
    assert len(priv) == 43 and len(pub) == 43  # base64url без '='
    assert "=" not in priv + pub
    assert x25519.public_key(priv) == pub
    raw = x25519.b64u_decode(priv)
    assert raw[0] & 7 == 0 and raw[31] & 0x80 == 0 and raw[31] & 0x40


# --- .env -------------------------------------------------------------------------

def test_envfile_roundtrip_special_characters(tmp_path):
    values = {
        "SN_A": "plain",
        "SN_QUOTE": "it's \"quoted\" $HOME `cmd` \\ end",
        "SN_EMPTY": "",
        "SN_SPACES": "a b  c",
        "SN_UNICODE": "пароль-ünï",
    }
    path = tmp_path / ".env"
    envfile.save(path, values, header="тест")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert envfile.load(path) == values


def test_envfile_is_bash_compatible(tmp_path):
    import subprocess

    values = {"SN_X": "a'b\"c $d", "SN_Y": "x y"}
    path = tmp_path / ".env"
    envfile.save(path, values)
    out = subprocess.run(["bash", "-c", f'source "{path}"; printf "%s|%s" "$SN_X" "$SN_Y"'], capture_output=True, text=True)
    assert out.stdout == "a'b\"c $d|x y"


@pytest.mark.parametrize("bad", ["NOEQUALS", "1BAD=x", "SN_X=a b"])
def test_envfile_rejects_garbage(bad):
    with pytest.raises(ValueError):
        envfile.parse(bad)


def test_envfile_comments_and_export():
    assert envfile.parse("# c\n\nexport SN_A='1'\nSN_B=2 # хвост\n") == {"SN_A": "1", "SN_B": "2"}


# --- параметры ----------------------------------------------------------------------

def test_fill_defaults_generates_everything_and_is_idempotent(sn_root):
    first = config.fill_defaults({"SN_DOMAIN": "VPN.Example.Test."}, "2.0.0")
    s = config.Settings(first)
    assert s.validate() == []
    assert s.domain == "vpn.example.test"
    assert first["SN_REALITY_SNI"] == "max.ru" and first["SN_REALITY_TARGET"] == "max.ru:443"
    assert first["SN_FINGERPRINT"] == "firefox"
    assert first["SN_XHTTP_PORT"] == "443" and first["SN_VISION_PORT"] == "8443" and first["SN_HY2_PORT"] == "443"
    assert 20000 <= int(first["SN_PANEL_PORT"]) <= 29999
    assert 30000 <= int(first["SN_XUI_PORT"]) <= 39999
    assert len(first["SN_XUI_PASSWORD"]) >= 16
    second = config.fill_defaults(first, "2.0.0")
    assert second == first  # повторная установка ничего не меняет


def test_validate_catches_errors(settings):
    bad = config.Settings(dict(settings.values))
    bad.values.update(
        SN_DOMAIN="not a domain",
        SN_FINGERPRINT="ios",
        SN_XUI_PASSWORD="short",
        SN_REALITY_PUBLIC_KEY="AAAA",
        SN_PANEL_PORT=bad.values["SN_XUI_PORT"],
    )
    errors = "\n".join(bad.validate())
    for needle in ("SN_DOMAIN", "SN_FINGERPRINT", "SN_XUI_PASSWORD", "SN_REALITY_PUBLIC_KEY", "TCP-порты"):
        assert needle in errors


def test_warnings_for_ru_domain_and_chrome(settings):
    s = config.Settings(dict(settings.values))
    s.values.update(SN_DOMAIN="vpn.shprv.ru", SN_FINGERPRINT="chrome")
    text = "\n".join(s.warnings())
    assert "chrome" in text and ".ru" in text


def test_urls(settings):
    assert settings.panel_url == f"https://vpn.example.test:{settings.get('SN_PANEL_PORT')}/{settings.get('SN_PANEL_PATH')}/"
    assert settings.sub_base_url.endswith(f"/{settings.get('SN_SUB_PATH')}/")
    assert settings.xui_api_base.startswith("http://127.0.0.1:")
