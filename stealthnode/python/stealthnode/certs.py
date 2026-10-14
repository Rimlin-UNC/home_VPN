"""Сертификат для Hysteria2.

Приоритет:
1. Сертификат Let's Encrypt, который Caddy получил для домена панели —
   клиенты проверяют его штатно, без insecure и без pin.
2. Если публичного сертификата нет (DNS ещё не настроен, режим ``tls internal``) —
   долгоживущий self-signed (10 лет) + ``pinSHA256`` в ссылке: клиент сверяет
   отпечаток, поэтому MITM невозможен даже без CA.

ВАЖНО: ``insecure=1`` из исходного ТЗ не используется — это уязвимость к MITM,
а Xray-core >= 26 вообще удалил ``allowInsecure``.

Копия активного сертификата лежит в /opt/stealthnode/hysteria/server.{crt,key}
(путь из ТЗ). Xray перечитывает файлы раз в час, но после замены мы всё равно
перезапускаем Xray через API.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from . import config
from .util import atomic_write, run

_PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----", re.S)


@dataclass
class CertState:
    mode: str  # "acme" | "selfsigned"
    cert_file: str
    key_file: str
    pin_sha256: str | None
    source: str
    changed: bool = False


def hy_dir() -> Path:
    return config.sn_root() / "hysteria"


def first_cert_der(pem: bytes) -> bytes:
    match = _PEM_RE.search(pem)
    if not match:
        raise ValueError("в файле нет PEM-сертификата")
    return base64.b64decode(b"".join(match.group(1).split()))


def cert_sha256_hex(cert_file: Path | str) -> str:
    """SHA-256 от DER листового сертификата (формат pinSHA256 / pinnedPeerCertSha256)."""
    return hashlib.sha256(first_cert_der(Path(cert_file).read_bytes())).hexdigest()


def find_caddy_cert(domain: str, data_dir: Path | None = None) -> tuple[Path, Path, str] | None:
    """Найти сертификат публичного ACME-УЦ, выпущенный Caddy для домена."""
    base = (data_dir or config.CADDY_DATA) / "certificates"
    if not base.is_dir():
        return None
    candidates = []
    for issuer_dir in sorted(base.iterdir()):
        name = issuer_dir.name
        # local — внутренний CA Caddy (tls internal), staging — тестовый УЦ: клиентам не подходят.
        if name == "local" or "staging" in name:
            continue
        crt = issuer_dir / domain / f"{domain}.crt"
        key = issuer_dir / domain / f"{domain}.key"
        if crt.is_file() and key.is_file():
            prio = 0 if "letsencrypt" in name else 1
            candidates.append((prio, crt, key, name))
    if not candidates:
        return None
    candidates.sort()
    _, crt, key, name = candidates[0]
    return crt, key, name


def ensure_selfsigned(domain: str) -> tuple[Path, Path]:
    crt = hy_dir() / "selfsigned.crt"
    key = hy_dir() / "selfsigned.key"
    if crt.is_file() and key.is_file():
        return crt, key
    hy_dir().mkdir(parents=True, exist_ok=True)
    hy_dir().chmod(0o700)
    tmp_key = hy_dir() / ".selfsigned.key.tmp"
    tmp_crt = hy_dir() / ".selfsigned.crt.tmp"
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "3650",
            "-subj",
            f"/CN={domain}",
            "-addext",
            f"subjectAltName=DNS:{domain}",
            "-keyout",
            str(tmp_key),
            "-out",
            str(tmp_crt),
        ],
        timeout=60,
    )
    tmp_key.chmod(0o600)
    tmp_key.replace(key)
    tmp_crt.chmod(0o644)
    tmp_crt.replace(crt)
    return crt, key


def _install(src_crt: Path, src_key: Path) -> bool:
    """Скопировать пару в server.crt/server.key, если содержимое изменилось."""
    dst_crt = hy_dir() / "server.crt"
    dst_key = hy_dir() / "server.key"
    new_crt = src_crt.read_bytes()
    new_key = src_key.read_bytes()
    if dst_crt.is_file() and dst_key.is_file() and dst_crt.read_bytes() == new_crt and dst_key.read_bytes() == new_key:
        return False
    hy_dir().mkdir(parents=True, exist_ok=True)
    hy_dir().chmod(0o700)
    atomic_write(dst_key, new_key, mode=0o600)
    atomic_write(dst_crt, new_crt, mode=0o644)
    return True


def ensure_hy2_cert(s: config.Settings) -> CertState:
    """Выбрать и разложить сертификат Hysteria2. Не трогает панель."""
    domain = s.domain
    found = find_caddy_cert(domain) if s.get("SN_TLS_MODE") == "acme" else None
    if found:
        crt, key, issuer = found
        changed = _install(crt, key)
        return CertState("acme", str(hy_dir() / "server.crt"), str(hy_dir() / "server.key"), None, issuer, changed)
    crt, key = ensure_selfsigned(domain)
    changed = _install(crt, key)
    pin = cert_sha256_hex(hy_dir() / "server.crt")
    return CertState("selfsigned", str(hy_dir() / "server.crt"), str(hy_dir() / "server.key"), pin, "self-signed", changed)


def not_after(cert_file: Path | str) -> str:
    """Дата окончания действия сертификата (строка openssl) или пустая строка."""
    try:
        out = run(["openssl", "x509", "-noout", "-enddate", "-in", str(cert_file)], timeout=15).stdout
    except Exception:  # noqa: BLE001
        return ""
    return out.strip().removeprefix("notAfter=")
