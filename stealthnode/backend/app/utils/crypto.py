# ============================================================
# StealthNode — криптографические утилиты.
# REALITY использует ключи X25519. В ссылках vless:// ключи идут
# в URL — поэтому base64 URL-safe БЕЗ padding ('='): ровно как
# выводит `xray x25519` (стандарт base64 с '+' и '=' внутри query
# сломал бы ссылку: '+' декодируется пробелом).
# ============================================================
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _b64url_nopad(raw: bytes) -> str:
    """base64url без '=' — формат ключей REALITY в ссылках vless://."""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_any_b64(key: str) -> bytes:
    """Принимает urlsafe/обычный base64, с padding или без (совместимость)."""
    key = key.strip()
    padded = key + "=" * (-len(key) % 4)
    return base64.urlsafe_b64decode(padded)


def x25519_keypair() -> tuple[str, str]:
    """(приватный, публичный) ключ base64url без padding — как `xray x25519`."""
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return _b64url_nopad(priv_raw), _b64url_nopad(pub_raw)


def x25519_public_from_private(priv_b64: str) -> str:
    """Вывод публичного ключа из приватного (для ссылок vless://)."""
    priv = X25519PrivateKey.from_private_bytes(_decode_any_b64(priv_b64))
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return _b64url_nopad(pub_raw)
