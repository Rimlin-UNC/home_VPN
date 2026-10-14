"""Чистая реализация X25519 (RFC 7748) для генерации ключей REALITY.

Нужна, чтобы не зависеть от сторонних пакетов. Используется только для
генерации пары ключей при установке (локально, однократно), поэтому
отсутствие постоянного времени выполнения не критично.

Формат ключей совпадает с ``xray x25519``: base64url без ``=``.
"""

from __future__ import annotations

import base64
import secrets

_P = 2**255 - 19
_A24 = 121665
_BASE_U = (9).to_bytes(32, "little")


def _decode_scalar(k: bytes) -> int:
    if len(k) != 32:
        raise ValueError("X25519 scalar must be 32 bytes")
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def _decode_u(u: bytes) -> int:
    if len(u) != 32:
        raise ValueError("X25519 u-coordinate must be 32 bytes")
    b = bytearray(u)
    b[31] &= 127
    return int.from_bytes(b, "little") % _P


def x25519(k: bytes, u: bytes) -> bytes:
    """Функция X25519 из RFC 7748 §5 (лестница Монтгомери)."""
    scalar = _decode_scalar(k)
    x1 = _decode_u(u)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        bit = (scalar >> t) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def clamp(private: bytes) -> bytes:
    b = bytearray(private)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def public_key(private_b64: str) -> str:
    """Публичный ключ (pbk / password) по приватному ключу в формате Xray."""
    priv = b64u_decode(private_b64)
    if len(priv) != 32:
        raise ValueError("приватный ключ REALITY должен быть 32 байта")
    return b64u_encode(x25519(priv, _BASE_U))


def generate_keypair() -> tuple[str, str]:
    """Новая пара ключей REALITY: (privateKey, publicKey)."""
    priv = clamp(secrets.token_bytes(32))
    priv_b64 = b64u_encode(priv)
    return priv_b64, public_key(priv_b64)
