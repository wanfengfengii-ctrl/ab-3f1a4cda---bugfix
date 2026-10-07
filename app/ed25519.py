"""Pure-python Ed25519 (RFC 8032) sign/verify.

No third-party dependency so the container image can be built offline.
Cross-checked against the RFC 8032 test vectors in the test-suite and,
when available, against the ``cryptography`` package.
"""

from __future__ import annotations

import hashlib

b = 256
q = 2 ** 255 - 19
l_ = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _expmod(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)


def _inv(x: int) -> int:
    return _expmod(x, q - 2, q)


d = -121665 * _inv(121666)
I = _expmod(2, (q - 1) // 4, q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = _expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


By = 4 * _inv(5)
Bx = _xrecover(By)
B = (Bx % q, By % q)


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - d * x1 * x2 * y1 * y2)
    return x3 % q, y3 % q


def _scalarmult(P, e: int):
    if e == 0:
        return 0, 1
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encodepoint(P) -> bytes:
    x, y = P
    bits = y & ((1 << 255) - 1)
    bits |= (x & 1) << 255
    return bits.to_bytes(32, "little")


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _hint(m: bytes) -> int:
    h = _H(m)
    return sum(2 ** i * _bit(h, i) for i in range(2 * b))


def publickey(seed: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte secret seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _H(seed)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    A = _scalarmult(B, a)
    return _encodepoint(A)


def sign(message: bytes, seed: bytes) -> bytes:
    """Return the 64-byte Ed25519 signature of ``message``."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _H(seed)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    pk = _encodepoint(_scalarmult(B, a))
    r = _hint(h[b // 8 : b // 4] + message)
    R = _scalarmult(B, r)
    S = (r + _hint(_encodepoint(R) + pk + message) * a) % l_
    return _encodepoint(R) + _encodeint(S)


def _decodeint(s: bytes) -> int:
    return sum(2 ** i * _bit(s, i) for i in range(0, b))


def _decodepoint(s: bytes):
    y = sum(2 ** i * _bit(s, i) for i in range(0, b - 1))
    x = _xrecover(y)
    if (x & 1) != _bit(s, b - 1):
        x = q - x
    P = x, y
    if (-x * x + y * y - 1 - d * x * x * y * y) % q != 0:
        raise ValueError("decoded point is not on the curve")
    return P


def verify(signature: bytes, message: bytes, public_key: bytes) -> None:
    """Verify an Ed25519 signature. Raises ValueError on any failure."""
    if len(public_key) != 32:
        raise ValueError("public key must be 32 bytes")
    if len(signature) != 64:
        raise ValueError("signature must be 64 bytes")
    R = _decodepoint(signature[0:32])
    A = _decodepoint(public_key)
    S = _decodeint(signature[32:64])
    if S >= l_:
        raise ValueError("signature scalar out of range")
    h = _hint(_encodepoint(R) + public_key + message)
    if _scalarmult(B, S) != _edwards(R, _scalarmult(A, h)):
        raise ValueError("signature verification failed")
