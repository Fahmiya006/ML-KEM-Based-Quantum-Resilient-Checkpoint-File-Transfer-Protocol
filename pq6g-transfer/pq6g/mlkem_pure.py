"""Pure-Python ML-KEM-768 (NIST FIPS 203).

Used only as a fallback when the installed `cryptography` package has no
ML-KEM support (for example an older build on a phone).  It is validated
against the native implementation in tests/test_core.py (same seed -> same
public key, and ciphertexts decapsulate across both implementations).

NOT constant-time and NOT hardened.  Research / demo use only.
"""
from __future__ import annotations

import hashlib
import hmac
import os

Q = 3329
K = 3          # ML-KEM-768
ETA1 = 2
ETA2 = 2
DU = 10
DV = 4

EK_LEN = 384 * K + 32          # 1184
DK_LEN = 768 * K + 96          # 2400
CT_LEN = 32 * (DU * K + DV)    # 1088


def _bitrev7(x: int) -> int:
    return int(format(x, "07b")[::-1], 2)


_ZETAS = [pow(17, _bitrev7(i), Q) for i in range(128)]
_GAMMAS = [pow(17, 2 * _bitrev7(i) + 1, Q) for i in range(128)]


def _ntt(f):
    f = list(f)
    k = 1
    ln = 128
    while ln >= 2:
        for start in range(0, 256, 2 * ln):
            zeta = _ZETAS[k]
            k += 1
            for j in range(start, start + ln):
                t = (zeta * f[j + ln]) % Q
                f[j + ln] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        ln >>= 1
    return f


def _invntt(f):
    f = list(f)
    k = 127
    ln = 2
    while ln <= 128:
        for start in range(0, 256, 2 * ln):
            zeta = _ZETAS[k]
            k -= 1
            for j in range(start, start + ln):
                t = f[j]
                f[j] = (t + f[j + ln]) % Q
                f[j + ln] = (zeta * (f[j + ln] - t)) % Q
        ln <<= 1
    return [(x * 3303) % Q for x in f]


def _mul_ntt(f, g):
    h = [0] * 256
    for i in range(128):
        a0, a1 = f[2 * i], f[2 * i + 1]
        b0, b1 = g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 * _GAMMAS[i]) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def _add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def _sample_ntt(seed: bytes):
    need = 672
    while True:
        b = hashlib.shake_128(seed).digest(need)
        a = []
        i = 0
        while i + 2 < len(b) and len(a) < 256:
            d1 = b[i] + 256 * (b[i + 1] & 15)
            d2 = (b[i + 1] >> 4) + 16 * b[i + 2]
            if d1 < Q:
                a.append(d1)
            if d2 < Q and len(a) < 256:
                a.append(d2)
            i += 3
        if len(a) == 256:
            return a
        need *= 2


def _cbd(b: bytes, eta: int):
    bits = int.from_bytes(b, "little")
    mask = (1 << eta) - 1
    span = (1 << (2 * eta)) - 1
    f = []
    for i in range(256):
        chunk = (bits >> (2 * eta * i)) & span
        x = bin(chunk & mask).count("1")
        y = bin(chunk >> eta).count("1")
        f.append((x - y) % Q)
    return f


def _prf(s: bytes, b: int, eta: int) -> bytes:
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def _byte_encode(F, d: int) -> bytes:
    acc = 0
    for i, x in enumerate(F):
        acc |= x << (d * i)
    return acc.to_bytes(32 * d, "little")


def _byte_decode(B: bytes, d: int):
    acc = int.from_bytes(B, "little")
    m = (1 << d) if d < 12 else Q
    mask = (1 << d) - 1
    return [((acc >> (d * i)) & mask) % m for i in range(256)]


def _compress(x: int, d: int) -> int:
    return (((x << d) + (Q >> 1)) // Q) & ((1 << d) - 1)


def _decompress(y: int, d: int) -> int:
    return (y * Q + (1 << (d - 1))) >> d


def _gen_matrix(rho: bytes):
    return [[_sample_ntt(rho + bytes([j, i])) for j in range(K)] for i in range(K)]


def _g(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def _h(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _kpke_keygen(d: bytes):
    g = _g(d + bytes([K]))
    rho, sigma = g[:32], g[32:]
    A = _gen_matrix(rho)
    s = [_ntt(_cbd(_prf(sigma, i, ETA1), ETA1)) for i in range(K)]
    e = [_ntt(_cbd(_prf(sigma, K + i, ETA1), ETA1)) for i in range(K)]
    t = []
    for i in range(K):
        acc = [0] * 256
        for j in range(K):
            acc = _add(acc, _mul_ntt(A[i][j], s[j]))
        t.append(_add(acc, e[i]))
    ek = b"".join(_byte_encode(t[i], 12) for i in range(K)) + rho
    dk = b"".join(_byte_encode(s[i], 12) for i in range(K))
    return ek, dk


def _kpke_encrypt(ek: bytes, m: bytes, r: bytes) -> bytes:
    t = [_byte_decode(ek[384 * i:384 * (i + 1)], 12) for i in range(K)]
    rho = ek[384 * K:]
    A = _gen_matrix(rho)
    y = [_ntt(_cbd(_prf(r, i, ETA1), ETA1)) for i in range(K)]
    e1 = [_cbd(_prf(r, K + i, ETA2), ETA2) for i in range(K)]
    e2 = _cbd(_prf(r, 2 * K, ETA2), ETA2)
    u = []
    for i in range(K):
        acc = [0] * 256
        for j in range(K):
            acc = _add(acc, _mul_ntt(A[j][i], y[j]))
        u.append(_add(_invntt(acc), e1[i]))
    mu = [_decompress((m[i // 8] >> (i % 8)) & 1, 1) for i in range(256)]
    acc = [0] * 256
    for j in range(K):
        acc = _add(acc, _mul_ntt(t[j], y[j]))
    v = _add(_add(_invntt(acc), e2), mu)
    c1 = b"".join(_byte_encode([_compress(x, DU) for x in u[i]], DU) for i in range(K))
    c2 = _byte_encode([_compress(x, DV) for x in v], DV)
    return c1 + c2


def _kpke_decrypt(dk: bytes, c: bytes) -> bytes:
    c1, c2 = c[:32 * DU * K], c[32 * DU * K:]
    u = [[_decompress(x, DU) for x in _byte_decode(c1[32 * DU * i:32 * DU * (i + 1)], DU)]
         for i in range(K)]
    v = [_decompress(x, DV) for x in _byte_decode(c2, DV)]
    s = [_byte_decode(dk[384 * i:384 * (i + 1)], 12) for i in range(K)]
    acc = [0] * 256
    for j in range(K):
        acc = _add(acc, _mul_ntt(s[j], _ntt(u[j])))
    w = [(a - b) % Q for a, b in zip(v, _invntt(acc))]
    bits = [_compress(x, 1) for x in w]
    out = bytearray(32)
    for i, bit in enumerate(bits):
        out[i // 8] |= bit << (i % 8)
    return bytes(out)


def keygen(seed: bytes | None = None):
    """Return (ek, dk).  `seed` is d||z (64 bytes) for deterministic tests."""
    seed = seed or os.urandom(64)
    d, z = seed[:32], seed[32:64]
    ek, dk_pke = _kpke_keygen(d)
    return ek, dk_pke + ek + _h(ek) + z


def encaps(ek: bytes, m: bytes | None = None):
    """Return (shared_secret, ciphertext)."""
    if len(ek) != EK_LEN:
        raise ValueError("bad ML-KEM-768 public key length")
    m = m or os.urandom(32)
    g = _g(m + _h(ek))
    return g[:32], _kpke_encrypt(ek, m, g[32:])


def decaps(dk: bytes, c: bytes) -> bytes:
    if len(dk) != DK_LEN or len(c) != CT_LEN:
        raise ValueError("bad ML-KEM-768 key or ciphertext length")
    dk_pke = dk[:384 * K]
    ek = dk[384 * K:768 * K + 32]
    h = dk[768 * K + 32:768 * K + 64]
    z = dk[768 * K + 64:]
    m = _kpke_decrypt(dk_pke, c)
    g = _g(m + h)
    k_good, r = g[:32], g[32:]
    k_bad = hashlib.shake_256(z + c).digest(32)
    c2 = _kpke_encrypt(ek, m, r)
    return k_good if hmac.compare_digest(c2, c) else k_bad
