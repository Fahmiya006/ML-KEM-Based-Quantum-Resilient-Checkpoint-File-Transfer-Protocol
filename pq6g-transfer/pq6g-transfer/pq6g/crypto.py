"""Cryptographic building blocks of the pq6g protocol.

KEM            ML-KEM-768 (FIPS 203): native `cryptography` if present, else pure Python
KDF            HKDF-SHA256 (RFC 5869) -> K (chunk key) and K_ck (checkpoint key)
Chunk cipher   AES-256-GCM, nonce = session id (4 B) || chunk number (8 B)
Hash chain     H_i = SHA-256( H_{i-1} || SHA-256(sealed chunk i) )
Checkpoint     84-byte record: sid | i* | o* | H_i* | HMAC-SHA256(K_ck, first 52 bytes)
Atomic write   tmp file -> fsync -> rename -> fsync directory
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time

from cryptography.exceptions import InvalidTag  # noqa: F401  (re-exported)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PROTO_INFO = b"pq6g/v1"
NONE_IDX = 0xFFFFFFFFFFFFFFFF     # "no chunk yet"
META_IDX = 0xFFFFFFFFFFFFFFFE     # reserved chunk number used to seal file metadata
TAG_LEN = 16
CKPT_BODY_LEN = 52
CKPT_LEN = 84
ZERO_H = b"\x00" * 32


# --------------------------------------------------------------------------- KEM
class NativeMLKEM768:
    name = "mlkem768"
    impl = "cryptography (native ML-KEM-768)"

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric.mlkem import (
            MLKEM768PrivateKey, MLKEM768PublicKey)
        self._priv, self._pub = MLKEM768PrivateKey, MLKEM768PublicKey

    def keygen(self):
        dk = self._priv.generate()
        return dk.public_key().public_bytes_raw(), dk

    def encaps(self, pk: bytes):
        ss, ct = self._pub.from_public_bytes(pk).encapsulate()
        return ss, ct

    def decaps(self, dk, ct: bytes) -> bytes:
        return dk.decapsulate(ct)


class PureMLKEM768:
    name = "mlkem768"
    impl = "pure-Python ML-KEM-768 (fallback)"

    def __init__(self):
        from . import mlkem_pure
        self._m = mlkem_pure

    def keygen(self):
        return self._m.keygen()

    def encaps(self, pk: bytes):
        return self._m.encaps(pk)

    def decaps(self, dk, ct: bytes) -> bytes:
        return self._m.decaps(dk, ct)


def get_kem(name: str = "mlkem768"):
    """mlkem768 (default) | mlkem768-pure | rsa-toy (quantum-attack demo only)."""
    if name == "mlkem768":
        try:
            return NativeMLKEM768()
        except Exception:
            return PureMLKEM768()
    if name == "mlkem768-pure":
        return PureMLKEM768()
    if name == "rsa-toy":
        from .toykem import ToyRSAKEM
        return ToyRSAKEM()
    raise ValueError(f"unknown KEM {name!r}")


# --------------------------------------------------------------------------- KDF
def hkdf_sha256(ikm: bytes, info: bytes, length: int, salt: bytes = b"") -> bytes:
    salt = salt or b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()          # extract
    okm, t, i = b"", b"", 1
    while len(okm) < length:                                       # expand
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def derive_keys(shared_secret: bytes, sid: bytes):
    """-> (K for chunks, K_ck for checkpoints), both 32 bytes."""
    okm = hkdf_sha256(shared_secret, PROTO_INFO + sid, 64)
    return okm[:32], okm[32:]


# ---------------------------------------------------------------- chunk cipher
class ChunkCipher:
    """Seals / opens chunks.  Nonce depends only on (session, chunk number), so a
    chunk that is re-sent after a disruption encrypts to the exact same bytes."""

    def __init__(self, key: bytes, sid: bytes):
        self.sid = sid
        self._aead = AESGCM(key)

    def nonce(self, idx: int) -> bytes:
        return self.sid + idx.to_bytes(8, "big")

    def aad(self, idx: int, plain_len: int) -> bytes:
        return self.nonce(idx) + plain_len.to_bytes(4, "big")

    def seal(self, idx: int, plain: bytes) -> bytes:
        return self._aead.encrypt(self.nonce(idx), plain, self.aad(idx, len(plain)))

    def open(self, idx: int, sealed: bytes) -> bytes:
        if len(sealed) < TAG_LEN:
            raise InvalidTag()
        return self._aead.decrypt(self.nonce(idx), sealed, self.aad(idx, len(sealed) - TAG_LEN))


# ------------------------------------------------------------------ hash chain
def chain_next(h_prev: bytes, sealed: bytes) -> bytes:
    return hashlib.sha256(h_prev + hashlib.sha256(sealed).digest()).digest()


# ------------------------------------------------------------------ checkpoint
def pack_ckpt(kck: bytes, sid: bytes, i_star: int, o_star: int, h: bytes) -> bytes:
    body = struct.pack(">4sQQ32s", sid, i_star, o_star, h)
    return body + hmac.new(kck, body, hashlib.sha256).digest()


def parse_ckpt(kck: bytes, rec: bytes):
    """Return dict if length and HMAC are valid, else None."""
    if len(rec) != CKPT_LEN:
        return None
    body, mac = rec[:CKPT_BODY_LEN], rec[CKPT_BODY_LEN:]
    if not hmac.compare_digest(hmac.new(kck, body, hashlib.sha256).digest(), mac):
        return None
    sid, i_star, o_star, h = struct.unpack(">4sQQ32s", body)
    return {"sid": sid, "i_star": i_star, "o_star": o_star, "h": h, "mac": mac}


def _fsync_dir(path: str):
    try:                                           # directory fsync is POSIX-only
        fd = os.open(path or ".", os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def atomic_write(path: str, data: bytes) -> float:
    """tmp file -> fsync -> atomic rename -> fsync dir.  Returns seconds taken."""
    t0 = time.perf_counter()
    tmp = path + ".tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    _fsync_dir(os.path.dirname(os.path.abspath(path)))
    return time.perf_counter() - t0


def sha256_file(path: str, bufsize: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(bufsize)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# ----------------------------------------------------- young's optimal interval
def optimal_interval(rate_bps: float, size_bits: float, t_ck: float, n_d: float, chunk_bits: float) -> float:
    """N* = sqrt( 2 R S t_ck / (n_d c^2) )   (Young 1974, applied to link outages)."""
    return (2.0 * rate_bps * size_bits * t_ck / (n_d * chunk_bits ** 2)) ** 0.5


def overhead_model(n: float, rate_bps, size_bits, t_ck, n_d, chunk_bits):
    """(saving cost, redo cost) in seconds for checkpoint interval n (in chunks)."""
    saving = size_bits / (n * chunk_bits) * t_ck
    redo = n_d * n * chunk_bits / (2.0 * rate_bps)
    return saving, redo
