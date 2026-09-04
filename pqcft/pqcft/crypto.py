"""
Cryptographic primitives for the quantum-resilient checkpoint file transfer protocol.

Two key-establishment backends are exposed behind one interface so the baseline
(classical ECDHE) and the proposed protocol (post-quantum ML-KEM) can be swapped
without touching the transport:

    * MLKEMBackend   -- NIST FIPS 203 ML-KEM-768 (formerly CRYSTALS-Kyber-768)
    * X25519Backend  -- classical ECDHE, the pre-quantum comparison point

Both produce a 32-byte shared secret that is expanded with HKDF-SHA256 into a
256-bit AES-GCM session key plus a per-session nonce salt.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from kyber_py.ml_kem import ML_KEM_768

HKDF_INFO_KEY = b"pqcft/v1 aes-256-gcm session key"
HKDF_INFO_SALT = b"pqcft/v1 nonce salt"


# --------------------------------------------------------------------------- #
# HKDF (RFC 5869) over SHA-256
# --------------------------------------------------------------------------- #
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


# --------------------------------------------------------------------------- #
# Key establishment backends
# --------------------------------------------------------------------------- #
@dataclass
class KexCost:
    """Bandwidth + CPU cost of one handshake, recorded for the evaluation."""

    scheme: str
    pub_bytes: int = 0          # bytes the responder puts on the wire
    ct_bytes: int = 0           # bytes the initiator puts on the wire
    keygen_ms: float = 0.0
    encaps_ms: float = 0.0
    decaps_ms: float = 0.0

    @property
    def wire_bytes(self) -> int:
        return self.pub_bytes + self.ct_bytes

    @property
    def cpu_ms(self) -> float:
        return self.keygen_ms + self.encaps_ms + self.decaps_ms


class MLKEMBackend:
    """Post-quantum KEM. Responder keygens, initiator encapsulates."""

    name = "ml-kem-768"

    @staticmethod
    def responder_keygen() -> Tuple[bytes, bytes, float]:
        t0 = time.perf_counter()
        ek, dk = ML_KEM_768.keygen()
        return ek, dk, (time.perf_counter() - t0) * 1e3

    @staticmethod
    def initiator_encaps(ek: bytes) -> Tuple[bytes, bytes, float]:
        t0 = time.perf_counter()
        shared, ct = ML_KEM_768.encaps(ek)
        return shared, ct, (time.perf_counter() - t0) * 1e3

    @staticmethod
    def responder_decaps(dk: bytes, ct: bytes) -> Tuple[bytes, float]:
        t0 = time.perf_counter()
        shared = ML_KEM_768.decaps(dk, ct)
        return shared, (time.perf_counter() - t0) * 1e3


class X25519Backend:
    """Classical ECDHE, shaped into the same encaps/decaps call pattern."""

    name = "x25519-ecdhe"

    @staticmethod
    def responder_keygen() -> Tuple[bytes, bytes, float]:
        t0 = time.perf_counter()
        sk = X25519PrivateKey.generate()
        pk = sk.public_key().public_bytes_raw()
        return pk, sk.private_bytes_raw(), (time.perf_counter() - t0) * 1e3

    @staticmethod
    def initiator_encaps(pk: bytes) -> Tuple[bytes, bytes, float]:
        t0 = time.perf_counter()
        eph = X25519PrivateKey.generate()
        shared = eph.exchange(X25519PublicKey.from_public_bytes(pk))
        ct = eph.public_key().public_bytes_raw()
        return shared, ct, (time.perf_counter() - t0) * 1e3

    @staticmethod
    def responder_decaps(sk_raw: bytes, ct: bytes) -> Tuple[bytes, float]:
        t0 = time.perf_counter()
        sk = X25519PrivateKey.from_private_bytes(sk_raw)
        shared = sk.exchange(X25519PublicKey.from_public_bytes(ct))
        return shared, (time.perf_counter() - t0) * 1e3


BACKENDS = {"mlkem": MLKEMBackend, "x25519": X25519Backend}


# --------------------------------------------------------------------------- #
# Session key derivation + chunk AEAD
# --------------------------------------------------------------------------- #
def derive_session(shared_secret: bytes, transcript: bytes) -> Tuple[bytes, bytes]:
    """Bind the session key to the handshake transcript, not just the secret."""
    key = hkdf(shared_secret, transcript, HKDF_INFO_KEY, 32)
    salt = hkdf(shared_secret, transcript, HKDF_INFO_SALT, 4)
    return key, salt


class ChunkCipher:
    """
    AES-256-GCM over file chunks.

    The nonce is deterministic (salt || counter) rather than random: chunk index
    is unique per session, so this gives nonce uniqueness without spending 12
    bytes of wire per chunk, and it means a resumed transfer reconstructs the
    exact same nonce for chunk N without extra state.
    """

    def __init__(self, key: bytes, nonce_salt: bytes, session_id: bytes):
        self.aead = AESGCM(key)
        self.salt = nonce_salt
        self.session_id = session_id

    def _nonce(self, index: int) -> bytes:
        return self.salt + struct.pack(">Q", index)

    def _aad(self, index: int, total: int) -> bytes:
        return self.session_id + struct.pack(">QQ", index, total)

    def seal(self, index: int, total: int, plaintext: bytes) -> bytes:
        return self.aead.encrypt(self._nonce(index), plaintext, self._aad(index, total))

    def open(self, index: int, total: int, ciphertext: bytes) -> bytes:
        return self.aead.decrypt(self._nonce(index), ciphertext, self._aad(index, total))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: str, block: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(block)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def new_session_id() -> bytes:
    return os.urandom(16)
