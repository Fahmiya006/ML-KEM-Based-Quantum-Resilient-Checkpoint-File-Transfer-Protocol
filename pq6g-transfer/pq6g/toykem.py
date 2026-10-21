"""Toy RSA key encapsulation - ONLY for the simulated-quantum-attack demo.

A real RSA-2048 modulus cannot be factored by a simulator, and a simulator
cannot hold the state of a real quantum computer.  So to *show the attack
pipeline working end to end* the demo transfers a file with a deliberately
tiny RSA modulus (about 11-12 bits).  At that size even a classical computer
breaks it instantly - the point is that the quantum algorithm (Shor) is run
for real, as a state-vector simulation, against a recorded transfer, and that
the same attacker has nothing to attack in an ML-KEM transfer.

Interface is identical to the ML-KEM wrappers in crypto.py.
"""
from __future__ import annotations

import hashlib
import math
import random
import struct


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _rand_prime(rng: random.Random, lo: int, hi: int) -> int:
    while True:
        c = rng.randrange(lo, hi) | 1
        if _is_prime(c):
            return c


def _derive(s: int) -> bytes:
    return hashlib.sha256(b"rsa-toy-kem" + s.to_bytes(8, "big")).digest()


class ToyRSAKEM:
    name = "rsa-toy"
    impl = "toy RSA-KEM (INSECURE, quantum-attack demo only)"

    def __init__(self, bits: int = 11, seed=None):
        self.bits = bits
        self._rng = random.Random(seed)

    def keygen(self):
        half = self.bits // 2
        while True:
            p = _rand_prime(self._rng, 1 << (half - 1), 1 << half)
            q = _rand_prime(self._rng, 1 << (self.bits - half - 1), 1 << (self.bits - half))
            if p == q:
                continue
            n = p * q
            if n.bit_length() != self.bits:
                continue
            phi = (p - 1) * (q - 1)
            e = 17
            while math.gcd(e, phi) != 1:
                e += 2
            d = pow(e, -1, phi)
            return struct.pack(">II", n, e), (n, d)

    def encaps(self, pk: bytes):
        n, e = struct.unpack(">II", pk)
        s = self._rng.randrange(2, n - 1)
        return _derive(s), struct.pack(">I", pow(s, e, n))

    def decaps(self, handle, ct: bytes) -> bytes:
        n, d = handle
        return _derive(pow(struct.unpack(">I", ct)[0], d, n))


def public_to_n_e(pk: bytes):
    return struct.unpack(">II", pk)


def secret_to_ss(s: int) -> bytes:
    return _derive(s)
