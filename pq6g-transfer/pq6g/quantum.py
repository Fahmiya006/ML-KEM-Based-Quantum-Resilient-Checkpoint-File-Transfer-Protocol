"""Simulated quantum attacker ("harvest now, decrypt later").

1. An eavesdropper recorded every frame that crossed the air (capture file).
2. Years later a quantum computer runs Shor's algorithm against the recorded
   key exchange.

What is simulated, and how honestly
  * Shor's algorithm runs as a real state-vector simulation: the measured
    register state is built, the quantum Fourier transform is applied (as an FFT,
    which is mathematically the same transform), a measurement is sampled from
    the resulting probability distribution, and the classical post-processing
    (continued fractions, gcd) recovers the factors.  Nothing is looked up.
  * A classical computer must hold 2^(2n) amplitudes to simulate it, so it only
    fits tiny moduli (n <= 12 bits here).  Real RSA-2048 needs a real, large,
    error-corrected quantum computer that does not exist yet.  The toy modulus is
    therefore trivially breakable even classically - the point is the pipeline:
    recorded traffic -> factor -> private key -> session key -> file.
  * The same attacker has nothing to attack in an ML-KEM-768 recording.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import struct
import time
from fractions import Fraction

import numpy as np

from . import crypto as C
from . import wire as W
from .link import CAPTURE_REC
from .testfile import png_prefix
from .toykem import public_to_n_e, secret_to_ss


# ------------------------------------------------------------------ capture
def parse_capture(path):
    """-> list of (timestamp, direction 0/1, frame_type, payload)"""
    out = []
    with open(path, "rb") as f:
        while True:
            hdr = f.read(CAPTURE_REC.size)
            if len(hdr) < CAPTURE_REC.size:
                break
            ts, d, ln = CAPTURE_REC.unpack(hdr)
            raw = f.read(ln)
            if len(raw) < ln:
                break
            t, plen = W.HDR.unpack_from(raw, 0)
            out.append((ts, d, t, raw[W.HDR.size:W.HDR.size + plen]))
    return out


# --------------------------------------------------------------------- Shor
def _order_find_once(a, N, rng):
    """One run of the quantum order-finding circuit, as a state-vector simulation."""
    n = N.bit_length()
    q = 1 << (2 * n)                              # size of the counting register: 2n qubits
    T = np.empty(q, dtype=np.int64)               # second register = a^x mod N for every x
    T[0] = 1
    k = 1
    while k < q:
        T[k:2 * k] = (T[:k] * pow(a, k, N)) % N
        k *= 2
    x0 = int(rng.integers(0, q))                  # Born rule: measuring register 2 picks v = a^x0 mod N
    v = int(T[x0])
    psi = (T == v).astype(np.complex128)          # register 1 collapses to the x with a^x = v
    del T
    psi /= math.sqrt(psi.real.sum())
    amp = np.fft.ifft(psi) * math.sqrt(q)         # quantum Fourier transform
    del psi
    prob = amp.real ** 2 + amp.imag ** 2
    del amp
    prob /= prob.sum()
    y = int(rng.choice(q, p=prob))                # measure register 1
    top = np.argsort(prob)[-24:][::-1]
    peaks = [(int(i), float(prob[i])) for i in top]
    return {"n": n, "q": q, "v": v, "y": y, "peaks": peaks}


def shor_factor(N, seed=1, max_attempts=14, log=print):
    rng = np.random.default_rng(seed)
    n = N.bit_length()
    t0 = time.time()
    attempts = []
    log(f"  Shor on N = {N} ({n} bits): textbook circuit = {3 * n} logical qubits "
        f"(2n counting + n work); state vector = 2^{2 * n} = {1 << (2 * n):,} amplitudes")
    for k in range(1, max_attempts + 1):
        a = int(rng.integers(2, N - 1))
        g = math.gcd(a, N)
        if g > 1:
            attempts.append({"a": a, "note": "lucky gcd", "ok": True})
            log(f"  attempt {k}: a={a} shares a factor with N by luck: gcd = {g}")
            return {"p": g, "q": N // g, "attempts": attempts, "n_bits": n, "qubits": 3 * n,
                    "amplitudes": 1 << (2 * n), "seconds": time.time() - t0, "peaks": []}
        s = _order_find_once(a, N, rng)
        frac = Fraction(s["y"], s["q"]).limit_denominator(N)
        r = None
        for mult in range(1, 7):
            cand = frac.denominator * mult
            if cand < N and pow(a, cand, N) == 1:
                r = cand
                break
        rec = {"a": a, "v": s["v"], "y": s["y"], "q": s["q"], "y_over_q": s["y"] / s["q"],
               "frac": f"{frac.numerator}/{frac.denominator}", "r": r, "peaks": s["peaks"]}
        if r is None:
            rec["ok"], rec["note"] = False, "measurement gave no valid period - run again"
            log(f"  attempt {k}: a={a}  measured y={s['y']} (y/q={s['y'] / s['q']:.5f} ~ {frac})  -> no valid period, retry")
        elif r % 2:
            rec["ok"], rec["note"] = False, f"order r={r} is odd - retry"
            log(f"  attempt {k}: a={a}  y/q ~ {frac}  -> order r={r} is odd, retry")
        else:
            x = pow(a, r // 2, N)
            if x == N - 1:
                rec["ok"], rec["note"] = False, f"a^(r/2) = -1 mod N - retry"
                log(f"  attempt {k}: a={a}  order r={r}, but a^(r/2) = -1 mod N, retry")
            else:
                p = math.gcd(x - 1, N)
                if 1 < p < N:
                    rec["ok"], rec["note"] = True, f"order r={r}; gcd(a^(r/2) - 1, N) = {p}"
                    attempts.append(rec)
                    log(f"  attempt {k}: a={a}  measured y={s['y']} (y/q = {s['y'] / s['q']:.5f} ~ {frac}) -> order r={r}; "
                        f"gcd(a^(r/2)-1, N) = {p}  -> N = {p} x {N // p}")
                    return {"p": p, "q": N // p, "attempts": attempts, "n_bits": n, "qubits": 3 * n,
                            "amplitudes": 1 << (2 * n), "seconds": time.time() - t0, "peaks": s["peaks"],
                            "r": r, "a": a}
                rec["ok"], rec["note"] = False, "trivial gcd - retry"
        attempts.append(rec)
    return None


# ------------------------------------------------------------------- attack
def _sessions(frames):
    """Group a capture into sessions: kem, sid, public key, ciphertext, meta, data frames."""
    sess, cur, order = {}, None, []
    for ts, d, t, p in frames:
        if t == W.T_START:
            cur = {"kem": json.loads(p.decode()).get("kem"), "pk": None, "ct": None, "sid": None,
                   "meta": None, "data": {}, "frames": 0}
        elif cur is not None and t == W.T_HELLO and cur["sid"] is None:
            cur["sid"], cur["pk"] = p[:4], p[4:]
            sess[cur["sid"]] = cur
            order.append(cur["sid"])
        elif cur is not None and t == W.T_KEMCT and cur["ct"] is None:
            cur["ct"] = p
        elif t == W.T_META and p[:4] in sess:
            sess[p[:4]]["meta"] = p
        elif t == W.T_DATA and p[:4] in sess:
            idx = int.from_bytes(p[4:12], "big")
            sess[p[:4]]["data"].setdefault(idx, p[12:])
    return [sess[s] for s in order]


def attack_capture(cap_path, original=None, out_dir="attack_out", shor_seed=1, log=print):
    os.makedirs(out_dir, exist_ok=True)
    frames = parse_capture(cap_path)
    sessions = _sessions(frames)
    total_bytes = sum(len(p) for _, _, _, p in frames)
    rep = {"capture": os.path.basename(cap_path), "frames": len(frames), "bytes": total_bytes,
           "sessions": len(sessions), "steps": [], "success": False}
    log(f"EAVESDROPPER: recorded {len(frames)} frames, {total_bytes / 2**20:.1f} MiB from the air interface, {len(sessions)} session(s)")
    if not sessions:
        rep["error"] = "no complete session in capture"
        return rep
    s = sessions[0]
    kem = s["kem"]
    log(f"  visible to anyone listening: key-exchange method '{kem}', public key {len(s['pk'])} B, "
        f"ciphertext {len(s['ct'] or b'')} B, {len(s['data'])} encrypted chunks (random-looking bytes)")
    rep["kem"], rep["pk_bytes"], rep["ct_bytes"], rep["chunks_recorded"] = kem, len(s["pk"]), len(s["ct"] or b""), len(s["data"])
    sample = next(iter(s["data"].values()))
    rep["wire_entropy_bits_per_byte"] = _entropy(sample)

    if kem == "rsa-toy":
        N, e = public_to_n_e(s["pk"])
        c = struct.unpack(">I", s["ct"])[0]
        log(f"QUANTUM COMPUTER (simulated): the key exchange is RSA with N = {N}, e = {e}")
        res = shor_factor(N, seed=shor_seed, log=log)
        rep["shor"] = {k: v for k, v in (res or {}).items() if k != "peaks"}
        rep["shor_peaks"] = (res or {}).get("peaks", [])
        rep["shor_attempts"] = [{k: v for k, v in a.items() if k != "peaks"} for a in (res or {}).get("attempts", [])]
        if not res:
            rep["error"] = "Shor failed within attempts"
            return rep
        p, q = res["p"], res["q"]
        d = pow(e, -1, (p - 1) * (q - 1))
        sec = pow(c, d, N)
        ss = secret_to_ss(sec)
        K, Kck = C.derive_keys(ss, s["sid"])
        cc = C.ChunkCipher(K, s["sid"])
        log(f"  private exponent d = {d}; session secret recovered; AES-256-GCM key derived (fingerprint "
            f"{hashlib.sha256(b'fp' + K).hexdigest()[:12]})")
        meta = json.loads(cc.open(C.META_IDX, s["meta"][12:]).decode())
        size, chunk, nchunks = meta["size"], meta["chunk"], meta["nchunks"]
        buf = bytearray(size)
        ok = 0
        for idx, sealed in s["data"].items():
            try:
                plain = cc.open(idx, sealed)
            except C.InvalidTag:
                continue
            buf[idx * chunk: idx * chunk + len(plain)] = plain
            ok += 1
        rec_path = os.path.join(out_dir, "recovered_from_" + os.path.basename(meta["name"]))
        open(rec_path, "wb").write(buf)
        sha = hashlib.sha256(buf).hexdigest()
        rep.update({"chunks_decrypted": ok, "chunks_total": nchunks, "recovered_sha256": sha, "recovered_path": rec_path,
                    "file_name": meta["name"], "d": d, "p": p, "q": q})
        if original:
            same = hashlib.sha256(open(original, "rb").read()).hexdigest() == sha
            rep["identical_to_original"] = same
            log(f"  decrypted {ok}/{nchunks} recorded chunks -> recovered file is {'IDENTICAL to the original' if same else 'different'} "
                f"(sha256 {sha[:16]}...)")
        banner = png_prefix(bytes(buf[:200000]))
        if banner:
            bp = os.path.join(out_dir, "recovered_banner.png")
            open(bp, "wb").write(banner)
            rep["banner_png"] = bp
        # for contrast: how long would a classical computer need for THIS toy modulus?
        t0 = time.time()
        f = next(x for x in range(2, N) if N % x == 0)
        rep["classical_trial_division_seconds"] = time.time() - t0
        rep["success"] = True
        log("RESULT: harvest-now-decrypt-later SUCCEEDED against the classical key exchange.")
        return rep

    # ----- ML-KEM-768 recording: nothing for Shor to grab
    log(f"QUANTUM COMPUTER (simulated): the key exchange is {kem}")
    log("  Shor's algorithm needs an integer to factor or a cyclic group with a hidden period.")
    log(f"  The recording contains: a public key = 3 polynomials of 256 numbers mod 3329 + a 32-byte seed ({len(s['pk'])} B),")
    log(f"  and a ciphertext of {len(s['ct'])} B. Recovering the secret means solving Module-LWE (noisy linear algebra), which has no such period.")
    log("  Best generic option left: guess the 256-bit AES key. Testing guesses against a recorded chunk:")
    sealed = sample
    idx0 = next(iter(s["data"]))
    guesses, t0 = 0, time.time()
    sid = s["sid"]
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = sid + idx0.to_bytes(8, "big")
    aad = nonce + (len(sealed) - 16).to_bytes(4, "big")
    hits = 0
    while time.time() - t0 < 3.0:
        for _ in range(500):
            try:
                AESGCM(os.urandom(32)).decrypt(nonce, sealed, aad)
                hits += 1
            except Exception:
                pass
            guesses += 1
    rate = guesses / (time.time() - t0)
    years = 2 ** 256 / rate / 3.15e7
    log(f"  tried {guesses:,} random keys in 3 s ({rate:,.0f}/s): {hits} authenticated.")
    log(f"  at this rate the 2^256 key space takes ~{years:.1e} years; even Grover's quantum search (2^128 steps) is out of reach.")
    # wrong-key decapsulation gives garbage, not an error: implicit rejection
    kem_obj = C.get_kem("mlkem768")
    pk2, dk2 = kem_obj.keygen()
    ss_wrong = kem_obj.decaps(dk2, s["ct"])
    K_wrong, _ = C.derive_keys(ss_wrong, sid)
    try:
        C.ChunkCipher(K_wrong, sid).open(idx0, sealed)
        wrong_ok = True
    except C.InvalidTag:
        wrong_ok = False
    log(f"  decapsulating the recorded ciphertext with any key but the receiver's gives an unrelated secret: chunk authenticates = {wrong_ok}")
    rep.update({"guesses": guesses, "guess_rate": rate, "years_for_2_256": years, "hits": hits,
                "wrong_key_authenticates": wrong_ok, "success": False})
    log("RESULT: harvest-now-decrypt-later FAILED. The recorded file stays encrypted.")
    return rep


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(b)
    return float(-(p * np.log2(p)).sum())


def run_attack(capture, original, bits_hint=11, out_dir="attack_out"):
    rep = attack_capture(capture, original, out_dir)
    json.dump(rep, open(os.path.join(out_dir, "attack_report.json"), "w"), indent=2, default=str)
    return 0 if rep.get("success") or rep.get("kem") == "mlkem768" else 1
