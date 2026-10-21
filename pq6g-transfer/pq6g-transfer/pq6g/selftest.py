"""Self-test: `python -m pq6g selftest`.  Each check prints PASS/FAIL; results are also returned as data
(the evidence report embeds them)."""
from __future__ import annotations

import hashlib
import os
import random
import subprocess
import sys
import tempfile
import time

from . import crypto as C


def _crash_child(path, kck_hex, sid_hex):
    kck, sid = bytes.fromhex(kck_hex), bytes.fromhex(sid_hex)
    i = 0
    while True:
        rec = C.pack_ckpt(kck, sid, i, (i + 1) * 65536, hashlib.sha256(str(i).encode()).digest())
        C.atomic_write(path, rec)
        i += 1


def crash_during_checkpoint_write(trials=80):
    """Kill a process at random moments while it writes checkpoints in a tight loop.  After every kill the
    committed checkpoint must exist-and-verify (or not exist yet), never be half written."""
    d = tempfile.mkdtemp(prefix="pq6g_crash_")
    path = os.path.join(d, "ckpt.bin")
    kck, sid = os.urandom(32), os.urandom(4)
    bad = good = absent = 0
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # a folder, or the .pyz file itself
    rng = random.Random(7)
    for _ in range(trials):
        p = subprocess.Popen([sys.executable, "-c",
                              "from pq6g.selftest import _crash_child; import sys; _crash_child(sys.argv[1], sys.argv[2], sys.argv[3])",
                              path, kck.hex(), sid.hex()], cwd=d,
                             env=dict(os.environ, PYTHONPATH=pkg_parent))
        time.sleep(rng.uniform(0.15, 0.45))
        p.kill()
        p.wait()
        if not os.path.exists(path):
            absent += 1
            continue
        rec = C.parse_ckpt(kck, open(path, "rb").read())
        if rec is None:
            bad += 1
        else:
            good += 1
    return {"trials": trials, "valid": good, "not_yet_written": absent, "corrupt": bad}


def main():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "ok": bool(ok), "detail": detail})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""), flush=True)

    print("crypto")
    ss, sid = os.urandom(32), os.urandom(4)
    check("HKDF-SHA256 matches RFC 5869 test case 1",
          C.hkdf_sha256(bytes.fromhex("0b" * 22), bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42,
                        bytes.fromhex("000102030405060708090a0b0c")).hex() ==
          "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    check("SHA-256('abc') matches the standard test vector",
          hashlib.sha256(b"abc").hexdigest() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    K, Kck = C.derive_keys(ss, sid)
    cc = C.ChunkCipher(K, sid)
    sealed = cc.seal(7, b"hello chunk!")
    check("chunk seals and opens", cc.open(7, sealed) == b"hello chunk!")

    def rejects(fn):
        try:
            fn()
            return False
        except C.InvalidTag:
            return True
    fl = bytearray(sealed)
    fl[0] ^= 1
    check("one flipped ciphertext bit is rejected", rejects(lambda: cc.open(7, bytes(fl))))
    check("right bytes, wrong chunk number is rejected", rejects(lambda: cc.open(8, sealed)))
    check("chunk from another session is rejected", rejects(lambda: C.ChunkCipher(K, b"\1\2\3\4").open(7, sealed)))
    check("re-sealing a chunk gives identical bytes (safe to resend)", cc.seal(7, b"hello chunk!") == sealed)
    rec = C.pack_ckpt(Kck, sid, 799, 800 * 65536, hashlib.sha256(b"x").digest())
    flips = 0
    for byte in range(len(rec)):
        for bit in range(8):
            r = bytearray(rec)
            r[byte] ^= 1 << bit
            flips += C.parse_ckpt(Kck, bytes(r)) is None
    check("checkpoint is 84 bytes and verifies", len(rec) == 84 and C.parse_ckpt(Kck, rec) is not None)
    check("every single-bit change of a checkpoint is rejected", flips == 672, f"{flips}/672")
    check("checkpoint under the wrong key is rejected", C.parse_ckpt(os.urandom(32), rec) is None)

    print("key exchange")
    nat, pur = C.get_kem("mlkem768"), C.get_kem("mlkem768-pure")
    pk, dk = nat.keygen()
    s1, ct = pur.encaps(pk)
    check("ML-KEM-768 sizes: public key 1184, ciphertext 1088, secret 32", len(pk) == 1184 and len(ct) == 1088 and len(s1) == 32,
          nat.impl)
    check("pure-Python ML-KEM encapsulates, native decapsulates", nat.decaps(dk, ct) == s1)
    s2, ct2 = nat.encaps(pk)
    pk3, dk3 = pur.keygen()
    s3, ct3 = nat.encaps(pk3)
    check("native encapsulates, pure-Python decapsulates", pur.decaps(dk3, ct3) == s3)
    bad = bytearray(ct)
    bad[5] ^= 1
    check("tampered ciphertext gives a different secret (implicit rejection)", nat.decaps(dk, bytes(bad)) != s1)

    print("atomic checkpoint write")
    r = crash_during_checkpoint_write(40)
    check("process killed mid-write 40 times: checkpoint never corrupt", r["corrupt"] == 0 and r["valid"] > 0,
          f"{r['valid']} valid, {r['not_yet_written']} not yet written, {r['corrupt']} corrupt")

    print("end to end over a simulated 6G link")
    from .config import PROFILES
    from .events import EventLog
    from .link import LinkEmulator
    from .receiver import Receiver
    from .sender import Sender
    d = tempfile.mkdtemp(prefix="pq6g_e2e_")
    src = os.path.join(d, "f.bin")
    open(src, "wb").write(os.urandom(6 * 1024 * 1024 + 321))
    ev = EventLog(None, role="t")
    rx = Receiver("127.0.0.1", 0, d + "/out", d + "/st", ev.view("receiver")).start()
    link = LinkEmulator(("127.0.0.1", rx.port), PROFILES["6g-slow"], ev.view("link"), cut_after_chunks=[30],
                        auto_blockage=False).start()
    tx = Sender(src, "127.0.0.1", link.port, ev.view("sender"), n=8, window=16)
    ok = tx.run()
    same = ok and hashlib.sha256(open(src, "rb").read()).digest() == hashlib.sha256(open(d + "/out/f.bin", "rb").read()).digest()
    check("file survives a link cut and arrives bit-identical", same, f"{tx.resumes} resume, {tx.handshakes} key exchange")
    check("resume reused the key (no second key exchange)", tx.handshakes == 1 and tx.resumes == 1)
    link.stop()
    rx.stop()
    n_fail = sum(1 for r in results if not r["ok"])
    print(f"\n{len(results) - n_fail}/{len(results)} checks passed")
    return results if False else (1 if n_fail else 0)


if __name__ == "__main__":
    sys.exit(main())
