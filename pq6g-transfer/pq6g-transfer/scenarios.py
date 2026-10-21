"""Scenario runner.  Every scenario really runs the sender, the 6G link emulator and the receiver (loopback TCP),
records the event log, and writes evidence/<id>.json + evidence/<id>.events.jsonl.

  python scenarios.py S0 S1 S3        run some
  python scenarios.py all             run everything (several minutes)
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pq6g.config import PROFILES                      # noqa: E402
from pq6g.events import EventLog, load_jsonl          # noqa: E402
from pq6g.link import LinkEmulator                    # noqa: E402
from pq6g.receiver import Receiver                    # noqa: E402
from pq6g.sender import Sender                        # noqa: E402
from pq6g.__main__ import _parse_attack               # noqa: E402

EVID = os.path.join(HERE, "evidence")
WORK = os.path.join(HERE, ".work")
os.makedirs(EVID, exist_ok=True)
os.makedirs(WORK, exist_ok=True)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def src_file(mb):
    p = os.path.join(WORK, f"src_{mb}.bin")
    if not os.path.exists(p):
        from pq6g.testfile import make_test_file
        make_test_file(p, mb)
    return p


def run(name, mb=100, profile="6g-demo", seed=1, cuts=(), auto=False, attack="", mode="checkpoint", n=32,
        window=32, give_up=120, lam=None, ckpt_delay_ms=0.0, save=True, capture=None, kem=None, quiet=False):
    d = os.path.join(WORK, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    src = src_file(mb)
    ev = EventLog(os.path.join(d, "events.jsonl"), role="app")
    rx = Receiver("127.0.0.1", 0, d + "/out", d + "/rx_state", ev.view("receiver"), ckpt_extra_delay_ms=ckpt_delay_ms).start()
    link = LinkEmulator(("127.0.0.1", rx.port), PROFILES[profile], ev.view("link"), seed=seed, cut_after_chunks=list(cuts),
                        auto_blockage=auto, blockage_rate=lam, attack=_parse_attack(attack), capture_path=capture).start()
    kw = {}
    if kem is not None:
        kw["kem_obj"] = kem
    tx = Sender(src, "127.0.0.1", link.port, ev.view("sender"), n=n, window=window, mode=mode, give_up_after=give_up, **kw)
    t0 = time.time()
    ok = tx.run()
    wall = time.time() - t0
    time.sleep(0.15)
    out = os.path.join(d, "out", os.path.basename(src))
    identical = os.path.exists(out) and sha(out) == sha(src)
    events = list(ev.events)
    done = [e for e in events if e["ev"] == "transfer_complete"]
    st = [e for e in events if e["ev"] == "send_start"]
    rx_done_s = (done[0]["t"] - st[0]["t"]) if (done and st) else None
    cks = [e for e in events if e["ev"] == "checkpoint"]
    res = {
        "id": name, "size_mb": mb, "link": profile, "seed": seed, "n": n, "mode": mode, "sender_ok": bool(ok),
        "file_identical": bool(identical), "wall_s": round(wall, 3), "receiver_completion_s": None if rx_done_s is None else round(rx_done_s, 3),
        "key_exchanges": tx.handshakes, "resumes": tx.resumes, "rewinds": getattr(tx, "rewinds", 0),
        "chunks_sent": tx.chunks_sent, "chunks_resent": tx.chunks_resent,
        "chunks_in_file": (os.path.getsize(src) + 65535) // 65536,
        "outages": link.stats["outages"], "outage_seconds": round(link.stats["outage_seconds"], 2),
        "checkpoints": len(cks),
        "t_ck_ms_mean": round(statistics.mean(c["t_ck_ms"] for c in cks), 3) if cks else None,
        "t_ck_ms_median": round(statistics.median(c["t_ck_ms"] for c in cks), 3) if cks else None,
        "resume_served": [{k: e.get(k) for k in ("i_star", "o_star", "had_verified_until", "redo_chunks", "t")} for e in events if e["ev"] == "resume_served"],
        "resume_rejected": [{k: v for k, v in e.items() if k in ("t", "reason", "verdict")} for e in events if e["ev"] == "resume_rejected"],
        "tag_rejects": sum(1 for e in events if e["ev"] == "tag_reject"),
        "attacks": [e["ev"] for e in events if e["ev"].startswith("attack_")],
        "bytes_resent_mb": round(tx.chunks_resent * 65536 / 2**20, 2),
    }
    link.stop(); rx.stop(); ev.close()
    if save:
        shutil.copy(os.path.join(d, "events.jsonl"), os.path.join(EVID, f"{name}.events.jsonl"))
        json.dump(res, open(os.path.join(EVID, f"{name}.json"), "w"), indent=1)
    if not quiet:
        print(f"[{name}] ok={ok} identical={identical} rx_done={res['receiver_completion_s']}s resumes={tx.resumes} "
              f"resent={tx.chunks_resent} outages={link.stats['outages']} ck={len(cks)} t_ck={res['t_ck_ms_median']}ms", flush=True)
    return res


def dump(name, obj):
    json.dump(obj, open(os.path.join(EVID, f"{name}.json"), "w"), indent=1)


# ---------------------------------------------------------------- scenarios
def S0():
    return run("S0_clean", mb=100, auto=False)


def S1():
    return [run(f"S1_random_seed{s}", mb=100, auto=True, seed=s) for s in (1, 2, 3)]


def S2():
    out = []
    for s in (1, 2, 3, 4, 5):
        a = run(f"S2_ckpt_seed{s}", mb=100, auto=True, seed=s, mode="checkpoint", give_up=60, save=(s == 1))
        b = run(f"S2_restart_seed{s}", mb=100, auto=True, seed=s, mode="restart", give_up=60, save=(s == 1))
        out.append({"seed": s, "checkpoint": a, "restart": b})
    summ = {}
    for k in ("checkpoint", "restart"):
        rs = [o[k] for o in out]
        done = [r for r in rs if r["file_identical"] and r["receiver_completion_s"] is not None]
        summ[k] = {"runs": len(rs), "completed": len(done),
                   "median_completion_s": round(statistics.median(r["receiver_completion_s"] for r in done), 2) if done else None,
                   "total_mb_sent": round(sum(r["chunks_sent"] for r in rs) * 65536 / 2**20, 1),
                   "total_mb_resent": round(sum(r["chunks_resent"] for r in rs) * 65536 / 2**20, 1)}
    dump("S2_summary", {"per_seed": [{"seed": o["seed"], **{k: {kk: o[k][kk] for kk in ("sender_ok", "file_identical", "receiver_completion_s", "chunks_sent", "chunks_resent", "outages", "resumes")} for k in ("checkpoint", "restart")}} for o in out], "summary": summ})
    print(json.dumps(summ, indent=1))
    return summ


def S3():
    """Deterministic cut after chunk 1000, N=64 -- the project guide's worked example."""
    return run("S3_cut_at_1000", mb=100, n=64, cuts=[1000], auto=False)


def S3b():
    return run("S3b_two_cuts", mb=100, n=32, cuts=[400, 900, 1300], auto=False)


def S4():
    """Receiver process killed with kill -9 in the middle of a transfer, restarted, and the transfer resumes."""
    d = os.path.join(WORK, "S4")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    src = src_file(60)
    port = 19000 + (os.getpid() % 500)
    py = sys.executable

    def start_rx(tag):
        return subprocess.Popen([py, "-m", "pq6g", "receive", "--listen", f"127.0.0.1:{port}", "--out", d + "/out",
                                 "--state", d + "/rx_state", "--dashboard", "0", "--persist", "--log", d + f"/rx_{tag}.jsonl"],
                                cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    rx1 = start_rx("a")
    time.sleep(1.0)
    tx = subprocess.Popen([py, "-m", "pq6g", "send", src, "--to", f"127.0.0.1:{port}", "--link", "6g-slow", "--no-random-blockage",
                           "--dashboard", "0", "--log", d + "/tx.jsonl", "--give-up", "120", "--n", "32"],
                          cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    t_kill = None
    for _ in range(200):
        time.sleep(0.1)
        try:
            n_ck = sum(1 for e in load_jsonl(d + "/rx_a.jsonl") if e["ev"] == "checkpoint")
        except FileNotFoundError:
            n_ck = 0
        if n_ck >= 4:
            os.kill(rx1.pid, signal.SIGKILL)
            t_kill = time.time()
            break
    rx1.wait()
    killed_at = n_ck
    time.sleep(2.0)                              # the receiver is dead for a while; the sender keeps retrying
    rx2 = start_rx("b")
    out_txt, _ = tx.communicate(timeout=180)
    time.sleep(0.3)
    rx2.terminate()
    rx2.wait()
    out = os.path.join(d, "out", os.path.basename(src))
    a = load_jsonl(d + "/rx_a.jsonl")
    b = load_jsonl(d + "/rx_b.jsonl")
    t = load_jsonl(d + "/tx.jsonl")
    res = {"id": "S4_receiver_kill9", "receiver_killed_after_checkpoints": killed_at, "sender_exit": tx.returncode,
           "file_identical": os.path.exists(out) and sha(out) == sha(src), "sender_output": out_txt.strip().splitlines()[-2:],
           "restored": [e for e in b if e["ev"] == "rx_session_restored"],
           "resume_served": [{k: e.get(k) for k in ("i_star", "o_star", "redo_chunks")} for e in b if e["ev"] == "resume_served"],
           "reconnect_attempts": sum(1 for e in t if e["ev"] == "tx_reconnect_attempt"),
           "key_exchanges_total": sum(1 for e in t if e["ev"] == "kex_done")}
    dump("S4_receiver_kill9", res)
    allev = sorted(a + b + t, key=lambda e: e["ts"])
    with open(os.path.join(EVID, "S4_receiver_kill9.events.jsonl"), "w") as f:
        for e in allev:
            f.write(json.dumps(e, separators=(",", ":")) + "\n")
    print(json.dumps(res, indent=1))
    return res


def S5():
    return run("S5_tamper", mb=30, attack="tamper:300", cuts=[], auto=False)


def S6():
    return run("S6_forged_checkpoint", mb=30, attack="forge", cuts=[200], auto=False)


def S7():
    return run("S7_replayed_checkpoint", mb=30, attack="replay", cuts=[150, 300], auto=False)


def S8():
    from pq6g.toykem import ToyRSAKEM
    from pq6g.quantum import run_attack
    out = {}
    for kem in ("rsa-toy", "mlkem768"):
        cap = os.path.join(WORK, f"S8_{kem}.cap")
        k = ToyRSAKEM(bits=11, seed=1) if kem == "rsa-toy" else None
        r = run(f"S8_record_{kem}", mb=20, auto=False, capture=cap, kem=k, quiet=True)
        od = os.path.join(EVID, f"S8_attack_{kem}")
        shutil.rmtree(od, ignore_errors=True)
        rc = run_attack(cap, src_file(20), bits_hint=11, out_dir=od)
        out[kem] = {"transfer_ok": r["file_identical"], "attack_exit": rc}
    dump("S8_quantum", out)
    return out


def S9():
    rows = []
    for delay in (0.0,):
        for n in (1, 4, 8, 16, 32, 64, 128, 400):
            for s in (1, 2, 3):
                r = run(f"S9_n{n}_s{s}", mb=60, auto=True, seed=s, n=n, ckpt_delay_ms=delay, save=False, quiet=True)
                rows.append({"n": n, "seed": s, "ok": r["file_identical"], "completion_s": r["receiver_completion_s"],
                             "resent": r["chunks_resent"], "checkpoints": r["checkpoints"], "t_ck_ms": r["t_ck_ms_median"],
                             "outages": r["outages"]})
                print(rows[-1], flush=True)
    dump("S9_sweep", rows)
    return rows


ALL = ["S0", "S1", "S2", "S3", "S3b", "S4", "S5", "S6", "S7", "S8", "S9"]
if __name__ == "__main__":
    want = sys.argv[1:] or ["S0"]
    if want == ["all"]:
        want = ALL
    for w in want:
        print(f"\n===== {w} =====", flush=True)
        globals()[w]()
