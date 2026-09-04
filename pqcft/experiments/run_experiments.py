#!/usr/bin/env python3
"""
Experiment orchestrator (Weeks 4 and 8 of the plan).

Runs four arms over identical, seed-reproducible channel conditions:

    baseline-tls    x25519-ECDHE + AES-256-GCM, no checkpointing   (Week 4)
    pq-nockpt       ML-KEM-768  + AES-256-GCM, no checkpointing    (isolates KEM cost)
    classical-ckpt  x25519-ECDHE + AES-256-GCM, checkpoint/resume  (isolates checkpoint gain)
    proposed        ML-KEM-768  + AES-256-GCM, checkpoint/resume   (Week 5-7)

The 2x2 factorial matters: with only baseline-vs-proposed you cannot tell whether
a difference came from the KEM or from the checkpointing. The two middle arms
separate those effects.

Usage:
    python3 experiments/run_experiments.py --quick
    python3 experiments/run_experiments.py --repeats 3 --out results/results.csv
"""

from __future__ import annotations

import argparse
import csv
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqcft.channel import ChannelProfile, SimulatedChannel
from pqcft.client import Sender
from pqcft.crypto import file_sha256
from pqcft.metrics import FIELDNAMES, TransferMetrics
from pqcft.server import Receiver

ARMS = {
    "baseline-tls":   dict(scheme="x25519", checkpointing=False),
    "pq-nockpt":      dict(scheme="mlkem",  checkpointing=False),
    "classical-ckpt": dict(scheme="x25519", checkpointing=True),
    "proposed":       dict(scheme="mlkem",  checkpointing=True),
}


def make_file(path: str, size: int) -> str:
    with open(path, "wb") as f:
        remaining = size
        while remaining:
            n = min(remaining, 1 << 20)
            f.write(os.urandom(n))
            remaining -= n
    return file_sha256(path)


def run_one(src, src_hash, arm, profile, chunk_size, ckpt_interval, workdir) -> TransferMetrics:
    run_dir = tempfile.mkdtemp(dir=workdir)
    rx = Receiver(
        out_dir=os.path.join(run_dir, "out"),
        state_dir=os.path.join(run_dir, "rx"),
        checkpointing=ARMS[arm]["checkpointing"],
        checkpoint_interval=ckpt_interval,
    ).start()
    ch = SimulatedChannel(("127.0.0.1", rx.port), profile).start()
    try:
        sender = Sender(
            src,
            ("127.0.0.1", ch.port),
            scheme=ARMS[arm]["scheme"],
            chunk_size=chunk_size,
            checkpointing=ARMS[arm]["checkpointing"],
            checkpoint_interval=ckpt_interval,
            state_dir=os.path.join(run_dir, "tx"),
        )
        m = TransferMetrics(
            channel=profile.name,
            disruptions_configured=len(profile.disruptions),
            disruption_duration_s=(
                profile.disruptions[0].duration_s if profile.disruptions else 0.0
            ),
        )
        m = sender.run(m)
        m.protocol = arm
        m.checkpoint_writes = max(m.checkpoint_writes, rx.stats.checkpoint_writes)

        # Verify against the source independently of what the sender believes.
        out = os.path.join(run_dir, "out", os.path.basename(src))
        delivered = os.path.exists(out) and file_sha256(out) == src_hash
        m.integrity_ok = delivered
        # "Did not finish in budget" and "finished but corrupted" are different
        # outcomes and must not be collapsed. A corrupted delivery is a bug; a
        # non-completion under heavy disruption is a result.
        if m.completed and not delivered:
            m.corrupted = True
        return m
    finally:
        ch.stop()
        rx.stop()
        shutil.rmtree(run_dir, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/results.csv")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--chunk-size", type=int, default=64 * 1024)
    ap.add_argument("--ckpt-interval", type=int, default=8)
    ap.add_argument("--quick", action="store_true", help="small matrix, ~1 min")
    args = ap.parse_args()

    if args.quick:
        file_sizes = [4 * 1024 * 1024]
        disruption_counts = [0, 2]
        durations = [0.5]
        args.repeats = min(args.repeats, 2)
    else:
        file_sizes = [4 * 1024 * 1024, 16 * 1024 * 1024]
        disruption_counts = [0, 1, 2, 4]
        durations = [0.3, 1.0]

    workdir = tempfile.mkdtemp(prefix="pqcft-exp-")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)

    rows, t0 = [], time.perf_counter()
    files = {}
    for size in file_sizes:
        p = os.path.join(workdir, f"payload-{size}.bin")
        files[size] = (p, make_file(p, size))

    total = (len(file_sizes) * len(ARMS) * args.repeats *
             (1 + (len(disruption_counts) - 1) * len(durations)))
    done = 0

    for size in file_sizes:
        src, src_hash = files[size]
        for count in disruption_counts:
            for duration in (durations if count else [0.0]):
                for arm in ARMS:
                    for rep in range(args.repeats):
                        profile = ChannelProfile.with_disruptions(
                            count=count,
                            duration_s=duration,
                            first_at_s=0.4,
                            spacing_s=1.2 + duration,
                            name=f"6g-d{count}x{duration}s",
                            seed=1000 + rep,
                        )
                        m = run_one(src, src_hash, arm, profile,
                                    args.chunk_size, args.ckpt_interval, workdir)
                        row = m.to_row()
                        row["repeat"] = rep
                        rows.append(row)
                        done += 1
                        if m.completed and m.integrity_ok:
                            flag = "ok"
                        elif m.completed:
                            flag = "CORRUPT"
                        else:
                            flag = "no-finish"
                        print(
                            f"[{done:3d}/{total}] {arm:15s} {size>>20:3d}MB "
                            f"d={count}x{duration}s  "
                            f"t={m.total_time_s:6.2f}s  "
                            f"gp={m.goodput_mbps:6.2f}Mbps  "
                            f"rtx={m.retransmission_overhead_pct:7.2f}%  "
                            f"rec={m.mean_recovery_s:5.2f}s  {flag}",
                            flush=True,
                        )

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES + ["repeat"])
        w.writeheader()
        w.writerows(rows)

    shutil.rmtree(workdir, ignore_errors=True)
    corrupt = sum(1 for r in rows if r["completed"] and not r["integrity_ok"])
    unfinished = sum(1 for r in rows if not r["completed"])
    print(f"\n{len(rows)} runs in {time.perf_counter()-t0:.1f}s -> {args.out}")
    print(f"corrupted deliveries (BUG if >0): {corrupt}")
    print(f"did not finish in budget (a result, not a bug): {unfinished}")
    return 1 if corrupt else 0


if __name__ == "__main__":
    raise SystemExit(main())
