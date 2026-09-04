#!/usr/bin/env python3
"""
Command-line interface.

    # terminal 1 -- receiver
    python3 -m pqcft.cli recv --port 9000 --out ./received

    # terminal 2 -- sender
    python3 -m pqcft.cli send bigfile.iso --host 127.0.0.1 --port 9000

    # self-contained demo: receiver + 6G channel + sender in one process
    python3 -m pqcft.cli demo --size 16 --disruptions 3 --duration 0.8
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile

from .channel import ChannelProfile, SimulatedChannel
from .client import Sender
from .crypto import file_sha256
from .metrics import TransferMetrics
from .server import Receiver


def _report(m: TransferMetrics) -> None:
    print("\n" + "=" * 58)
    print(f"  {'completed':<28} {m.completed}")
    print(f"  {'integrity verified':<28} {m.integrity_ok}")
    print(f"  {'scheme':<28} {m.scheme}")
    print(f"  {'checkpointing':<28} {m.checkpointing}")
    print(f"  {'file size':<28} {m.file_size/1e6:.2f} MB in {m.total_chunks} chunks")
    print(f"  {'total time':<28} {m.total_time_s:.2f} s")
    print(f"  {'goodput':<28} {m.goodput_mbps:.2f} Mbps")
    print(f"  {'connection attempts':<28} {m.attempts}")
    print(f"  {'disruptions survived':<28} {len(m.recovery_times_s)}")
    if m.recovery_times_s:
        print(f"  {'mean / max recovery':<28} "
              f"{m.mean_recovery_s:.2f} s / {m.max_recovery_s:.2f} s")
        print(f"  {'resumed from chunks':<28} {m.resumed_from_chunks}")
    print(f"  {'payload pushed':<28} {m.payload_bytes_sent/1e6:.2f} MB")
    print(f"  {'retransmission overhead':<28} {m.retransmission_overhead_pct:.2f}%")
    print(f"  {'bandwidth wasted':<28} {m.wasted_bytes/1e6:.2f} MB")
    print(f"  {'KEM handshake wire':<28} {m.kex_wire_bytes} B "
          f"over {m.attempts} handshake(s)")
    print(f"  {'KEM CPU (initiator)':<28} {m.kex_cpu_ms:.2f} ms")
    print(f"  {'checkpoint writes':<28} {m.checkpoint_writes} "
          f"({m.checkpoint_overhead_ms:.1f} ms total)")
    print("=" * 58)


def cmd_recv(a) -> int:
    rx = Receiver(out_dir=a.out, state_dir=a.state,
                  checkpointing=not a.no_checkpoint,
                  checkpoint_interval=a.interval, port=a.port).start()
    print(f"receiver listening on 127.0.0.1:{rx.port} -> {a.out}")
    print("checkpointing:", not a.no_checkpoint, "| Ctrl-C to stop")
    try:
        while True:
            import time
            time.sleep(0.5)
    except KeyboardInterrupt:
        rx.stop()
    return 0


def cmd_send(a) -> int:
    s = Sender(a.path, (a.host, a.port), scheme=a.scheme, chunk_size=a.chunk_size,
               checkpointing=not a.no_checkpoint, checkpoint_interval=a.interval,
               state_dir=a.state)
    m = s.run()
    _report(m)
    return 0 if m.completed and m.integrity_ok else 1


def cmd_demo(a) -> int:
    d = tempfile.mkdtemp(prefix="pqcft-demo-")
    try:
        src = os.path.join(d, "payload.bin")
        size = int(a.size * 1024 * 1024)
        with open(src, "wb") as f:
            left = size
            while left:
                n = min(left, 1 << 20)
                f.write(os.urandom(n))
                left -= n
        want = file_sha256(src)

        rx = Receiver(out_dir=os.path.join(d, "out"), state_dir=os.path.join(d, "rx"),
                      checkpointing=not a.no_checkpoint,
                      checkpoint_interval=a.interval).start()
        prof = ChannelProfile.with_disruptions(
            count=a.disruptions, duration_s=a.duration, first_at_s=0.4,
            spacing_s=1.2 + a.duration, latency_ms=a.latency,
            jitter_ms=a.jitter, bandwidth_mbps=a.bandwidth,
        )
        ch = SimulatedChannel(("127.0.0.1", rx.port), prof).start()
        print(f"channel: {prof.describe()}")
        print(f"source:  {size/1e6:.1f} MB, sha256 {want[:16]}...")

        m = Sender(src, ("127.0.0.1", ch.port), scheme=a.scheme,
                   chunk_size=a.chunk_size, checkpointing=not a.no_checkpoint,
                   checkpoint_interval=a.interval,
                   state_dir=os.path.join(d, "tx")).run()
        ch.stop()
        rx.stop()

        out = os.path.join(d, "out", "payload.bin")
        got = file_sha256(out) if os.path.exists(out) else "<missing>"
        _report(m)
        match = got == want
        print(f"  sha256 match: {match}  ({got[:16]}...)")
        return 0 if match else 1
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pqcft", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--scheme", choices=["mlkem", "x25519"], default="mlkem")
        p.add_argument("--chunk-size", type=int, default=64 * 1024)
        p.add_argument("--interval", type=int, default=8,
                       help="checkpoint every N verified chunks")
        p.add_argument("--no-checkpoint", action="store_true",
                       help="disable checkpoint/resume (baseline behaviour)")
        p.add_argument("--state", default="./state")

    r = sub.add_parser("recv", help="run the receiver")
    r.add_argument("--port", type=int, default=0)
    r.add_argument("--out", default="./received")
    common(r)
    r.set_defaults(fn=cmd_recv)

    s = sub.add_parser("send", help="send a file")
    s.add_argument("path")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, required=True)
    common(s)
    s.set_defaults(fn=cmd_send)

    d = sub.add_parser("demo", help="receiver + simulated 6G channel + sender")
    d.add_argument("--size", type=float, default=8, help="payload size in MB")
    d.add_argument("--disruptions", type=int, default=2)
    d.add_argument("--duration", type=float, default=0.5, help="outage seconds")
    d.add_argument("--latency", type=float, default=4.0)
    d.add_argument("--jitter", type=float, default=1.5)
    d.add_argument("--bandwidth", type=float, default=200.0)
    common(d)
    d.set_defaults(fn=cmd_demo)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
