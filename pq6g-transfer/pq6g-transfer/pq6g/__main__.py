"""Command line:  python -m pq6g <command>

  receive   run the receiver (e.g. on the phone)           -> saves the file, keeps signed checkpoints
  send      send a file to a receiver through a simulated 6G link
  demo      sender + 6G link + receiver in one process on this machine, with a live dashboard
  attack    run the simulated quantum computer against a recorded transfer
  makefile  create a test file
  selftest  quick checks of the crypto and protocol
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from . import crypto as C
from .config import CHUNK, DEFAULT_N, DEFAULT_WINDOW, PROFILES
from .events import EventLog


def _hostport(s, default_host="127.0.0.1"):
    if ":" in s:
        h, p = s.rsplit(":", 1)
        return (h or default_host), int(p)
    return default_host, int(s)


def _parse_attack(spec):
    """tamper:40 | forge | replay | drop:30   (comma separated)"""
    a = {}
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        k, _, v = part.partition(":")
        if k == "tamper":
            a["tamper_chunk"] = int(v or 10)
        elif k == "drop":
            a["drop_chunk"] = int(v or 10)
        elif k == "forge":
            a["forge_resume"], a["forge_on"] = True, int(v or 0)
        elif k == "replay":
            a["replay_resume"], a["replay_on"] = True, int(v or 1)
        else:
            raise SystemExit(f"unknown attack {part!r}")
    return a


def _link_args(p):
    p.add_argument("--link", default="6g-demo", choices=list(PROFILES) + ["none"],
                   help="simulated link profile (default 6g-demo); 'none' = plain TCP")
    p.add_argument("--seed", type=int, default=1, help="random seed for blockage times")
    p.add_argument("--lambda", dest="lam", type=float, default=None, help="override blockage rate per second")
    p.add_argument("--no-random-blockage", action="store_true", help="only cut when asked (--cut-after / button)")
    p.add_argument("--cut-after", default="", help="comma list of chunk numbers: cut the link right after each is delivered")
    p.add_argument("--attack", default="", help="active attacker on the link: tamper:40,forge,replay,drop:30")
    p.add_argument("--capture", default=None, help="write everything the eavesdropper hears to this file")
    p.add_argument("--n", type=int, default=DEFAULT_N, help=f"checkpoint every N chunks (default {DEFAULT_N})")
    p.add_argument("--window", type=int, default=DEFAULT_WINDOW)
    p.add_argument("--kem", default="mlkem768", choices=["mlkem768", "mlkem768-pure", "rsa-toy"])
    p.add_argument("--mode", default="checkpoint", choices=["checkpoint", "restart"],
                   help="restart = baseline without checkpoints")
    p.add_argument("--rsa-bits", type=int, default=11)


def _make_link(args, upstream, ev, profile=None):
    from .link import LinkEmulator
    cuts = [int(x) for x in args.cut_after.split(",") if x.strip()]
    return LinkEmulator(upstream, profile or PROFILES[args.link], ev.view("link"), seed=args.seed,
                        capture_path=args.capture, cut_after_chunks=cuts, attack=_parse_attack(args.attack),
                        auto_blockage=not args.no_random_blockage, blockage_rate=args.lam).start()


def _make_kem(args):
    if args.kem == "rsa-toy":
        from .toykem import ToyRSAKEM
        return ToyRSAKEM(bits=args.rsa_bits, seed=args.seed)
    return C.get_kem(args.kem)


def _print_dash(port):
    from .dashboard import lan_ip
    print(f"  dashboard:  http://localhost:{port}      (other devices on this Wi-Fi: http://{lan_ip()}:{port})", flush=True)
    print(f"  phone page: http://{lan_ip()}:{port}/phone   (open this on the phone: it says 'file received' at the end)", flush=True)


def cmd_receive(a):
    from . import dashboard
    from .receiver import Receiver
    ev = EventLog(a.log, role="receiver")
    host, port = _hostport(a.listen, "0.0.0.0")
    rx = Receiver(host, port, a.out, a.state, ev, persist=a.persist, fsync_data=not a.no_fsync_data,
                  ckpt_extra_delay_ms=a.ckpt_delay_ms).start()
    print(f"receiver listening on {host}:{rx.port}   files go to {os.path.abspath(a.out)}", flush=True)
    if a.dashboard:
        dashboard.serve(ev, a.dashboard)
        _print_dash(a.dashboard)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


def cmd_send(a):
    from . import dashboard
    from .sender import Sender
    ev = EventLog(a.log, role="sender")
    host, port = _hostport(a.to)
    link = None
    if a.link != "none":
        link = _make_link(a, (host, port), ev)
        host, port = "127.0.0.1", link.port
    if a.dashboard:
        dashboard.serve(ev, a.dashboard, link=link)
        _print_dash(a.dashboard)
        if a.wait:
            print(f"  open the dashboard, then press Enter to start sending...", flush=True)
            input()
    tx = Sender(a.file, host, port, ev.view("sender"), kem_obj=_make_kem(a), n=a.n, window=a.window,
                mode=a.mode, state_dir=a.state, give_up_after=a.give_up)
    ok = tx.run()
    print(("DONE: file delivered and verified" if ok else "FAILED"),
          f"| chunks sent {tx.chunks_sent} (resent {tx.chunks_resent}), key exchanges {tx.handshakes}, resumes {tx.resumes}",
          flush=True)
    if link:
        print(f"  link: {link.stats['outages']} outages, {link.stats['outage_seconds']:.1f}s lost", flush=True)
    if a.dashboard and a.hold:
        print(f"  dashboard stays up for {a.hold}s (Ctrl-C to quit)", flush=True)
        try:
            time.sleep(a.hold)
        except KeyboardInterrupt:
            pass
    return 0 if ok else 1


def cmd_demo(a):
    import tempfile
    from . import dashboard
    from .receiver import Receiver
    from .sender import Sender
    work = a.workdir or tempfile.mkdtemp(prefix="pq6g_demo_")
    os.makedirs(work, exist_ok=True)
    if a.file is None or a.guided:
        # dashboard-driven mode: pick the file in the browser, then use the Presenter buttons
        from .studio import Studio
        st = Studio(a, work, _make_kem, _make_link)
        srv = dashboard.serve(st.ev, a.dashboard, link=None, guide=None)
        st.attach(srv)
        print("pq6g: secure checkpoint/resume file transfer over a simulated 6G link")
        _print_dash(a.dashboard)
        if a.file:
            st.choose(a.file)
            print(f"  sending {a.file}; use the Presenter box on the dashboard")
        else:
            print("  open the dashboard and choose the file to send (Ctrl-C here to quit)", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        return 0
    ev = EventLog(os.path.join(work, "events.jsonl"), role="app")
    rx = Receiver("127.0.0.1", 0, os.path.join(work, "received"), os.path.join(work, "rx_state"),
                  ev.view("receiver")).start()
    link = None
    host, port = "127.0.0.1", rx.port
    if a.link != "none":
        link = _make_link(a, ("127.0.0.1", rx.port), ev)
        port = link.port
    dashboard.serve(ev, a.dashboard, link=link)
    print(f"demo: sending {a.file} -> simulated {a.link} link -> receiver, all on this machine")
    _print_dash(a.dashboard)
    print("  press Enter once the dashboard is open to start...", flush=True)
    if not a.no_wait:
        input()
    tx = Sender(a.file, host, port, ev.view("sender"), kem_obj=_make_kem(a), n=a.n, window=a.window,
                mode=a.mode, give_up_after=a.give_up)
    ok = tx.run()
    print("DONE" if ok else "FAILED", f"| resent {tx.chunks_resent} chunks, {tx.handshakes} key exchange(s), {tx.resumes} resume(s)")
    print(f"  files and event log: {work}")
    try:
        time.sleep(a.hold)
    except KeyboardInterrupt:
        pass
    return 0 if ok else 1


def cmd_attack(a):
    from .quantum import run_attack
    return run_attack(a.capture, a.original, bits_hint=a.rsa_bits, out_dir=a.out)


def cmd_makefile(a):
    from .testfile import make_test_file
    make_test_file(a.path, a.mb)
    print(f"wrote {a.path} ({os.path.getsize(a.path)/2**20:.1f} MiB)")


def cmd_selftest(a):
    from .selftest import main
    return main()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pq6g", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("receive", help="run the receiver")
    r.add_argument("--listen", default="0.0.0.0:9000")
    r.add_argument("--out", default="received")
    r.add_argument("--state", default="rx_state")
    r.add_argument("--dashboard", type=int, default=8080, help="dashboard port (0 = off)")
    r.add_argument("--persist", action="store_true", help="keep session keys on disk so the receiver can be killed and resume")
    r.add_argument("--no-fsync-data", action="store_true")
    r.add_argument("--ckpt-delay-ms", type=float, default=0.0, help="emulate a slow flash chip (extra ms per checkpoint)")
    r.add_argument("--log", default="receiver_events.jsonl")
    r.set_defaults(fn=cmd_receive)

    s = sub.add_parser("send", help="send a file")
    s.add_argument("file")
    s.add_argument("--to", required=True, help="receiver HOST:PORT")
    _link_args(s)
    s.add_argument("--dashboard", type=int, default=8081, help="dashboard port (0 = off)")
    s.add_argument("--wait", action="store_true", help="wait for Enter before sending (time to open the dashboard)")
    s.add_argument("--hold", type=float, default=0, help="keep dashboard alive N seconds after finishing")
    s.add_argument("--state", default=None, help="folder to remember the session (lets a restarted sender resume)")
    s.add_argument("--give-up", type=float, default=600.0)
    s.add_argument("--log", default="sender_events.jsonl")
    s.set_defaults(fn=cmd_send)

    d = sub.add_parser("demo", help="everything on this machine, with a dashboard")
    d.add_argument("file", nargs="?", default=None, help="file to send (leave out to choose it in the dashboard)")
    _link_args(d)
    d.add_argument("--dashboard", type=int, default=8080)
    d.add_argument("--hold", type=float, default=600)
    d.add_argument("--no-wait", action="store_true")
    d.add_argument("--guided", action="store_true",
                   help="presenter mode: buttons on the dashboard step through key exchange, data, cut, resume, finish (or run it all at once)")
    d.add_argument("--workdir", default=None)
    d.add_argument("--give-up", type=float, default=600.0)
    d.set_defaults(fn=cmd_demo)

    q = sub.add_parser("attack", help="simulated quantum computer vs a recorded transfer")
    q.add_argument("capture")
    q.add_argument("--original", default=None, help="original file, to prove the recovered copy is identical")
    q.add_argument("--rsa-bits", type=int, default=11)
    q.add_argument("--out", default="attack_out")
    q.set_defaults(fn=cmd_attack)

    m = sub.add_parser("makefile", help="make a test file")
    m.add_argument("path")
    m.add_argument("--mb", type=float, default=100)
    m.set_defaults(fn=cmd_makefile)

    t = sub.add_parser("selftest", help="quick self-checks")
    t.set_defaults(fn=cmd_selftest)

    a = ap.parse_args(argv)
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())
