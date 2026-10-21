"""Studio: the dashboard-driven demo.  The person picks a file in the browser; the laptop then builds the receiver,
the simulated 6G link, the presenter and the sender for that file.  'Send another file' tears it all down and starts clean."""
from __future__ import annotations

import dataclasses
import os
import re
import threading
import time

from .config import CHUNK, DEFAULT_N, DEFAULT_WINDOW, PROFILES
from .events import EventLog
from .guide import Guide


def safe_name(name: str) -> str:
    base = os.path.basename(name.replace("\\", "/")) or "file.bin"
    base = re.sub(r"[^A-Za-z0-9._ ()+-]", "_", base).strip(". ") or "file.bin"
    return base[:120]


class Studio:
    def __init__(self, args, work, make_kem, make_link):
        self.a, self.work = args, work
        self.make_kem, self.make_link = make_kem, make_link
        self.lock = threading.Lock()
        self.run_no = 0
        self.ev = self.rx = self.link = self.guide = self.tx = None
        self.srv = None
        self.file = None
        self.size = 0
        self.uploads = os.path.join(work, "uploads")
        os.makedirs(self.uploads, exist_ok=True)
        self._new_log()

    # -------------------------------------------------------------- run lifecycle
    def _new_log(self):
        self.run_no += 1
        d = os.path.join(self.work, f"run{self.run_no}")
        os.makedirs(d, exist_ok=True)
        self.rundir = d
        self.ev = EventLog(os.path.join(d, "events.jsonl"), role="app")
        self.ev.emit("run_start", run=self.run_no)
        if self.srv is not None:
            self.srv.events, self.srv.link, self.srv.guide = self.ev, None, None
        self.file, self.size = None, 0

    def attach(self, srv):
        self.srv = srv
        srv.events = self.ev
        srv.studio = self

    def info(self):
        return {"run": self.run_no, "file": os.path.basename(self.file) if self.file else None, "size": self.size}

    def reset(self):
        with self.lock:
            if self.tx is not None:
                self.tx.stop_flag.set()
            if self.guide is not None:
                self.guide.abort()
            for o in (self.link, self.rx):
                try:
                    if o is not None:
                        o.stop()
                except Exception:
                    pass
            self.link = self.rx = self.guide = self.tx = None
            self._new_log()
        return self.info()

    def save_upload(self, name, rfile, length):
        d = os.path.join(self.uploads, str(int(time.time() * 1000)))
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, safe_name(name))
        left = length
        with open(path, "wb") as f:
            while left > 0:
                b = rfile.read(min(1 << 20, left))
                if not b:
                    break
                f.write(b)
                left -= len(b)
        return path

    def choose(self, path):
        from .receiver import Receiver
        from .sender import Sender
        a = self.a
        with self.lock:
            if self.file is not None:
                return False
            self.file = path
            self.size = os.path.getsize(path)
            size = self.size
            nch = max(1, -(-size // CHUNK))
            n = a.n if a.n != DEFAULT_N else max(2, min(32, nch // 8))
            window = a.window if a.window != DEFAULT_WINDOW else 8
            cut_at = max(n + 1, int(nch * 0.55))
            if cut_at % n == 0:
                cut_at += max(1, n // 2)
            cut_at = min(cut_at, max(1, nch - 2))
            base = PROFILES[a.link if a.link != "none" else "6g-demo"]
            rate = min(base.rate_mbps, max(2.0, round(size * 8 / 1e6 / 8.0, 1)))
            prof = dataclasses.replace(base, rate_mbps=rate, desc=base.desc + f" (slowed to {rate} Mb/s for the presenter)")
            d = self.rundir
            self.rx = Receiver("127.0.0.1", 0, os.path.join(d, "received"), os.path.join(d, "rx_state"),
                               self.ev.view("receiver")).start()
            cap = os.path.join(d, "capture_main.cap")
            a2 = argparse_copy(a, no_random_blockage=True, cut_after="", capture=cap, seed=a.seed)
            self.link = self.make_link(a2, ("127.0.0.1", self.rx.port), self.ev, profile=prof)
            self.guide = Guide(self.ev, self.link, os.path.basename(path), size, nch, n, cut_at, path=path, capture=cap, workdir=d)
            self.tx = Sender(path, "127.0.0.1", self.link.port, self.ev.view("sender"), kem_obj=self.make_kem(a),
                             n=n, window=window, mode=a.mode, give_up_after=max(a.give_up, 6 * 3600), gate=self.guide)
            self.srv.link, self.srv.guide = self.link, self.guide
            tx, guide = self.tx, self.guide

            def go():
                guide.point("start")
                if not tx.stop_flag.is_set():
                    tx.run()
            threading.Thread(target=go, daemon=True, name="studio-send").start()
            print(f"  file chosen: {os.path.basename(path)} ({size / 1048576:.1f} MB, {nch} chunks), checkpoint every {n}, "
                  f"link will be cut after chunk {cut_at}, link slowed to {rate} Mb/s", flush=True)
        return True

    def sample(self, mb=20):
        from .testfile import make_test_file
        d = os.path.join(self.uploads, str(int(time.time() * 1000)))
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"sample_{mb}MB.bin")
        make_test_file(path, mb)
        return self.choose(path)


def argparse_copy(a, **over):
    import argparse
    d = dict(vars(a))
    d.update(over)
    return argparse.Namespace(**d)
