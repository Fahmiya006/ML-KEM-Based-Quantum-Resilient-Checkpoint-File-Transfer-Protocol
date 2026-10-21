"""Presenter mode: pause the transfer at five points so each stage can be explained, or run it all at once.

The sender calls `guide.point(name)`; the call blocks until the presenter presses the button
(or passes straight through once 'Run everything at once' was pressed).
"""
from __future__ import annotations

import os
import tempfile
import threading
import time

ORDER = ["start", "after_kex", "data_pause", "before_resume", "after_resume"]
TITLES = ["Start sending", "Send the data", "Cut the link", "Resume from the checkpoint", "Finish the transfer",
          "Quantum attack on this transfer", "Quantum attack on old RSA"]
BUTTONS = ["Start: key exchange", "Send the data", "Cut the link now", "Resume from the checkpoint", "Finish the transfer",
           "Attack the recording with a quantum computer", "Repeat with the old RSA key exchange"]
NT = 5                      # transfer steps; the two quantum steps follow
JOBS = ["mlkem", "rsa"]


def _mb(n):
    return f"{n / 1048576:.1f} MB"


class Guide:
    def __init__(self, events, link, name, size, nchunks, n, cut_at, path=None, capture=None, workdir=None):
        self.ev, self.link = events, link
        self.path, self.capture = path, capture
        self.workdir = workdir or tempfile.mkdtemp(prefix="pq6g_q_")
        self.q_jobs: list[dict] = []
        self.q_busy = False
        self._auto_q = False
        self.aborted = False
        self.name, self.size, self.N, self.n, self.cut_at = name, size, nchunks, n, cut_at
        self.cv = threading.Condition()
        self.waiting = None
        self.passed: set[str] = set()
        self.auto = False
        self._scan_i = 0
        self.f = {"ck": None, "delivered": 0, "resume": None, "done": None, "resent": 0}

    # ------------------------------------------------------ called by the sender
    def is_passed(self, name):
        return name in self.passed

    def point(self, name):
        with self.cv:
            if name in self.passed:
                return
            if self.auto:
                if name == "data_pause":
                    self._cut()
                self.passed.add(name)
                return
            self.waiting = name
            while self.waiting == name:
                self.cv.wait(0.2)

    def abort(self):
        """Release a sender that is waiting at a gate (used when the run is thrown away)."""
        with self.cv:
            self.aborted = True
            self.waiting = None
            self.cv.notify_all()

    def _cut(self):
        if self.link is not None:
            self.link.request_blockage("presenter (button)")

    # ------------------------------------------------------ called from the web page
    def next(self):
        with self.cv:
            name = self.waiting
            if name is None:
                if self.f["done"] is not None and not self.q_busy and len(self.q_jobs) < len(JOBS):
                    self._start_job(JOBS[len(self.q_jobs)])
                    return True
                return False
            if name == "data_pause":
                self._cut()
            self.passed.add(name)
            self.waiting = None
            self.cv.notify_all()
            return True

    def run_all(self):
        with self.cv:
            self.auto = True
        self.next()
        return True

    # ------------------------------------------------------ simulated quantum attacker
    def _start_job(self, kind):
        job = {"kind": kind, "lines": [], "running": True, "result": None, "noise": None, "image": None, "image_type": None,
               "title": "Attack on the recording of this transfer (ML-KEM key exchange)" if kind == "mlkem"
               else "Comparison: the same file with the old RSA key exchange (not our protocol)"}
        self.q_jobs.append(job)
        self.q_busy = True
        threading.Thread(target=self._job, args=(job,), daemon=True, name="quantum-" + kind).start()

    def _run_all_quantum(self):
        for k in JOBS[len(self.q_jobs):]:
            while self.q_busy:
                time.sleep(0.2)
            with self.cv:
                self._start_job(k)
        return True

    def _job(self, job):
        from .quantum import attack_capture, parse_capture, _sessions
        try:
            def log(msg):
                job["lines"].append(msg)
                time.sleep(0.45)                 # slow enough to read while presenting
            if job["kind"] == "mlkem":
                if self.link is not None:
                    self.link.flush_capture()
                cap, orig = self.capture, self.path
            else:
                log("Recording the same file again, but this time the key exchange is the old RSA kind (11-bit toy key).")
                cap, orig = self._record_rsa()
                log("Recording finished. The attacker now has it.")
            out = os.path.join(self.workdir, "attack_" + job["kind"])
            rep = attack_capture(cap, orig, out, log=log)
            job["result"] = {k: rep.get(k) for k in ("success", "kem", "identical_to_original", "chunks_decrypted", "chunks_total",
                                                     "chunks_recorded", "guesses", "years_for_2_256", "file_name",
                                                     "wire_entropy_bits_per_byte")}
            sess = _sessions(parse_capture(cap))
            if sess:
                blob = b"".join(sess[0]["data"][i] for i in sorted(sess[0]["data"]))
                job["noise"] = blob[:420 * 150]
            rp = rep.get("recovered_path")
            if rp and os.path.isfile(rp):
                with open(rp, "rb") as f:
                    head = f.read(16)
                typ = ("image/jpeg" if head[:3] == b"\xff\xd8\xff" else "image/png" if head[:4] == b"\x89PNG"
                       else "image/gif" if head[:4] == b"GIF8" else None)
                if typ:
                    job["image"], job["image_type"] = rp, typ
                elif rep.get("banner_png"):
                    job["image"], job["image_type"] = rep["banner_png"], "image/png"
        except Exception as e:                    # keep the demo alive
            job["lines"].append(f"error: {type(e).__name__}: {e}")
        finally:
            job["running"] = False
            self.q_busy = False

    def _record_rsa(self):
        from .config import PROFILES
        from .events import EventLog
        from .link import LinkEmulator
        from .receiver import Receiver
        from .sender import Sender
        from .toykem import ToyRSAKEM
        d = os.path.join(self.workdir, "rsa_run")
        os.makedirs(d, exist_ok=True)
        cap = os.path.join(d, "rsa.cap")
        ev = EventLog(None, role="side")
        rx = Receiver("127.0.0.1", 0, d + "/out", d + "/state", ev.view("receiver")).start()
        link = LinkEmulator(("127.0.0.1", rx.port), PROFILES["ideal"], ev.view("link"), seed=1, auto_blockage=False,
                            capture_path=cap).start()
        tx = Sender(self.path, "127.0.0.1", link.port, ev.view("sender"), kem_obj=ToyRSAKEM(bits=11, seed=1),
                    n=32, window=32, give_up_after=120)
        tx.run()
        link.stop()
        rx.stop()
        return cap, self.path

    def job_noise(self, i):
        return self.q_jobs[i]["noise"] if 0 <= i < len(self.q_jobs) else None

    def job_image(self, i):
        if 0 <= i < len(self.q_jobs) and self.q_jobs[i]["image"]:
            return self.q_jobs[i]["image"], self.q_jobs[i]["image_type"]
        return None

    # ------------------------------------------------------ state for the page
    def _scan(self):
        evs = self.ev.events
        for e in evs[self._scan_i:]:
            k = e["ev"]
            if k == "checkpoint":
                self.f["ck"] = e["i_star"]
            elif k == "chunk_ok":
                self.f["delivered"] = max(self.f["delivered"], e["i"] + 1)
            elif k == "resume_served":
                self.f["resume"] = e
            elif k == "file_verified":
                self.f["done"] = e
            elif k == "send_complete":
                self.f["resent"] = e.get("chunks_resent", 0)
        self._scan_i = len(evs)

    def state(self):
        self._scan()
        f = self.f
        finished = f["done"] is not None
        if finished and self.auto and not self._auto_q:
            self._auto_q = True
            threading.Thread(target=self._run_all_quantum, daemon=True).start()
        nq_done = sum(1 for j in self.q_jobs if not j["running"])
        ck = f["ck"]
        ck_txt = f"chunk {ck}" if ck is not None and ck >= 0 else "none yet"
        r = f["resume"]
        if not finished:
            cur = ORDER.index(self.waiting) if self.waiting in ORDER else -1
            done_count = len(self.passed)
        else:
            done_count = NT + nq_done
            cur = NT + len(self.q_jobs) if (not self.q_busy and len(self.q_jobs) < len(JOBS) and not self._auto_q) else -1
        text = ""
        if finished and self.q_busy:
            text = "The simulated quantum computer is working on the recording. Watch the Quantum attacker box below."
        elif finished and nq_done >= len(JOBS):
            text = ("All done. The transfer survived a cut with a checkpoint, and the recording of it is useless to a quantum "
                    "computer when ML-KEM is used, but readable when the old RSA key exchange is used.")
        elif finished and cur == NT:
            text = (f"File received and verified ({f['resent']} of {self.N} chunks were sent a second time because of the cut). "
                    f"Anyone listening to the beam could have recorded everything. Years from now they have a quantum computer. "
                    f"The button lets the simulated quantum computer attack that recording.")
        elif finished and cur == NT + 1:
            text = ("That was the transfer protected by ML-KEM. Now the same file again with the old RSA key exchange "
                    "(a tiny 11-bit key so a simulation can break it), recorded and attacked the same way.")
        elif finished:
            text = "File received."
        elif cur == 0:
            text = (f"Ready to send {self.name} ({_mb(self.size)}) as {self.N} chunks of 64 KB through the simulated 6G link. "
                    f"Nothing has been sent yet. The button makes the laptop and the phone agree on a secret key (ML-KEM-768).")
        elif cur == 1:
            text = (f"Key exchange finished. Only a public key (1184 bytes) and a ciphertext (1088 bytes) crossed the air. "
                    f"The secret key never did, and a quantum computer cannot work it out from them. "
                    f"Next the data is sent in encrypted chunks, and the receiver saves a signed checkpoint every {self.n} chunks.")
        elif cur == 2:
            text = (f"{f['delivered']} of {self.N} chunks are delivered and verified. "
                    f"The last signed checkpoint on the receiver is at {ck_txt}. "
                    f"The button blocks the beam, like a hand or a wall in the way.")
        elif cur == 3:
            text = (f"The beam was blocked and the connection broke, so neither side can talk. "
                    f"The receiver still holds its checkpoint at {ck_txt}, so nothing it saved is lost. "
                    f"The button reconnects and asks to resume.")
        elif cur == 4 and r:
            text = (f"Resumed from the checkpoint at chunk {r['i_star']}. The sender checked the signature and the hash chain and skipped "
                    f"the key exchange. The receiver had verified up to chunk {r['had_verified_until']}, so {r['redo_chunks']} chunks "
                    f"after the checkpoint are sent again. The button sends the rest.")
        elif cur == 4:
            text = "Resumed from the checkpoint. The button sends the rest."
        else:
            text = "Running..."
        q = [{"title": j["title"], "lines": list(j["lines"]), "running": j["running"], "result": j["result"],
              "has_noise": j["noise"] is not None, "has_image": j["image"] is not None} for j in self.q_jobs]
        return {"steps": TITLES, "current": cur, "done": done_count, "text": text, "auto": self.auto,
                "button": BUTTONS[cur] if cur >= 0 else "", "danger": cur == 2, "finished": finished and nq_done >= len(JOBS),
                "transfer_finished": finished, "quantum": q,
                "running": self.waiting is None and not finished}
