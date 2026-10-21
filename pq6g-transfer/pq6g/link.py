"""Simulated 6G link: a TCP relay between sender and receiver.

What it imposes on the traffic that passes through it
  * rate R       - frames are serialised at R bits/s (full duplex)
  * delay        - RTT/2 propagation in each direction
  * blockages    - Poisson process with rate lambda (counted over "link up" time).
                   A blockage first black-holes all traffic for T_d (detection
                   delay: the endpoints still think the link is alive), then
                   aborts every connection (TCP reset), then refuses new
                   connections for T_r (reconnection delay) before the link is up
                   again.  Total outage = T_d + T_r.
  * manual cuts  - "cut after chunk X is delivered" triggers, or via the dashboard
It also plays two attacker roles
  * passive eavesdropper: every frame that enters the link is written to a
    capture file (what a harvest-now-decrypt-later adversary would record)
  * optional active man-in-the-middle: flip a bit in a chunk, drop a chunk,
    forge or replay a checkpoint
"""
from __future__ import annotations

import queue
import random
import socket
import struct
import threading
import time

from . import wire as W
from .config import LinkProfile

CAPTURE_REC = struct.Struct(">dBI")     # timestamp, direction (0 = sender->receiver, 1 = back), frame length


def _abort(sock):
    """Close with RST so the peer sees a connection reset (what a dead radio link looks like)."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.shutdown(socket.SHUT_RDWR)       # wakes any thread blocked in recv() on this socket
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class _Conn:
    def __init__(self, cs, us):
        self.cs, self.us = cs, us
        self.closed = False
        self.q = {"up": queue.Queue(maxsize=512), "down": queue.Queue(maxsize=512)}
        self.lock = threading.Lock()

    def abort(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
        _abort(self.cs)
        _abort(self.us)
        for q in self.q.values():
            try:
                q.put_nowait(None)
            except queue.Full:
                pass


class LinkEmulator:
    def __init__(self, upstream, profile: LinkProfile, events, listen=("127.0.0.1", 0), seed=1,
                 capture_path=None, cut_after_chunks=(), attack=None, auto_blockage=True,
                 blockage_rate=None):
        self.upstream = upstream
        self.p = profile
        self.ev = events
        self.listen_addr = listen
        self.rng = random.Random(seed)
        self.rate_bps = profile.rate_mbps * 1e6
        self.one_way = profile.rtt_ms / 2000.0
        self.lam = profile.blockage_rate if blockage_rate is None else blockage_rate
        self.auto = auto_blockage
        self.cut_triggers = set(cut_after_chunks)
        self.attack = dict(attack or {})
        self.state = "UP"                    # UP | BLOCKED | DOWN
        self.lock = threading.RLock()
        self.conns: list[_Conn] = []
        self.free = {"up": 0.0, "down": 0.0}
        self.armed = False                   # blockage clock starts with the first data chunk
        self.finished = False
        self._stop = threading.Event()
        self.stats = {"bytes_up": 0, "bytes_down": 0, "frames_dropped": 0, "outages": 0,
                      "outage_seconds": 0.0, "bytes_offered_up": 0}
        self._tp = {"up": 0, "down": 0}
        self._cap = open(capture_path, "wb") if capture_path else None
        self._cap_lock = threading.Lock()
        self._resp_seen: list[bytes] = []    # genuine RESUME_RESP frames seen (for the replay attack)
        self._tamper_next = bool(self.attack.get("tamper_next"))
        self.port = None

    # ----------------------------------------------------------- lifecycle
    def start(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(self.listen_addr)
        self._srv.listen(16)
        self.port = self._srv.getsockname()[1]
        self.ev.emit("link_start", src="link", profile=self.p.name, rate_mbps=self.p.rate_mbps,
                     rtt_ms=self.p.rtt_ms, t_detect=self.p.t_detect, t_reconnect=self.p.t_reconnect,
                     blockage_rate=self.lam, listen_port=self.port, upstream=f"{self.upstream[0]}:{self.upstream[1]}")
        threading.Thread(target=self._accept_loop, daemon=True, name="link-accept").start()
        threading.Thread(target=self._scheduler, daemon=True, name="link-sched").start()
        threading.Thread(target=self._sampler, daemon=True, name="link-tp").start()
        return self

    def flush_capture(self):
        if self._cap:
            try:
                self._cap.flush()
            except (OSError, ValueError):
                pass

    def stop(self):
        self._stop.set()
        try:
            self._srv.close()
        except OSError:
            pass
        for c in list(self.conns):
            c.abort()
        if self._cap:
            self._cap.close()
            self._cap = None

    # -------------------------------------------------------------- accept
    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                cs, _ = self._srv.accept()
            except OSError:
                return
            if self.state != "UP":
                self.ev.emit("link_refused", src="link", state=self.state)
                _abort(cs)
                continue
            try:
                us = socket.create_connection(self.upstream, timeout=1.5)
            except OSError as e:
                self.ev.emit("link_upstream_down", src="link", reason=str(e)[:60])
                _abort(cs)
                continue
            us.settimeout(None)       # the connect timeout must not stay on the socket, or an idle link (presenter pause) would be closed
            W.tune(cs)
            W.tune(us)
            conn = _Conn(cs, us)
            with self.lock:
                self.conns.append(conn)
            self.ev.emit("link_conn_open", src="link")
            for d, a, b in (("up", cs, us), ("down", us, cs)):
                threading.Thread(target=self._pump, args=(conn, a, b, d), daemon=True).start()
                threading.Thread(target=self._deliver, args=(conn, b, d), daemon=True).start()

    # ---------------------------------------------------------------- pump
    def _tap(self, d, raw):
        if self._cap:
            with self._cap_lock:
                self._cap.write(CAPTURE_REC.pack(time.time(), 0 if d == "up" else 1, len(raw)) + raw)

    def _pump(self, conn, src, dst, d):
        rd = W.FrameReader(src)
        try:
            while not conn.closed and not self._stop.is_set():
                t, payload, raw = rd.read_raw()
                self._tap(d, raw)                         # eavesdropper hears everything on the air
                if d == "up":
                    self.stats["bytes_offered_up"] += len(raw)
                    if t == W.T_DATA and not self.armed:
                        self.armed = True
                raw = self._attack(d, t, payload, raw)
                if raw is None:
                    continue
                with self.lock:
                    if self.state != "UP":
                        self.stats["frames_dropped"] += 1
                        continue
                    now = time.monotonic()
                    start = max(now, self.free[d])
                    self.free[d] = start + len(raw) * 8.0 / self.rate_bps
                    due = self.free[d] + self.one_way
                conn.q[d].put((due, raw, t))
        except (ConnectionError, OSError, W.ProtocolError):
            pass
        finally:
            conn.abort() if (self.state != "UP" or self._stop.is_set()) else self._close_soft(conn)

    def _close_soft(self, conn):
        """Peer closed normally: let queued frames drain, then close both sides."""
        def later():
            time.sleep(self.one_way + 0.05)
            conn.abort()
        threading.Thread(target=later, daemon=True).start()

    def _deliver(self, conn, dst, d):
        q = conn.q[d]
        while True:
            item = q.get()
            if item is None:
                return
            due, raw, t = item
            delay = due - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            with self.lock:
                if self.state != "UP" or conn.closed:
                    self.stats["frames_dropped"] += 1
                    continue
            try:
                dst.sendall(raw)
            except OSError:
                conn.abort()
                return
            n = len(raw)
            self.stats["bytes_" + d] += n
            self._tp[d] += n
            if t == W.T_FIN_OK and d == "down":
                self.finished = True
            if d == "up" and t == W.T_DATA and self.cut_triggers:
                idx = int.from_bytes(raw[W.HDR.size + 4:W.HDR.size + 12], "big")
                if idx in self.cut_triggers:
                    self.cut_triggers.discard(idx)
                    self.request_blockage(f"cut_after_chunk_{idx}")

    # ------------------------------------------------------------- attacker
    def arm_tamper(self):
        self._tamper_next = True

    def _attack(self, d, t, payload, raw):
        a = self.attack
        if d == "up" and t == W.T_DATA:
            idx = int.from_bytes(payload[4:12], "big")
            if self._tamper_next or a.get("tamper_chunk") == idx:
                self._tamper_next = False
                a.pop("tamper_chunk", None)
                b = bytearray(raw)
                b[W.HDR.size + 12 + 3] ^= 0x01            # one flipped bit inside the ciphertext
                self.ev.emit("attack_tamper", src="attacker", chunk=idx, what="flipped 1 bit of the ciphertext in flight")
                return bytes(b)
            if a.get("drop_chunk") == idx:
                a.pop("drop_chunk")
                self.ev.emit("attack_drop", src="attacker", chunk=idx, what="dropped the frame")
                return None
        if d == "down" and t == W.T_RESUME_RESP:
            genuine = raw
            nth = len(self._resp_seen)
            self._resp_seen.append(genuine)
            if a.get("forge_resume") and nth == a.get("forge_on", 0):
                forged = bytearray(payload)
                forged[4:12] = (10 ** 9).to_bytes(8, "big")      # "I already have a huge amount"
                self.ev.emit("attack_forge", src="attacker",
                             what="replaced the checkpoint with a forged one (claims huge progress; attacker has no K_ck so MAC is wrong)")
                return W.pack(W.T_RESUME_RESP, bytes(forged))
            if a.get("replay_resume") and nth == a.get("replay_on", 1) and self._resp_seen:
                self.ev.emit("attack_replay", src="attacker",
                             what="replaced the checkpoint with an OLD genuine one captured earlier")
                return self._resp_seen[0]
        return raw

    # ------------------------------------------------------------ blockages
    def request_blockage(self, reason, t_detect=None, t_reconnect=None) -> bool:
        with self.lock:
            if self.state != "UP":
                return False
            self.state = "BLOCKED"            # synchronous: frames after this point are lost
        threading.Thread(target=self._outage, args=(reason, t_detect, t_reconnect), daemon=True).start()
        return True

    def _outage(self, reason, t_detect, t_reconnect):
        td = self.p.t_detect if t_detect is None else t_detect
        tr = self.p.t_reconnect if t_reconnect is None else t_reconnect
        t0 = time.time()
        self.stats["outages"] += 1
        self.ev.emit("link_blockage", src="link", reason=reason, t_detect=td, t_reconnect=tr,
                     n=self.stats["outages"])
        time.sleep(td)                                   # endpoints do not know yet: traffic is black-holed
        with self.lock:
            conns, self.conns = list(self.conns), []
            self.state = "DOWN"
        for c in conns:
            c.abort()
        self.ev.emit("link_down", src="link", conns_cut=len(conns))
        time.sleep(tr)
        with self.lock:
            self.free = {"up": 0.0, "down": 0.0}
            self.state = "UP"
        dur = time.time() - t0
        self.stats["outage_seconds"] += dur
        self.ev.emit("link_up", src="link", outage_s=round(dur, 3))

    def _scheduler(self):
        """Poisson blockages, counted over the time the link is up and carrying data."""
        while not self._stop.is_set():
            if not self.auto or self.lam <= 0:
                time.sleep(0.1)
                continue
            gap, waited = self.rng.expovariate(self.lam), 0.0
            while waited < gap and not self._stop.is_set():
                time.sleep(0.01)
                if self.armed and self.state == "UP" and not self.finished:
                    waited += 0.01
            if self._stop.is_set() or self.finished:
                return
            self.request_blockage("random (Poisson)")

    def _sampler(self):
        """10 Hz throughput samples: what actually crossed the link (the evidence plot)."""
        while not self._stop.is_set():
            time.sleep(0.1)
            if self.armed and not self.finished:
                up, dn = self._tp["up"], self._tp["down"]
                self._tp["up"] = self._tp["down"] = 0
                self.ev.emit("link_tp", src="link", up=up, down=dn, state=self.state)
