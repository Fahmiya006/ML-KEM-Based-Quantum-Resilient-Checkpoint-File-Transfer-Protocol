"""
Simulated 6G channel.

Implemented as a userspace TCP relay that sits between client and server and
applies the impairments that matter for this study:

    * one-way latency with Gaussian jitter (mobility-driven RTT variation)
    * a bandwidth ceiling (THz link capacity)
    * disruption events (THz blockage / handover gaps) that tear the connection
      down and refuse new connections for the duration of the outage

Why a relay instead of `tc`/`netem`: netem needs CAP_NET_ADMIN and a real
interface, which makes the experiment un-runnable in CI/containers and on
laptops. The relay reproduces the same impairment knobs portably and, crucially,
gives exact control over *when* a disruption starts and stops so that baseline
and proposed runs see byte-for-byte identical outage patterns. `scripts/netem.sh`
is provided for validating against real kernel-level netem where root is
available.

Note on packet loss: this relay is TCP-to-TCP, so kernel retransmission already
hides sub-connection loss. Loss is therefore modelled through its two observable
effects at the file-transfer layer -- reduced goodput (bandwidth cap) and
connection death (disruption) -- rather than by corrupting the byte stream,
which would be physically meaningless above TCP.
"""

from __future__ import annotations

import random
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class DisruptionEvent:
    start_s: float
    duration_s: float
    kind: str = "blockage"  # "blockage" | "handover"

    def active_at(self, t: float) -> bool:
        return self.start_s <= t < self.start_s + self.duration_s


@dataclass
class ChannelProfile:
    """Configurable 6G channel conditions."""

    name: str = "6g-urban"
    latency_ms: float = 4.0            # one-way base latency
    jitter_ms: float = 1.5             # std-dev of per-write jitter
    bandwidth_mbps: float = 200.0      # link ceiling
    disruptions: List[DisruptionEvent] = field(default_factory=list)
    seed: int = 1234
    # Socket buffer ceiling. Left unbounded, loopback buffers hold megabytes of
    # data the sender believes is "in flight", so a disruption appears to
    # destroy far more bytes than a real radio link ever would. Capping the
    # buffers near the bandwidth-delay product keeps in-flight loss physical.
    sockbuf_bytes: int = 128 * 1024

    @property
    def bdp_bytes(self) -> float:
        """Bandwidth-delay product for the configured link."""
        rtt_s = 2 * self.latency_ms / 1e3
        return self.bandwidth_mbps * 1e6 * rtt_s / 8

    @staticmethod
    def with_disruptions(
        count: int,
        duration_s: float,
        first_at_s: float = 1.0,
        spacing_s: float = 2.0,
        kind: str = "blockage",
        **kw,
    ) -> "ChannelProfile":
        events = [
            DisruptionEvent(first_at_s + i * spacing_s, duration_s, kind)
            for i in range(count)
        ]
        return ChannelProfile(disruptions=events, **kw)

    def describe(self) -> str:
        return (
            f"{self.name}: {self.latency_ms}ms±{self.jitter_ms}ms, "
            f"{self.bandwidth_mbps}Mbps, {len(self.disruptions)} disruption(s)"
        )


class SimulatedChannel:
    """
    Listens on (host, 0) and relays to `upstream`. Start it, read `.port`, and
    point the client at that port.
    """

    def __init__(self, upstream: Tuple[str, int], profile: ChannelProfile):
        self.upstream = upstream
        self.profile = profile
        self.rng = random.Random(profile.seed)
        self._lock = threading.Lock()
        self._listener: Optional[socket.socket] = None
        self._running = False
        self._t0 = 0.0
        self._threads: List[threading.Thread] = []
        self.port = 0
        # telemetry
        self.bytes_relayed = 0
        self.connections_killed = 0
        self.connections_refused = 0

    # -- lifecycle ---------------------------------------------------------- #
    def start(self) -> "SimulatedChannel":
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tune(self._listener)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._running = True
        self._t0 = time.perf_counter()
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        self._threads.append(t)
        return self

    def stop(self) -> None:
        self._running = False
        if self._listener:
            try:
                self._listener.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=1.0)

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.stop()

    def _tune(self, sock: socket.socket) -> None:
        n = self.profile.sockbuf_bytes
        if n <= 0:
            return
        for opt in (socket.SO_SNDBUF, socket.SO_RCVBUF):
            try:
                sock.setsockopt(socket.SOL_SOCKET, opt, n)
            except OSError:
                pass

    # -- channel state ------------------------------------------------------ #
    def elapsed(self) -> float:
        return time.perf_counter() - self._t0

    def in_disruption(self) -> Optional[DisruptionEvent]:
        t = self.elapsed()
        for ev in self.profile.disruptions:
            if ev.active_at(t):
                return ev
        return None

    def _delay(self, nbytes: int) -> float:
        base = self.profile.latency_ms / 1e3
        jitter = abs(self.rng.gauss(0, self.profile.jitter_ms / 1e3))
        serialize = (nbytes * 8) / (self.profile.bandwidth_mbps * 1e6)
        return base + jitter + serialize

    # -- relay -------------------------------------------------------------- #
    def _accept_loop(self) -> None:
        while self._running:
            try:
                client, _ = self._listener.accept()
            except (socket.timeout, OSError):
                continue

            if self.in_disruption():
                # Link is down: the connection attempt does not reach the cell.
                with self._lock:
                    self.connections_refused += 1
                try:
                    client.close()
                except OSError:
                    pass
                continue

            t = threading.Thread(target=self._handle, args=(client,), daemon=True)
            t.start()
            self._threads.append(t)

    def _handle(self, client: socket.socket) -> None:
        self._tune(client)
        try:
            server = socket.create_connection(self.upstream, timeout=5)
            self._tune(server)
        except OSError:
            client.close()
            return

        stop = threading.Event()
        pumps = [
            threading.Thread(target=self._pump, args=(client, server, stop), daemon=True),
            threading.Thread(target=self._pump, args=(server, client, stop), daemon=True),
        ]
        for p in pumps:
            p.start()

        # Watchdog: kill the connection the instant a disruption begins.
        while not stop.is_set() and self._running:
            if self.in_disruption():
                with self._lock:
                    self.connections_killed += 1
                stop.set()
                break
            time.sleep(0.01)

        stop.set()
        for s in (client, server):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def _pump(self, src: socket.socket, dst: socket.socket, stop: threading.Event) -> None:
        src.settimeout(0.2)
        while not stop.is_set():
            try:
                data = src.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            if self.in_disruption():
                stop.set()
                break
            time.sleep(self._delay(len(data)))
            try:
                dst.sendall(data)
            except OSError:
                break
            with self._lock:
                self.bytes_relayed += len(data)
        stop.set()
