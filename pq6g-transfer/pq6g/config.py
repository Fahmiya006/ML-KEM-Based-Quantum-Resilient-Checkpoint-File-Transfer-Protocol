"""Simulated link profiles.

The first three rows are the paper's Table I operating points.  The `-demo`
profiles keep the same blockage statistics but throttle the rate so that a
100 MiB transfer lasts a few seconds - long enough to watch, and slow enough
for Python endpoints (and a phone) to keep up.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass
class LinkProfile:
    name: str
    rate_mbps: float          # link rate R
    rtt_ms: float             # round-trip time tau
    t_detect: float           # T_d: seconds until the endpoints notice the link died
    t_reconnect: float        # T_r: seconds until a new connection can be set up
    blockage_rate: float      # lambda: expected blockages per second of "link up" time
    desc: str = ""

    def as_dict(self):
        return asdict(self)


PROFILES = {
    "5g-mmwave": LinkProfile("5g-mmwave", 800, 2.0, 0.3, 0.3, 0.8, "5G mmWave, paper Table I"),
    "b5g":       LinkProfile("b5g", 900, 1.5, 0.4, 0.4, 1.0, "Beyond-5G, paper Table I"),
    "6g-thz":    LinkProfile("6g-thz", 1000, 1.0, 0.5, 0.5, 1.2, "6G terahertz, paper Table I (1 Gb/s)"),
    "6g-demo":   LinkProfile("6g-demo", 200, 1.0, 0.5, 0.5, 1.2,
                             "6G THz blockage statistics, rate throttled to 200 Mb/s for demos"),
    "6g-slow":   LinkProfile("6g-slow", 40, 1.0, 0.5, 0.5, 0.6,
                             "slow-motion 6G (40 Mb/s) for small files and live viewing"),
    "ideal":     LinkProfile("ideal", 1000, 1.0, 0.5, 0.5, 0.0, "6G rate, no blockage"),
}

CHUNK = 64 * 1024
DEFAULT_N = 32          # checkpoint every N chunks
DEFAULT_WINDOW = 32     # max un-acknowledged chunks in flight (2 MiB)
ACK_TIMEOUT = 3.0       # seconds of silence before the sender declares the link dead
