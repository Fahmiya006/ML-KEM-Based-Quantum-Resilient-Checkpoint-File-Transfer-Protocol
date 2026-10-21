"""Structured event log: JSON lines on disk + in-memory list + live subscribers.

Every interesting thing that happens (key exchange, each chunk, each ACK, each
checkpoint, each link outage, each resume, each attack) is an event.  The live
dashboard, the replay pages and the evidence report are all built from them.
"""
from __future__ import annotations

import json
import queue
import threading
import time


class EventLog:
    def __init__(self, path: str | None = None, role: str = "app", max_mem: int = 400000):
        self.role = role
        self.path = path
        self.t0 = time.time()
        self.events: list[dict] = []
        self.max_mem = max_mem
        self._lock = threading.Lock()
        self._subs: list[queue.Queue] = []
        self._fh = open(path, "w", buffering=1, encoding="utf-8") if path else None

    def emit(self, ev: str, src: str | None = None, **fields):
        now = time.time()
        rec = {"t": round(now - self.t0, 6), "ts": round(now, 6), "src": src or self.role, "ev": ev}
        rec.update(fields)
        with self._lock:
            if len(self.events) < self.max_mem:
                self.events.append(rec)
            if self._fh:
                self._fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(rec)
            except queue.Full:
                pass
        return rec

    def view(self, role: str):
        """Handle that stamps events with `role` (lets sender, receiver and link share one log)."""
        parent = self

        class _View:
            def emit(self, ev, src=None, **fields):
                return parent.emit(ev, src=src or role, **fields)
        return _View()

    def subscribe(self):
        """Return (snapshot_of_existing_events, queue_for_new_ones)."""
        q: queue.Queue = queue.Queue(maxsize=200000)
        with self._lock:
            snap = list(self.events)
            self._subs.append(q)
        return snap, q

    def unsubscribe(self, q):
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def close(self):
        if self._fh:
            self._fh.close()
            self._fh = None


def load_jsonl(path: str):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass          # a process killed mid-write can leave one partial line
    return out
