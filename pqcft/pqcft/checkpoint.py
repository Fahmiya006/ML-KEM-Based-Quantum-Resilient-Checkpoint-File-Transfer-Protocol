"""
Checkpoint manager.

Persists transfer state on both sender and receiver so an interrupted session
resumes at the last *verified* chunk instead of restarting.

Safety properties:
  * Atomic write (tmp file + os.replace) so a crash mid-write can never leave a
    torn checkpoint -- the old one survives intact.
  * Self-authenticating: each record carries a SHA-256 over its own canonical
    JSON body. A corrupted or truncated checkpoint is detected on load and
    treated as "no checkpoint" (restart) rather than silently trusted.
  * Records only chunks the receiver has decrypted, hash-verified and flushed to
    disk, so the resume point is never optimistic.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class CheckpointRecord:
    session_id: str
    file_name: str
    file_size: int
    file_hash: str
    chunk_size: int
    total_chunks: int
    next_chunk: int              # first chunk NOT yet verified
    last_chunk_hash: str = ""
    scheme: str = ""
    key_material: str = ""       # hex; only populated in --resume-mode cached
    updated_at: float = field(default_factory=time.time)

    def digest(self) -> str:
        body = {k: v for k, v in asdict(self).items() if k != "mac"}
        return hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


class CheckpointManager:
    def __init__(self, path: str, interval_chunks: int = 8):
        self.path = path
        self.interval = max(1, interval_chunks)
        self.writes = 0
        self.bytes_written = 0
        self.write_time_s = 0.0
        self._since_last = 0

    # -- io ----------------------------------------------------------------- #
    def save(self, rec: CheckpointRecord, force: bool = False) -> bool:
        self._since_last += 1
        if not force and self._since_last < self.interval:
            return False
        self._since_last = 0

        t0 = time.perf_counter()
        rec.updated_at = time.time()
        payload = {"record": asdict(rec), "mac": rec.digest()}
        blob = json.dumps(payload, separators=(",", ":")).encode()
        tmp = f"{self.path}.tmp"
        os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".", exist_ok=True)
        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

        self.writes += 1
        self.bytes_written += len(blob)
        self.write_time_s += time.perf_counter() - t0
        return True

    def load(self, expect_session: Optional[str] = None) -> Optional[CheckpointRecord]:
        if not os.path.exists(self.path):
            return None
        try:
            with open(self.path, "rb") as f:
                payload = json.loads(f.read())
            rec = CheckpointRecord(**payload["record"])
        except Exception:
            return None  # truncated / corrupted -> restart from zero
        if rec.digest() != payload.get("mac"):
            return None  # tampered / partial
        if expect_session and rec.session_id != expect_session:
            return None
        return rec

    def clear(self) -> None:
        for p in (self.path, f"{self.path}.tmp"):
            try:
                os.remove(p)
            except OSError:
                pass

    @property
    def overhead_ms(self) -> float:
        return self.write_time_s * 1e3
