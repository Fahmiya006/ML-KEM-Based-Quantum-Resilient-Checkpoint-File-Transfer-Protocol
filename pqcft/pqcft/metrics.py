"""Metric collection for the baseline-vs-proposed evaluation."""

from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass, field
from typing import List


@dataclass
class TransferMetrics:
    # --- configuration ------------------------------------------------------
    protocol: str = ""              # "baseline" | "proposed"
    scheme: str = ""                # "x25519-ecdhe" | "ml-kem-768"
    checkpointing: bool = False
    file_size: int = 0
    chunk_size: int = 0
    total_chunks: int = 0
    channel: str = ""
    disruptions_configured: int = 0
    disruption_duration_s: float = 0.0

    # --- outcome ------------------------------------------------------------
    completed: bool = False
    integrity_ok: bool = False
    corrupted: bool = False
    attempts: int = 0               # connection attempts (1 = no interruption)

    # --- time ---------------------------------------------------------------
    total_time_s: float = 0.0
    handshake_time_s: float = 0.0   # summed across all attempts
    recovery_times_s: List[float] = field(default_factory=list)

    # --- bandwidth ----------------------------------------------------------
    payload_bytes_sent: int = 0     # ciphertext bytes pushed, including re-sends
    kex_wire_bytes: int = 0         # summed across all attempts
    kex_cpu_ms: float = 0.0

    # --- checkpoint ---------------------------------------------------------
    checkpoint_writes: int = 0
    checkpoint_bytes: int = 0
    checkpoint_overhead_ms: float = 0.0
    resumed_from_chunks: List[int] = field(default_factory=list)

    # --- derived ------------------------------------------------------------
    @property
    def goodput_mbps(self) -> float:
        if self.total_time_s <= 0:
            return 0.0
        return (self.file_size * 8) / (self.total_time_s * 1e6)

    @property
    def retransmission_overhead_pct(self) -> float:
        """Extra payload pushed beyond one clean copy of the file."""
        if self.file_size <= 0:
            return 0.0
        return (self.payload_bytes_sent / self.file_size - 1.0) * 100.0

    @property
    def wasted_bytes(self) -> int:
        return max(0, self.payload_bytes_sent - self.file_size)

    @property
    def mean_recovery_s(self) -> float:
        return statistics.fmean(self.recovery_times_s) if self.recovery_times_s else 0.0

    @property
    def max_recovery_s(self) -> float:
        return max(self.recovery_times_s) if self.recovery_times_s else 0.0

    def to_row(self) -> dict:
        row = asdict(self)
        row["recovery_times_s"] = ";".join(f"{x:.4f}" for x in self.recovery_times_s)
        row["resumed_from_chunks"] = ";".join(str(x) for x in self.resumed_from_chunks)
        row.update(
            goodput_mbps=round(self.goodput_mbps, 4),
            retransmission_overhead_pct=round(self.retransmission_overhead_pct, 3),
            wasted_bytes=self.wasted_bytes,
            mean_recovery_s=round(self.mean_recovery_s, 4),
            max_recovery_s=round(self.max_recovery_s, 4),
        )
        return row


FIELDNAMES = list(TransferMetrics().to_row().keys())
