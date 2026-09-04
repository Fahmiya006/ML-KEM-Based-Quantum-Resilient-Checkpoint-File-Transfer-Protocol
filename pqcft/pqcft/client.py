"""
Sender node.

Drives the transfer: establishes the session key, chunks + encrypts the file,
transmits, and -- when the 6G link dies -- reconnects and resumes from the
receiver's last verified checkpoint instead of restarting.

The same code path runs the baseline: with `checkpointing=False` the receiver
always answers `resume_from=0`, so every disruption costs a full restart. That
is deliberate -- baseline and proposed differ only in the checkpoint mechanism
and the KEM, never in transport or I/O, so the measured deltas are attributable.
"""

from __future__ import annotations

import hashlib
import os
import socket
import time
from typing import Optional

from . import protocol as P
from .checkpoint import CheckpointManager, CheckpointRecord
from .crypto import (
    BACKENDS,
    ChunkCipher,
    derive_session,
    file_sha256,
    new_session_id,
    sha256,
)
from .metrics import TransferMetrics

DEFAULT_CHUNK = 64 * 1024


class TransferAborted(Exception):
    pass


class Sender:
    def __init__(
        self,
        path: str,
        target: tuple,
        scheme: str = "mlkem",
        chunk_size: int = DEFAULT_CHUNK,
        checkpointing: bool = True,
        checkpoint_interval: int = 8,
        resume_mode: str = "rekey",
        state_dir: str = "./state",
        max_attempts: int = 500,
        retry_budget_s: float = 120.0,
        reconnect_backoff_s: float = 0.05,
        max_backoff_s: float = 0.4,
        connect_timeout_s: float = 3.0,
        io_timeout_s: float = 10.0,
        sockbuf_bytes: int = 128 * 1024,
    ):
        self.path = path
        self.target = target
        self.scheme = scheme
        self.chunk_size = chunk_size
        self.checkpointing = checkpointing
        self.checkpoint_interval = checkpoint_interval
        self.resume_mode = resume_mode
        self.max_attempts = max_attempts
        self.retry_budget_s = retry_budget_s
        self.backoff = reconnect_backoff_s
        self.max_backoff = max_backoff_s
        self.connect_timeout = connect_timeout_s
        self.last_ack = 0
        self._disconnect_at = None
        self.io_timeout = io_timeout_s
        self.sockbuf_bytes = sockbuf_bytes

        os.makedirs(state_dir, exist_ok=True)
        self.session_id = new_session_id()
        self.sid_hex = self.session_id.hex()
        self.file_size = os.path.getsize(path)
        self.file_hash = file_sha256(path)
        self.total_chunks = max(1, (self.file_size + chunk_size - 1) // chunk_size)
        self.ckpt = CheckpointManager(
            os.path.join(state_dir, f"tx-{self.sid_hex}.ckpt"), checkpoint_interval
        )

    # -- public ------------------------------------------------------------- #
    def run(self, m: Optional[TransferMetrics] = None) -> TransferMetrics:
        m = m or TransferMetrics()
        m.protocol = "proposed" if self.checkpointing else "baseline"
        m.scheme = BACKENDS[self.scheme].name
        m.checkpointing = self.checkpointing
        m.file_size = self.file_size
        m.chunk_size = self.chunk_size
        m.total_chunks = self.total_chunks

        t_start = time.perf_counter()
        self._disconnect_at = None

        # Retry against a wall-clock budget, not a raw attempt count. A fixed
        # count is really a hidden *time* limit (count x backoff), so a harsh
        # disruption schedule exhausts it and the run looks like a protocol
        # failure when it is only a client-configuration artifact.
        backoff = self.backoff
        for attempt in range(1, self.max_attempts + 1):
            if time.perf_counter() - t_start > self.retry_budget_s:
                break
            m.attempts = attempt
            try:
                self._attempt(m)
                m.completed = True
                break
            except TransferAborted:
                break
            except (P.Disconnected, OSError, ConnectionError):
                # Link down. Stamp the outage start once, back off, retry.
                # Subsequent refused connects during the same outage must not
                # reset the clock, or recovery time is under-reported.
                if self._disconnect_at is None:
                    self._disconnect_at = time.perf_counter()
                time.sleep(backoff)
                # Exponential backoff, capped: probing a blocked THz link every
                # 50 ms for a full second is not what a real UE does, and the
                # cap keeps recovery latency low once the link returns.
                backoff = min(backoff * 1.5, self.max_backoff)
                continue
            else:
                backoff = self.backoff

        m.total_time_s = time.perf_counter() - t_start
        m.checkpoint_writes = self.ckpt.writes
        m.checkpoint_bytes = self.ckpt.bytes_written
        m.checkpoint_overhead_ms = self.ckpt.overhead_ms
        self.ckpt.clear()
        return m

    # -- one connection attempt --------------------------------------------- #
    def _attempt(self, m: TransferMetrics) -> None:
        backend = BACKENDS[self.scheme]
        hs_t0 = time.perf_counter()

        conn = socket.create_connection(self.target, timeout=self.connect_timeout)
        if self.sockbuf_bytes > 0:
            # Match the channel's buffer ceiling. Without this the sender parks
            # megabytes in its own send buffer and calls them "transmitted",
            # which would credit the baseline with work it never delivered.
            try:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF,
                                self.sockbuf_bytes)
            except OSError:
                pass
        conn.settimeout(self.io_timeout)

        hello = {
            "v": P.MAGIC_VERSION,
            "session_id": self.sid_hex,
            "file_name": os.path.basename(self.path),
            "file_size": self.file_size,
            "file_hash": self.file_hash,
            "chunk_size": self.chunk_size,
            "total_chunks": self.total_chunks,
            "scheme": self.scheme,
            "resume_mode": self.resume_mode,
        }
        import json

        hello_raw = json.dumps(hello, separators=(",", ":")).encode()
        P.send_frame(conn, P.HELLO, hello_raw)

        mtype, payload = P.recv_frame(conn)
        if mtype != P.HELLO_ACK:
            raise P.ProtocolError("expected HELLO_ACK")
        ack = P.parse_json(payload)
        resume_from = int(ack["resume_from"])

        if ack.get("already_complete"):
            # A previous attempt got the whole file through; only the DONE frame
            # was lost. Nothing left to send.
            m.integrity_ok = bool(ack.get("verified")) and \
                ack.get("file_hash") == self.file_hash
            m.handshake_time_s += time.perf_counter() - hs_t0
            conn.close()
            return

        if ack["need_handshake"]:
            mtype, ek = P.recv_frame(conn)
            if mtype != P.KEM_PUB:
                raise P.ProtocolError("expected KEM_PUB")
            shared, ct, encaps_ms = backend.initiator_encaps(ek)
            P.send_frame(conn, P.KEM_CT, ct)
            transcript = hashlib.sha256(hello_raw + ek + ct).digest()
            key, salt = derive_session(shared, transcript)
            m.kex_wire_bytes += len(ek) + len(ct)
            m.kex_cpu_ms += encaps_ms
            self._cached = key + salt
        else:
            key, salt = self._cached[:32], self._cached[32:36]

        m.handshake_time_s += time.perf_counter() - hs_t0
        cipher = ChunkCipher(key, salt, self.session_id)

        if resume_from > 0:
            m.resumed_from_chunks.append(resume_from)

        # ---- transmit ----------------------------------------------------- #
        with open(self.path, "rb") as f:
            f.seek(resume_from * self.chunk_size)
            index = resume_from
            while index < self.total_chunks:
                plain = f.read(self.chunk_size)
                if not plain:
                    break
                sealed = cipher.seal(index, self.total_chunks, plain)
                sent = P.send_frame(conn, P.CHUNK, P.pack_chunk(index, sealed))
                m.payload_bytes_sent += sent

                if self._disconnect_at is not None:
                    # First chunk to survive the outage: this outage is over.
                    # Clearing the stamp is what makes the *next* disruption a
                    # separately-measured recovery event.
                    m.recovery_times_s.append(time.perf_counter() - self._disconnect_at)
                    self._disconnect_at = None

                self._checkpoint(index + 1, sha256(plain), key + salt,
                                 force=(index + 1 == self.total_chunks))
                index += 1

        P.send_frame(conn, P.FIN)
        conn.settimeout(self.io_timeout)

        # The receiver ACKs each checkpoint write asynchronously, so ACK frames
        # are queued ahead of DONE. Drain them; the last one is the receiver's
        # confirmed resume point.
        while True:
            mtype, payload = P.recv_frame(conn)
            if mtype == P.ACK:
                self.last_ack = int.from_bytes(payload, "big")
                continue
            break

        if mtype == P.ABORT:
            raise TransferAborted(P.parse_json(payload).get("reason", "aborted"))
        if mtype != P.DONE:
            raise P.ProtocolError(f"expected DONE, got {P.NAMES.get(mtype, mtype)}")
        done = P.parse_json(payload)
        m.integrity_ok = bool(done.get("verified"))
        conn.close()

    def _checkpoint(self, next_chunk: int, last_hash: str, key_material: bytes,
                    force: bool = False) -> None:
        if not self.checkpointing:
            return
        self.ckpt.save(
            CheckpointRecord(
                session_id=self.sid_hex,
                file_name=os.path.basename(self.path),
                file_size=self.file_size,
                file_hash=self.file_hash,
                chunk_size=self.chunk_size,
                total_chunks=self.total_chunks,
                next_chunk=next_chunk,
                last_chunk_hash=last_hash,
                scheme=self.scheme,
                key_material=key_material.hex() if self.resume_mode == "cached" else "",
            ),
            force=force,
        )
