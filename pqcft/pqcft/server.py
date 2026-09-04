"""
Receiver node.

Accepts sessions, runs the KEM as responder, decrypts + hash-verifies each
chunk, writes it at its exact file offset, and persists a checkpoint every N
verified chunks. On reconnect it looks up the session's checkpoint and tells the
sender exactly which chunk to resume from.
"""

from __future__ import annotations

import hashlib
import os
import socket
import threading
import time
from typing import Optional

from . import protocol as P
from .checkpoint import CheckpointManager, CheckpointRecord
from .crypto import BACKENDS, ChunkCipher, derive_session, file_sha256, sha256


class ReceiverStats:
    def __init__(self):
        self.checkpoint_writes = 0
        self.checkpoint_bytes = 0
        self.checkpoint_overhead_ms = 0.0
        self.chunks_verified = 0
        self.chunks_rejected = 0


class Receiver:
    def __init__(
        self,
        out_dir: str,
        state_dir: str,
        checkpointing: bool = True,
        checkpoint_interval: int = 8,
        resume_mode: str = "rekey",
        host: str = "127.0.0.1",
        port: int = 0,
    ):
        self.out_dir = out_dir
        self.state_dir = state_dir
        self.checkpointing = checkpointing
        self.checkpoint_interval = checkpoint_interval
        self.resume_mode = resume_mode
        os.makedirs(out_dir, exist_ok=True)
        os.makedirs(state_dir, exist_ok=True)

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.stats = ReceiverStats()
        self.last_result: Optional[dict] = None
        # Sessions that reached FIN and passed verification. A DONE frame can
        # die in the outage it was racing; without this the sender concludes
        # failure and restarts a transfer that already succeeded, destroying the
        # completed file. Completion must be idempotent.
        self._completed: dict = {}

    # -- lifecycle ---------------------------------------------------------- #
    def start(self) -> "Receiver":
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.stop()

    def _serve(self) -> None:
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    # -- helpers ------------------------------------------------------------ #
    def _ckpt_path(self, session_id: str) -> str:
        return os.path.join(self.state_dir, f"rx-{session_id}.ckpt")

    def _partial_path(self, session_id: str, file_name: str) -> str:
        return os.path.join(self.out_dir, f"{file_name}.{session_id[:8]}.part")

    # -- one connection ----------------------------------------------------- #
    def _session(self, conn: socket.socket) -> None:
        conn.settimeout(10.0)
        try:
            self._run_session(conn)
        except (P.Disconnected, P.ProtocolError, OSError):
            pass  # link died; sender will reconnect and resume
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _run_session(self, conn: socket.socket) -> None:
        mtype, payload = P.recv_frame(conn)
        if mtype != P.HELLO:
            raise P.ProtocolError(f"expected HELLO, got {P.NAMES.get(mtype)}")
        hello_raw = payload
        hello = P.parse_json(payload)

        sid = hello["session_id"]
        scheme = hello["scheme"]
        backend = BACKENDS[scheme]
        total_chunks = hello["total_chunks"]
        chunk_size = hello["chunk_size"]

        # Idempotent completion: if this session already finished and verified,
        # re-announce DONE instead of starting over. This is what makes a lost
        # DONE frame harmless.
        prior = self._completed.get(sid)
        if prior is not None:
            P.send_json(conn, P.HELLO_ACK, {
                "resume_from": total_chunks,
                "need_handshake": False,
                "checkpointing": self.checkpointing,
                "already_complete": True,
                "file_hash": prior["hash"],
                "verified": prior["ok"],
            })
            return

        ckpt = CheckpointManager(self._ckpt_path(sid), self.checkpoint_interval)
        rec = ckpt.load(expect_session=sid) if self.checkpointing else None

        part = self._partial_path(sid, hello["file_name"])
        resume_from = 0
        cached_key = None

        if rec is not None and os.path.exists(part):
            resume_from = rec.next_chunk
            if self.resume_mode == "cached" and rec.key_material:
                cached_key = bytes.fromhex(rec.key_material)
        else:
            # No usable checkpoint: start the file over.
            ckpt.clear()
            with open(part, "wb") as f:
                f.truncate(hello["file_size"])

        need_handshake = cached_key is None
        P.send_json(conn, P.HELLO_ACK, {
            "resume_from": resume_from,
            "need_handshake": need_handshake,
            "checkpointing": self.checkpointing,
        })

        # ---- key establishment ------------------------------------------- #
        if need_handshake:
            ek, dk, _ = backend.responder_keygen()
            P.send_frame(conn, P.KEM_PUB, ek)
            mtype, ct = P.recv_frame(conn)
            if mtype != P.KEM_CT:
                raise P.ProtocolError("expected KEM_CT")
            shared, _ = backend.responder_decaps(dk, ct)
            transcript = hashlib.sha256(hello_raw + ek + ct).digest()
            key, salt = derive_session(shared, transcript)
        else:
            key, salt = cached_key[:32], cached_key[32:36]

        cipher = ChunkCipher(key, salt, bytes.fromhex(sid))

        # ---- chunk loop --------------------------------------------------- #
        next_chunk = resume_from
        last_hash = rec.last_chunk_hash if rec else ""
        fh = open(part, "r+b")
        try:
            while True:
                mtype, payload = P.recv_frame(conn)

                if mtype == P.CHUNK:
                    index, ct_bytes = P.unpack_chunk(payload)
                    if index != next_chunk:
                        # Out-of-order/duplicate: the checkpoint is authoritative.
                        continue
                    try:
                        plain = cipher.open(index, total_chunks, ct_bytes)
                    except Exception:
                        self.stats.chunks_rejected += 1
                        P.send_json(conn, P.ABORT, {"reason": "auth failure",
                                                    "index": index})
                        return
                    fh.seek(index * chunk_size)
                    fh.write(plain)
                    fh.flush()
                    last_hash = sha256(plain)
                    next_chunk = index + 1
                    self.stats.chunks_verified += 1

                    wrote = self._maybe_checkpoint(
                        ckpt, sid, hello, next_chunk, last_hash, scheme,
                        key + salt, force=(next_chunk == total_chunks),
                    )
                    if wrote:
                        P.send_frame(conn, P.ACK, next_chunk.to_bytes(8, "big"))

                elif mtype == P.FIN:
                    fh.flush()
                    os.fsync(fh.fileno())
                    fh.close()
                    final = os.path.join(self.out_dir, hello["file_name"])
                    os.replace(part, final)
                    digest = file_sha256(final)
                    ok = digest == hello["file_hash"] and next_chunk == total_chunks
                    P.send_json(conn, P.DONE, {
                        "ok": ok, "file_hash": digest,
                        "verified": ok, "chunks": next_chunk,
                    })
                    ckpt.clear()
                    self.last_result = {"ok": ok, "hash": digest, "path": final}
                    self._completed[sid] = self.last_result
                    return

                else:
                    raise P.ProtocolError(f"unexpected {P.NAMES.get(mtype, mtype)}")
        finally:
            if not fh.closed:
                fh.close()

    def _maybe_checkpoint(self, ckpt, sid, hello, next_chunk, last_hash,
                          scheme, key_material, force=False) -> bool:
        if not self.checkpointing:
            return False
        rec = CheckpointRecord(
            session_id=sid,
            file_name=hello["file_name"],
            file_size=hello["file_size"],
            file_hash=hello["file_hash"],
            chunk_size=hello["chunk_size"],
            total_chunks=hello["total_chunks"],
            next_chunk=next_chunk,
            last_chunk_hash=last_hash,
            scheme=scheme,
            key_material=key_material.hex() if self.resume_mode == "cached" else "",
        )
        before = ckpt.writes
        ckpt.save(rec, force=force)
        if ckpt.writes > before:
            self.stats.checkpoint_writes = ckpt.writes
            self.stats.checkpoint_bytes = ckpt.bytes_written
            self.stats.checkpoint_overhead_ms = ckpt.overhead_ms
            return True
        return False
