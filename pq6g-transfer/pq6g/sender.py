"""Sender.

  * agrees a key once with the receiver (ML-KEM-768), derives K and K_ck (HKDF),
  * cuts the file into numbered chunks, seals each with AES-256-GCM, keeps a
    window of un-acknowledged chunks in flight,
  * on a broken connection reconnects with exponential back-off and RESUMES:
    asks for the signed checkpoint, verifies its HMAC *and* compares the hash
    chain value with its own copy, and continues from chunk i*+1 with the same key,
  * mode="restart" is the baseline without checkpoints: every break means a new
    handshake and starting again from chunk 0.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time

from . import crypto as C
from . import wire as W
from .config import ACK_TIMEOUT, CHUNK, DEFAULT_N, DEFAULT_WINDOW


class GiveUp(Exception):
    pass


class _State:
    def __init__(self):
        self.cond = threading.Condition()
        self.acked = -1
        self.next_idx = 0
        self.err = None
        self.fin_sent = False
        self.fin_time = 0.0
        self.fin_ok = None
        self.last_progress = time.time()


class Sender:
    def __init__(self, path, host, port, events, kem_name="mlkem768", n=DEFAULT_N,
                 window=DEFAULT_WINDOW, mode="checkpoint", chunk=CHUNK, ack_timeout=ACK_TIMEOUT,
                 state_dir=None, give_up_after=600.0, kem_obj=None, gate=None):
        self.path, self.host, self.port, self.ev = path, host, port, events
        self.kem = kem_obj or C.get_kem(kem_name)
        self.n, self.window, self.mode, self.chunk = n, window, mode, chunk
        self.ack_timeout, self.give_up_after = ack_timeout, give_up_after
        self.state_dir = state_dir
        self.gate = gate
        self.size = os.path.getsize(path)
        self.nchunks = max(1, -(-self.size // chunk))
        self.name = os.path.basename(path)
        self._fh = open(path, "rb")
        self.file_sha = b""
        self.stop_flag = threading.Event()
        self._reset_session()
        # counters
        self.chunks_sent = self.chunks_resent = self.handshakes = self.resumes = 0
        self.rewinds = self.disconnects = self.reconnect_attempts = 0
        self.bytes_sent = 0
        self.sent_max = -1

    def _gate(self, name):
        """Presenter pause point (no-op unless a Guide is attached)."""
        if self.gate is None:
            return
        self.gate.point(name)
        st = getattr(self, "st", None)
        if st is not None:
            with st.cond:
                st.last_progress = time.time()

    # --------------------------------------------------------------- session
    def _reset_session(self):
        self.sid = None
        self.cipher = None
        self.K = self.Kck = None
        self.chain: list[bytes] = []          # H_0 .. H_k as first sealed
        self.digests: list[bytes] = []        # sha256(sealed)[:8] of each chunk, for the determinism check
        self.sent_max = -1

    def _read_chunk(self, idx):
        self._fh.seek(idx * self.chunk)
        return self._fh.read(self.chunk)

    def _chain_at(self, i):
        """H_i, recomputing by re-sealing chunks if the cache does not reach that far.
        Works because sealing is deterministic."""
        while len(self.chain) <= i:
            j = len(self.chain)
            sealed = self.cipher.seal(j, self._read_chunk(j))
            self.chain.append(C.chain_next(self.chain[-1] if self.chain else b"", sealed))
            self.digests.append(hashlib.sha256(sealed).digest()[:8])
        return self.chain[i]

    # ----------------------------------------------------------------- run
    def run(self) -> bool:
        t_start = time.time()
        t0 = time.perf_counter()
        h = hashlib.sha256()
        with open(self.path, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
        self.file_sha = h.digest()
        self.ev.emit("send_start", file=self.name, size=self.size, chunk=self.chunk,
                     nchunks=self.nchunks, n=self.n, window=self.window, mode=self.mode,
                     kem=self.kem.name, kem_impl=self.kem.impl, sha256=self.file_sha.hex(),
                     t_hash_ms=round((time.perf_counter() - t0) * 1e3, 2))
        self._load_persisted()
        st = _State()
        self.st = st
        delay = 0.05
        while not self.stop_flag.is_set():
            if time.time() - t_start > self.give_up_after:
                self.ev.emit("send_failed", reason="gave up", elapsed=round(time.time() - t_start, 3))
                return False
            conn = None
            established = False
            try:
                conn = socket.create_connection((self.host, self.port), timeout=2.0)
                W.tune(conn)
                conn.settimeout(self.ack_timeout)
                rd = W.FrameReader(conn)
                if self.sid is None:
                    self._handshake(conn, rd, st)
                    established = True
                    self._gate("after_kex")
                else:
                    r = self._resume(conn, rd, st)
                    established = True
                    if r == "unknown":
                        self.sid = None
                        conn.close()
                        continue
                    self._gate("after_resume")
                    if r == "done":
                        self._finish(t_start, st)
                        return True
                delay = 0.05
                if self._transfer(conn, rd, st):
                    self._finish(t_start, st)
                    return True
            except (ConnectionError, OSError, socket.timeout, W.ProtocolError) as e:
                reason = f"{type(e).__name__}: {e}"[:100]
                if established:
                    self.disconnects += 1
                    self.ev.emit("tx_disconnect", reason=reason, acked=st.acked, next=st.next_idx)
                    self._gate("before_resume")
                    if self.mode == "restart":
                        self.ev.emit("tx_restart_session", note="no checkpoint: new handshake, start from chunk 0")
                        self._reset_session()
                        st = _State()
                        self.st = st
                else:
                    self.reconnect_attempts += 1
                    self.ev.emit("tx_reconnect_attempt", n=self.reconnect_attempts,
                                 wait_ms=round(delay * 1e3), reason=reason[:60])
                    time.sleep(delay)
                    delay = min(delay * 2, 0.25)
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except OSError:
                        pass
        return False

    def _finish(self, t_start, st):
        self._clear_persisted()
        self.ev.emit("send_complete", elapsed=round(time.time() - t_start, 3),
                     chunks_sent=self.chunks_sent, chunks_resent=self.chunks_resent,
                     handshakes=self.handshakes, resumes=self.resumes,
                     rewinds=self.rewinds, disconnects=self.disconnects,
                     bytes_sent=self.bytes_sent, size=self.size,
                     file_sha_ok=bool(st.fin_ok == self.file_sha))

    # ------------------------------------------------------------ handshake
    def _handshake(self, conn, rd, st):
        W.send_frame(conn, W.T_START, json.dumps({"kem": self.kem.name, "v": 1}).encode())
        t, p = rd.read()
        if t != W.T_HELLO:
            raise W.ProtocolError("expected HELLO")
        sid, pk = p[:4], p[4:]
        t0 = time.perf_counter()
        ss, ct = self.kem.encaps(pk)
        t_enc = (time.perf_counter() - t0) * 1e3
        W.send_frame(conn, W.T_KEMCT, ct)
        self.sid = sid
        self.K, self.Kck = C.derive_keys(ss, sid)
        self.cipher = C.ChunkCipher(self.K, sid)
        self.chain, self.digests, self.sent_max = [], [], -1
        self.handshakes += 1
        self.ev.emit("kex_done", kem=self.kem.name, impl=self.kem.impl, pk_bytes=len(pk),
                     ct_bytes=len(ct), ct_head=ct[:8].hex(), t_encaps_ms=round(t_enc, 3),
                     key_fp=hashlib.sha256(b"fp" + self.K).hexdigest()[:12], sid=sid.hex(),
                     handshake_no=self.handshakes, wire_bytes=len(pk) + len(ct))
        meta = json.dumps({"name": self.name, "size": self.size, "chunk": self.chunk,
                           "nchunks": self.nchunks, "n": self.n}).encode()
        W.send_frame(conn, W.T_META, sid + C.META_IDX.to_bytes(8, "big") + self.cipher.seal(C.META_IDX, meta))
        t, p = rd.read()
        if t != W.T_ACK:
            raise W.ProtocolError("expected ACK after META")
        with st.cond:
            st.acked, st.next_idx = -1, 0
            st.last_progress = time.time()
        self._persist()

    # --------------------------------------------------------------- resume
    def _resume(self, conn, rd, st):
        t0 = time.perf_counter()
        W.send_frame(conn, W.T_RESUME_REQ, self.sid)
        t, p = rd.read()
        if t == W.T_ERR:
            if p == b"unknown_session":
                self.ev.emit("resume_unknown", note="receiver lost the session; doing a new handshake")
                return "unknown"
            raise W.ProtocolError(p.decode(errors="replace"))
        if t == W.T_FIN_OK:
            st.fin_ok = p[:32]
            self.ev.emit("resume_found_complete", note="receiver already finished and verified the file")
            return "done"
        if t != W.T_RESUME_RESP:
            raise W.ProtocolError("expected RESUME_RESP")
        rec = C.parse_ckpt(self.Kck, p)
        verdict, i_star = "ok", None
        if rec is None:
            verdict = "bad_hmac"
        elif rec["sid"] != self.sid:
            verdict = "wrong_session"
        else:
            i_star = -1 if rec["i_star"] == C.NONE_IDX else rec["i_star"]
            if i_star > self.sent_max:
                verdict = "claims_more_than_sent"
            elif i_star >= 0:
                if rec["h"] != self._chain_at(i_star):
                    verdict = "chain_mismatch"
            elif rec["h"] != C.ZERO_H:
                verdict = "chain_mismatch"
        t_verify = (time.perf_counter() - t0) * 1e3
        if verdict == "ok":
            with st.cond:
                before = st.next_idx
                st.acked, st.next_idx = i_star, i_star + 1
                st.err = None
                st.last_progress = time.time()
            self.resumes += 1
            self.ev.emit("resume_accepted", i_star=i_star, o_star=rec["o_star"], h=rec["h"][:6].hex(),
                         mac=rec["mac"][:6].hex(), hmac_ok=True, chain_ok=True,
                         resume_from=i_star + 1, sent_before=before - 1, t_verify_ms=round(t_verify, 3),
                         handshake_skipped=True)
        else:
            self.rewinds += 1
            self.ev.emit("resume_rejected", reason=verdict, claimed_i_star=(i_star if rec else None),
                         action="rewind to chunk 0 (safe fallback)")
            W.send_frame(conn, W.T_REWIND, self.sid + (0).to_bytes(8, "big"))
            t, p = rd.read()
            if t != W.T_ACK:
                raise W.ProtocolError("expected ACK after REWIND")
            with st.cond:
                st.acked, st.next_idx, st.err = -1, 0, None
                st.last_progress = time.time()
        return verdict

    # ------------------------------------------------------------- transfer
    def _reader(self, conn, rd, st):
        try:
            while True:
                try:
                    t, p = rd.read()
                except socket.timeout:
                    if st.fin_sent and time.time() - st.fin_time < 300:
                        continue
                    raise
                with st.cond:
                    if t == W.T_ACK:
                        v = int.from_bytes(p[4:12], "big")
                        v = -1 if v == C.NONE_IDX else v
                        if v > st.acked:
                            st.acked = v
                        st.last_progress = time.time()
                        self.ev.emit("ack", i=v)
                    elif t == W.T_NAK:
                        want = int.from_bytes(p[4:12], "big")
                        self.ev.emit("tx_nak", want=want, was_next=st.next_idx)
                        if st.next_idx > want:
                            st.next_idx = want
                        if st.acked >= want:
                            st.acked = want - 1
                        st.last_progress = time.time()
                    elif t == W.T_FIN_OK:
                        st.fin_ok = p[:32]
                    elif t == W.T_ERR:
                        st.err = W.ProtocolError(p.decode(errors="replace"))
                    st.cond.notify_all()
                    if t in (W.T_FIN_OK, W.T_ERR):
                        return
        except Exception as e:           # noqa: BLE001 - propagate any failure to the sender thread
            with st.cond:
                st.err = e
                st.cond.notify_all()

    def _transfer(self, conn, rd, st) -> bool:
        """One connection's worth of sending.  Returns True when FIN_OK arrives."""
        threading.Thread(target=self._reader, args=(conn, rd, st), daemon=True, name="tx-ack").start()
        N = self.nchunks
        with st.cond:
            st.fin_sent, st.fin_ok = False, None
        while True:
            action, idx = None, None
            with st.cond:
                while action is None:
                    if st.err:
                        raise st.err if isinstance(st.err, Exception) else ConnectionError(str(st.err))
                    if st.fin_ok is not None:
                        action = "done"
                        break
                    if st.fin_sent:                                   # waiting for the receiver's whole-file check
                        if time.time() - st.fin_time > 300:
                            raise socket.timeout("no FIN_OK")
                        st.cond.wait(0.1)
                        continue
                    if st.next_idx < N:
                        if st.next_idx - (st.acked + 1) < self.window:
                            action, idx = "send", st.next_idx
                            break
                    elif st.acked >= N - 1:
                        action = "fin"
                        break
                    if time.time() - st.last_progress > self.ack_timeout:
                        raise socket.timeout("no acknowledgement (link presumed dead)")
                    st.cond.wait(0.05)
            if action == "send":
                if self.gate is not None and idx == self.gate.cut_at and not self.gate.is_passed("data_pause"):
                    with st.cond:                       # let everything sent so far be acknowledged, so the screen shows it as delivered
                        t_w = time.time()
                        while st.acked < idx - 1 and not st.err and time.time() - t_w < 10:
                            st.cond.wait(0.05)
                    self._gate("data_pause")
                self._send_chunk(conn, idx)
                with st.cond:
                    if st.next_idx == idx:            # a NAK may have rewound us meanwhile
                        st.next_idx = idx + 1
            elif action == "fin":
                W.send_frame(conn, W.T_FIN, self.file_sha + N.to_bytes(8, "big"))
                with st.cond:
                    st.fin_sent, st.fin_time = True, time.time()
                self.ev.emit("fin_sent", sha256=self.file_sha.hex()[:16])
            else:
                ok = st.fin_ok == self.file_sha
                self.ev.emit("fin_ok", sha256_match=ok)
                return ok

    def _send_chunk(self, conn, idx):
        data = self._read_chunk(idx)
        sealed = self.cipher.seal(idx, data)
        digest = hashlib.sha256(sealed).digest()[:8]
        resend = idx <= self.sent_max
        same = None
        if idx == len(self.chain):
            self.chain.append(C.chain_next(self.chain[-1] if self.chain else b"", sealed))
            self.digests.append(digest)
        elif idx < len(self.chain):
            same = (self.digests[idx] == digest)
        payload = self.sid + idx.to_bytes(8, "big") + sealed
        W.send_frame(conn, W.T_DATA, payload)
        self.chunks_sent += 1
        self.bytes_sent += len(payload) + W.HDR.size
        if resend:
            self.chunks_resent += 1
        if idx > self.sent_max:
            self.sent_max = idx
        self.ev.emit("chunk_sent", i=idx, n=len(data), resend=resend, same_ct=same,
                     nonce=self.cipher.nonce(idx).hex(), ct8=sealed[:8].hex(), tag=sealed[-16:-8].hex())

    # ---------------------------------------------------------- persistence
    def _pfile(self):
        return os.path.join(self.state_dir, "send_session.json") if self.state_dir else None

    def _persist(self):
        pf = self._pfile()
        if not pf:
            return
        os.makedirs(self.state_dir, exist_ok=True)
        st = os.stat(self.path)
        doc = {"file": os.path.abspath(self.path), "size": st.st_size, "mtime_ns": st.st_mtime_ns,
               "sid": self.sid.hex(), "K": self.K.hex(), "Kck": self.Kck.hex(), "n": self.n,
               "chunk": self.chunk, "sent_max": self.sent_max}
        fd = os.open(pf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(doc))

    def _load_persisted(self):
        pf = self._pfile()
        if not pf or not os.path.exists(pf) or self.mode == "restart":
            return
        try:
            doc = json.load(open(pf))
            st = os.stat(self.path)
            if (doc["file"] != os.path.abspath(self.path) or doc["size"] != st.st_size
                    or doc["mtime_ns"] != st.st_mtime_ns or doc["chunk"] != self.chunk):
                return
            self.sid = bytes.fromhex(doc["sid"])
            self.K, self.Kck = bytes.fromhex(doc["K"]), bytes.fromhex(doc["Kck"])
            self.cipher = C.ChunkCipher(self.K, self.sid)
            self.sent_max = self.nchunks - 1        # unknown how far we got: chain is recomputed on demand
            self.ev.emit("send_session_restored", sid=self.sid.hex())
        except (OSError, ValueError, KeyError):
            pass

    def _clear_persisted(self):
        pf = self._pfile()
        if pf and os.path.exists(pf):
            try:
                os.remove(pf)
            except OSError:
                pass
