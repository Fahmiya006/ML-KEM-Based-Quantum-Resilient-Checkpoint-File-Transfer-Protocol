"""Receiver: the 'authority' of the transfer.

It alone knows what it has safely received, so it owns the checkpoint:
  * verifies every chunk (AES-GCM tag) and extends the hash chain,
  * writes the plain chunk into <name>.part,
  * every N chunks flushes the data to disk and then commits a signed
    84-byte checkpoint atomically,
  * after a disruption answers RESUME_REQ with that checkpoint,
  * at the end verifies the SHA-256 of the whole file.
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
from .config import CHUNK, DEFAULT_N


class Session:
    def __init__(self, sid, kem_name, K, Kck, meta):
        self.sid, self.kem_name, self.K, self.Kck = sid, kem_name, K, Kck
        self.cipher = C.ChunkCipher(K, sid)
        self.meta = meta
        self.expected = 0               # next chunk number we want
        self.H = b""                    # hash chain value after chunk expected-1
        self.fh = None
        self.part_path = self.final_path = self.ckpt_path = self.sess_path = None
        self.conn = None
        self.lock = threading.RLock()
        self.nak_for = None
        self.done = False
        self.n_ckpts = 0


class Receiver:
    def __init__(self, host, port, out_dir, state_dir, events, persist=False,
                 fsync_data=True, ckpt_extra_delay_ms=0.0):
        self.host, self.port = host, port
        self.out_dir, self.state_dir = out_dir, state_dir
        self.ev = events
        self.persist = persist
        self.fsync_data = fsync_data
        self.extra_delay = ckpt_extra_delay_ms / 1000.0
        self.sessions: dict[bytes, Session] = {}
        self.completed: dict[bytes, bytes] = {}   # sid -> sha256 of a finished transfer (answers late RESUME_REQs)
        self._srv = None
        self._stop = threading.Event()
        os.makedirs(out_dir, exist_ok=True)
        os.makedirs(state_dir, exist_ok=True)

    # ------------------------------------------------------------ lifecycle
    def start(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((self.host, self.port))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        self.ev.emit("rx_listen", host=self.host, port=self.port, persist=self.persist,
                     fsync_data=self.fsync_data, kem_impl=C.get_kem("mlkem768").impl)
        if self.persist:
            self._load_persisted()
        threading.Thread(target=self._accept_loop, daemon=True, name="rx-accept").start()
        return self

    def stop(self):
        self._stop.set()
        try:
            self._srv.close()
        except OSError:
            pass
        for s in list(self.sessions.values()):
            try:
                if s.conn:
                    s.conn.close()
                if s.fh:
                    s.fh.close()
            except OSError:
                pass

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True, name="rx-conn").start()

    # ----------------------------------------------------------- connection
    def _handle(self, conn, addr):
        W.tune(conn)
        rd = W.FrameReader(conn)
        try:
            t, p = rd.read()
            if t == W.T_START:
                self._on_start(conn, rd, p)
            elif t == W.T_RESUME_REQ:
                self._on_resume(conn, rd, p)
            else:
                W.send_frame(conn, W.T_ERR, b"expected START or RESUME_REQ")
        except (ConnectionError, OSError, W.ProtocolError, ValueError) as e:
            self.ev.emit("rx_conn_lost", reason=f"{type(e).__name__}: {e}"[:120])
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # ---------------------------------------------------------- new session
    def _on_start(self, conn, rd, p):
        info = json.loads(p.decode())
        kem = C.get_kem(info.get("kem", "mlkem768"))
        sid = os.urandom(4)
        t0 = time.perf_counter()
        pk, dk = kem.keygen()
        t_keygen = (time.perf_counter() - t0) * 1e3
        W.send_frame(conn, W.T_HELLO, sid + pk)
        self.ev.emit("kex_hello", kem=kem.name, impl=kem.impl, sid=sid.hex(), pk_bytes=len(pk),
                     pk_head=pk[:8].hex(), t_keygen_ms=round(t_keygen, 3))
        t, ct = rd.read()
        if t != W.T_KEMCT:
            raise W.ProtocolError("expected KEMCT")
        t0 = time.perf_counter()
        ss = kem.decaps(dk, ct)
        t_decaps = (time.perf_counter() - t0) * 1e3
        K, Kck = C.derive_keys(ss, sid)
        kfp = hashlib.sha256(b"fp" + K).hexdigest()[:12]
        self.ev.emit("kex_done", kem=kem.name, ct_bytes=len(ct), ct_head=ct[:8].hex(),
                     t_decaps_ms=round(t_decaps, 3), key_fp=kfp, sid=sid.hex())
        t, payload = rd.read()
        if t != W.T_META or payload[:4] != sid:
            raise W.ProtocolError("expected META")
        cipher = C.ChunkCipher(K, sid)
        meta = json.loads(cipher.open(C.META_IDX, payload[12:]).decode())
        sess = Session(sid, kem.name, K, Kck, meta)
        self._init_session_files(sess)
        sess.conn = conn
        self.sessions[sid] = sess
        if self.persist:
            self._persist(sess)
        W.send_frame(conn, W.T_ACK, sid + C.NONE_IDX.to_bytes(8, "big"))
        self.ev.emit("meta", name=meta["name"], size=meta["size"], chunk=meta["chunk"],
                     nchunks=meta["nchunks"], n=meta["n"], sid=sid.hex())
        self._serve(conn, rd, sess)

    def _init_session_files(self, sess):
        name = os.path.basename(sess.meta["name"])
        # a new session supersedes any earlier session for the same file
        for old in [s for s in self.sessions.values() if os.path.basename(s.meta["name"]) == name]:
            self._drop(old)
        sess.final_path = os.path.join(self.out_dir, name)
        sess.part_path = sess.final_path + ".part"
        sess.ckpt_path = os.path.join(self.state_dir, f"ckpt_{sess.sid.hex()}.bin")
        sess.sess_path = os.path.join(self.state_dir, f"session_{sess.sid.hex()}.json")
        with open(sess.part_path, "wb") as f:
            f.truncate(sess.meta["size"])
        sess.fh = open(sess.part_path, "r+b", buffering=0)

    def _drop(self, sess):
        try:
            if sess.fh:
                sess.fh.close()
        except OSError:
            pass
        for pth in (sess.ckpt_path, sess.sess_path):
            if pth and os.path.exists(pth):
                try:
                    os.remove(pth)
                except OSError:
                    pass
        self.sessions.pop(sess.sid, None)

    # ------------------------------------------------------------- persist
    def _persist(self, sess):
        """Demo extension: keep session keys on disk so the receiver *process* can
        be killed and still resume.  Keys at rest are a security trade-off (file is
        0600); the paper lists secure key storage as future work."""
        doc = {"sid": sess.sid.hex(), "kem": sess.kem_name, "K": sess.K.hex(),
               "Kck": sess.Kck.hex(), "meta": sess.meta}
        tmp = sess.sess_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(doc))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, sess.sess_path)

    def _load_persisted(self):
        for fn in sorted(os.listdir(self.state_dir)):
            if fn.startswith("done_") and fn.endswith(".sha"):
                try:
                    self.completed[bytes.fromhex(fn[5:-4])] = bytes.fromhex(open(os.path.join(self.state_dir, fn)).read().strip())
                except (OSError, ValueError):
                    pass
                continue
            if not (fn.startswith("session_") and fn.endswith(".json")):
                continue
            try:
                doc = json.load(open(os.path.join(self.state_dir, fn)))
                sess = Session(bytes.fromhex(doc["sid"]), doc["kem"], bytes.fromhex(doc["K"]),
                               bytes.fromhex(doc["Kck"]), doc["meta"])
                name = os.path.basename(sess.meta["name"])
                sess.final_path = os.path.join(self.out_dir, name)
                sess.part_path = sess.final_path + ".part"
                sess.ckpt_path = os.path.join(self.state_dir, f"ckpt_{sess.sid.hex()}.bin")
                sess.sess_path = os.path.join(self.state_dir, fn)
                if not os.path.exists(sess.part_path):
                    continue
                sess.fh = open(sess.part_path, "r+b", buffering=0)
                self.sessions[sess.sid] = sess
                rec = self._read_ckpt(sess)
                self.ev.emit("rx_session_restored", sid=sess.sid.hex(), name=name,
                             ckpt_i_star=(-1 if rec["i_star"] == C.NONE_IDX else rec["i_star"]))
            except (OSError, ValueError, KeyError) as e:
                self.ev.emit("rx_restore_failed", file=fn, reason=str(e)[:100])

    # --------------------------------------------------------------- resume
    def _read_ckpt(self, sess):
        """Latest valid checkpoint from disk, or the signed 'nothing yet' record."""
        rec = None
        if os.path.exists(sess.ckpt_path):
            try:
                rec = C.parse_ckpt(sess.Kck, open(sess.ckpt_path, "rb").read())
            except OSError:
                rec = None
            if rec is None or rec["sid"] != sess.sid:
                self.ev.emit("ckpt_corrupt", sid=sess.sid.hex())
                rec = None
        if rec is None:
            raw = C.pack_ckpt(sess.Kck, sess.sid, C.NONE_IDX, 0, C.ZERO_H)
            rec = C.parse_ckpt(sess.Kck, raw)
        rec["raw"] = C.pack_ckpt(sess.Kck, sess.sid, rec["i_star"], rec["o_star"], rec["h"])
        return rec

    def _on_resume(self, conn, rd, p):
        sid = p[:4]
        sess = self.sessions.get(sid)
        if sess is None and sid in self.completed:
            # the transfer finished but our FIN_OK was lost in a blockage: say so again
            W.send_frame(conn, W.T_FIN_OK, self.completed[sid])
            self.ev.emit("resume_after_complete", sid=sid.hex(), note="FIN_OK re-sent: transfer was already complete")
            return
        if sess is None:
            W.send_frame(conn, W.T_ERR, b"unknown_session")
            self.ev.emit("resume_unknown_session", sid=sid.hex())
            return
        with sess.lock:
            if sess.conn is not None and sess.conn is not conn:
                try:
                    sess.conn.close()
                except OSError:
                    pass
            sess.conn = conn
            rec = self._read_ckpt(sess)
            before = sess.expected
            if rec["i_star"] == C.NONE_IDX:
                sess.expected, sess.H = 0, b""
            else:
                sess.expected, sess.H = rec["i_star"] + 1, rec["h"]
            sess.nak_for = None
            rewound = max(0, before - sess.expected)
        W.send_frame(conn, W.T_RESUME_RESP, rec["raw"])
        self.ev.emit("resume_served", sid=sid.hex(),
                     i_star=(-1 if rec["i_star"] == C.NONE_IDX else rec["i_star"]),
                     o_star=rec["o_star"], h=rec["h"][:6].hex(), mac=rec["mac"][:6].hex(),
                     had_verified_until=before - 1, redo_chunks=rewound)
        self._serve(conn, rd, sess)

    # ----------------------------------------------------------- main loop
    def _serve(self, conn, rd, sess):
        try:
            while True:
                t, p = rd.read()
                if t == W.T_DATA:
                    self._on_data(conn, sess, p)
                elif t == W.T_REWIND:
                    self._on_rewind(conn, sess, p)
                elif t == W.T_FIN:
                    if self._on_fin(conn, sess, p):
                        return
                else:
                    W.send_frame(conn, W.T_ERR, b"unexpected message")
        except (ConnectionError, OSError, W.ProtocolError):
            with sess.lock:
                self.ev.emit("rx_link_lost", sid=sess.sid.hex(), verified_until=sess.expected - 1,
                             ckpt_i_star=self._ckpt_istar(sess))
            return

    def _ckpt_istar(self, sess):
        try:
            rec = self._read_ckpt(sess)
            return -1 if rec["i_star"] == C.NONE_IDX else rec["i_star"]
        except Exception:
            return None

    def _ack(self, conn, sess, idx_or_none):
        v = C.NONE_IDX if idx_or_none is None or idx_or_none < 0 else idx_or_none
        W.send_frame(conn, W.T_ACK, sess.sid + v.to_bytes(8, "big"))

    def _on_data(self, conn, sess, p):
        sid, idx, sealed = p[:4], int.from_bytes(p[4:12], "big"), p[12:]
        if sid != sess.sid:
            self.ev.emit("rx_wrong_session", got=sid.hex())
            return
        with sess.lock:
            if idx < sess.expected:                       # duplicate (e.g. after a replayed checkpoint)
                self.ev.emit("chunk_dup", i=idx)
                self._ack(conn, sess, sess.expected - 1)
                return
            if idx > sess.expected:                       # gap: ask once for the missing chunk
                if sess.nak_for != sess.expected:
                    sess.nak_for = sess.expected
                    self.ev.emit("chunk_gap", i=idx, want=sess.expected)
                    W.send_frame(conn, W.T_NAK, sess.sid + sess.expected.to_bytes(8, "big"))
                return
            try:
                plain = sess.cipher.open(idx, sealed)
            except C.InvalidTag:
                self.ev.emit("tag_reject", i=idx, n=len(sealed))
                sess.nak_for = idx
                W.send_frame(conn, W.T_NAK, sess.sid + idx.to_bytes(8, "big"))
                return
            sess.fh.seek(idx * sess.meta["chunk"])
            sess.fh.write(plain)
            sess.H = C.chain_next(sess.H, sealed)
            sess.expected += 1
            sess.nak_for = None
            self.ev.emit("chunk_ok", i=idx, n=len(plain), h=sess.H[:4].hex())
            self._ack(conn, sess, idx)
            n = sess.meta["n"]
            if n > 0 and sess.expected % n == 0 and sess.expected < sess.meta["nchunks"]:
                self._checkpoint(sess)

    def _checkpoint(self, sess):
        t0 = time.perf_counter()
        if self.fsync_data:
            os.fsync(sess.fh.fileno())            # data must be on disk BEFORE the bookmark says so
        t_data = time.perf_counter() - t0
        if self.extra_delay:
            time.sleep(self.extra_delay)          # emulate a slow flash chip (phone) if requested
        i_star = sess.expected - 1
        o_star = min(sess.expected * sess.meta["chunk"], sess.meta["size"])
        rec = C.pack_ckpt(sess.Kck, sess.sid, i_star, o_star, sess.H)
        t_write = C.atomic_write(sess.ckpt_path, rec)
        sess.n_ckpts += 1
        self.ev.emit("checkpoint", i_star=i_star, o_star=o_star, h=sess.H[:6].hex(),
                     mac=rec[52:58].hex(), t_data_ms=round(t_data * 1e3, 3),
                     t_write_ms=round(t_write * 1e3, 3),
                     t_ck_ms=round((time.perf_counter() - t0) * 1e3, 3), k=sess.n_ckpts)

    def _on_rewind(self, conn, sess, p):
        to = int.from_bytes(p[4:12], "big")
        with sess.lock:
            before = sess.expected
            if to != 0:
                W.send_frame(conn, W.T_ERR, b"can only rewind to 0")
                return
            sess.expected, sess.H, sess.nak_for = 0, b"", None
        self.ev.emit("rewind", to=0, was=before - 1)
        self._ack(conn, sess, None)

    def _on_fin(self, conn, sess, p):
        want_sha, n = p[:32], int.from_bytes(p[32:40], "big")
        with sess.lock:
            if sess.expected != n:
                self.ev.emit("fin_incomplete", have=sess.expected, need=n)
                W.send_frame(conn, W.T_ERR, b"incomplete")
                return False
            os.fsync(sess.fh.fileno())
            t0 = time.perf_counter()
            actual = bytes.fromhex(C.sha256_file(sess.part_path))
            t_hash = (time.perf_counter() - t0) * 1e3
            if actual != want_sha:
                self.ev.emit("file_corrupt", expected=want_sha.hex()[:16], got=actual.hex()[:16])
                W.send_frame(conn, W.T_ERR, b"hash_mismatch")
                return False
            sess.fh.close()
            os.replace(sess.part_path, sess.final_path)
            sess.done = True
            self.ev.emit("file_verified", sha256=actual.hex(), bytes=sess.meta["size"],
                         t_hash_ms=round(t_hash, 2), path=sess.final_path)
            W.send_frame(conn, W.T_FIN_OK, actual)
            for pth in (sess.ckpt_path, sess.sess_path):
                if pth and os.path.exists(pth):
                    os.remove(pth)
            self.sessions.pop(sess.sid, None)
            self.completed[sess.sid] = actual
            if self.persist:
                with open(os.path.join(self.state_dir, f"done_{sess.sid.hex()}.sha"), "w") as f:
                    f.write(actual.hex())
            self.ev.emit("transfer_complete", path=sess.final_path)
            return True
