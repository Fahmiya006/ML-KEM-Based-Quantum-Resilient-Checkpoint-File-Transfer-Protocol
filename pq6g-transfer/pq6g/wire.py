"""Framing and message types.  Frame = type (1 B) | length (4 B, big endian) | payload."""
from __future__ import annotations

import socket
import struct

T_START = 1        # sender -> receiver   {"kem": ..., "v": 1}                 (new session)
T_HELLO = 2        # receiver -> sender   sid (4) || ML-KEM public key
T_KEMCT = 3        # sender -> receiver   ML-KEM ciphertext
T_META = 4         # sender -> receiver   sid || META_IDX || sealed JSON (name, size, chunk, nchunks, ckpt interval)
T_DATA = 5         # sender -> receiver   sid || chunk no. || sealed chunk (ciphertext || 16-byte tag)
T_ACK = 6          # receiver -> sender   sid || last in-order verified chunk (cumulative)
T_NAK = 7          # receiver -> sender   sid || chunk number it wants next
T_RESUME_REQ = 8   # sender -> receiver   sid
T_RESUME_RESP = 9  # receiver -> sender   84-byte signed checkpoint record
T_REWIND = 10      # sender -> receiver   sid || chunk number to restart from (safe fallback)
T_FIN = 11         # sender -> receiver   SHA-256 of whole file (32) || number of chunks (8)
T_FIN_OK = 12      # receiver -> sender   SHA-256 the receiver computed (32)
T_ERR = 13         # either               utf-8 reason

NAMES = {1: "START", 2: "HELLO", 3: "KEMCT", 4: "META", 5: "DATA", 6: "ACK", 7: "NAK",
         8: "RESUME_REQ", 9: "RESUME_RESP", 10: "REWIND", 11: "FIN", 12: "FIN_OK", 13: "ERR"}

MAX_PAYLOAD = 4 * 1024 * 1024
HDR = struct.Struct(">BI")


class ProtocolError(Exception):
    pass


def pack(t: int, payload: bytes = b"") -> bytes:
    return HDR.pack(t, len(payload)) + payload


def send_frame(sock: socket.socket, t: int, payload: bytes = b""):
    sock.sendall(pack(t, payload))


class FrameReader:
    """Buffered frame reader on a blocking socket."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = bytearray()

    def _fill(self, n: int):
        while len(self.buf) < n:
            chunk = self.sock.recv(max(65536, n - len(self.buf)))
            if not chunk:
                raise ConnectionError("connection closed by peer")
            self.buf += chunk

    def read_raw(self):
        """-> (type, payload, raw_frame_bytes)"""
        self._fill(HDR.size)
        t, ln = HDR.unpack_from(self.buf, 0)
        if ln > MAX_PAYLOAD:
            raise ProtocolError(f"frame too large: {ln}")
        self._fill(HDR.size + ln)
        raw = bytes(self.buf[:HDR.size + ln])
        del self.buf[:HDR.size + ln]
        return t, raw[HDR.size:], raw

    def read(self):
        t, payload, _ = self.read_raw()
        return t, payload


def tune(sock: socket.socket):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
