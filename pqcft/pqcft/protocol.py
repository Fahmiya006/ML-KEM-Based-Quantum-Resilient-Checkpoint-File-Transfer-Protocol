"""
Wire protocol.

Every message is a frame:  [1B type][4B big-endian length][payload]

Handshake (client = sender, server = receiver):

    C -> S   HELLO      json: session, file metadata, scheme, resume_mode
    S -> C   HELLO_ACK  json: {resume_from, need_handshake}
    S -> C   KEM_PUB    raw encapsulation key      (if need_handshake)
    C -> S   KEM_CT     raw ciphertext             (if need_handshake)
    C -> S   CHUNK      [8B index][AES-256-GCM ciphertext]  ... repeated
    S -> C   ACK        [8B next_chunk]            (one per checkpoint write)
    C -> S   FIN
    S -> C   DONE       json: {ok, file_hash, verified}

Session key = HKDF(shared_secret, salt=transcript_hash) where the transcript is
HELLO || KEM_PUB || KEM_CT. Binding to the transcript means a tampered HELLO
(e.g. a downgraded scheme or altered chunk_size) yields a different key and the
first chunk fails to authenticate.
"""

from __future__ import annotations

import json
import socket
import struct
from typing import Tuple

MAGIC_VERSION = 1

HELLO = 0x01
HELLO_ACK = 0x02
KEM_PUB = 0x03
KEM_CT = 0x04
CHUNK = 0x05
ACK = 0x06
FIN = 0x07
DONE = 0x08
ABORT = 0x09

NAMES = {
    HELLO: "HELLO", HELLO_ACK: "HELLO_ACK", KEM_PUB: "KEM_PUB", KEM_CT: "KEM_CT",
    CHUNK: "CHUNK", ACK: "ACK", FIN: "FIN", DONE: "DONE", ABORT: "ABORT",
}

MAX_FRAME = 8 << 20


class ProtocolError(Exception):
    pass


class Disconnected(ProtocolError):
    """Peer vanished mid-frame -- i.e. the 6G link dropped."""


def send_frame(sock: socket.socket, mtype: int, payload: bytes = b"") -> int:
    if len(payload) > MAX_FRAME:
        raise ProtocolError(f"frame too large: {len(payload)}")
    header = struct.pack(">BI", mtype, len(payload))
    try:
        sock.sendall(header + payload)
    except OSError as e:
        raise Disconnected(str(e)) from e
    return len(header) + len(payload)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout as e:
            raise Disconnected("timeout") from e
        except OSError as e:
            raise Disconnected(str(e)) from e
        if not chunk:
            raise Disconnected("peer closed")
        buf += chunk
    return bytes(buf)


def recv_frame(sock: socket.socket) -> Tuple[int, bytes]:
    mtype, length = struct.unpack(">BI", _recv_exact(sock, 5))
    if length > MAX_FRAME:
        raise ProtocolError(f"declared frame too large: {length}")
    return mtype, _recv_exact(sock, length) if length else b""


def send_json(sock: socket.socket, mtype: int, obj: dict) -> int:
    return send_frame(sock, mtype, json.dumps(obj, separators=(",", ":")).encode())


def parse_json(payload: bytes) -> dict:
    return json.loads(payload.decode())


def pack_chunk(index: int, ciphertext: bytes) -> bytes:
    return struct.pack(">Q", index) + ciphertext


def unpack_chunk(payload: bytes) -> Tuple[int, bytes]:
    if len(payload) < 8:
        raise ProtocolError("short chunk frame")
    return struct.unpack(">Q", payload[:8])[0], payload[8:]
