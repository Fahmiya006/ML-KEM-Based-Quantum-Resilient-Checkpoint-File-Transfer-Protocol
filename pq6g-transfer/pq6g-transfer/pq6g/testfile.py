"""Create a deterministic test file: a small PNG banner followed by padding.

The banner gives the quantum-attack demo something recognisable to steal: if the
attacker decrypts the first chunk, a readable image appears.  Pure Python, no Pillow.
"""
from __future__ import annotations

import hashlib
import struct
import zlib

_FONT = {
    "A": "01110 10001 10001 11111 10001 10001 10001", "C": "01110 10001 10000 10000 10000 10001 01110",
    "D": "11110 10001 10001 10001 10001 10001 11110", "E": "11111 10000 10000 11110 10000 10000 11111",
    "F": "11111 10000 10000 11110 10000 10000 10000", "G": "01110 10001 10000 10111 10001 10001 01111",
    "I": "01110 00100 00100 00100 00100 00100 01110", "L": "10000 10000 10000 10000 10000 10000 11111",
    "M": "10001 11011 10101 10101 10001 10001 10001", "N": "10001 11001 10101 10011 10001 10001 10001",
    "O": "01110 10001 10001 10001 10001 10001 01110", "P": "11110 10001 10001 11110 10000 10000 10000",
    "Q": "01110 10001 10001 10001 10101 10010 01101", "T": "11111 00100 00100 00100 00100 00100 00100",
    "6": "00110 01000 10000 11110 10001 10001 01110", " ": "00000 00000 00000 00000 00000 00000 00000",
}


def _text_pixels(text, scale):
    """-> list of rows, each a list of 0/1, for the text at the given pixel scale."""
    rows = [[] for _ in range(7 * scale)]
    for ch in text:
        glyph = _FONT.get(ch, _FONT[" "]).split()
        for r in range(7):
            line = []
            for c in range(5):
                line += [int(glyph[r][c])] * scale
            line += [0] * scale                      # letter spacing
            for k in range(scale):
                rows[r * scale + k] += line
    return rows


def make_banner_png(width=520, height=210) -> bytes:
    px = [[(14 + 40 * x // width, 33 + 60 * x // width, 61 + 50 * x // width) for x in range(width)] for _ in range(height)]
    for y in range(height):                           # vertical shade
        for x in range(width):
            r, g, b = px[y][x]
            f = 0.75 + 0.25 * y / height
            px[y][x] = (int(r * f), int(g * f), int(b * f))

    def blit(rows, x0, y0, color):
        for j, row in enumerate(rows):
            for i, v in enumerate(row):
                if v and 0 <= y0 + j < height and 0 <= x0 + i < width:
                    px[y0 + j][x0 + i] = color

    big = _text_pixels("CONFIDENTIAL", 5)
    blit(big, (width - len(big[0])) // 2, 52, (255, 255, 255))
    small = _text_pixels("PQ6G DEMO FILE", 3)
    blit(small, (width - len(small[0])) // 2, 120, (249, 115, 22))
    for x in range(width):                            # border
        for t in range(4):
            px[t][x] = px[height - 1 - t][x] = (249, 115, 22)
    for y in range(height):
        for t in range(4):
            px[y][t] = px[y][width - 1 - t] = (249, 115, 22)
    raw = b"".join(b"\x00" + bytes(c for p in row for c in p) for row in px)

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def make_test_file(path: str, mb: float = 100.0):
    target = int(mb * 1024 * 1024)
    banner = make_banner_png()
    with open(path, "wb") as f:
        f.write(banner)
        written, i = len(banner), 0
        buf = []
        while written < target:
            line = f"pq6g demo payload block {i:09d} {hashlib.sha256(str(i).encode()).hexdigest()}\n".encode()
            buf.append(line)
            written += len(line)
            i += 1
            if len(buf) >= 20000:
                f.write(b"".join(buf))
                buf = []
        f.write(b"".join(buf))
        f.truncate(target)


def png_prefix(data: bytes):
    """Extract the PNG banner from the start of a (recovered) file, or None."""
    if not data.startswith(b"\x89PNG"):
        return None
    end = data.find(b"IEND")
    return data[:end + 8] if end != -1 else None
