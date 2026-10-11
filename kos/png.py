"""PNG output for screenshots. Standard library only (zlib)."""

from __future__ import annotations

import struct
import zlib


def encode(width: int, height: int, bgrx: bytes) -> bytes:
    """A 24-bit RGB PNG from a Framebuffer's BGRX bytes."""
    raw = bytearray()
    stride = width * 4
    for y in range(height):
        row = bgrx[y * stride:(y + 1) * stride]
        rgb = bytearray(width * 3)
        rgb[0::3], rgb[1::3], rgb[2::3] = row[2::4], row[1::4], row[0::4]
        raw += b"\x00" + rgb

    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 6)) + chunk(b"IEND", b""))


def save(fb, path) -> None:
    with open(path, "wb") as f:
        f.write(encode(fb.width, fb.height, bytes(fb.buf)))
