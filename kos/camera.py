"""Cameras the OS can read for an app (V4L2: the ordinary Linux webcam interface).

An app never opens a camera (kos-hardware: apps get commands, never devices). The OS opens it, takes a few
greyscale pictures, closes it, and hands the pictures over, only through the ``camera`` service group and
only after the owner typed the password for that capture. There is no background capture: a capture is one
bounded call (at most 30 seconds), the camera is open only inside it, and it is closed in a ``finally``.

What it can do: a camera that offers plain YUYV (most webcams do). It keeps the brightness (the Y bytes),
shrinks the picture by whole-number averaging, and returns it. It cannot decode MJPEG (there is no JPEG
decoder in the standard library), does not take colour, and does not synchronise two cameras in hardware:
the cameras are read one after the other, a few milliseconds apart, so a fast-moving thing is seen in two
places. Two or more cameras must give the same picture size.

**This code has never run against a real camera.** It is tested against a fake kernel built from the same
structure layouts (``tests/test_camera.py``), and its ioctl numbers are checked against the values 64-bit
Linux uses. Only 64-bit is supported: the structures are laid out for it and it refuses to start otherwise.
"""

from __future__ import annotations

import contextlib
import fcntl
import mmap
import os
import re
import select
import stat
import struct
import time
from pathlib import Path

V4L = Path("/sys/class/video4linux")
DEV = Path("/dev")
NODE_RE = re.compile(r"^video([0-9]{1,3})$")
V4L_MAJOR = 81                 # character device major number of video4linux
MAX_CAMERAS = 4
MAX_SECONDS = 30
MAX_REPLY_CHARS = 600_000      # of hex characters in one answer (a reply may carry 700,000 characters)
WARM_UP = 3                    # frames thrown away first so auto-exposure settles


class CameraError(Exception):
    pass


# ---- the kernel's structures (64-bit) ------------------------------------------------------------------

def _ioc(direction: int, nr: int, size: int) -> int:
    return (direction << 30) | (size << 16) | (ord("V") << 8) | nr


FMT_SIZE, REQ_SIZE, BUF_SIZE = 208, 20, 88
VIDIOC_S_FMT = _ioc(3, 5, FMT_SIZE)
VIDIOC_REQBUFS = _ioc(3, 8, REQ_SIZE)
VIDIOC_QUERYBUF = _ioc(3, 9, BUF_SIZE)
VIDIOC_QBUF = _ioc(3, 15, BUF_SIZE)
VIDIOC_DQBUF = _ioc(3, 17, BUF_SIZE)
VIDIOC_STREAMON = _ioc(1, 18, 4)
VIDIOC_STREAMOFF = _ioc(1, 19, 4)
BUF_TYPE_CAPTURE, MEMORY_MMAP, FIELD_NONE = 1, 1, 1
PIX_YUYV = 0x56595559          # 'YUYV'
# index, type, bytesused, flags, field, pad, timestamp (2 x 8), timecode (16), sequence, memory,
# offset (8), length, reserved2, request_fd, pad  = 88 bytes
BUF = struct.Struct("=IIIII4xqq16sIIQIIi4x")
assert BUF.size == BUF_SIZE


def format_request(width: int, height: int) -> bytes:
    pix = struct.pack("=12I", width, height, PIX_YUYV, FIELD_NONE, 0, 0, 0, 0, 0, 0, 0, 0)
    data = struct.pack("=I4x", BUF_TYPE_CAPTURE) + pix + bytes(200 - len(pix))
    assert len(data) == FMT_SIZE
    return data


def format_answer(data: bytes) -> tuple:
    """(width, height, pixel format) the driver settled on."""
    if len(data) != FMT_SIZE:
        raise CameraError("the driver answered with the wrong size")
    return struct.unpack_from("=III", data, 8)


class _Kernel:
    """The few calls that reach the kernel. Tests hand the stream a fake with the same four methods."""

    @staticmethod
    def open(path: str) -> int:
        return os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)

    @staticmethod
    def ioctl(fd: int, request: int, data: bytes) -> bytes:
        buf = bytearray(data)
        fcntl.ioctl(fd, request, buf, True)
        return bytes(buf)

    @staticmethod
    def mmap(fd: int, length: int, offset: int):
        return mmap.mmap(fd, length, mmap.MAP_SHARED, mmap.PROT_READ, offset=offset)

    @staticmethod
    def wait(fd: int, ms: int) -> bool:
        p = select.poll()
        p.register(fd, select.POLLIN)
        return bool(p.poll(ms))

    @staticmethod
    def close(fd: int) -> None:
        os.close(fd)

    @staticmethod
    def fstat(fd: int):
        return os.fstat(fd)


class V4L2Stream:
    """One camera, streaming, for the length of a ``with`` block. ``grab()`` returns the newest picture's
    brightness bytes at the camera's own size."""

    def __init__(self, node: int, width: int, height: int, kernel=None):
        if struct.calcsize("P") != 8:
            raise CameraError("cameras are supported on 64-bit systems only")
        if not (isinstance(node, int) and 0 <= node <= 999):
            raise CameraError("bad camera")
        self.node, self.k = node, kernel or _Kernel
        self.want = (width, height)
        self.fd, self.maps, self.size, self.on = None, [], (0, 0), False

    def __enter__(self) -> "V4L2Stream":
        try:
            self._start()
        except BaseException:
            self._stop()
            raise
        return self

    def __exit__(self, *exc) -> None:
        self._stop()

    def _start(self) -> None:
        k = self.k
        try:
            self.fd = k.open(f"{DEV}/video{self.node}")
        except OSError as e:
            raise CameraError(f"cannot open video{self.node}: {e.strerror or 'refused'}") from None
        st = k.fstat(self.fd)
        if not stat.S_ISCHR(st.st_mode) or os.major(st.st_rdev) != V4L_MAJOR:
            raise CameraError(f"video{self.node} is not a camera")
        try:
            w, h, fmt = format_answer(k.ioctl(self.fd, VIDIOC_S_FMT, format_request(*self.want)))
            if fmt != PIX_YUYV:
                raise CameraError("this camera does not offer plain YUYV pictures (MJPEG is not supported)")
            if not (16 <= w <= 4096 and 16 <= h <= 4096):
                raise CameraError("the camera chose a picture size that makes no sense")
            self.size = (w, h)
            req = struct.pack("=IIII4B", 3, BUF_TYPE_CAPTURE, MEMORY_MMAP, 0, 0, 0, 0, 0)
            count = struct.unpack_from("=I", k.ioctl(self.fd, VIDIOC_REQBUFS, req))[0]
            if not 2 <= count <= 8:
                raise CameraError("the camera gave too few buffers")
            for i in range(count):
                b = BUF.pack(i, BUF_TYPE_CAPTURE, 0, 0, FIELD_NONE, 0, 0, bytes(16), 0, MEMORY_MMAP, 0, 0, 0, 0)
                got = BUF.unpack(k.ioctl(self.fd, VIDIOC_QUERYBUF, b))
                offset, length = got[10], got[11]
                if not 0 < length <= 64 << 20:
                    raise CameraError("the camera gave a buffer of a size that makes no sense")
                self.maps.append(k.mmap(self.fd, length, offset))
                k.ioctl(self.fd, VIDIOC_QBUF, b)
            k.ioctl(self.fd, VIDIOC_STREAMON, struct.pack("=i", BUF_TYPE_CAPTURE))
            self.on = True
        except OSError as e:
            raise CameraError(f"camera error: {e.strerror or 'failed'}") from None

    def _stop(self) -> None:
        k = self.k
        if self.fd is not None and self.on:
            with contextlib.suppress(OSError, CameraError):
                k.ioctl(self.fd, VIDIOC_STREAMOFF, struct.pack("=i", BUF_TYPE_CAPTURE))
        self.on = False
        for m in self.maps:
            with contextlib.suppress(Exception):
                m.close()
        self.maps = []
        if self.fd is not None:
            with contextlib.suppress(OSError):
                k.close(self.fd)
            self.fd = None

    def grab(self, skip: int = 0, timeout_ms: int = 2000) -> bytes:
        """The brightness of the newest picture; ``skip`` pictures are taken and thrown away first."""
        w, h = self.size
        k, last = self.k, b""
        for _ in range(skip + 1):
            if not k.wait(self.fd, timeout_ms):
                raise CameraError(f"video{self.node} gave no picture in {timeout_ms} ms")
            probe = BUF.pack(0, BUF_TYPE_CAPTURE, 0, 0, FIELD_NONE, 0, 0, bytes(16), 0, MEMORY_MMAP, 0, 0, 0, 0)
            got = BUF.unpack(k.ioctl(self.fd, VIDIOC_DQBUF, probe))
            index, used = got[0], got[2]
            if not 0 <= index < len(self.maps) or not 0 < used <= len(self.maps[index]):
                raise CameraError("the camera returned a picture that does not fit its buffer")
            data = bytes(self.maps[index][:used])
            k.ioctl(self.fd, VIDIOC_QBUF, BUF.pack(index, BUF_TYPE_CAPTURE, 0, 0, FIELD_NONE, 0, 0, bytes(16), 0,
                                                    MEMORY_MMAP, 0, 0, 0, 0))
            last = data
        if len(last) < w * h * 2:
            raise CameraError("the picture is smaller than the camera said")
        return last[0:w * h * 2:2]          # YUYV: every other byte is the brightness


# ---- turning what the camera gave into what Atlas wants -------------------------------------------------

def shrunk_size(w: int, h: int, tw: int, th: int) -> tuple:
    """The size ``shrink`` will give: whole blocks, rounded so the result is never larger than asked for."""
    fx, fy = max(1, -(-w // tw)), max(1, -(-h // th))
    return w // fx, h // fy


def shrink(grey: bytes, w: int, h: int, tw: int, th: int) -> bytes:
    """``grey`` (w x h) averaged down by whole blocks to at most tw x th (see ``shrunk_size``)."""
    if len(grey) != w * h or tw < 1 or th < 1:
        raise CameraError("bad picture")
    fx, fy = max(1, -(-w // tw)), max(1, -(-h // th))
    ow, oh = w // fx, h // fy
    out = bytearray()
    area = fx * fy
    for y in range(oh):
        acc = [0] * ow
        for j in range(fy):
            row = grey[(y * fy + j) * w:(y * fy + j) * w + ow * fx]
            for i in range(fx):
                acc = [a + b for a, b in zip(acc, row[i::fx])]
        out.extend(a // area for a in acc)
    return bytes(out)


def list_cameras(root: Path | None = None) -> list:
    """``[{"node": N, "name": ...}]``: the capture nodes of the cameras plugged in."""
    root = root or V4L
    out = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return out
    for n in names:
        m = NODE_RE.match(n)
        if not m:
            continue
        try:
            with open(root.joinpath(n, "index"), "rb") as f:
                if f.read(8).strip() != b"0":          # the other nodes of a camera carry metadata, not pictures
                    continue
            with open(root.joinpath(n, "name"), "rb") as f:
                name = f.read(80).decode("utf-8", "replace").strip()
        except OSError:
            continue
        out.append({"node": int(m.group(1)), "name": name[:60] or "camera"})
    return out[:16]


def check_budget(cams: int, width: int, height: int, count: int, every_ms: int) -> None:
    """Refuse a capture that would not fit in one answer or would run too long."""
    if not 1 <= cams <= MAX_CAMERAS:
        raise CameraError(f"between 1 and {MAX_CAMERAS} cameras")
    if cams * width * height * 2 * count > MAX_REPLY_CHARS:
        raise CameraError("that is more picture than one answer can carry: fewer pictures or a smaller size")
    if count * every_ms > MAX_SECONDS * 1000:
        raise CameraError(f"a capture may last at most {MAX_SECONDS} seconds")


def capture(nodes: list, width: int, height: int, count: int, every_ms: int, kernel=None, now=None) -> dict:
    """Take ``count`` sets of pictures, one per camera in ``nodes``, ``every_ms`` apart. Every camera is
    started first, then read in turn each time, so the pictures of one set are a few milliseconds apart and
    no more. Cameras are closed whatever happens. Returns ``{"w", "h", "sets": [{"t": seconds, "frames":
    [hex, ...]}]}`` with one hex string of brightness bytes per camera."""
    check_budget(len(nodes), width, height, count, every_ms)
    if len(set(nodes)) != len(nodes):
        raise CameraError("the same camera twice")
    stamp = now or (lambda: time.time_ns() // 1_000_000_000)
    sets, size = [], None
    with contextlib.ExitStack() as stack:
        streams = [stack.enter_context(V4L2Stream(n, width, height, kernel)) for n in nodes]
        if len({s.size for s in streams}) != 1:
            raise CameraError("the cameras give different picture sizes: they cannot be compared")
        nw, nh = streams[0].size
        for i in range(count):
            frames = [shrink(s.grab(WARM_UP if i == 0 else 0), nw, nh, width, height) for s in streams]
            size = shrunk_size(nw, nh, width, height)
            sets.append({"t": stamp(), "frames": [f.hex() for f in frames]})
            if i + 1 < count and every_ms:
                select.poll().poll(every_ms)               # nothing is registered: this only waits
    return {"w": size[0], "h": size[1], "sets": sets}
