"""A plain-text summary for every user file.

A *user file* is anything the user's data ends up in: an item in an app's vault
or a shared folder (``vault.py``, which is where every export - text, SVG,
PPM, PNG - lands), a file written with ``kos write`` (``admin.py``), and a file
in a backup (``backup.py``). Each gets a short summary written in text, so a
file that is not text (an image, an archive, a binary) can still be read, found
and described, and a file that *is* text but is really a drawing (box lines,
block characters) is described as a drawing rather than shown as noise.

Rules this module keeps:

* **Deterministic and local.** No model, no network, no dependency: the same
  bytes always give the same summary, so the summary can be keyed by the
  content hash and can never go stale.
* **Untrusted data.** A summary quotes the file (its first line, an SVG title).
  That text is stripped of control characters and cut short, and is only ever
  shown as data, never as an instruction.
* **Never fails a write.** Hostile or broken input gives a plain "unreadable"
  summary, not an exception.

Honest limit: this describes the *kind, size and shape* of a file ("PNG image,
64x48 pixels") and quotes its start. It does not understand what a picture
shows - that would need a model, which this layer deliberately does not use.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import struct
from pathlib import Path

from .paths import Paths, atomic_write

MAX_SUMMARY = 300           # characters
_QUOTE = 70                 # characters of the file quoted back
_SCAN = 1 << 20             # bytes looked at; a bigger file is summarised from its start
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f  ]")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_DRAWING_CHARS = set("─│┌┐└┘├┤┬┴┼═║╔╗╚╝█▀▄▌▐░▒▓■□●○◆◇▲△▼▽*+#|/\\_-=<>^~")


def _clean(s: str, limit: int = _QUOTE) -> str:
    s = _CTRL.sub(" ", s).strip()
    s = re.sub(r"\s+", " ", s)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _size(n: int) -> str:
    return f"{n:,} byte{'' if n == 1 else 's'}"


def _png_dims(b: bytes):
    if b[:8] == b"\x89PNG\r\n\x1a\n" and b[12:16] == b"IHDR" and len(b) >= 24:
        return struct.unpack(">II", b[16:24])
    return None


def _looks_like_drawing(text: str) -> bool:
    """Text art: several lines in which most non-space characters are drawing symbols."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return False
    chars = [c for ln in lines for c in ln if not c.isspace()]
    if not chars:
        return False
    art = sum(1 for c in chars if c in _DRAWING_CHARS)
    letters = sum(1 for c in chars if c.isalnum())
    # art/n >= 6/10 and letters/n < 3/10, in whole numbers
    return art * 10 >= len(chars) * 6 and letters * 10 < len(chars) * 3


def _text_summary(name: str, text: str, total: int) -> str:
    lines = text.splitlines()
    first = next((ln for ln in lines if ln.strip()), "")
    if text.lstrip()[:5].lower() in ("<svg ", "<?xml") or "<svg" in text[:400].lower():
        shapes = len(re.findall(r"<(?:rect|circle|ellipse|line|polyline|polygon|path|text)\b", text))
        m = re.search(r"viewBox=\"([^\"]{1,60})\"", text) or re.search(r"width=\"([^\"]{1,20})\"", text)
        t = re.search(r"<title>([^<]{1,120})</title>", text)
        out = f"SVG drawing, {shapes} shape(s)"
        if m:
            out += f", size {_clean(m.group(1), 40)}"
        if t:
            out += f', titled "{_clean(t.group(1))}"'
        return out + f"; {_size(total)}"
    if re.match(r"\s*P[1-6]\s", text[:4]):
        parts = text.split(None, 4)
        if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
            return f"PPM image (text), {parts[1]}x{parts[2]} pixels; {_size(total)}"
    if _looks_like_drawing(text):
        width = max((len(ln) for ln in lines), default=0)
        return (f"text drawing, {len(lines)} line(s) up to {width} characters wide; "
                f"{_size(total)}; starts with: \"{_clean(first)}\"")
    words = len(text.split())
    return (f"text, {len(lines)} line(s), {words} word(s); {_size(total)}; "
            f"starts with: \"{_clean(first)}\"" if first else
            f"empty or blank text; {_size(total)}")


def summarize(name: str, data: bytes) -> str:
    """One short line of text describing ``data``. Never raises."""
    try:
        return _clean(_summarize(name, data), MAX_SUMMARY)
    except Exception:                                   # hostile bytes must not break a write
        return _clean(f"file, {_size(len(data))}; could not be read for a summary", MAX_SUMMARY)


def _summarize(name: str, data: bytes) -> str:
    total = len(data)
    head = data[:_SCAN]
    if total == 0:
        return "empty file, 0 bytes"
    dims = _png_dims(head)
    if dims:
        return f"PNG image, {dims[0]}x{dims[1]} pixels; {_size(total)}"
    if name.endswith(".b64"):                           # a PNG exported as base64 text
        try:
            raw = base64.b64decode(head[:48], validate=True)     # 48 chars = 36 bytes: the PNG header
        except (binascii.Error, ValueError):
            raw = b""
        d = _png_dims(raw)
        if d:
            return f"PNG image stored as base64 text, {d[0]}x{d[1]} pixels; {_size(total)}"
    for magic, label in ((b"%PDF-", "PDF document"), (b"PK\x03\x04", "zip archive"),
                         (b"\x1f\x8b", "gzip data"), (b"\x7fELF", "ELF program"),
                         (b"GIF8", "GIF image"), (b"\xff\xd8\xff", "JPEG image"),
                         (b"RIFF", "RIFF media (audio or video)"), (b"OggS", "Ogg media")):
        if head.startswith(magic):
            return f"{label}; {_size(total)}; not text"
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None and "\x00" not in text:
        return _text_summary(name, text, total)
    return f"binary data; {_size(total)}; not text; first bytes {head[:8].hex()}"


class SummaryStore:
    """Summaries keyed by the SHA-256 of the content (``<state>/summaries/<sha>.txt``).
    Same bytes, same summary - so it follows a file through renames and backups
    and cannot describe the wrong content."""

    def __init__(self, paths: Paths):
        self.dir = paths.state.joinpath("summaries")

    def put(self, name: str, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        text = summarize(name, data)
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        atomic_write(self.dir.joinpath(f"{digest}.txt"), (text + "\n").encode("utf-8"))
        return text

    def get(self, digest: str):
        if not _SHA_RE.match(digest or ""):
            return None
        try:
            return (self.dir.joinpath(f"{digest}.txt")).read_text(encoding="utf-8").strip()
        except OSError:
            return None
