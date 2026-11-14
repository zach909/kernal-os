"""File names that are safe to receive and that survive every operating system data may move to.

Two different questions, kept apart on purpose:

* ``safe_relative`` is **security**. A path that arrives from another device (a sync peer, a
  migration bundle) is hostile input. It must be relative, free of ``..``, drive letters,
  backslashes, NUL and control characters, and it must not name KOS's own bookkeeping. A path
  that fails is refused, never repaired.
* ``problems`` / ``portable`` are **portability**. A name that is legal on Linux can be illegal
  on Windows (``a:b``, ``con``, a trailing dot) or collide on macOS and Windows (``A.txt`` and
  ``a.txt``, or the same accented letter composed two ways). ``problems`` lists what would break;
  ``portable`` gives a deterministic replacement so nothing is dropped, and the original name is
  kept by the caller in its manifest.

Whole numbers only (rule 1): no decimals anywhere in this file. Standard library only.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata

MAX_COMPONENT = 255        # bytes of UTF-8: the smallest limit among ext4, APFS and NTFS
MAX_PATH = 1024            # whole relative path; Windows' old 260 limit is opt-out on current releases
MAX_DEPTH = 64
RESERVED_PREFIX = ".kos-"  # KOS's own bookkeeping inside a synced or restored tree

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")
_WINDOWS_BAD = set('<>:"|?*\\')
_WINDOWS_RESERVED = {"con", "prn", "aux", "nul",
                     *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
_DRIVE = re.compile(r"^[A-Za-z]:")


class PathRefused(ValueError):
    """The path is hostile or malformed. Nothing is written for it."""


def normalize(rel: str) -> str:
    """The one spelling KOS compares and stores: Unicode NFC, forward slashes."""
    return unicodedata.normalize("NFC", rel)


def safe_relative(rel: str) -> str:
    """``rel`` unchanged if it is a safe relative path, else ``PathRefused``. Checks bytes, not intent."""
    if not isinstance(rel, str) or not rel:
        raise PathRefused("a path must be non-empty text")
    if len(rel.encode("utf-8", "surrogatepass")) > MAX_PATH:
        raise PathRefused(f"path longer than {MAX_PATH} bytes")
    if _CONTROL.search(rel):
        raise PathRefused("path contains a control character")
    if "\\" in rel or rel.startswith("/") or _DRIVE.match(rel):
        raise PathRefused("path must be relative and use / only (no drive letter, no backslash)")
    parts = rel.split("/")
    if len(parts) > MAX_DEPTH:
        raise PathRefused(f"path deeper than {MAX_DEPTH} folders")
    for part in parts:
        if part in ("", ".", ".."):
            raise PathRefused("path has an empty, '.' or '..' part")
        if len(part.encode("utf-8", "surrogatepass")) > MAX_COMPONENT:
            raise PathRefused(f"a name is longer than {MAX_COMPONENT} bytes")
        if part.startswith(RESERVED_PREFIX):
            raise PathRefused(f"names starting {RESERVED_PREFIX!r} belong to KOS")
    return rel


def problems(rel: str) -> list[str]:
    """What would stop this (already safe) path existing on Windows or macOS. Empty means portable."""
    out = []
    for part in rel.split("/"):
        stem = part.split(".")[0].lower()
        if any(c in _WINDOWS_BAD for c in part):
            out.append(f"{part!r}: has a character Windows forbids")
        if stem in _WINDOWS_RESERVED:
            out.append(f"{part!r}: is a reserved Windows device name")
        if part.endswith((" ", ".")):
            out.append(f"{part!r}: ends with a space or dot (Windows drops it)")
    return out


def _fix_part(part: str) -> str:
    changed = False
    clean = "".join("_" if c in _WINDOWS_BAD else c for c in part)
    changed = clean != part
    if clean.split(".")[0].lower() in _WINDOWS_RESERVED:
        clean, changed = "_" + clean, True
    stripped = clean.rstrip(" .")
    if stripped != clean or not stripped:
        clean, changed = (stripped or "_"), True
    if not changed:
        return part
    tag = hashlib.sha256(part.encode("utf-8", "surrogatepass")).hexdigest()[:6]
    stem, dot, ext = clean.rpartition(".")
    # the tag makes the mapping injective: two different originals never share a replacement
    return f"{stem}~{tag}.{ext}" if dot and stem else f"{clean}~{tag}"


def portable(rel: str) -> str:
    """A deterministic, portable spelling of a safe path. Identical for a portable input."""
    return "/".join(_fix_part(p) for p in rel.split("/"))


def collisions(paths) -> list[tuple[str, str]]:
    """Pairs of paths that become one file on a case-insensitive or normalising file system
    (macOS APFS default, Windows NTFS): same text after NFC and case-folding."""
    seen: dict[str, str] = {}
    out = []
    for p in sorted(paths):
        key = unicodedata.normalize("NFC", p).casefold()
        if key in seen and seen[key] != p:
            out.append((seen[key], p))
        else:
            seen[key] = p
    return out
