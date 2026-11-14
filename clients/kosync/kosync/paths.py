"""File names across operating systems.

A name that is fine on Linux can be illegal on Windows (``a:b``, ``CON``, a trailing dot) and two names that
differ only in case collide on Windows and macOS. ``plan`` gives every path a legal, unique name on the target
OS and returns the full list of changes, so nothing is dropped and nothing is renamed without being reported.
"""

from __future__ import annotations

import re
import sys
import unicodedata

OS_NAMES = ("linux", "macos", "windows", "android", "ios", "kos")
CASE_INSENSITIVE = {"windows", "macos", "ios", "android"}     # the default file systems on these
MAX_PATH_BYTES = 4096
MAX_COMPONENT = 255
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_WIN_BAD = re.compile(r'[<>:"|?*\\\x00-\x1f]')
_MAC_BAD = re.compile(r"[:\x00-\x1f]")
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


class PathError(ValueError):
    pass


def detect_os() -> str:
    p = sys.platform
    if p.startswith("win"):
        return "windows"
    if p == "darwin":
        return "macos"
    if p == "ios":
        return "ios"
    if p == "android":
        return "android"
    return "linux"


def validate(path: str) -> str:
    """A path from a bundle or a sync folder is hostile input: relative, forward slashes, no dot parts."""
    if not isinstance(path, str) or not path:
        raise PathError("empty path")
    if len(path.encode("utf-8", "surrogatepass")) > MAX_PATH_BYTES:
        raise PathError("path too long")
    if _CONTROL.search(path):
        raise PathError("control character in path")
    if path.startswith("/"):
        raise PathError("absolute path")
    for part in path.split("/"):
        if part in ("", ".", ".."):
            raise PathError(f"bad path part {part!r}")
    return path


def _component(name: str, target: str) -> str:
    if target in ("windows", "android"):
        name = _WIN_BAD.sub("_", name)
    elif target in ("macos", "ios"):
        name = _MAC_BAD.sub("_", name)
    if target == "windows":
        name = name.rstrip(" .") or "_"
        if name.split(".")[0].rstrip(" ").upper() in _RESERVED:
            name = "_" + name
    if len(name) > MAX_COMPONENT:
        stem, dot, ext = name.rpartition(".")
        ext = ("." + ext) if dot and len(ext) < 32 else ""
        name = name[:MAX_COMPONENT - len(ext)] + ext
    return name or "_"


def _key(name: str, target: str) -> str:
    if target in CASE_INSENSITIVE:
        return unicodedata.normalize("NFC", name).casefold()
    return name


def _with_suffix(name: str, n: int) -> str:
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem:
        return f"{name} (copy {n})"
    return f"{stem} (copy {n}).{ext}"


def plan(paths, target: str) -> dict[str, str]:
    """Map every original path to a path that is legal and unique on ``target``.

    Folders are renamed consistently (every file in a renamed folder follows it), and two names that would
    collide on the target (case, or because cleaning made them equal) get ``(copy N)`` instead of replacing
    one another. Order does not matter: the result depends only on the set of paths.
    """
    if target not in OS_NAMES:
        raise PathError(f"unknown OS {target!r}")
    prefixes = set()
    for p in paths:
        validate(p)
        parts = p.split("/")
        for i in range(1, len(parts) + 1):
            prefixes.add("/".join(parts[:i]))
    mapping: dict[str, str] = {}
    taken: dict[tuple[str, str], str] = {}
    for pre in sorted(prefixes, key=lambda s: (s.count("/"), s)):
        parent, _, name = pre.rpartition("/")
        new_parent = mapping[parent] if parent else ""
        new = _component(name, target)
        n = 1
        while (new_parent, _key(new, target)) in taken and taken[(new_parent, _key(new, target))] != pre:
            n += 1
            new = _with_suffix(_component(name, target), n)
        taken[(new_parent, _key(new, target))] = pre
        mapping[pre] = f"{new_parent}/{new}" if new_parent else new
    return {p: mapping[p] for p in paths}


def is_portable(path: str, target: str) -> bool:
    """True when ``path`` is already a legal name on ``target`` (so a sync can use it as it is)."""
    try:
        return plan([path], target)[path] == path
    except PathError:
        return False
