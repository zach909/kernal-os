"""List a whole folder tree in one go, for an app that wants to map it (Atlas files).

``files.list`` shows one folder and asks for the password each time; the guard that stops an app flooding
the owner with prompts (6 a minute) makes it useless for a tree of a hundred folders. This reads the tree
once, after one password that names the root, and hands back a flat list. It is bounded on every side:

* it never follows a symlink and never leaves the filesystem it started on;
* at most ``limit`` entries, ``depth`` levels deep, names at most 200 characters;
* with ``heads`` it also returns the first 1,500 characters of small text files (``head``) and the first 4 KiB of
  any other file as hex (``sample``: an image, an archive, anything), but never of a file whose *name* looks like
  a secret (``.env``, ``*.pem``, ``id_rsa``, anything with ``secret``, ``token``, ``password`` or ``credential``
  in it). That is a name pattern, not a classifier: a secret saved as ``notes.txt`` would be read. Together they
  are limited to 400,000 characters per call (so a reply always fits) and nothing bigger than 32 MiB is opened.
"""

from __future__ import annotations

import os
import re
import stat
import time

HEAD_CHARS = 1500
MAX_HEADS = 300
MAX_HEAD_FILE = 1 << 20
MAX_SAMPLE_FILE = 32 << 20
SAMPLE_BYTES = 4096
HEAD_BUDGET = 400_000
MAX_NAME = 200
SECRET_RE = re.compile(r"(^\.env|\.pem$|\.key$|\.p12$|\.pfx$|^id_(rsa|dsa|ecdsa|ed25519)|secret|token|passw|credential|"
                       r"\.kdbx$|\.keystore$|wallet)", re.I)
TEXT_EXT = frozenset({"", "txt", "md", "py", "js", "ts", "json", "html", "css", "c", "h", "cpp", "java", "kt", "go",
                      "rs", "sh", "toml", "yaml", "yml", "ini", "cfg", "csv", "rst", "tex", "sql", "xml"})


def walk(root: str, limit: int = 500, depth: int = 4, heads: bool = False) -> dict:
    """``{"root", "t", "entries": [{"path", "dir", "size", "head"? or "sample"?}], "truncated"}``, paths relative to ``root``."""
    root = os.path.abspath(root)
    try:
        st = os.lstat(root)
    except OSError as e:
        raise ValueError(f"cannot look at that: {e.strerror or 'refused'}") from None
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError("that is not a folder")
    dev = st.st_dev
    entries, truncated, head_count, budget = [], False, 0, HEAD_BUDGET
    stack = [("", 0)]
    while stack:
        rel, level = stack.pop()
        try:
            with os.scandir(os.path.join(root, rel) if rel else root) as it:
                found = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        subdirs = []
        for e in found:
            if len(entries) >= limit:
                truncated = True
                break
            if e.is_symlink() or len(e.name) > MAX_NAME or "\x00" in e.name or "/" in e.name:
                continue
            try:
                s = e.stat(follow_symlinks=False)
            except OSError:
                continue
            path = f"{rel}/{e.name}" if rel else e.name
            if stat.S_ISDIR(s.st_mode):
                if s.st_dev != dev:
                    continue
                entries.append({"path": path, "dir": True, "size": 0})
                if level + 1 < depth:
                    subdirs.append((path, level + 1))
            elif stat.S_ISREG(s.st_mode):
                item = {"path": path, "dir": False, "size": s.st_size}
                if heads and head_count < MAX_HEADS and budget > 0 and not SECRET_RE.search(e.name):
                    got = _look(os.path.join(root, path), e.name, s.st_size)
                    if got is not None:
                        key, value = got
                        item[key] = value
                        head_count += 1
                        budget -= len(value)
                entries.append(item)
        stack.extend(reversed(subdirs))
        if truncated:
            break
    return {"root": root, "t": time.time_ns() // 1_000_000_000, "entries": entries, "truncated": truncated}


def _text_name(name: str) -> bool:
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ext in TEXT_EXT


def _look(path: str, name: str, size: int):
    """``("head", text)`` for a small text file, ``("sample", hex)`` for the start of anything else, or ``None``."""
    if _text_name(name) and size <= MAX_HEAD_FILE:
        text = _head(path)
        if text is not None:
            return "head", text
    if size <= MAX_SAMPLE_FILE:
        raw = _raw(path, SAMPLE_BYTES)
        if raw:
            return "sample", raw.hex()
    return None


def _raw(path: str, n: int):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, n)
    except OSError:
        return None
    finally:
        os.close(fd)


def _head(path: str):
    raw = _raw(path, HEAD_CHARS * 4)
    if raw is None or b"\x00" in raw:
        return None
    return raw.decode("utf-8", "replace")[:HEAD_CHARS]
