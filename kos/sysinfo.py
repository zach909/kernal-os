"""Read-only facts the system apps show: kernel protections, the audit log,
what is owed, directory listings, file text, scan reports.

Every function returns plain strings/dicts for the system bridge to send back
to an app. Nothing here changes anything, and nothing reveals file *contents*
except ``view_lines``, which the bridge only calls after the password.
"""

from __future__ import annotations

import os
import time

from .admin import AdminKeyboard
from .paths import Paths
from .protocol import clean_text
from .requires import Ledger
from .scan import scan_file
from .vfs import VFS, VFSError

MAX_ENTRIES = 300
MAX_VIEW_BYTES = 64 << 10
MAX_VIEW_LINES = 400


def doctor_lines() -> list[str]:
    from .sandbox import report
    r = report()
    yes = lambda b: "yes" if b else "NO"
    return [f"Landlock ABI        : {r['landlock_abi'] or 'NOT AVAILABLE'}",
            f"user namespaces     : {yes(r['user_namespaces'])}",
            f"KVM (kernel cells)  : {yes(r['kvm'])}",
            f"framebuffer         : {yes(r['framebuffer'])}",
            f"evdev (/dev/input)  : {yes(r['evdev'])}"]


def admin_line(paths: Paths) -> str:
    return clean_text(AdminKeyboard(paths).status(), 200)


def owed_lines(paths: Paths) -> list[str]:
    owed = Ledger(paths).owed()
    if not owed:
        return ["nothing is owed"]
    return [clean_text(f"{e['target']} still owes: {', '.join(e['pending'])}", 200) for e in owed]


def audit_lines(paths: Paths, n: int = 12) -> list[str]:
    from .auth import AuditLog
    out = []
    for e in AuditLog(paths).entries()[-n:]:
        t = time.strftime("%H:%M:%S", time.localtime(e["t"]))
        out.append(clean_text(f"{t} {e['outcome']:<10} {e['action']} {e['target']}", 200))
    return out or ["(no decisions yet)"]


def _walk(path: str) -> tuple[VFS, str]:
    """A VFS positioned at the parent of ``path`` (real dirs and zips alike)."""
    parts = [p for p in os.path.abspath(path).split(os.sep) if p]
    vfs = VFS("/")
    for part in parts[:-1]:
        vfs.cd(part)
    return vfs, (parts[-1] if parts else "")


def list_path(path: str) -> list[dict]:
    vfs, last = _walk(path)
    if last:
        vfs.cd(last)
    out = []
    for e in vfs.list()[:MAX_ENTRIES]:
        kind = "dir" if e.is_dir else ("zip" if e.is_archive else "file")
        out.append({"name": clean_text(e.name, 120), "kind": kind})
    return sorted(out, key=lambda d: (d["kind"] == "file", d["name"].lower()))


def view_text(path: str) -> tuple[list[str], bool]:
    """(lines, lossy). ``lossy`` is True when what is shown differs from the
    file - truncated, tabs/CRLF/control characters changed, long lines cut,
    not UTF-8 - so an editor knows saving it back would damage the file."""
    vfs, last = _walk(path)
    if not last:
        raise VFSError("that is a directory")
    raw = vfs.read_bytes(last)
    truncated = len(raw) > MAX_VIEW_BYTES
    text = raw[:MAX_VIEW_BYTES].decode("utf-8", errors="replace")
    every = text.splitlines()
    lines = [clean_text(l.replace("\t", "    "), 300) for l in every[:MAX_VIEW_LINES]]
    lossy = (truncated or "\r" in text or "\ufffd" in text
             or len(every) > MAX_VIEW_LINES or "\n".join(lines) != "\n".join(every))
    return lines, lossy


def view_lines(path: str) -> list[str]:
    return view_text(path)[0]


def scan_lines(path: str) -> list[str]:
    result = scan_file(__import__("pathlib").Path(path))
    lines = [f"{path}: {result.summary()}"]
    lines += [clean_text(f"  [{f.severity}] {f.rule} in {f.path}: {f.note}", 200)
              for f in result.findings]
    return lines
