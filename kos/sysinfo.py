"""Read-only facts about this computer, read by the OS on an app's behalf.

An app never opens /proc, /sys or a device. It sends ``request sysinfo {topic}``; the OS (system.py)
asks the owner's password, audits it, and only then calls :func:`read`. The topic is looked up in the
fixed dict ``TOPICS``: nothing an app sends is ever used to build a path or a command.

What is returned is bounded numbers, booleans and short strings (control characters cleaned with the
protocol's own cleaner), at most 200 list entries. NEVER included: host name, user names, IP/MAC
addresses, serial numbers, file paths, environment variables, command lines, other processes. A
missing or unreadable source gives an absent field or an empty list, never an exception text.

``root`` (default ``/``) exists only so tests can point at fixture directories.
"""

from __future__ import annotations

import math
import os
import re
import sys
from typing import Any, Callable, Optional

from .protocol import clean_text

MAX_ITEMS = 200
MAX_STR = 64
READ_LIMIT = 16384                  # bytes read from any one source file
WALK_ENTRIES = 20000                # directory entries visited per app's appdata
WALK_DEPTH = 12
NUM_MAX = 1e15
_RELEASE_RE = re.compile(r"[^0-9A-Za-z._+-]")
_KERNEL_RE = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}[0-9A-Za-z._+-]{0,48}")
POWER_TYPES = ("Battery", "Mains", "USB", "UPS", "Wireless")
POWER_STATUS = ("Charging", "Discharging", "Full", "Not charging", "Unknown")


class SysinfoError(Exception):
    pass


def _file(root: str, rel: str) -> Optional[str]:
    """Up to READ_LIMIT bytes of one fixed file under root, or None. The one place a file is opened."""
    try:
        with open(os.path.join(root, rel), "rb") as f:
            return f.read(READ_LIMIT).decode("ascii", "replace")
    except (OSError, ValueError):
        return None


def _num(v: Any) -> Optional[float]:
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if math.isfinite(x) and abs(x) <= NUM_MAX else None


def _os(root: str, paths) -> dict:
    out: dict = {}
    rel = _file(root, "proc/sys/kernel/osrelease")
    if rel is None and root in ("/", ""):
        try:
            rel = os.uname().release
        except OSError:
            rel = None
    if rel:
        rel = rel.strip()
        if _KERNEL_RE.fullmatch(rel):         # a release looks like 6.1.0-test; anything else is not shown
            out["kernel"] = rel
    if root in ("/", ""):
        try:
            out["machine"] = _RELEASE_RE.sub("", os.uname().machine)[:MAX_STR]
        except OSError:
            pass
    v = sys.version_info
    out["python"] = f"{v.major}.{v.minor}.{v.micro}"
    try:
        from . import __version__
        out["kos"] = str(__version__)[:MAX_STR]
    except ImportError:
        pass
    return out


def _sandbox(root: str, paths) -> dict:
    from . import sandbox
    r = sandbox.report()
    out: dict = {}
    abi = r.get("landlock_abi")
    if isinstance(abi, int) and not isinstance(abi, bool) and 0 <= abi < 100:
        out["landlock_abi"] = abi
    for k in ("seccomp_filter", "user_namespaces", "kvm", "vhost_vsock"):
        if isinstance(r.get(k), bool):
            out[k] = r[k]
    return out


def _memory(root: str, paths) -> dict:
    text = _file(root, "proc/meminfo")
    if text is None:
        return {}
    want = {"MemTotal": "total_mib", "MemAvailable": "available_mib",
            "SwapTotal": "swap_total_mib", "SwapFree": "swap_free_mib"}
    out: dict = {}
    for line in text.splitlines()[:100]:
        key, _, rest = line.partition(":")
        if key in want and want[key] not in out:
            parts = rest.split()
            n = _num(parts[0]) if parts else None
            if n is not None and n >= 0 and len(parts) > 1 and parts[1] == "kB":
                out[want[key]] = int(n // 1024)
    return out


def _load(root: str, paths) -> dict:
    out: dict = {}
    up = _file(root, "proc/uptime")
    n = _num(up.split()[0]) if up and up.split() else None
    if n is not None and n >= 0:
        out["uptime_s"] = int(n)
    la = _file(root, "proc/loadavg")
    parts = la.split()[:3] if la else []
    vals = [_num(p) for p in parts]
    if len(vals) == 3 and all(v is not None and v >= 0 for v in vals):
        out["load1"], out["load5"], out["load15"] = (round(v, 2) for v in vals)
    return out


def _tree_bytes(top: str) -> tuple:
    """(bytes, complete) under top: bounded, never follows a symlink, counts a link as the link itself."""
    total, seen, complete = 0, 0, True
    stack = [(top, 0)]
    while stack:
        d, depth = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for e in it:
                seen += 1
                if seen > WALK_ENTRIES:
                    return total, False
                try:
                    st = e.stat(follow_symlinks=False)
                    if e.is_dir(follow_symlinks=False):
                        if depth < WALK_DEPTH:
                            stack.append((e.path, depth + 1))
                        else:
                            complete = False
                    else:
                        total += st.st_size
                except OSError:
                    continue
    return total, complete


def _storage(root: str, paths) -> dict:
    out: dict = {}
    if paths is None:
        return out
    try:
        st = os.statvfs(str(paths.state))
        out["total_bytes"] = int(st.f_blocks * st.f_frsize)
        out["free_bytes"] = int(st.f_bavail * st.f_frsize)
    except OSError:
        pass
    rows = []
    try:
        from .appdirs import AppDirs
        from .store import AppStore
        for a in AppStore(paths).installed()[:MAX_ITEMS]:
            b, ok = _tree_bytes(str(AppDirs(paths, a.name).root))
            rows.append({"name": a.name, "bytes": b, "complete": ok})
    except Exception:       # a damaged store gives an empty list, never an error text
        rows = []
    rows.sort(key=lambda r: -r["bytes"])
    out["apps"] = rows
    return out


def _battery(root: str, paths) -> dict:
    base = os.path.join(root, "sys/class/power_supply")
    try:
        names = sorted(os.listdir(base))[:MAX_ITEMS]
    except OSError:
        return {"batteries": []}
    out = []
    for n in names:
        d = os.path.join("sys/class/power_supply", n)
        typ = (_file(root, d + "/type") or "").strip()
        if typ not in POWER_TYPES:
            continue
        row: dict = {"type": typ}
        cap = _num((_file(root, d + "/capacity") or "").strip())
        if cap is not None and 0 <= cap <= 100:
            row["percent"] = int(cap)
        status = (_file(root, d + "/status") or "").strip()
        if status in POWER_STATUS:
            row["status"] = status
        out.append(row)
    return {"batteries": out}


def _apps(root: str, paths) -> dict:
    if paths is None:
        return {}
    from .system import list_apps, list_open
    try:
        installed = [{"name": a["name"], "version": a["version"], "permitted": bool(a["permitted"])}
                     for a in list_apps(paths)]
    except Exception:
        installed = []
    try:
        opened = [{"name": i["name"], "mode": i["mode"], "status": i["status"]} for i in list_open(paths)]
    except Exception:
        opened = []
    return {"installed": installed, "open": opened}


TOPICS: dict[str, Callable] = {"os": _os, "sandbox": _sandbox, "memory": _memory, "load": _load,
                               "storage": _storage, "battery": _battery, "apps": _apps}


def _bound(v: Any, depth: int = 0) -> Any:
    """Final pass over everything returned: bounded numbers, booleans, short clean strings, short lists."""
    if depth > 4:
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v if abs(v) <= NUM_MAX else None
    if isinstance(v, float):
        return v if math.isfinite(v) and abs(v) <= NUM_MAX else None
    if isinstance(v, str):
        return clean_text(v, MAX_STR)
    if isinstance(v, list):
        return [x for x in (_bound(i, depth + 1) for i in v[:MAX_ITEMS]) if x is not None]
    if isinstance(v, dict):
        return {clean_text(str(k), MAX_STR): x for k, x in
                ((k, _bound(i, depth + 1)) for k, i in list(v.items())[:MAX_ITEMS]) if x is not None}
    return None


def read(topic: str, root: Optional[str] = None, *, paths=None):
    """The facts for one fixed topic: always a dict (``battery`` -> {"batteries": [...]}). Raises SysinfoError only for a
    topic that is not in TOPICS; any trouble reading gives absent fields or ``[]``."""
    fn = TOPICS.get(topic) if isinstance(topic, str) else None
    if fn is None:
        raise SysinfoError("unavailable")
    try:
        return _bound(fn(root or "/", paths))
    except Exception:
        return {"batteries": []} if topic == "battery" else {}
