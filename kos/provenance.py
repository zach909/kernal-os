"""Where everything comes from.

Two things are recorded or discovered here:

* **Apps** - when an app is installed or updated, ``record`` writes one line
  about it to ``<state>/provenance.json``: the source it came from, the exact
  location (folder / URL / file), its version and sha256, and when. Apps
  installed before this existed show up as "unknown".
* **Everything else KOS runs on** - ``components`` reads, live, where the KOS
  code itself came from (git remote + commit, or "installed from an image"),
  and which Python, Node.js/npm and kernel are underneath, with who updates
  each. KOS only ever *updates* its own apps and its own git checkout; the
  rest is reported honestly as managed by your operating system.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from .paths import Paths, atomic_write
from .protocol import clean_text

KOS_ROOT_DIR = Path(__file__).resolve().parent.parent


def ledger_path(paths: Paths) -> Path:
    return paths.state / "provenance.json"


def _load(paths: Paths) -> dict:
    try:
        d = json.loads(ledger_path(paths).read_text())
        return d if isinstance(d, dict) else {}
    except (FileNotFoundError, ValueError):
        return {}


def record(paths: Paths, name: str, version: str, sha256: str, *, source: str, location: str,
           via: str, now: Optional[float] = None) -> None:
    """Remember where an app came from. ``via`` is "install" or "update"."""
    data = _load(paths)
    old = data.get(name, {})
    t = now or time.time()
    data[name] = {"version": version, "sha256": sha256, "source": clean_text(source, 60),
                  "location": clean_text(location, 300), "via": via,
                  "first_installed": old.get("first_installed", t), "updated": t,
                  "history": (old.get("history", []) + [{"version": old.get("version"), "t": old.get("updated")}]
                              if old.get("version") else [])[-10:]}
    paths.ensure()
    atomic_write(ledger_path(paths), json.dumps(data, indent=2).encode())


def forget(paths: Paths, name: str) -> None:
    data = _load(paths)
    if data.pop(name, None) is not None:
        atomic_write(ledger_path(paths), json.dumps(data, indent=2).encode())


def apps(paths: Paths) -> list[dict]:
    """Every installed app with what is known about where it came from."""
    from .store import AppStore
    ledger = _load(paths)
    out = []
    for a in AppStore(paths).installed():
        p = ledger.get(a.name)
        known = p is not None and p.get("sha256") == a.sha256
        out.append({"name": a.name, "version": a.version, "sha256": a.sha256[:16],
                    "source": p["source"] if known else ("changed since recorded" if p else "unknown"),
                    "location": p["location"] if known else (p["location"] if p else ""),
                    "via": p["via"] if p else "", "installed": p["first_installed"] if p else 0,
                    "updated": p["updated"] if p else 0, "known": known})
    return out


def _run(cmd: list[str], cwd: Optional[Path] = None, timeout: float = 8.0) -> str:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        return r.stdout.strip() if r.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def core(root: Path = KOS_ROOT_DIR) -> dict:
    """Where the KOS code itself came from."""
    if not (root / ".git").exists():
        return {"kind": "image", "origin": "installed with the system image",
                "update": "updated by installing a new image", "commit": "", "branch": ""}
    url = _run(["git", "remote", "get-url", "origin"], root)
    # never show credentials that someone embedded in a remote URL
    if "@" in url and "://" in url:
        url = url.split("://", 1)[0] + "://" + url.split("@", 1)[1]
    return {"kind": "git", "origin": clean_text(url or "(no remote)", 200),
            "commit": _run(["git", "rev-parse", "--short", "HEAD"], root),
            "branch": _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], root),
            "subject": clean_text(_run(["git", "log", "-1", "--format=%s"], root), 100),
            "date": _run(["git", "log", "-1", "--format=%cs"], root),
            "dirty": bool(_run(["git", "status", "--porcelain"], root)),
            "update": "git: fast-forward from its remote (needs your password)"}


def runtimes() -> list[dict]:
    out = [{"name": "python", "version": platform.python_version(), "origin": os.path.realpath(sys.executable),
            "update": "your OS package manager"}]
    node = shutil.which("node")
    if node:
        out.append({"name": "node.js", "version": _run([node, "--version"]).lstrip("v"),
                    "origin": os.path.realpath(node), "update": "your OS package manager / Node installer"})
        npm = shutil.which("npm")
        if npm:
            out.append({"name": "npm", "version": _run([node, os.path.realpath(npm), "--version"]),
                        "origin": os.path.realpath(npm), "update": "ships with Node.js"})
    out.append({"name": "linux kernel", "version": platform.release(), "origin": "the boot image / your OS",
                "update": "your OS package manager or a new boot image"})
    try:
        pretty = dict(l.split("=", 1) for l in Path("/etc/os-release").read_text().splitlines() if "=" in l)
        out.append({"name": "operating system", "version": pretty.get("PRETTY_NAME", "").strip('"'),
                    "origin": "/etc/os-release", "update": "your OS package manager"})
    except OSError:
        pass
    return out


def components(paths: Paths) -> dict:
    return {"apps": apps(paths), "core": core(), "runtimes": runtimes()}
