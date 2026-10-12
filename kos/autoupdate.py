"""Auto-update: keep everything current without ever lowering a gate.

What "everything" means here, and who can do what:

* **KOS's apps** - from the sources you added (``kos/sources.py``). Checked and installed by KOS.
* **KOS itself** - fast-forwarded from its own remote. Always asks (a kernel-layer action; never remembered).
* **The operating system underneath** - packages, the kernel, drivers, firmware (``kos/osupdate.py``). KOS can only *list* these
  and hand you the root command, because it holds no root.

Every install is sealed with a key derived from your password, so truly unattended installs cannot exist by design. What this does
instead: it knows when an update is **due**, tells you (a notification), and does the whole job on one click with one password. If
you have deliberately opened a **sudo window** that covers the app and command layers, a due check *and* the app updates run by
themselves inside it (mode ``auto``) - KOS never prompts on its own in the middle of the night, and never touches KOS itself or the
OS without you. The policy lives in ``<state>/autoupdate.json``.
"""

from __future__ import annotations

import json
import time
from typing import Callable, Optional

from . import osupdate
from .auth import Authority, sudo_status
from .paths import Paths, atomic_write
from .sources import Sources

DEFAULT = {"enabled": False, "mode": "ask", "every_hours": 24, "last_run": 0.0, "last_summary": ""}
MODES = ("ask", "auto")


class AutoUpdate:
    def __init__(self, paths: Paths, *, sources: Optional[Sources] = None, os_pending: Callable = osupdate.pending,
                 now: Callable[[], float] = time.time):
        self.paths, self.sources, self.os_pending, self._now = paths, sources or Sources(paths), os_pending, now
        self.file = paths.state / "autoupdate.json"

    def policy(self) -> dict:
        try:
            d = json.loads(self.file.read_text())
        except (OSError, ValueError):
            d = {}
        out = dict(DEFAULT)
        if isinstance(d.get("enabled"), bool):
            out["enabled"] = d["enabled"]
        if d.get("mode") in MODES:
            out["mode"] = d["mode"]
        if isinstance(d.get("every_hours"), int) and 1 <= d["every_hours"] <= 24 * 30:
            out["every_hours"] = d["every_hours"]
        if isinstance(d.get("last_run"), (int, float)):
            out["last_run"] = float(d["last_run"])
        if isinstance(d.get("last_summary"), str):
            out["last_summary"] = d["last_summary"][:300]
        return out

    def _save(self, p: dict) -> None:
        self.file.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self.file, json.dumps(p).encode())

    def set(self, authority: Authority, **changes) -> dict:
        """Change the policy. Turning auto-install on is a kernel-layer decision: it asks for the password."""
        p = self.policy()
        for k, v in changes.items():
            if k == "enabled" and isinstance(v, bool):
                p["enabled"] = v
            elif k == "mode" and v in MODES:
                p["mode"] = v
            elif k == "every_hours" and isinstance(v, int) and 1 <= v <= 24 * 30:
                p["every_hours"] = v
        if changes.get("mode") == "auto" or changes.get("enabled") is True:
            with authority.authorize("policy.change", f"autoupdate={p['mode']}"):
                pass
        self._save(p)
        return p

    def due(self) -> bool:
        p = self.policy()
        return p["enabled"] and self._now() - p["last_run"] >= p["every_hours"] * 3600

    def status(self) -> dict:
        p = self.policy()
        rep = self.sources.last_report() or {}
        return {**p, "due": self.due(), "sudo": sudo_status(self.paths),
                "apps_waiting": len(rep.get("updates", [])), "new_available": len(rep.get("new", [])),
                "core_behind": (rep.get("core") or {}).get("behind", 0), "checked": rep.get("t", 0)}

    def can_run_unattended(self) -> bool:
        """Is there an open sudo window covering what an unattended run needs (the app and command layers)?"""
        s = sudo_status(self.paths)
        return s["active"] and {"app", "command"} <= set(s["layers"])

    def run(self, authority: Authority, *, scheduled: bool = False, include_os: bool = True, include_core: bool = True) -> dict:
        """Check every source, install the app updates, look at KOS itself and the OS. A *scheduled* run refuses
        (rather than prompting) unless a sudo window covers it. Returns what happened."""
        if scheduled and not self.can_run_unattended():
            return {"ran": False, "reason": "needs your password (no sudo window is open)", "lines": []}
        lines: list[str] = []
        rep = self.sources.check(authority, include_core=include_core)
        lines += [f"source error: {e}" for e in rep["errors"]]
        held = [u for u in rep["updates"] if u["adds_permissions"]]
        if held:
            lines += [f"{u['name']} {u['installed']} -> {u['version']} asks for new permissions: {', '.join(u['adds_permissions'])} (not installed; review it)"
                      for u in held]
        for line in self.sources.install_all(authority):
            lines.append(line)
        core = rep.get("core") or {}
        if core.get("behind"):
            lines.append(f"KOS itself is {core['behind']} commit(s) behind: update it yourself (it always asks): kos updates core")
        os_info = self.os_pending() if include_os else {"packages": [], "counts": {}}
        if os_info.get("packages"):
            c = os_info["counts"]
            lines.append("the OS has " + ", ".join(f"{n} {k}" for k, n in sorted(c.items())) + f" upgrade(s) waiting - as root: {os_info['apply']}")
        p = self.policy()
        p["last_run"] = self._now()
        p["last_summary"] = "; ".join(lines)[:300] or "everything is current"
        self._save(p)
        return {"ran": True, "lines": lines or ["everything is current"], "os": os_info}
