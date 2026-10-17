"""The rule: every service, system and part of KOS is an app - and nothing, the OS included, has power over everything.

This module is the honest ledger of that rule.

**The trusted core** is the small part that cannot be an app, because an app is something the core launches, seals, sandboxes and
asks the password for. It is listed here with the one thing each piece is for and what it deliberately cannot do:

* the **authority**: asks for the password and hands out one grant for one action. It never runs anyone else's code.
* the **store and seal check**: verifies that an app is the one you installed. It never executes an app.
* the **sandbox launcher and broker**: confine a process (Landlock, no new privileges, resource limits) and relay its messages. They
  hold no files of yours and draw nothing.
* the **registry**: the list of what is running.
* the **compositor**: draws what apps send and routes input. It reads no files, runs no commands and has no network.

**Everything else is an app**: the wallpaper, menubar, dock, sidebar, launcher, pins, cursor and effects; every widget; the file
manager, editor, terminal, settings, backup, updates, health, mods, passwords; the browser; optional hardware drivers. Each runs
sandboxed, with only the ``system:<scope>`` permissions it needs (see :mod:`kos.capabilities`) - none uses the bare ``system`` any more -
and each change it asks for needs its own password. A fake app, or a compromised one, gets one slice of what the OS can do and not
the rest; the OS-side code that answers its requests (backup, updates, mods, ...) only runs when a scope allows the request *and*
the owner types the password.

``report`` is what ``kos services`` prints, and the tests keep it true: no built-in app asks for more scope than its code uses,
and none holds the bare ``system`` permission.
"""

from __future__ import annotations

import glob
import json
import os
import re
from pathlib import Path

from . import capabilities

CORE = (
    ("authority (kos/auth.py)", "asks the password; one grant for one action; remembers nothing on disk",
     "run anyone's code, read your files, draw anything"),
    ("store and seals (kos/store.py, kos/kapp.py)", "checks an app is exactly what you installed",
     "run an app"),
    ("sandbox launcher and broker (kos/sandbox.py, kos/loader.py, kos/broker.py)", "confine a process and relay its messages",
     "hold your files, draw, or widen a permission"),
    ("registry (kos/registry.py)", "the list of what is running", "start or stop anything by itself"),
    ("compositor (kos/shell.py)", "draws what apps send; routes input; shows the password prompt",
     "read files, run commands, use the network"),
)

_METHOD_ACTION = {
    "Apps": "apps", "Open": "open", "Focus": "focus", "Close": "close", "Info": "info", "Ls": "ls", "View": "view", "Scan": "scan",
    "Optimize": "optimize", "Settle": "settle", "Permit": "permit", "Line": "line", "Save": "save", "Backup": "backup",
    "Backups": "backups", "Restore": "restore", "Push": "push", "Remote": "remote", "Sys": "sys", "Signal": "signal",
    "Renice": "renice", "FsChange": "fschange", "Updates": "updates", "Notify": "notify", "NotifyClear": "notify",
    "NotifyDismiss": "notify", "Links": "links", "OpenLink": "openlink", "Quantum": "quantum", "AutoUpdate": "autoupdate",
    "Heal": "heal", "Mods": "mods", "Encryption": "encryption", "Services": "services", "Addons": "addons", "Policy": "policy", "Sudo": "sudo", "NetCheck": "netcheck", "Revoke": "revoke",
}


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def actions_used(src_dir: Path) -> set[str]:
    """The OS requests an app's own source makes (read from its code, so a manifest cannot understate it)."""
    snake = {_snake(k): v for k, v in _METHOD_ACTION.items()}
    acts: set[str] = set()
    for f in list(Path(src_dir).glob("*.js")) + list(Path(src_dir).glob("*.py")):
        try:
            text = f.read_text()
        except OSError:
            continue
        acts |= {_METHOD_ACTION[m] for m in re.findall(r"request([A-Z]\w*)\(", text) if m in _METHOD_ACTION}
        acts |= {snake[m] for m in re.findall(r"request_(\w+)\(", text) if m in snake}
        acts |= set(re.findall(r"action['\"]?: *['\"](\w+)['\"]", text))
    return acts


def scopes_needed(src_dir: Path) -> set[str]:
    return {capabilities.ACTION_SCOPE[a] for a in actions_used(src_dir) if a in capabilities.ACTION_SCOPE}


def report(paths, sandboxed: bool = True) -> dict:
    """Every installed app with the scopes it holds, and whether any holds the bare ``system`` permission."""
    from .kapp import KApp
    from .store import AppStore
    apps, blanket = [], []
    for a in AppStore(paths).installed():
        try:
            m = KApp.from_file(paths.apps / f"{a.name}.kapp").manifest
        except Exception:
            continue
        scopes = sorted(m.scopes)
        if "*" in scopes:
            blanket.append(m.name)
        apps.append({"name": m.name, "runtime": m.runtime, "scopes": scopes, "network": "network" in m.permissions,
                     "devices": list(m.devices), "driver": m.driver, "slot": m.slot})
    return {"core": [{"part": p, "does": d, "cannot": c} for p, d, c in CORE], "apps": apps, "blanket": blanket}
