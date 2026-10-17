"""What an outside AI agent may propose, checked before it reaches the agent bridge (``examples/optional/agent-bridge``).

An agent that lives outside the OS can only hand over a *plan*: at most eight steps, and only launching and looking actions (open an
app, look at an instance, read the machine's facts). The OS still shows the plan and asks the owner's password before any step runs.
``examples/optional/agent-bridge/plan.js`` applies the same rules on the app's side; a test keeps the two in step.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Optional

_APP = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_INSTANCE = re.compile(r"^[a-z][a-z0-9-]{0,31}-[0-9a-f]{6}$")
SYS_KINDS = ("devices", "health", "isolation", "memory", "mounts", "network", "processes", "resources")
MAX_STEPS = 8
MAX_BYTES = 20000


def _text(v, n: int) -> bool:
    return isinstance(v, str) and 0 < len(v) <= n and not re.search(r"[\x00-\x1f]", v)


def _step(st) -> Optional[dict]:
    if not isinstance(st, dict):
        return None
    a = st.get("action")
    if a in ("apps", "info", "netcheck"):
        return {"action": a}
    if a == "open":
        if not isinstance(st.get("app"), str) or not _APP.match(st["app"]):
            return None
        mode = st.get("mode", "graphical")
        return {"action": "open", "app": st["app"], "mode": mode} if mode in ("tui", "graphical") else None
    if a in ("focus", "close"):
        return {"action": a, "id": st["id"]} if isinstance(st.get("id"), str) and _INSTANCE.match(st["id"]) else None
    if a == "sys":
        return {"action": "sys", "kind": st["kind"]} if st.get("kind") in SYS_KINDS else None
    return None


def check(doc) -> tuple[bool, str, Optional[dict]]:
    """(ok, why, plan): the plan with every step normalised, or the reason it was refused."""
    if not isinstance(doc, dict):
        return False, "a plan is a JSON object", None
    if not _text(doc.get("title"), 80):
        return False, "title: 1 to 80 characters", None
    steps = doc.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        return False, f"steps: 1 to {MAX_STEPS}", None
    clean = []
    for i, st in enumerate(steps):
        s = _step(st)
        if s is None:
            return False, f"step {i + 1} is not an allowed launching or looking action", None
        clean.append(s)
    out = {"title": doc["title"], "steps": clean}
    if isinstance(doc.get("agent"), str):
        out["agent"] = re.sub(r"[^A-Za-z0-9 ._-]", "", doc["agent"])[:30]
    return True, "", out


def submit(inbox: Path, raw: bytes, name: str) -> tuple[bool, str, Optional[Path]]:
    """Check a plan file and put the cleaned version in the bridge's inbox. Returns (ok, why, where)."""
    if len(raw) > MAX_BYTES:
        return False, "a plan file is at most 20 KB", None
    try:
        doc = json.loads(raw)
    except ValueError:
        return False, "not valid JSON", None
    ok, why, plan = check(doc)
    if not ok:
        return False, why, None
    stem = re.sub(r"[^A-Za-z0-9_-]", "-", Path(name).stem)[:40] or "plan"
    inbox.mkdir(parents=True, exist_ok=True)
    owner = inbox.parent.stat()
    dest, n = inbox / f"{stem}.json", 1
    while dest.exists():
        n += 1
        dest = inbox / f"{stem}-{n}.json"
    dest.write_text(json.dumps(plan, indent=2))
    if os.geteuid() == 0:                                   # (development as root: the app runs as another user and must be able to take the file)
        for p in (inbox, dest):
            os.chown(p, owner.st_uid, owner.st_gid)
    return True, "", dest
