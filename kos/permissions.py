"""The universal permission store: one file, every grant.

    {"app": "email-client", "resource": "space:contacts", "level": "read", "at": ...}

Resources are ``run`` (may this app run at all), ``space:NAME`` (a shared
folder). Levels, lowest to highest: ``use`` < ``read`` < ``write`` < ``own``.
Anyone holding a grant of at least the level asked for may do the thing -
that is the whole rule. Granting and revoking go through the password in the
CLI, same as everything else that changes state.

A grant can also remember the manifest permissions the owner approved
(``declared``), so an update that quietly asks for more (say, ``network``)
is refused until the owner approves again.
"""

from __future__ import annotations

import json
import time
from typing import Optional

from .paths import Paths, atomic_write

LEVELS = {"use": 0, "read": 1, "write": 2, "own": 3}


class PermissionError_(Exception):
    pass


class Permissions:
    def __init__(self, paths: Paths):
        self.dir = paths.state / "permissions"
        self.file = self.dir / "grants.json"

    def _load(self) -> list:
        try:
            d = json.loads(self.file.read_text())
            return d if isinstance(d, list) else []
        except (FileNotFoundError, ValueError):
            return []

    def _save(self, entries: list) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        atomic_write(self.file, json.dumps(entries, indent=1).encode())

    def grant(self, app: str, resource: str, level: str = "use", declared: Optional[list] = None,
              pin: Optional[str] = None) -> None:
        """``pin`` ties the grant to one exact build of the app (its sha256): a grant that is
        pinned is only honoured by whoever checks the pin, so a replaced app does not inherit it."""
        if level not in LEVELS:
            raise PermissionError_(f"level must be one of {sorted(LEVELS, key=LEVELS.get)}")
        entries = [e for e in self._load() if not (e["app"] == app and e["resource"] == resource)]
        entry = {"app": app, "resource": resource, "level": level, "at": time.time()}
        if declared is not None:
            entry["declared"] = sorted(declared)
        if pin is not None:
            entry["pin"] = pin
        entries.append(entry)
        self._save(entries)

    def revoke(self, app: str, resource: Optional[str] = None) -> int:
        before = self._load()
        after = [e for e in before if not (e["app"] == app and (resource is None or e["resource"] == resource))]
        if len(after) != len(before):
            self._save(after)
        return len(before) - len(after)

    def get(self, app: str, resource: str) -> Optional[dict]:
        return next((e for e in self._load() if e["app"] == app and e["resource"] == resource), None)

    def has(self, app: str, resource: str, need: str = "use") -> bool:
        e = self.get(app, resource)
        return bool(e) and LEVELS.get(e["level"], -1) >= LEVELS[need]

    def owner_of(self, resource: str) -> Optional[str]:
        return next((e["app"] for e in self._load() if e["resource"] == resource and e["level"] == "own"), None)

    def list(self, resource_prefix: str = "") -> list:
        return [e for e in self._load() if e["resource"].startswith(resource_prefix)]
