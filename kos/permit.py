"""Run permission: a separate, persistent grant from the per-run password.

The password proves it's really you, every single time. A permit is a
different thing - your standing decision that a given app is *allowed to
run at all*, recorded once so `run`/`open` can refuse an app you never
permitted before they even get to the password prompt. Installing an app
does not permit it; you decide separately, the same way a phone asks you to
allow an app before its first launch.

Stored as one small file per app; granting and revoking both still go
through the password, same as everything else that changes state.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

from .kapp import NAME_RE, KAppError
from .paths import Paths, atomic_write


class PermitError(Exception):
    pass


@dataclass(frozen=True)
class Permit:
    name: str
    granted_at: float


class PermitStore:
    def __init__(self, paths: Paths):
        self.dir = paths.state / "permits"

    def _file(self, name: str):
        if not NAME_RE.match(name):
            raise KAppError(f"invalid app name {name!r}")
        return self.dir / f"{name}.json"

    def grant(self, name: str) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        atomic_write(self._file(name), json.dumps({"name": name, "granted_at": time.time()}).encode())

    def revoke(self, name: str) -> None:
        try:
            self._file(name).unlink()
        except FileNotFoundError:
            pass

    def is_permitted(self, name: str) -> bool:
        return self._file(name).exists()

    def require(self, name: str) -> None:
        if not self.is_permitted(name):
            raise PermitError(
                f"{name} has not been given permission to run (run: kos permit {name})")

    def list(self) -> list[Permit]:
        if not self.dir.exists():
            return []
        out = []
        for f in sorted(self.dir.glob("*.json")):
            try:
                d = json.loads(f.read_text())
                out.append(Permit(d["name"], d["granted_at"]))
            except (ValueError, KeyError):
                continue
        return out
