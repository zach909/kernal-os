"""Tracks apps opened with ``kos open`` so they can run concurrently.

``run APP`` owns your terminal for the app's whole life and ends it on
Ctrl-C. ``open APP`` is different: it launches the app in the background,
under a small relay process (the *broker*, see ``broker.py``), and returns
your shell immediately. You can have several open at once. ``kos ps`` lists
them; ``kos attach ID`` connects your terminal, mouse and keyboard to one of
them (detach with Ctrl-C, the app keeps running); ``kos close ID`` actually
stops it.

One JSON file per instance under ``<state>/appdata/<app>/run/<id>.json`` is both
the record and the lock (its socket and log sit beside it): the broker holding that instance is the only process
that ever attaches a live app to it.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .kapp import ID_RE
from .paths import Paths, atomic_write


class RegistryError(Exception):
    pass


@dataclass
class Instance:
    id: str
    name: str
    mode: str
    broker_pid: int
    sock_path: str
    log_path: str
    started: float
    app_pid: int = 0
    status: str = "starting"  # starting -> running -> exited
    system: bool = False      # manifest has the 'system' permission (set by the OS, never the app)
    asks: list = field(default_factory=list)   # the single requests its manifest allows (ask:ACTION), set by the OS
    address: str = ""         # the path+query of the kos:// address it was opened with (checked by the OS)


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class Registry:
    def __init__(self, paths: Paths):
        self.base = paths.state / "appdata"

    def new_id(self, name: str) -> str:
        return f"{name}-{secrets.token_hex(3)}"

    def _file(self, instance_id: str) -> Path:
        name = instance_id.rsplit("-", 1)[0]
        if "/" in instance_id or instance_id in ("", ".", "..") or not ID_RE.match(name):
            raise RegistryError(f"invalid instance id {instance_id!r}")
        return self.base / name / "run" / f"{instance_id}.json"

    def write(self, inst: Instance) -> None:
        f = self._file(inst.id)
        f.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(f.parent, 0o700)
        atomic_write(f, json.dumps(asdict(inst), indent=2).encode())

    def get(self, instance_id: str) -> Instance:
        try:
            d = json.loads(self._file(instance_id).read_text())
        except FileNotFoundError:
            raise RegistryError(f"no such open instance {instance_id!r}") from None
        return Instance(**d)

    def remove(self, instance_id: str) -> None:
        try:
            self._file(instance_id).unlink()
        except FileNotFoundError:
            pass

    def list(self) -> list[Instance]:
        if not self.base.exists():
            return []
        out = []
        for f in sorted(self.base.glob("*/run/*.json")):
            try:
                inst = Instance(**json.loads(f.read_text()))
            except (ValueError, TypeError, KeyError):
                continue
            if inst.status != "exited" and not _alive(inst.broker_pid):
                inst.status = "exited"
            out.append(inst)
        return out

    def prune(self) -> int:
        """Drop registry entries whose broker is gone (crashed without cleanup)."""
        n = 0
        for inst in self.list():
            if inst.status == "exited":
                self.remove(inst.id)
                try:
                    os.unlink(inst.sock_path)
                except FileNotFoundError:
                    pass
                n += 1
        return n
