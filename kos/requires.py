"""Requirements: a thing can *require* other things.

``require`` is not "run this". It says what has to be true for something to
happen at all, or what it leaves owed once it has happened:

* **before** - what must already be in place. Unlocking the computer requires
  the elevated administrator keyboard; the keyboard requires the kernel. If
  the kernel can't run, the keyboard can't boot; if the keyboard can't boot,
  the computer does not unlock. The chain is followed all the way down and
  the refusal names it ("session.unlock requires admin.keyboard requires
  kernel: ...").
* **after** - what the thing leaves owed. Writing a file requires a security
  scan and a disk optimize *afterwards*. Those are written to a ledger the
  moment the write happens and struck off as each is done; anything still owed
  (a crash, a failed step) is remembered across restarts, and the next write is
  refused until it is settled (``kos settle``).

The table below is the whole policy. Providers (what "kernel" or "scan"
actually mean) are plugged in by the caller, so the policy can be tested
without hardware.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .paths import Paths, atomic_write


@dataclass(frozen=True)
class Rule:
    before: tuple[str, ...] = ()
    after: tuple[str, ...] = ()


RULES: dict[str, Rule] = {
    "session.unlock": Rule(before=("admin.keyboard",)),
    "admin.keyboard": Rule(before=("kernel",)),
    "file.write": Rule(before=("admin.keyboard",), after=("scan", "optimize")),
}


class Unsatisfied(Exception):
    """A requirement could not be met. ``chain`` is how we got to it."""

    def __init__(self, chain: list[str], reason: str):
        self.chain, self.reason = chain, reason
        super().__init__(" requires ".join(chain) + f": {reason}")


class Requirements:
    """Resolves the *before* side. ``checks[name]()`` returns None when ``name``
    is satisfied or a reason when it is not; ``boots[name]()`` brings it up."""

    def __init__(self, checks: dict[str, Callable[[], Optional[str]]],
                 boots: Optional[dict[str, Callable[[], None]]] = None,
                 rules: Optional[dict[str, Rule]] = None):
        self.checks, self.boots, self.rules = checks, boots or {}, rules or RULES

    def ensure(self, name: str, _chain: Optional[list[str]] = None) -> list[str]:
        """Make everything ``name`` requires true, deepest first. Returns the
        names that had to be booted. Raises :class:`Unsatisfied`."""
        chain = (_chain or []) + [name]
        if name in (_chain or []):
            raise Unsatisfied(chain, "requirements go in a circle")
        brought_up: list[str] = []
        for dep in self.rules.get(name, Rule()).before:
            brought_up += self.ensure(dep, chain)
        check = self.checks.get(name)
        if check is not None:
            reason = check()
            if reason and name in self.boots:
                try:
                    self.boots[name]()
                    brought_up.append(name)
                except Exception as e:           # a failed boot is a reason, not a crash
                    raise Unsatisfied(chain, str(e)) from e
                reason = check()
            if reason:
                raise Unsatisfied(chain, reason)
        return brought_up


class Ledger:
    """What is still owed. One JSON file under the KOS state directory."""

    def __init__(self, paths: Paths, rules: Optional[dict[str, Rule]] = None,
                 now: Callable[[], float] = time.time):
        self.file = paths.state / "owed.json"
        self.rules, self._now = rules or RULES, now

    def _load(self) -> list[dict]:
        try:
            return json.loads(self.file.read_text())
        except FileNotFoundError:
            return []
        except ValueError:
            return [{"id": "corrupt", "trigger": "ledger", "target": str(self.file),
                     "pending": ["repair"], "t": 0}]   # an unreadable ledger blocks, never frees

    def _save(self, entries: list[dict]) -> None:
        self.file.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self.file, json.dumps(entries, indent=2).encode())

    def owe(self, trigger: str, target: str) -> str:
        """Record what ``trigger`` leaves owed. Returns the entry id."""
        entry = {"id": os.urandom(4).hex(), "trigger": trigger, "target": target,
                 "pending": list(self.rules[trigger].after), "t": self._now()}
        self._save(self._load() + [entry])
        return entry["id"]

    def done(self, entry_id: str, step: str) -> None:
        entries = self._load()
        for e in entries:
            if e["id"] == entry_id and step in e["pending"]:
                e["pending"].remove(step)
        self._save([e for e in entries if e["pending"]])

    def owed(self, trigger: Optional[str] = None) -> list[dict]:
        return [e for e in self._load() if trigger is None or e["trigger"] == trigger]
