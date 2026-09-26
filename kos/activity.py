"""``kos activity``: one glanceable feed of what KOS is doing right now.

It merges two things that already exist separately - the audit log (every
password decision, permanent) and the instance registry (apps currently
open) - into one time-ordered feed, so you don't have to check `kos audit`
and `kos ps` separately to see what's going on.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .auth import AuditLog
from .paths import Paths
from .registry import Registry


@dataclass(frozen=True)
class ActivityItem:
    t: float
    text: str
    live: bool  # True for "still happening" rows (open apps); sorted to the top


def build_feed(paths: Paths, limit: int = 30) -> list[ActivityItem]:
    items: list[ActivityItem] = []
    for i in Registry(paths).list():
        state = {"running": "open", "starting": "opening", "exited": "closed"}.get(
            i.status, i.status)
        items.append(ActivityItem(i.started, f"{i.name} [{i.mode}] {state} - {i.id}", True))
    for e in AuditLog(paths).entries()[-limit:]:
        items.append(ActivityItem(e["t"], f"{e['outcome']}: {e['action']} {e['target']}".strip(),
                                  False))
    items.sort(key=lambda x: (x.live, x.t), reverse=True)
    return items[:limit]


def render_feed(items: list[ActivityItem]) -> str:
    if not items:
        return "nothing has happened yet"
    lines = []
    for it in items:
        when = "now" if it.live else time.strftime("%H:%M:%S", time.localtime(it.t))
        lines.append(f"{when:>10}  {it.text}")
    return "\n".join(lines)
