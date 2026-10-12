"""Self-healing: notice what is broken and put it right - without ever lowering a gate.

Two kinds of healing:

* **Live**: the desktop restarts an interface app that stopped (``Shell._run_heal``): after 1, 3 and 8 seconds, with a
  notification; an app that was merely disconnected is re-attached, one that died needs a fresh start (which asks for your
  password, unless a sudo window covers it); a mod that keeps failing is replaced by the built-in app for its slot.
* **Repair** (this module, ``kos heal``): look at the state on disk and fix what can be fixed.

What repair does, and what it will not do:

* a corrupt preference file (``shell.json``, ``links.json``, ``mods.json``, ``policy.json``) is *moved aside* into
  ``<state>/quarantine/`` (never deleted, in case it matters) and the defaults come back; ``policy.json`` falls back to the
  strict setting, never a looser one;
* instance records whose broker is gone are dropped, and RAM scratch directories nobody uses any more are wiped;
* a built-in app that is missing or fails its seal is reinstalled from the copy shipped with KOS - which asks for your
  password, like any install; an app that is *not* built in and fails its seal is reported and left alone (KOS cannot know
  what it used to be) - reinstall it from its source;
* a mod that no longer fits its slot's permission ceiling is switched off (password).

Nothing here widens a permission, turns a prompt off, or restores anything from a place the owner did not choose.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .paths import Paths

STATE_FILES = ("shell.json", "links.json", "mods.json", "policy.json")
SCRATCH_MAX_AGE = 3600


@dataclass
class Finding:
    kind: str          # corrupt-state | stale-instance | stale-scratch | missing-app | bad-seal | bad-mod
    subject: str
    detail: str
    fix: str = ""      # what repair would do; "" when there is nothing safe to do
    needs_password: bool = False

    def as_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    left: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings


def _scratch_dirs() -> list[Path]:
    base = Path("/dev/shm")
    out: list[Path] = []
    mine = base / f"kos-{os.getuid()}"
    if mine.is_dir():
        out += [d for d in mine.iterdir() if d.is_dir()]
    out += [d for d in base.glob("kos-run-*") if d.is_dir()]
    return out


def _in_use(path: Path) -> bool:
    """Does some process have this directory as its working directory or open? (Best effort, /proc only.)"""
    target = str(path)
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            if os.readlink(proc / "cwd").startswith(target):
                return True
            for fd in (proc / "fd").iterdir():
                if os.readlink(fd).startswith(target):
                    return True
        except OSError:
            continue
    return False


def check(paths: Paths, *, builtin: Optional[tuple[str, ...]] = None) -> Report:
    """Look for problems. Needs no password and changes nothing."""
    from .mods import Mods
    from .registry import Registry
    from .store import AppStore
    rep = Report()
    for name in STATE_FILES:
        f = paths.state / name
        if f.exists():
            try:
                json.loads(f.read_text())
            except (OSError, ValueError):
                rep.findings.append(Finding("corrupt-state", name, "not valid JSON", "move it to quarantine; defaults return"))
    for inst in Registry(paths).list():
        if inst.status == "exited":
            rep.findings.append(Finding("stale-instance", inst.id, "its broker is gone", "drop the record"))
    now = time.time()
    for d in _scratch_dirs():
        try:
            if now - d.stat().st_mtime > SCRATCH_MAX_AGE and not _in_use(d):
                rep.findings.append(Finding("stale-scratch", str(d), "RAM scratch nobody uses", "wipe it"))
        except OSError:
            continue
    have = {a.name for a in AppStore(paths).installed()}
    for name in builtin or ():
        files = [paths.apps / f"{name}.kapp", paths.apps / f"{name}.seal"]
        if name not in have or not all(f.exists() for f in files):
            rep.findings.append(Finding("missing-app", name, "a built-in app is missing", "reinstall it from KOS", True))
    try:
        for m in Mods(paths).installed():
            if m["enabled"] and m["problem"]:
                rep.findings.append(Finding("bad-mod", m["name"], m["problem"], "switch the mod off", True))
    except Exception:
        pass
    return rep


def quarantine(paths: Paths, name: str) -> Path:
    q = paths.state / "quarantine"
    q.mkdir(parents=True, exist_ok=True)
    dest = q / f"{name}.{int(time.time())}"
    shutil.move(str(paths.state / name), dest)
    return dest


def quick(paths: Paths) -> list[str]:
    """The fixes that need no password and trust nothing new: corrupt preference files aside, dead instance records
    dropped, stale scratch wiped. Safe to run at every boot. Returns what it did."""
    from . import cache
    from .registry import Registry
    did = []
    for f in check(paths).findings:
        if f.kind == "corrupt-state":
            dest = quarantine(paths, f.subject)
            did.append(f"{f.subject} was corrupt: kept as {dest.name}, defaults restored")
        elif f.kind == "stale-scratch":
            cache.wipe(Path(f.subject))
            shutil.rmtree(f.subject, ignore_errors=True)
            did.append(f"wiped stale scratch {Path(f.subject).name}")
    n = Registry(paths).prune()
    if n:
        did.append(f"dropped {n} dead instance record(s)")
    return did


def repair(paths: Paths, authority=None, *, builtin: tuple[str, ...] = (), src: Optional[Path] = None) -> Report:
    """Fix what can be fixed. ``authority`` is needed for reinstalling built-ins, verifying seals and switching off a
    bad mod; without it only the password-free fixes run and the rest is reported."""
    from .kapp import KApp, KAppError, pack
    from .mods import Mods
    from .store import AppStore, TamperedError
    rep = Report()
    rep.fixed += quick(paths)
    after = check(paths, builtin=builtin)
    store = AppStore(paths)
    src = Path(src) if src else Path(__file__).resolve().parent.parent / "examples" / "system"
    todo_missing = [f for f in after.findings if f.kind == "missing-app"]
    bad_mods = [f for f in after.findings if f.kind == "bad-mod"]
    if authority is None:
        rep.left += [f"{f.kind}: {f.subject} - {f.detail}" for f in after.findings]
        return rep
    # seals of everything installed: one password
    names = [a.name for a in store.installed()]
    tampered = []
    if names:
        grants = authority.authorize_batch([("app.open", n) for n in names], f"check the seals of {len(names)} apps")
        for n, g in zip(names, grants):
            try:
                store.load_verified(n, g)
            except (TamperedError, KAppError):
                tampered.append(n)
            finally:
                g.close()
    reinstall = list(dict.fromkeys([f.subject for f in todo_missing] + [n for n in tampered if n in builtin]))
    for n in tampered:
        if n not in builtin:
            rep.left.append(f"{n} fails its seal and is not a built-in app: reinstall it from its source")
    if reinstall:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            grants = authority.authorize_batch([("app.install", n) for n in reinstall], f"repair {len(reinstall)} built-in app(s)")
            for n, g in zip(reinstall, grants):
                try:
                    for f in (paths.apps / f"{n}.kapp", paths.apps / f"{n}.seal"):
                        f.unlink(missing_ok=True)
                    kapp = Path(tmp) / f"{n}.kapp"
                    pack(src / n, kapp)
                    store.install(kapp, authority, origin={"source": "built-in (repaired)", "location": str(src / n)}, grant=g)
                    rep.fixed.append(f"reinstalled {n} from the copy shipped with KOS")
                except Exception as e:
                    g.close()
                    rep.left.append(f"could not repair {n}: {e}")
    mods = Mods(paths)
    for f in bad_mods:
        with authority.authorize("mod.disable", f.subject):
            mods.disable(f.subject)
        rep.fixed.append(f"switched off mod {f.subject}: {f.detail}")
    return rep
