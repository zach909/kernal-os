"""No reboot: swap what is out of date while the machine stays on, and say honestly when a reboot is real.

A reboot is mostly a way of getting new code into running programs. In KOS most of that is an app: it runs
from a RAM copy of the ``.kapp`` it was launched from, so after an update the running copy is the old one
until it is started again. This module finds those copies, starts the new file next to the old one, and only
when the new one is running closes the old one (make before break: a failed start leaves the old app alone).

What it does NOT do, and says so instead of pretending:

* **The kernel and firmware.** KOS compiles kexec out and loads only signed modules, so a new kernel or a new
  firmware image needs a reboot. ``report`` names that reason; it never hides it.
* **The OS's own Python code.** A process keeps the modules it imported. Apps started before the OS files
  changed are listed under ``session`` (restart the desktop, not the machine). The watcher stops itself when
  its own code changed rather than start new programs with old code.
* **In-memory state.** An app's private data survives a swap (it lives in its own folder); what was only on its
  screen or in its variables does not.

"Fully automatic" and rule 1 (nothing without the password) are reconciled like this:

* The owner types the password once, for ``norestart.auto``. That is a recorded decision: "for the next N hours,
  while this machine is unlocked, swap stale apps for me".
* The password is not kept. What is kept is a :class:`Lease`: three keys derived from the password (the seal
  key, the firewall key, the audit key), in locked memory, never on disk, with an end time. It is wiped when the
  watcher stops, when the time is up, and in every process forked from the holder (so a broker started by a swap
  never inherits it).
* The lease can authorize exactly two things, and only for one app each: ``app.open`` of an app whose file was
  updated, and ``app.close`` of the old copy. It cannot prompt, so anything that needs a decision (a network
  grant, a wider permission, a file the owner has not permitted) is left running as it was and reported as
  ``needs-you``. It goes through the same door as every launch (``layers.traverse``): the seal is checked, the
  permit pin and the approved permissions are checked, the sandbox and the firewall are set up. Each unattended
  decision is written to the audit log as ``lease:ACTION`` so it can never be mistaken for a typed password.

What it cannot protect against: whatever holds the OS process's memory while the lease is alive holds the keys.
That is the same trust as the session that holds them for one launch, for longer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import firewall
from .auth import AUDIT_KEY_LABEL, AuditLog, AuthorizationDenied, Grant
from .kapp import KApp, KAppError, supports_mode
from .layers import CLOSE, OPEN, UNATTENDED
from .paths import Paths, atomic_write
from .permit import PermitError, PermitStore
from .registry import Instance, Registry
from .secret import SecretBytes
from .store import SEAL_KEY_LABEL, AppStore, version_key

PKG = Path(__file__).resolve().parent

CURRENT, STALE, IN_USE, NEEDS_YOU, UNKNOWN = "current", "stale", "in-use", "needs-you", "unknown"
SWAPPED, KEPT = "swapped", "kept"

LEASE_LABELS = (SEAL_KEY_LABEL, firewall.KEY_LABEL, AUDIT_KEY_LABEL)
LEASE_ACTIONS = UNATTENDED                      # the only two things a lease may authorize (named in layers.py)
MAX_LEASE_S = 24 * 3600
INTERVAL_S = 10                                 # how often the watcher looks
BILLION = 1_000_000_000


class NoRestartError(Exception):
    pass


# ---- the lease ----------------------------------------------------------------------------------

_LIVE: "weakref.WeakSet[Lease]" = weakref.WeakSet()


def _wipe_after_fork() -> None:
    """A forked child (a broker started by a swap) must not keep the keys of the process that forked it."""
    for lease in list(_LIVE):
        lease.wipe()


os.register_at_fork(after_in_child=_wipe_after_fork)


class Lease:
    """Three derived keys, held in locked memory until ``seconds`` have passed or ``wipe`` is called."""

    def __init__(self, keys: dict, seconds: int, clock: Callable[[], int] = time.monotonic_ns):
        if set(keys) != set(LEASE_LABELS):
            raise NoRestartError("a lease holds exactly the seal, firewall and audit keys")
        if type(seconds) is not int or not 1 <= seconds <= MAX_LEASE_S:
            raise NoRestartError(f"a lease lasts from 1 second to {MAX_LEASE_S} seconds")
        self._keys = dict(keys)
        self._clock = clock
        self.seconds = seconds
        self._deadline = clock() + seconds * BILLION
        _LIVE.add(self)

    @classmethod
    def from_grant(cls, grant: Grant, seconds: int, clock: Callable[[], int] = time.monotonic_ns) -> "Lease":
        """Derive the keys from a grant the owner just typed the password for, then let the grant go."""
        return cls({label: SecretBytes(grant.key(label)) for label in LEASE_LABELS}, seconds, clock)

    @classmethod
    def from_hex(cls, keys: dict, seconds: int) -> "Lease":
        try:
            return cls({label: SecretBytes(bytes.fromhex(keys[label])) for label in LEASE_LABELS}, seconds)
        except (KeyError, TypeError, ValueError):
            raise NoRestartError("the watcher was not given the three keys") from None

    @property
    def alive(self) -> bool:
        return bool(self._keys) and self._clock() < self._deadline

    def left(self) -> int:
        """Whole seconds still to run (0 once it has ended)."""
        return max(0, (self._deadline - self._clock()) // BILLION) if self._keys else 0

    def key(self, label: str) -> bytes:
        if not self.alive:
            self.wipe()
            raise AuthorizationDenied("the lease has ended")
        if label not in LEASE_LABELS:
            raise AuthorizationDenied(f"the lease holds no {label!r} key")
        return bytes(self._keys[label].raw)

    def hex_keys(self) -> dict:
        return {label: self.key(label).hex() for label in LEASE_LABELS}

    def wipe(self) -> None:
        for k in self._keys.values():
            k.wipe()
        self._keys = {}


class LeasedGrant(Grant):
    """A grant backed by a lease: serves only the lease's three keys and gives up no master key."""

    def __init__(self, action: str, target: str, lease: Lease):
        self.action, self.target, self._lease = action, target, lease

    def check(self, action: str, target: str) -> None:
        if not self._lease.alive:
            raise AuthorizationDenied("the lease has ended")
        if (action, target) != (self.action, self.target):
            raise AuthorizationDenied(f"grant is for {self.action}:{self.target}, not {action}:{target}")

    def key(self, label: str) -> bytes:
        return self._lease.key(label)

    def chip_master(self, chip_secret: bytes):
        raise AuthorizationDenied("a lease cannot give a master key")

    def close(self) -> None:
        pass                                    # the lease is not this grant's to wipe


class _NoPrompter:
    """Nobody is there. A question that reaches it is a decision only the owner may make: stop, do not guess."""

    def info(self, text: str) -> None:
        pass

    def confirm(self, question: str) -> bool:
        raise AuthorizationDenied("it needs a decision only you can make: " + question[:120])

    def password(self, prompt: str):
        raise AuthorizationDenied("unattended: no password can be typed")

    def close(self) -> None:
        pass


class LeaseAuthority:
    """Stands where an ``Authority`` stands for ``layers.traverse``, but never prompts. ``allow`` lets one
    ``app.open`` or ``app.close`` of one named target through, once; anything else is refused and logged."""

    def __init__(self, paths: Paths, lease: Lease):
        self.paths, self.lease = paths, lease
        self.prompter = _NoPrompter()
        self.audit = AuditLog(paths)
        self._allowed: set = set()

    def allow(self, action: str, target: str) -> None:
        if action not in LEASE_ACTIONS:
            raise NoRestartError(f"a lease can authorize only {', '.join(LEASE_ACTIONS)}, not {action}")
        self._allowed.add((action, target))

    def authorize(self, action: str, target: str = "") -> Grant:
        if (action, target) not in self._allowed:
            self.audit.record(f"lease:{action}", target, "refused")
            raise AuthorizationDenied(f"a lease does not cover {action}")
        self._allowed.discard((action, target))                 # one permission, one use
        self.audit.record(f"lease:{action}", target, "granted", key=self.lease.key(AUDIT_KEY_LABEL))
        return LeasedGrant(action, target, self.lease)


# ---- what is out of date ------------------------------------------------------------------------

@dataclass(frozen=True)
class Row:
    id: str
    name: str
    mode: str
    running: str            # the version it was started from ("" if unrecorded)
    installed: str
    state: str              # current | stale | in-use | needs-you | unknown
    why: str = ""


def _unattended_blocker(paths: Paths, inst: Instance, installed_sha: str, permits: PermitStore) -> str:
    """Why the new file may not replace this instance without the owner, or "" if it may. An unattended swap
    only ever replaces like with like: it never widens what the app may do and never asks a question."""
    try:
        permits.require(inst.name)
        permits.check_pin(inst.name, installed_sha)
    except (PermitError, KAppError) as e:
        return str(e)
    try:
        m = KApp.from_file(paths.apps.joinpath(f"{inst.name}.kapp")).manifest      # display-only; the seal is checked at launch
    except (KAppError, OSError):
        return "its file cannot be read"
    try:
        permits.check_declared(inst.name, m.permissions)
    except PermitError as e:
        return str(e)
    if "network" in m.permissions:
        return "it asks for network access, which only you can allow"
    if "system" in m.permissions and not inst.system:
        return "the new version asks for the system permission the running one did not have"
    if "admin" in m.permissions and not inst.admin:
        return "the new version asks for the admin permission the running one did not have"
    extra = sorted(set(m.asks) - set(inst.asks))
    if extra:
        return f"the new version asks the OS for {extra[0]}, which the running one could not"
    if not supports_mode(m.modes, inst.mode):
        return f"the new version has no {inst.mode} mode"
    return ""


def _judge(paths: Paths, inst: Instance, app, permits: PermitStore) -> Row:
    def row(state: str, why: str = "") -> Row:
        return Row(inst.id, inst.name, inst.mode, inst.version, app.version if app else "", state, why)
    if app is None:
        return row(UNKNOWN, "it is no longer installed")
    if not inst.sha256:
        return row(UNKNOWN, "it was started before the OS recorded which file it ran; restart it once")
    if inst.sha256 == app.sha256:
        return row(CURRENT)
    if inst.version and version_key(app.version) < version_key(inst.version):
        return row(NEEDS_YOU, f"the installed version {app.version} is older than the running {inst.version}")
    blocker = _unattended_blocker(paths, inst, app.sha256, permits)
    if blocker:
        return row(NEEDS_YOU, blocker)
    if inst.attached:
        return row(IN_USE, "someone is looking at it; it is swapped when they leave it")
    return row(STALE, "a newer file is installed")


def scan(paths: Paths, registry: Optional[Registry] = None) -> list:
    """One row per running app instance. Needs no password: it compares the sha256 each instance recorded when
    it was launched with the sha256 in the install seal. Nothing is verified or run here."""
    installed = {a.name: a for a in AppStore(paths).installed()}
    permits = PermitStore(paths)
    return [_judge(paths, inst, installed.get(inst.name), permits)
            for inst in (registry or Registry(paths)).list() if inst.status == "running"]


# ---- when a reboot really is needed --------------------------------------------------------------

def _numbers(release: str) -> tuple:
    m = re.match(r"\d+(?:\.\d+)*", release or "")
    return tuple(int(p) for p in m.group(0).split(".")) if m else ()


def pending_kernel(root: Path, running: str) -> str:
    """A reason if a newer kernel than the running one is installed under ``root`` (/boot/vmlinuz-*,
    /lib/modules/*), else "". Only the numeric part is compared, so a rebuild with the same number is not seen."""
    have = _numbers(running)
    if not have:
        return ""
    best, best_name = have, ""
    candidates = [(p.name[len("vmlinuz-"):]) for p in root.joinpath("boot").glob("vmlinuz-*")]
    candidates += [p.name for p in root.joinpath("lib", "modules").glob("*")]
    for name in candidates:
        n = _numbers(name)
        if n > best:
            best, best_name = n, name
    return f"kernel {running} is running and {best_name} is installed: a new kernel loads only at boot" if best_name else ""


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return ""


def _state_dir(paths: Paths) -> Path:
    return paths.state.joinpath("norestart")


def note_reboot_needed(paths: Paths, why: str) -> None:
    """Record that a reboot is needed for ``why`` (the firmware flasher calls this after a verified write). The
    note is dropped by itself once the machine has booted again. Not secret: a reason and a boot id."""
    d = _state_dir(paths)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    notes = _read_notes(paths)
    notes.append({"why": re.sub(r"[^\x20-\x7e]", "?", why)[:200], "boot": _boot_id()})
    atomic_write(d.joinpath("reboot-needed.json"), json.dumps(notes[-20:]).encode())


def _read_notes(paths: Paths) -> list:
    try:
        raw = json.loads(_state_dir(paths).joinpath("reboot-needed.json").read_text())
    except (OSError, ValueError):
        return []
    here = _boot_id()
    return [n for n in raw if isinstance(n, dict) and isinstance(n.get("why"), str)
            and n.get("boot") == here] if isinstance(raw, list) else []


def reboot_reasons(paths: Paths, running: Optional[str] = None, root: Optional[Path] = None) -> list:
    out = []
    k = pending_kernel(root if root is not None else paths.root, running if running is not None else os.uname().release)
    if k:
        out.append(k)
    out += [n["why"] for n in _read_notes(paths)]
    return out


def code_stamp() -> str:
    """A fingerprint of the OS's own Python files (name, size, change time): has the OS been updated?"""
    h = hashlib.sha256()
    for p in [*sorted(PKG.glob("*.py")), *sorted(PKG.joinpath("office").glob("*.py"))]:
        try:
            st = p.stat()
        except OSError:
            continue
        h.update(f"{p.name}:{st.st_size}:{st.st_mtime_ns}\n".encode())
    return h.hexdigest()


def _newest_code_s() -> int:
    newest = 0
    for p in [*PKG.glob("*.py"), *PKG.joinpath("office").glob("*.py")]:
        try:
            newest = max(newest, p.stat().st_mtime_ns // BILLION)
        except OSError:
            continue
    return newest


def session_reasons(paths: Paths, registry: Optional[Registry] = None) -> list:
    """Apps whose broker started before the OS's own files last changed: they run the old OS code. A swap would
    not help (the new broker would be forked by a process that may be old too), so this is advice only."""
    newest = _newest_code_s()
    old = sorted({i.name for i in (registry or Registry(paths)).list()
                  if i.status == "running" and int(i.started) < newest})
    return [f"{len(old)} open app(s) started before the OS's own code changed ({', '.join(old[:6])}): "
            "restart the desktop (not the machine) to run the new OS code"] if old else []


@dataclass
class Report:
    reboot: list = field(default_factory=list)
    session: list = field(default_factory=list)
    apps: list = field(default_factory=list)
    auto: Optional[dict] = None

    @property
    def reboot_needed(self) -> bool:
        return bool(self.reboot)


def report(paths: Paths, running: Optional[str] = None, root: Optional[Path] = None) -> Report:
    return Report(reboot_reasons(paths, running, root), session_reasons(paths), scan(paths), watcher_state(paths))


# ---- swapping ------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Result:
    name: str
    old: str
    new: str
    outcome: str            # swapped | kept
    why: str = ""
    key: tuple = ()         # (instance id, installed sha256): what a watcher will not try twice


def _clip(e: BaseException) -> str:
    return re.sub(r"[^\x20-\x7e]", "?", f"{type(e).__name__}: {e}")[:160]


def _swap(paths: Paths, lease: Lease, row: Row, installed_sha: str, spawner: Callable, wait: int) -> Result:
    from .system import close_instance, open_background
    registry, audit = Registry(paths), AuditLog(paths)
    auth = LeaseAuthority(paths, lease)
    ident = (row.id, installed_sha)

    def kept(why: str) -> Result:
        audit.record("lease:norestart.swap", row.name, "kept: " + why[:100])
        return Result(row.name, row.running, row.installed, KEPT, why, ident)

    def drop(inst_id: str) -> None:
        try:
            auth.allow(CLOSE, inst_id)
            close_instance(paths, auth, inst_id)
        except Exception:
            pass

    try:
        old = registry.get(row.id)
    except Exception as e:
        return kept(_clip(e))
    if old.status != "running" or old.sha256 == installed_sha:
        return kept("it changed while the OS was looking")
    if old.attached:
        return kept("someone attached to it just now")
    before = {i.id for i in registry.list() if i.name == row.name}
    try:
        auth.allow(OPEN, row.name)
        new = open_background(paths, auth, row.name, old.mode, address=old.address, spawner=spawner, wait=wait)
    except Exception as e:
        for i in registry.list():                      # a half-started copy must not be left behind
            if i.name == row.name and i.id not in before:
                drop(i.id)
        return kept(_clip(e))
    if new.sha256 != installed_sha:
        drop(new.id)
        return kept("the copy that started is not the installed file")
    try:
        if registry.get(old.id).attached:              # looked at since the first check: leave them on the old one
            drop(new.id)
            return kept("someone attached to it during the swap")
    except Exception:
        pass
    note = ""
    try:
        auth.allow(CLOSE, old.id)
        close_instance(paths, auth, old.id)
    except Exception as e:
        note = "; the old copy could not be closed: " + _clip(e)
    audit.record("lease:norestart.swap", f"{row.name} {row.running or '?'} -> {new.version}", "granted",
                 key=lease.key(AUDIT_KEY_LABEL))
    return Result(row.name, row.running, new.version, SWAPPED, ("now running " + new.id + note), ident)


def refresh(paths: Paths, lease: Lease, only: str = "", skip: Optional[set] = None, spawner: Optional[Callable] = None,
            wait: int = 5) -> list:
    """Swap every stale, unattended-safe instance (or just the app ``only``). Returns one Result per attempt.
    An instance that needs the owner, is being looked at, or is already current is not touched."""
    if spawner is None:
        from .broker import spawn as spawner
    installed = {a.name: a.sha256 for a in AppStore(paths).installed()}
    out = []
    for row in scan(paths):
        if row.state != STALE or (only and row.name != only):
            continue
        if skip and (row.id, installed.get(row.name, "")) in skip:
            continue
        out.append(_swap(paths, lease, row, installed.get(row.name, ""), spawner, wait))
    return out


# ---- the watcher: "fully automatic" -------------------------------------------------------------

def _watcher_file(paths: Paths) -> Path:
    return _state_dir(paths).joinpath("watcher.json")


def _is_watcher(pid: int) -> bool:
    try:
        args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return False
    return b"kos.norestart" in args and b"watch" in args


def watcher_state(paths: Paths) -> Optional[dict]:
    """The running watcher's public state (pid, end time, counts), or None. Holds no key. A file left by a
    watcher that died is removed; a pid in the file that is not a watcher is never signalled."""
    f = _watcher_file(paths)
    try:
        d = json.loads(f.read_text())
        pid = d["pid"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if type(pid) is not int or pid <= 0 or not _is_watcher(pid):
        try:
            f.unlink()
        except OSError:
            pass
        return None
    return {k: d.get(k) for k in ("pid", "started", "until", "swapped", "kept", "last")}


def _write_state(paths: Paths, d: dict) -> None:
    _state_dir(paths).mkdir(parents=True, exist_ok=True)
    os.chmod(_state_dir(paths), 0o700)
    atomic_write(_watcher_file(paths), json.dumps(d).encode())


def start_watcher(paths: Paths, lease: Lease, seconds: int, interval: int = INTERVAL_S) -> int:
    """Start the watcher as a fresh process (new OS code, none of this process's open devices or sockets) and
    hand it the keys over a pipe. The caller wipes its own lease afterwards."""
    if watcher_state(paths) is not None:
        raise NoRestartError("the watcher is already running (stop it first)")
    d = _state_dir(paths)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    cmd = [sys.executable, "-m", "kos.norestart", "watch", "--root", str(paths.root), "--seconds", str(seconds),
           "--interval", str(interval)]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True, close_fds=True, cwd=str(PKG.parent))
    threading.Thread(target=p.wait, daemon=True).start()           # reap it when it ends
    try:
        p.stdin.write(json.dumps(lease.hex_keys()).encode())
        p.stdin.close()
    except OSError:
        p.kill()
        raise NoRestartError("the watcher could not be given its keys") from None
    end = time.monotonic_ns() + 10 * BILLION
    while time.monotonic_ns() < end:
        st = watcher_state(paths)
        if st is not None and st["pid"] == p.pid:
            return p.pid
        if p.poll() is not None:
            break
        time.sleep(1)
    p.kill()
    raise NoRestartError("the watcher did not start")


def stop_watcher(paths: Paths) -> bool:
    """Ask the watcher to stop (it wipes its keys as it ends). False if none was running."""
    st = watcher_state(paths)
    if st is None:
        return False
    try:
        os.kill(st["pid"], signal.SIGTERM)
    except ProcessLookupError:
        return False
    end = time.monotonic_ns() + 5 * BILLION
    while time.monotonic_ns() < end and _watcher_file(paths).exists() and _is_watcher(st["pid"]):
        time.sleep(1)
    return True


def watch(paths: Paths, lease: Lease, interval: int = INTERVAL_S, sleep: Callable = time.sleep,
          stopped: Callable[[], bool] = lambda: False, stamp: Callable[[], str] = code_stamp,
          rounds: int = 0, spawner: Optional[Callable] = None) -> str:
    """Refresh stale apps every ``interval`` seconds until the lease ends, ``stopped()`` is true, or the OS's
    own code changed under this process. Always wipes the lease. Returns why it ended."""
    started = time.time_ns() // BILLION
    state = {"pid": os.getpid(), "started": started, "until": started + lease.left(), "swapped": 0, "kept": 0,
             "last": []}
    audit = AuditLog(paths)
    tried: set = set()
    base, why, n = stamp(), "", 0
    try:
        _write_state(paths, state)
        while True:
            if stopped():
                why = "stopped"
            elif not lease.alive:
                why = "the lease ran out"
            elif stamp() != base:
                why = "the OS's own code changed: start the watcher again (password) to use the new code"
            if why:
                break
            results = refresh(paths, lease, skip=tried, spawner=spawner)
            for r in results:
                state["swapped" if r.outcome == SWAPPED else "kept"] += 1
                if r.outcome == KEPT:
                    tried.add(r.key)
            state["last"] = ([{"name": r.name, "outcome": r.outcome, "why": r.why[:120]} for r in results]
                             + state["last"])[:5]
            _write_state(paths, state)
            n += 1
            if rounds and n >= rounds:
                why = "finished"
                break
            for _ in range(max(1, interval)):
                if stopped() or not lease.alive:
                    break
                sleep(1)
    finally:
        lease.wipe()
        try:
            _watcher_file(paths).unlink()
        except OSError:
            pass
        try:
            audit.record("lease:norestart.watch", f"{state['swapped']} swapped, {state['kept']} kept", "ended: " + (why or "error"))
        except OSError:
            pass
    return why


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m kos.norestart")
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("watch")
    w.add_argument("--root", required=True)
    w.add_argument("--seconds", type=int, required=True)
    w.add_argument("--interval", type=int, default=INTERVAL_S)
    args = ap.parse_args(argv)
    try:
        lease = Lease.from_hex(json.loads(sys.stdin.read()), args.seconds)
    except (ValueError, NoRestartError) as e:
        print(f"kos norestart: {e}", file=sys.stderr)
        return 2
    flag = {"stop": False}
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda *_: flag.update(stop=True))
    watch(Paths(Path(args.root)), lease, interval=max(1, args.interval), stopped=lambda: flag["stop"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
