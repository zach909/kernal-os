"""The elevated administrator keyboard, and the guarded file write that needs it.

What "booting" it means
-----------------------
The password you type to unlock the computer (``session.login``) is reused,
once, to boot the administrator keyboard: no second prompt. Booting

1. checks the **kernel** - the administrator keyboard refuses to exist unless
   the KOS kernel protections (Landlock, user namespaces) are present, and it
   re-checks on every use, so it cannot be run on a kernel that cannot
   enforce what KOS promises;
2. finds the physical keyboards it will take over (evdev);
3. writes a *lease*: who/when/which keyboards, signed with a key derived from
   your password (``HMAC(master, "admin-keyboard")``).

The lease is bound to this boot (``boot_id``) and expires; locking the
session deletes it. Nobody can forge one without the password, because the
signature can only be checked - or made - while the password is known.

What it is for
--------------
Writing a file is an administrator action. ``kos write`` needs:

* a live, correctly signed lease (the keyboard was booted at login, on a
  capable kernel);
* the password again, **typed on that keyboard**: while a write is waiting for
  its password the keyboards are taken exclusively (``EVIOCGRAB``), so no
  other program can read the keystrokes, and if somebody else already holds a
  keyboard the write is refused;
* afterwards - ``file.write`` *requires* it, see ``requires.py`` - the file
  is **security scanned** (``kos/scan.py``; flagged means quarantined) and the
  disk is **optimized** (``kos/optimize.py``), in that order, under the same
  password. Whatever is not done stays owed on a ledger and blocks the next
  write until ``kos settle``.

Honest limits
-------------
* The lease is a signed record, not a separate privileged process: a program
  running as you can read it but cannot forge it, and it still cannot write
  through KOS without the password. It does not stop a program running as you
  from writing files with its own ``open()`` - only KOS's own write path is
  guarded, which is why apps run sandboxed.
* Exclusive keyboard capture needs real evdev hardware (a KOS console). Over
  a plain terminal (ssh, a dev container) set ``KOS_DEV_ADMIN_WEAK=1``: the
  lease is then marked WEAK and the keyboard is *not* exclusive.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import select
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .auth import AuditLog, Authority, Grant
from .paths import Paths, atomic_write
from .requires import Ledger, Requirements, Unsatisfied
from .scan import ScanResult, scan_bytes

LEASE_LABEL = "admin-keyboard"
LEASE_TTL = 8 * 3600.0
MAX_WRITE = 16 << 20
BOOT_ACTIONS = ("session.login", "admin.boot")


class AdminError(Exception):
    pass


class WriteBlocked(AdminError):
    """The security scan flagged the data; nothing was written."""

    def __init__(self, result: ScanResult):
        self.result = result
        super().__init__(f"security scan failed - {result.summary()}")


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return ""


def kernel_gaps(report: dict) -> list[str]:
    """What the KOS kernel must provide for the administrator keyboard to run."""
    gaps = []
    if not report.get("landlock_abi"):
        gaps.append("Landlock (kernel sandbox) is not available")
    if not report.get("user_namespaces"):
        gaps.append("user namespaces are not available")
    return gaps


def probe_keyboards() -> list[str]:
    from .devices import find_evdev
    try:
        return find_evdev("keyboard")
    except OSError:
        return []


def weak_allowed() -> bool:
    return os.environ.get("KOS_DEV_ADMIN_WEAK") == "1"


@dataclass
class Lease:
    id: str
    booted: float
    expires: float
    boot_id: str
    keyboards: list[str] = field(default_factory=list)
    exclusive: bool = True
    weak: bool = False
    mac: str = ""

    def body(self) -> bytes:
        d = asdict(self)
        d.pop("mac")
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

    def sign(self, key: bytes) -> "Lease":
        self.mac = hmac.new(key, b"kos-admin-lease-v1\x00" + self.body(), hashlib.sha256).hexdigest()
        return self

    def verify_mac(self, key: bytes) -> bool:
        want = hmac.new(key, b"kos-admin-lease-v1\x00" + self.body(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(want, self.mac)


class AdminKeyboard:
    def __init__(self, paths: Paths, *, kernel_report: Optional[Callable[[], dict]] = None,
                 probe: Callable[[], list[str]] = probe_keyboards,
                 now: Callable[[], float] = time.time,
                 boot_id: Callable[[], str] = _boot_id):
        self.paths = paths
        self._report = kernel_report
        self._probe = probe
        self._now = now
        self._boot_id = boot_id
        self.file = paths.state / "admin-lease.json"

    def kernel_report(self) -> dict:
        if self._report is not None:
            return self._report()
        from .sandbox import report
        return report()

    # --- booting -----------------------------------------------------------
    def boot(self, grant: Grant) -> Lease:
        """Boot the keyboard with a password grant (the login one, or ``admin.boot``)."""
        if grant.action not in BOOT_ACTIONS:
            raise AdminError(f"the administrator keyboard is booted with the login password, "
                             f"not a '{grant.action}' grant")
        weak = False
        gaps = kernel_gaps(self.kernel_report())
        keyboards = self._probe()
        if not keyboards:
            gaps.append("no keyboard device to take over")
        if gaps:
            if not weak_allowed():
                raise AdminError("the elevated administrator keyboard needs the KOS kernel: "
                                 + "; ".join(gaps))
            weak = True
        now = self._now()
        lease = Lease(id=os.urandom(8).hex(), booted=now, expires=now + LEASE_TTL,
                      boot_id=self._boot_id(), keyboards=keyboards,
                      exclusive=bool(keyboards) and not weak, weak=weak)
        lease.sign(grant.key(LEASE_LABEL))
        self.paths.ensure()
        atomic_write(self.file, json.dumps(asdict(lease), indent=2).encode())
        AuditLog(self.paths).record("admin.boot", lease.id, "weak" if weak else "booted")
        return lease

    def shutdown(self) -> None:
        try:
            self.file.unlink()
        except FileNotFoundError:
            return
        AuditLog(self.paths).record("admin.lock", "", "locked")

    # --- using it ----------------------------------------------------------
    def _load(self) -> Lease:
        try:
            return Lease(**json.loads(self.file.read_text()))
        except FileNotFoundError:
            raise AdminError("the administrator keyboard is not booted "
                             "(it boots when you unlock; or run: admin boot)") from None
        except (ValueError, TypeError):
            raise AdminError("administrator lease is corrupt - lock and unlock again") from None

    def require_booted(self) -> Lease:
        """Everything that can be checked *without* the password: present, this
        boot, unexpired, and the kernel can still do its job. Used to refuse
        early, before asking for a password."""
        lease = self._load()
        if lease.boot_id != self._boot_id():
            raise AdminError("administrator lease is from a previous boot")
        if self._now() >= lease.expires:
            raise AdminError("administrator lease expired - lock and unlock again")
        gaps = kernel_gaps(self.kernel_report())
        if gaps and not (lease.weak and weak_allowed()):
            raise AdminError("the elevated administrator keyboard needs the KOS kernel: "
                             + "; ".join(gaps))
        return lease

    def verify(self, grant: Grant) -> Lease:
        """``require_booted`` plus the signature, which needs the password."""
        lease = self.require_booted()
        if not lease.verify_mac(grant.key(LEASE_LABEL)):
            raise AdminError("administrator lease signature is invalid - refusing")
        return lease

    def status(self) -> str:
        try:
            lease = self.require_booted()
        except AdminError as e:
            return f"administrator keyboard: OFF ({e})"
        left = int(lease.expires - self._now())
        kind = ("WEAK - terminal keyboard, not exclusive" if lease.weak else
                f"exclusive on {', '.join(lease.keyboards)}")
        return f"administrator keyboard: ON ({kind}; {left // 60} min left)"


# --- typing the admin password on the exclusive keyboard ----------------------

class AdminPrompter:
    """A prompter that reads from OS-owned input devices (``fds()``/``read()``,
    the same interface the app sessions use) instead of the terminal. With
    ``EvdevDevices`` the keyboards are grabbed, so nothing else can see these keys."""

    def __init__(self, devices, out=None):
        self.devices = devices
        self.out = out or sys.stderr

    def info(self, message: str) -> None:
        print(message, file=self.out, flush=True)

    def _keys(self, timeout: float = 120.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select(self.devices.fds(), [], [], 0.25)
            for fd in ready:
                yield from self.devices.read(fd)

    def password(self, prompt: str) -> Optional[bytes]:
        print(prompt, end="", file=self.out, flush=True)
        buf = bytearray()
        try:
            for ev in self._keys():
                if ev["type"] == "interrupt":
                    return None
                if ev["type"] != "key":
                    continue
                k = ev["key"]
                if k == "enter":
                    print("", file=self.out)
                    return bytes(buf)
                if k == "escape":
                    return None
                if k == "backspace":
                    if buf:
                        buf.pop()
                elif len(k) == 1:
                    buf += k.encode()
            return None
        finally:
            for i in range(len(buf)):
                buf[i] = 0

    def confirm(self, question: str) -> bool:
        print(f"{question} [y/N] ", end="", file=self.out, flush=True)
        for ev in self._keys():
            if ev["type"] == "interrupt":
                return False
            if ev["type"] == "key" and ev["key"].lower() in ("y", "n", "enter", "escape"):
                print(ev["key"] if len(ev["key"]) == 1 else "", file=self.out)
                return ev["key"].lower() == "y"
        return False


def open_admin_devices(lease: Lease):
    """Take the keyboards exclusively for the length of one admin action.
    Raises (and the write is refused) if someone else already holds one."""
    if not lease.exclusive:
        return None
    from .devices import DeviceError, EvdevDevices
    try:
        return EvdevDevices(1, 1)   # grabs every keyboard; refuses if one is already grabbed
    except DeviceError as e:
        raise AdminError(f"cannot take the keyboard exclusively: {e}") from None


# --- what the policy table means here ----------------------------------------------

def requirements(keyboard: AdminKeyboard, grant: Optional[Grant] = None) -> Requirements:
    """The ``before`` side of ``requires.RULES`` for this machine. With a login
    ``grant`` the administrator keyboard can be *booted* to satisfy it."""
    def kernel() -> Optional[str]:
        gaps = kernel_gaps(keyboard.kernel_report())
        return None if (not gaps or weak_allowed()) else "; ".join(gaps)

    def booted() -> Optional[str]:
        try:
            keyboard.require_booted()
            return None
        except AdminError as e:
            return str(e)

    boots = {"admin.keyboard": lambda: keyboard.boot(grant)} if grant is not None else {}
    return Requirements({"kernel": kernel, "admin.keyboard": booted}, boots)


def _quarantine(paths: Paths, file: Path) -> Path:
    import shutil
    qdir = paths.state / "quarantine"
    qdir.mkdir(parents=True, exist_ok=True)
    os.chmod(qdir, 0o700)
    dest = qdir / f"write-{int(time.time())}-{file.name}"
    shutil.move(str(file), dest)
    return dest


def _discharge(paths: Paths, ledger: Ledger, entry: dict, *, scanner, optimize_once,
               audit: AuditLog) -> Optional[ScanResult]:
    """Strike off what one ledger entry still owes. Returns a failed scan, if any.
    A step that raises stays owed (and keeps blocking) until it succeeds."""
    flagged = None
    for step in list(entry["pending"]):
        if step == "scan":
            target = Path(entry["target"])
            if target.exists():
                result = scanner(target.read_bytes(), str(target))
                if not result.clean:
                    flagged = result
                    audit.record("file.write", str(target), "quarantined-by-scan")
                    _quarantine(paths, target)
        elif step == "optimize":
            optimize_once()
        ledger.done(entry["id"], step)
    return flagged


# --- the guarded write -----------------------------------------------------------

@dataclass
class WriteReport:
    path: str
    bytes_written: int
    scan: ScanResult
    optimize_summary: str

    def summary(self) -> str:
        return (f"wrote {self.bytes_written:,} bytes to {self.path}\n"
                f"  security scan: {self.scan.summary()}\n"
                f"  disk optimize: {self.optimize_summary}")


def _protected(paths: Paths, target: Path) -> Optional[Path]:
    for guarded in (paths.etc, paths.state):
        g = Path(os.path.realpath(guarded))
        if target == g or g in target.parents:
            return g
    return None


def write_file(paths: Paths, authority: Authority, keyboard: AdminKeyboard, target: str,
               data: bytes, *, scanner: Callable[[bytes, str], ScanResult] = scan_bytes,
               optimizer: Optional[Callable[..., object]] = None,
               ledger: Optional[Ledger] = None) -> WriteReport:
    """Write a file. ``file.write`` *requires* the administrator keyboard
    (before) and leaves a security scan and a disk optimize owed (after) - both
    discharged right here, in that order, under the same password. Anything not
    discharged stays on the ledger and blocks the next write until settled."""
    from .optimize import optimize as default_optimize
    optimizer = optimizer or default_optimize
    ledger = ledger or Ledger(paths)

    if len(data) > MAX_WRITE:
        raise AdminError(f"refusing to write more than {MAX_WRITE >> 20} MiB at once")
    path = Path(os.path.abspath(target))
    parent = Path(os.path.realpath(path.parent))
    if not parent.is_dir():
        raise AdminError(f"no such directory: {path.parent}")
    final = parent / path.name
    if path.name in ("", ".", ".."):
        raise AdminError(f"not a file name: {target!r}")
    guarded = _protected(paths, final)
    if guarded:
        raise AdminError(f"{guarded} is KOS system state; it is only changed by KOS itself")
    if final.is_symlink() or final.is_dir():
        raise AdminError(f"{final} is a symlink or directory; refusing to write through it")

    try:                                              # refuse before asking for a password
        requirements(keyboard).ensure("file.write")
    except Unsatisfied as e:
        raise AdminError(str(e)) from None
    owed = ledger.owed("file.write")
    if owed:
        steps = sorted({s for e in owed for s in e["pending"]})
        raise AdminError(f"an earlier write still owes: {', '.join(steps)} - run 'settle' first")

    audit = AuditLog(paths)
    summary = {"opt": "not run"}
    with authority.authorize("file.write", str(final)) as grant:
        keyboard.verify(grant)
        atomic_write(final, data, mode=0o600)
        entry_id = ledger.owe("file.write", str(final))
        audit.record("file.write", str(final), "written")

        def optimize_once() -> None:
            opt = optimizer(paths, authority, grant=grant)
            summary["opt"] = opt.summary() if hasattr(opt, "summary") else str(opt)

        entry = ledger.owed("file.write")[-1]
        assert entry["id"] == entry_id
        flagged = _discharge(paths, ledger, entry, scanner=scanner,
                             optimize_once=optimize_once, audit=audit)
    if flagged is not None:
        raise WriteBlocked(flagged)
    return WriteReport(str(final), len(data), scan_bytes(data), summary["opt"])


def settle(paths: Paths, authority: Authority, *, scanner=scan_bytes,
           ledger: Optional[Ledger] = None) -> list[str]:
    """Discharge everything still owed (a crash, a failed step). Needs the
    password once, for the optimize."""
    from .optimize import optimize as default_optimize
    ledger = ledger or Ledger(paths)
    audit, lines = AuditLog(paths), []
    entries = ledger.owed()
    if not entries:
        return ["nothing is owed"]
    with authority.authorize("disk.optimize") as grant:
        def optimize_once() -> None:
            lines.append("disk optimize: " + default_optimize(paths, authority, grant=grant).summary())
        for entry in entries:
            if entry["trigger"] == "ledger":
                raise AdminError("the ledger is unreadable - refusing to guess what is owed")
            flagged = _discharge(paths, ledger, entry, scanner=scanner,
                                 optimize_once=optimize_once, audit=audit)
            lines.append(f"{entry['target']}: " + ("FLAGGED and quarantined" if flagged else "settled"))
    return lines
