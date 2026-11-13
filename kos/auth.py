"""The Authority: every privileged action in KOS is gated on the owner's password.

How the password is tied to everything
--------------------------------------
The password is never stored. At setup we pick a random salt and run scrypt
(memory-hard, so GPU guessing is expensive) to derive a 256-bit *master key*.
We store only the scrypt parameters and a *verifier* = HMAC(master, "verifier").

Every other secret in the system is derived from the master key with a label,
e.g. the key that seals installed apps is HMAC(master, "kapp-seal"). That means:

* Without the password nobody (including root on a running system, or someone
  who copied the disk) can produce a valid app seal, so they cannot slip a
  modified app in.
* There is no key sitting in a file or a daemon waiting to be used. Each action
  asks for the password, derives the master key into locked memory, uses it and
  wipes it. Nothing can act autonomously because there is nothing to act *with*.

Grants
------
``Authority.authorize(action, target)`` prompts, verifies, and returns a
:class:`Grant` bound to exactly that ``(action, target)`` pair. Components that
perform the action call ``grant.check(action, target)`` so a grant for
"boot the mouse" cannot be reused to install an app.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .paths import Paths, atomic_write
from .secret import SecretBytes

# Every action the system knows about. Anything not listed here is refused.
ACTIONS: dict[str, str] = {
    "session.login": "log in",
    "auth.change": "change password",
    "app.install": "install app",
    "app.update": "update app",
    "app.remove": "remove app",
    "file.view": "view file",
    "app.run": "run app",
    "app.graphical": "run app graphically",
    "app.network": "give app network access",
    "device.mouse": "boot mouse",
    "device.keyboard": "boot keyboard",
    "device.desktop": "boot desktop",
    "app.open": "open app",
    "app.close": "close app",
    "app.permit": "give app permission to run",
    "app.revoke": "revoke app's permission to run",
    "space.grant": "give an app access to a shared folder",
    "space.revoke": "take an app's access to a shared folder away",
    "app.update.all": "update all apps",
    "scan.watch": "start virus scan watcher",
    "disk.optimize": "optimize disk space",
    "cell.start": "start kernel cell",
    "cell.stop": "stop kernel cell",
    "file.write": "write file",
    "code.run": "run code",
    "runtime.add": "add a programming language to run code in",
    "runtime.remove": "remove a programming language you added",
    "admin.boot": "boot the administrator keyboard",
    "backup.add": "back up",
    "backup.list": "list backups",
    "backup.remove": "remove backup",
    "backup.restore": "restore backup",
    "applink.add": "back up an app as a download address",
    "applink.list": "list app download addresses",
    "applink.remove": "forget an app download address",
    "applink.fetch": "download a linked app",
    "folders.create": "create the standard data folders",
    "app.convert": "convert a Debian package into an app",
    "skill.make": "make agent skills from the installed apps and commands",
    "audit.verify": "check the authorization log for tampering",
    "app.extend": "switch on an extension for an app",
    "app.mod": "let a mod modify a system app",
    "app.unextend": "switch off an extension or mod",
    "ai.ask": "send text to the AI",
    "ai.config": "set up or look at the AI connection",
    "state.view": "look at what is installed, open or logged",
    "overlay.order": "set the load order of mod file layers",
    "overlay.view": "look at the merged mod file layers",
}


class AuthError(Exception):
    pass


class AuthorizationDenied(AuthError):
    pass


@dataclass(frozen=True)
class KdfParams:
    n: int
    r: int
    p: int
    salt: bytes

    # ~128 MiB of RAM per attempt: each guess costs an attacker real memory.
    DEFAULT_N = 2**17
    DEFAULT_R = 8
    DEFAULT_P = 1

    @classmethod
    def fresh(cls, n: int = DEFAULT_N, r: int = DEFAULT_R, p: int = DEFAULT_P) -> "KdfParams":
        return cls(n=n, r=r, p=p, salt=os.urandom(32))

    def to_json(self) -> dict:
        return {"alg": "scrypt", "n": self.n, "r": self.r, "p": self.p,
                "salt": base64.b64encode(self.salt).decode()}

    @classmethod
    def from_json(cls, d: dict) -> "KdfParams":
        if d.get("alg") != "scrypt":
            raise AuthError(f"unsupported KDF {d.get('alg')!r}")
        params = cls(n=int(d["n"]), r=int(d["r"]), p=int(d["p"]),
                     salt=base64.b64decode(d["salt"]))
        if params.n < 2**10 or params.n & (params.n - 1) or len(params.salt) < 16:
            raise AuthError("refusing weak or malformed KDF parameters")
        return params


def derive_master(password: bytes, params: KdfParams) -> SecretBytes:
    maxmem = 256 * params.r * params.n * max(1, params.p) + (1 << 24)
    key = hashlib.scrypt(password, salt=params.salt, n=params.n, r=params.r,
                         p=params.p, maxmem=maxmem, dklen=32)
    return SecretBytes(key)


def subkey(master: SecretBytes, label: str) -> bytes:
    return hmac.new(master.raw, b"kos:v1:" + label.encode(), hashlib.sha256).digest()


class PasswordStore:
    """Holds the KDF parameters and verifier, never the password itself."""

    def __init__(self, paths: Paths):
        self.paths = paths

    def exists(self) -> bool:
        return self.paths.auth_file.exists()

    def _load(self) -> dict:
        try:
            return json.loads(self.paths.auth_file.read_text())
        except FileNotFoundError:
            raise AuthError("no password has been set up (run: kos setup)") from None

    def create(self, password: bytes, params: Optional[KdfParams] = None,
               throttle_base: float = 1.0, overwrite: bool = False) -> SecretBytes:
        if self.exists() and not overwrite:
            raise AuthError("a password already exists (use: kos passwd)")
        if len(password) < 8:
            raise AuthError("password must be at least 8 characters")
        params = params or KdfParams.fresh()
        master = derive_master(password, params)
        self.write(params, master, throttle_base)
        return master

    def write(self, params: KdfParams, master: SecretBytes, throttle_base: float = 1.0) -> None:
        doc = {
            "version": 1,
            "kdf": params.to_json(),
            "verifier": base64.b64encode(subkey(master, "verifier")).decode(),
            "throttle_base": throttle_base,
        }
        self.paths.ensure()
        atomic_write(self.paths.auth_file, json.dumps(doc, indent=2).encode())

    def verify(self, password: bytes) -> Optional[SecretBytes]:
        doc = self._load()
        params = KdfParams.from_json(doc["kdf"])
        expected = base64.b64decode(doc["verifier"])
        master = derive_master(password, params)
        if hmac.compare_digest(subkey(master, "verifier"), expected):
            return master
        master.wipe()
        return None

    def throttle_base(self) -> float:
        return float(self._load().get("throttle_base", 1.0))


class Throttle:
    """Persistent back-off after failed attempts.

    Stored on disk so that restarting the program does not reset the delay.
    The first three failures are free (typos happen); after that each failure
    doubles the wait, capped at five minutes.
    """

    FREE_ATTEMPTS = 3
    MAX_DELAY = 300.0

    def __init__(self, paths: Paths, base: float = 1.0,
                 sleep: Callable[[float], None] = time.sleep):
        self.file = paths.state / "auth-throttle.json"
        self.base = base
        self._sleep = sleep

    def _read(self) -> tuple[int, float]:
        try:
            d = json.loads(self.file.read_text())
            return int(d["failures"]), float(d["last"])
        except (FileNotFoundError, ValueError, KeyError):
            return 0, 0.0

    def delay(self) -> float:
        failures, last = self._read()
        if failures < self.FREE_ATTEMPTS or self.base <= 0:
            return 0.0
        d = min(self.base * 2 ** (failures - self.FREE_ATTEMPTS), self.MAX_DELAY)
        return max(0.0, last + d - time.time())

    def wait(self, notify: Optional[Callable[[str], None]] = None) -> None:
        d = self.delay()
        if d > 0:
            if notify:
                notify(f"too many failed attempts; waiting {d:.0f}s")
            self._sleep(d)

    def fail(self) -> None:
        failures, _ = self._read()
        self.file.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self.file, json.dumps({"failures": failures + 1, "last": time.time()}).encode())

    def success(self) -> None:
        try:
            self.file.unlink()
        except FileNotFoundError:
            pass


GENESIS = "0" * 64
AUDIT_KEY_LABEL = "audit-chain"
_TAIL_CHUNK = 64 << 10
_LOCK_WAIT = 5.0
_FACTS = ("t", "action", "target", "outcome")


def _link(prev: str, entry: dict) -> str:
    """Hash of one entry, committing to the entry before it."""
    facts = json.dumps({k: entry[k] for k in _FACTS}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(prev.encode() + b"\n" + facts.encode()).hexdigest()


def _anchor(key: bytes, h: str) -> str:
    return hmac.new(key, h.encode(), hashlib.sha256).hexdigest()


@dataclass
class ChainReport:
    entries: int = 0        # lines in the file
    legacy: int = 0         # written before the chain existed: unprotected
    chained: int = 0
    anchored: int = 0       # chained lines carrying a password-derived MAC
    anchors_checked: bool = False   # a key was given and every anchor matched
    trimmed: bool = False   # the file starts mid-chain (optimize dropped older lines)
    problem: Optional[str] = None
    bad_line: Optional[int] = None  # 1-based

    @property
    def ok(self) -> bool:
        return self.problem is None


class AuditLog:
    """Append-only, tamper-evident record of every authorization decision.
    Contains no secrets.

    Each line commits to the one before it (``p`` is the previous ``h``; ``h`` is
    SHA-256 over ``p`` and the entry), so editing, deleting or reordering a line
    breaks the chain from there on. A line written while the owner's password was
    in hand (a grant) also carries ``m``, an HMAC of ``h`` under a key derived from
    the password. Anyone can recompute a plain chain after editing it; nobody can
    recompute ``m`` without the password, so rewriting history *before* a grant
    is noticed by :meth:`verify` given the key.

    Limits, stated plainly: a forger who also relabels every grant, or who cuts
    the end off the log, is not caught - nothing outside this file remembers what
    it should say. And ``optimize`` trims old lines, so the chain is checked from
    the first line that is left."""

    def __init__(self, paths: Paths):
        self.file = paths.logs / "audit.log"

    # --- writing ----------------------------------------------------------
    @contextlib.contextmanager
    def _locked(self):
        """The log open for appending and exclusively locked, and guaranteed to be
        the file that is at ``self.file`` now (``trim`` replaces the file)."""
        self.file.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + _LOCK_WAIT
        while True:
            fd = os.open(self.file, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
            try:
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() > deadline:
                            raise OSError("audit log is locked by another process") from None
                        time.sleep(0.005)
                try:
                    current = os.fstat(fd).st_ino == os.stat(self.file).st_ino
                except FileNotFoundError:
                    current = False
                if current:
                    yield fd
                    return
            finally:
                os.close(fd)        # also releases the lock
            if time.monotonic() > deadline:
                raise OSError("audit log kept changing under us")

    @staticmethod
    def _last_line(fd: int) -> bytes:
        end = os.fstat(fd).st_size
        buf = b""
        while end > 0:
            start = max(0, end - _TAIL_CHUNK)
            buf = os.pread(fd, end - start, start) + buf
            end = start
            body = buf.rstrip(b"\n")
            cut = body.rfind(b"\n")
            if cut >= 0 or start == 0:
                return body[cut + 1:]
        return b""

    def _head(self, fd: int) -> str:
        """Hash of the newest chained line (GENESIS if there is none yet). A corrupt
        or old-format last line starts a fresh chain - ``verify`` reports the
        damage; recording an event must never fail because of it."""
        try:
            h = json.loads(self._last_line(fd)).get("h")
        except (ValueError, AttributeError):
            return GENESIS
        return h if isinstance(h, str) and len(h) == 64 else GENESIS

    def record(self, action: str, target: str, outcome: str, key: Optional[bytes] = None) -> None:
        """Append one decision. Pass ``key`` (``grant.key(AUDIT_KEY_LABEL)``) when the
        password was just verified, so the line is anchored to it."""
        facts = {"t": round(time.time(), 3), "action": action, "target": target, "outcome": outcome}
        with self._locked() as fd:
            prev = self._head(fd)
            entry = dict(facts, p=prev, h=_link(prev, facts))
            if key is not None:
                entry["m"] = _anchor(key, entry["h"])
            data = json.dumps(entry, separators=(",", ":")).encode() + b"\n"
            while data:
                data = data[os.write(fd, data):]

    def trim(self, keep: int) -> int:
        """Keep only the newest ``keep`` lines; returns how many were dropped. The
        chain stays valid from the first line kept."""
        with self._locked() as fd:
            lines = [l for l in os.pread(fd, os.fstat(fd).st_size, 0).split(b"\n") if l]
            if len(lines) <= keep:
                return 0
            atomic_write(self.file, b"\n".join(lines[-keep:]) + b"\n")
            return len(lines) - keep

    # --- reading ----------------------------------------------------------
    @staticmethod
    def _parse(raw: bytes) -> Optional[dict]:
        try:
            e = json.loads(raw)
        except ValueError:
            return None
        return e if isinstance(e, dict) and all(k in e for k in _FACTS) else None

    def entries(self) -> list[dict]:
        try:
            data = self.file.read_bytes()
        except FileNotFoundError:
            return []
        return [e for e in map(self._parse, data.split(b"\n")) if e]

    def tail(self, n: int) -> list[dict]:
        """The newest ``n`` entries, reading only the end of the file."""
        if n <= 0:
            return []
        try:
            fd = os.open(self.file, os.O_RDONLY | os.O_CLOEXEC)
        except FileNotFoundError:
            return []
        try:
            end, buf = os.fstat(fd).st_size, b""
            while end > 0 and buf.count(b"\n") <= n:
                start = max(0, end - _TAIL_CHUNK)
                buf = os.pread(fd, end - start, start) + buf
                end = start
        finally:
            os.close(fd)
        lines = buf.split(b"\n")
        if end > 0:
            lines = lines[1:]       # the first piece is the end of a line we did not read
        return [e for e in map(self._parse, lines) if e][-n:]

    def verify(self, key: Optional[bytes] = None) -> ChainReport:
        """Check the chain (and, given ``key``, every password anchor)."""
        rep = ChainReport()
        try:
            data = self.file.read_bytes()
        except FileNotFoundError:
            return rep

        def fail(n: int, why: str) -> ChainReport:
            rep.problem, rep.bad_line = why, n
            return rep

        prev: Optional[str] = None
        for n, raw in enumerate(data.split(b"\n"), 1):
            if not raw.strip():
                continue
            rep.entries += 1
            e = self._parse(raw)
            if e is None:
                return fail(n, "not a valid log entry (damaged or inserted)")
            if "h" not in e:
                if prev is not None:
                    return fail(n, "an unchained line after the chain began (inserted or rewritten)")
                rep.legacy += 1
                continue
            p, h = e.get("p"), e["h"]
            if not (isinstance(p, str) and isinstance(h, str)):
                return fail(n, "malformed chain fields")
            if prev is None:
                rep.trimmed = p != GENESIS
            elif p != prev:
                return fail(n, "chain broken: this line does not follow the one before it "
                               "(a line was deleted, moved or edited)")
            if h != _link(p, e):
                return fail(n, "line does not match its hash (it was edited)")
            prev = h
            rep.chained += 1
            m = e.get("m")
            if e["outcome"] == "granted" and m is None:
                return fail(n, "a grant is missing its password anchor (removed or rewritten)")
            if m is not None:
                rep.anchored += 1
                if key is not None and not (isinstance(m, str) and hmac.compare_digest(m, _anchor(key, h))):
                    return fail(n, "password anchor does not match: history was rewritten "
                                   "without the password")
        rep.anchors_checked = key is not None
        return rep


class Grant:
    """Proof that the owner typed the password for one specific action."""

    def __init__(self, action: str, target: str, master: SecretBytes):
        self.action = action
        self.target = target
        self._master = master

    def check(self, action: str, target: str) -> None:
        if not self._master:
            raise AuthorizationDenied("grant already closed")
        if (action, target) != (self.action, self.target):
            raise AuthorizationDenied(
                f"grant is for {self.action}:{self.target}, not {action}:{target}")

    def key(self, label: str) -> bytes:
        if not self._master:
            raise AuthorizationDenied("grant already closed")
        return subkey(self._master, label)

    def close(self) -> None:
        self._master.wipe()

    def __enter__(self) -> "Grant":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class Authority:
    MAX_ATTEMPTS = 3

    def __init__(self, paths: Paths, prompter, throttle: Optional[Throttle] = None):
        self.paths = paths
        self.store = PasswordStore(paths)
        self.prompter = prompter
        self.audit = AuditLog(paths)
        self._throttle = throttle

    @property
    def throttle(self) -> Throttle:
        if self._throttle is None:
            self._throttle = Throttle(self.paths, base=self.store.throttle_base())
        return self._throttle

    def authorize(self, action: str, target: str = "") -> Grant:
        if action not in ACTIONS:
            raise AuthorizationDenied(f"unknown action {action!r}")
        if not self.store.exists():
            raise AuthError("no password has been set up (run: kos setup)")
        label = ACTIONS[action] + (f" '{target}'" if target else "")
        for _ in range(self.MAX_ATTEMPTS):
            self.throttle.wait(self.prompter.info)
            password = self.prompter.password(f"Password to {label}: ")
            if password is None:
                self.audit.record(action, target, "cancelled")
                raise AuthorizationDenied("cancelled")
            master = self.store.verify(password)
            if master is not None:
                self.throttle.success()
                self.audit.record(action, target, "granted", key=subkey(master, AUDIT_KEY_LABEL))
                return Grant(action, target, master)
            self.throttle.fail()
            self.audit.record(action, target, "bad-password")
            self.prompter.info("Wrong password.")
        self.audit.record(action, target, "denied")
        raise AuthorizationDenied(f"not authorized to {label}")
