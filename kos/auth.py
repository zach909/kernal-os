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
    "app.update.all": "update all apps",
    "scan.watch": "start virus scan watcher",
    "scan.protect": "lock directory until scanner runs",
    "scan.unprotect": "unlock directory permanently",
    "device.control": "send a command to a booted device",
    "fs.move": "move or rename a file",
    "fs.verify": "scan a file after changing it",
    "disk.optimize": "optimize disk space",
    "autonomy.grant": "issue a temporary autonomous permission",
    "autonomy.revoke": "revoke an autonomous permission",
    "autonomy.grant.privileged": "issue a PRIVILEGED autonomous permission",
    "admin.create": "create an admin account",
    "admin.remove": "remove the admin account",
    "cell.start": "start kernel cell",
    "cell.stop": "stop kernel cell",
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


class AuditLog:
    """Append-only record of every authorization decision. Contains no secrets."""

    def __init__(self, paths: Paths):
        self.file = paths.logs / "audit.log"

    def record(self, action: str, target: str, outcome: str) -> None:
        self.file.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"t": round(time.time(), 3), "action": action,
                           "target": target, "outcome": outcome})
        fd = os.open(self.file, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, line.encode() + b"\n")
        finally:
            os.close(fd)

    def entries(self) -> list[dict]:
        try:
            return [json.loads(l) for l in self.file.read_text().splitlines() if l]
        except FileNotFoundError:
            return []


class Grant:
    """Proof that a valid password (the owner's, or an admin's - see
    ``via_admin``) was typed for one specific action."""

    def __init__(self, action: str, target: str, master: SecretBytes, via_admin: bool = False):
        self.action = action
        self.target = target
        self._master = master
        self.via_admin = via_admin

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

    def raw_master(self) -> bytes:
        """A copy of the actual master key, not a derived subkey. Narrowly
        needed for admin-slot wrapping (the new slot has to unlock to the
        exact same master everything else already derives from) - not
        meaningfully more powerful than ``key()`` already is, since that
        can derive an HMAC of the master under any label you choose."""
        if not self._master:
            raise AuthorizationDenied("grant already closed")
        return bytes(self._master.raw)

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

    # Actions only the owner's own password can authorize, even if an admin
    # slot exists - an admin cannot use their own password to erase the
    # record of their own elevation, or to remove the owner's password.
    OWNER_ONLY = frozenset({"admin.remove", "auth.change"})

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
            via_admin = False
            if master is None and action not in self.OWNER_ONLY:
                from .admin import AdminStore
                admin_master = AdminStore(self.paths).unlock(password)
                if admin_master is not None:
                    master, via_admin = admin_master, True
            if master is not None:
                self.throttle.success()
                self.audit.record(action, target, "granted-admin" if via_admin else "granted")
                return Grant(action, target, master, via_admin=via_admin)
            self.throttle.fail()
            self.audit.record(action, target, "bad-password")
            self.prompter.info("Wrong password.")
        self.audit.record(action, target, "denied")
        raise AuthorizationDenied(f"not authorized to {label}")
