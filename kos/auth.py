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
    "disk.optimize": "optimize disk space",
    "cell.start": "start kernel cell",
    "cell.stop": "stop kernel cell",
    "file.write": "write file",
    "code.run": "run code",
    "backup.create": "back up files",
    "sources.change": "change where software comes from",
    "updates.check": "check your software sources for updates",
    "updates.install": "update KOS itself",
    "process.signal": "send a signal to a process",
    "process.renice": "change a process priority",
    "file.change": "change files or permissions",
    "net.check": "check the internet connection",
    "backup.remote": "set the off-site backup repository",
    "backup.push": "push a backup to your private GitHub",
    "admin.boot": "boot the administrator keyboard",
    "sudo.open": "remember your password for a while (sudo window)",
    "mod.enable": "make a system mod part of your desktop",
    "mod.disable": "remove a system mod from your desktop",
    "policy.change": "change which layers ask for your password",
}

# The four layers that each ask for the password. Interface: starting the desktop and its devices (this
# layer can be turned off). App: starting, stopping, installing, permitting apps. Command: what a running
# app asks the OS to do (read or write files, run code, signal processes, back up, check the network).
# Kernel: what changes the system itself (the administrator keyboard, the password, where software comes
# from, KOS itself, kernel cells, the policy). Every layer asks by default.
LAYERS = ("interface", "app", "command", "kernel")
LAYER_OF: dict[str, str] = {
    "session.login": "kernel", "device.mouse": "interface", "device.keyboard": "interface",
    "device.desktop": "interface",
    "app.install": "app", "app.update": "app", "app.update.all": "app", "app.remove": "app", "app.run": "app",
    "app.graphical": "app", "app.open": "app", "app.close": "app", "app.permit": "app", "app.revoke": "app",
    "app.network": "app",
    "file.view": "command", "file.write": "command", "file.change": "command", "code.run": "command",
    "backup.create": "command", "backup.push": "command", "backup.remote": "command",
    "process.signal": "command", "process.renice": "command", "net.check": "command", "scan.watch": "command",
    "disk.optimize": "command", "updates.check": "command",
    "auth.change": "kernel", "admin.boot": "kernel", "sources.change": "kernel", "updates.install": "kernel",
    "cell.start": "kernel", "cell.stop": "kernel", "sudo.open": "kernel", "policy.change": "kernel",
    "mod.enable": "kernel", "mod.disable": "kernel",
}
# Never remembered by a sudo window, whatever layers it covers: these change who or what is trusted, or
# send your data out. They ask every time.
NEVER_REMEMBERED = frozenset({"session.login", "auth.change", "app.permit", "app.revoke", "app.network",
                              "sources.change", "backup.push", "backup.remote", "updates.install",
                              "admin.boot", "sudo.open", "policy.change", "cell.start", "cell.stop",
                              "mod.enable", "mod.disable"})
KEYLESS = frozenset({"device.mouse", "device.keyboard", "device.desktop"})   # use no key: nothing is sealed
SUDO_DEFAULT_MINUTES, SUDO_MAX_MINUTES = 5, 60
SUDO_DEFAULT_LAYERS = ("interface", "app", "command")      # the kernel layer is never remembered


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
    """Proof that the owner typed the password for one specific action."""

    def __init__(self, action: str, target: str, master: Optional[SecretBytes], *, via: str = "password"):
        self.action = action
        self.target = target
        self._master = master
        self.via = via                     # password | sudo | interface-off

    def check(self, action: str, target: str) -> None:
        if self._master is None and self.via == "interface-off" and (action, target) == (self.action, self.target):
            return
        if not self._master:
            raise AuthorizationDenied("grant already closed")
        if (action, target) != (self.action, self.target):
            raise AuthorizationDenied(
                f"grant is for {self.action}:{self.target}, not {action}:{target}")

    def key(self, label: str) -> bytes:
        if self._master is None:
            raise AuthorizationDenied("this grant carries no key (the interface layer is set to not ask)")
        if not self._master:
            raise AuthorizationDenied("grant already closed")
        return subkey(self._master, label)

    def close(self) -> None:
        if self._master is not None:
            self._master.wipe()

    def __enter__(self) -> "Grant":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class Authority:
    MAX_ATTEMPTS = 3

    def _prompt_batch(self, items: list[tuple[str, str]], label: str) -> list[Grant]:
        """One password, several grants - for starting something made of parts (the
        desktop and each of its built-in apps and devices). The prompt names the whole
        batch; every (action, target) is audited separately and gets its own grant."""
        for action, _ in items:
            if action not in ACTIONS:
                raise AuthorizationDenied(f"unknown action {action!r}")
        if not self.store.exists():
            raise AuthError("no password has been set up (run: kos setup)")
        for _ in range(self.MAX_ATTEMPTS):
            self.throttle.wait(self.prompter.info)
            password = self.prompter.password(f"Password to {label}: ")
            if password is None:
                for a, t in items:
                    self.audit.record(a, t, "cancelled")
                raise AuthorizationDenied("cancelled")
            master = self.store.verify(password)
            if master is not None:
                self.throttle.success()
                grants = []
                for a, t in items:
                    self.audit.record(a, t, "granted")
                    grants.append(Grant(a, t, SecretBytes(bytes(master.raw))))
                master.wipe()
                return grants
            self.throttle.fail()
            for a, t in items:
                self.audit.record(a, t, "bad-password")
            self.prompter.info("Wrong password.")
        for a, t in items:
            self.audit.record(a, t, "denied")
        raise AuthorizationDenied(f"not authorized to {label}")

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

    def _prompt_one(self, action: str, target: str = "") -> Grant:
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
                self.audit.record(action, target, "granted")
                return Grant(action, target, master)
            self.throttle.fail()
            self.audit.record(action, target, "bad-password")
            self.prompter.info("Wrong password.")
        self.audit.record(action, target, "denied")
        raise AuthorizationDenied(f"not authorized to {label}")

    # ---- the layers: what asks, what may be remembered, what may be turned off ---------------------
    def _shortcut(self, action: str, target: str) -> Optional[Grant]:
        """A grant without a prompt, if the owner's own settings allow it: the interface layer set to
        not ask, or a live sudo window covering this action's layer. Never for NEVER_REMEMBERED."""
        if action not in ACTIONS:
            raise AuthorizationDenied(f"unknown action {action!r}")
        layer = LAYER_OF.get(action, "kernel")
        if action in KEYLESS and Policy(self.paths).interface() == "off":
            self.audit.record(action, target, "granted-interface-off")
            return Grant(action, target, None, via="interface-off")
        win = _WINDOWS.get(str(self.paths.state))
        if win and win.live() and layer in win.layers and action not in NEVER_REMEMBERED:
            self.audit.record(action, target, "granted-sudo")
            return Grant(action, target, SecretBytes(bytes(win.master.raw)), via="sudo")
        return None

    def authorize(self, action: str, target: str = "") -> Grant:
        return self._shortcut(action, target) or self._prompt_one(action, target)

    def authorize_batch(self, items: list[tuple[str, str]], label: str) -> list[Grant]:
        got = [self._shortcut(a, t) for a, t in items]
        need = [(i, it) for i, (g, it) in enumerate(zip(got, items)) if g is None]
        if need:
            for (i, _), g in zip(need, self._prompt_batch([it for _, it in need], label)):
                got[i] = g
        return got

    def sudo_open(self, minutes: int = SUDO_DEFAULT_MINUTES, layers: tuple[str, ...] = SUDO_DEFAULT_LAYERS) -> dict:
        """Ask for the password once and remember it - in this process's locked memory only, never on disk -
        for ``minutes`` (at most 60) for the given layers. The kernel layer is never remembered, and
        NEVER_REMEMBERED actions still ask."""
        layers = tuple(dict.fromkeys(layers))
        if not layers or not set(layers) <= set(LAYERS):
            raise AuthorizationDenied(f"layers must be a subset of {LAYERS}")
        if "kernel" in layers:
            raise AuthorizationDenied("the kernel layer is never remembered")
        if not isinstance(minutes, int) or isinstance(minutes, bool) or not 1 <= minutes <= SUDO_MAX_MINUTES:
            raise AuthorizationDenied(f"a sudo window lasts 1 to {SUDO_MAX_MINUTES} minutes")
        with self._prompt_one("sudo.open", f"{minutes} min: {', '.join(layers)}") as g:
            sudo_close(self.paths)
            _WINDOWS[str(self.paths.state)] = _SudoWindow(SecretBytes(bytes(g._master.raw)), minutes, set(layers))
        return sudo_status(self.paths)

    def sudo_close(self) -> None:
        sudo_close(self.paths)

    def sudo_status(self) -> dict:
        return sudo_status(self.paths)


class Policy:
    """Which layers ask for the password. Only the interface layer can be turned off (it is optional by
    design); app, command and kernel always ask. Changing it is itself a kernel-layer action."""

    def __init__(self, paths: Paths):
        self.file = paths.state / "policy.json"

    def interface(self) -> str:
        try:
            v = json.loads(self.file.read_text()).get("interface", "required")
        except (OSError, ValueError, AttributeError):
            return "required"
        return v if v in ("required", "off") else "required"

    def set_interface(self, value: str) -> None:
        if value not in ("required", "off"):
            raise AuthorizationDenied("the interface layer is 'required' or 'off'")
        self.file.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self.file, json.dumps({"interface": value}).encode())


class _SudoWindow:
    def __init__(self, master: SecretBytes, minutes: int, layers: set[str]):
        self.master, self.layers = master, layers
        self.started = time.monotonic()                      # monotonic: moving the clock cannot extend it
        self.until = self.started + minutes * 60

    def live(self) -> bool:
        if time.monotonic() < self.until and self.master:
            return True
        self.master.wipe()
        return False

    def left(self) -> int:
        return max(0, int(self.until - time.monotonic()))


_WINDOWS: dict[str, _SudoWindow] = {}


def sudo_status(paths: Paths) -> dict:
    win = _WINDOWS.get(str(paths.state))
    if win and win.live():
        return {"active": True, "left": win.left(), "layers": sorted(win.layers)}
    _WINDOWS.pop(str(paths.state), None)
    return {"active": False, "left": 0, "layers": []}


def sudo_close(paths: Paths) -> None:
    win = _WINDOWS.pop(str(paths.state), None)
    if win:
        win.master.wipe()
