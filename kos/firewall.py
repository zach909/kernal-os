"""The firewall's policy: which app may open which connection. Enforcement is the kernel's.

A rule names one app (by name), one protocol, connect or listen, one IP address typed out
and one port. There are no wildcards, ranges or host names, and no rule means no connection:
the kernel module (kos/kernel.py) denies every connection of every confined app, so this
file can only ever *add* a hole, one at a time, each time the owner types the password.

The rules are kept sealed (HMAC under a key derived from the password) so a file edited by
someone who does not have the password is not believed: its rules are dropped and the app
gets none. At launch the core turns an app's rules into kernel rules for that run's app id,
and takes them away again when the app ends (so a grant lasts until the app exits, as the
README promises). The firewall *app* (kos/office/pack_system.py) is only a front end: it asks
for these functions through the ``firewall`` service and the password is typed in the OS's
own prompt.

Gaps, stated plainly: changing a rule affects apps opened afterwards, not ones already
running; a rule is for an app *name*, so a reinstalled app of the same name inherits it
(revoke with ``firewall.remove`` or remove the file); the OS's own connections and
connections from outside the sandbox are not covered by the kernel module yet.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from . import kernel
from .auth import AuditLog
from .kapp import NAME_RE
from .paths import Paths, atomic_write

KEY_LABEL = "firewall-rules"
MAX_ENTRIES = 200


class FirewallError(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    app: str
    proto: str
    direction: str
    host: str
    port: int

    def kernel_rule(self, app_id: int) -> kernel.Rule:
        return kernel.check_rule(app_id, self.proto, self.direction, self.host, self.port)


def check_entry(app: str, proto: str, direction: str, host: str, port: int) -> Entry:
    if not isinstance(app, str) or not NAME_RE.match(app):
        raise FirewallError("rule: app must be an installed app's name")
    try:
        r = kernel.check_rule(1, proto, direction, host, port)     # id 1 stands in for the checks
    except kernel.KernelError as e:
        raise FirewallError(str(e)) from None
    return Entry(app, r.proto, r.direction, r.host, r.port)


def _canonical(entries: list[Entry]) -> bytes:
    return json.dumps([asdict(e) for e in entries], sort_keys=True, separators=(",", ":")).encode()


def _mac(key: bytes, entries: list[Entry]) -> str:
    return hmac.new(key, _canonical(entries), hashlib.sha256).hexdigest()


class FirewallStore:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.file = paths.state.joinpath("firewall", "rules.json")

    def load(self, key: bytes) -> tuple[list[Entry], str]:
        """(entries, state). state is 'ok', 'empty' or 'tampered'. A tampered file gives no
        entries: the default stays deny."""
        try:
            raw = json.loads(self.file.read_text())
            entries = [Entry(**e) for e in raw["rules"]]
            mac = raw["mac"]
            if not isinstance(mac, str) or len(entries) > MAX_ENTRIES:
                raise ValueError
            for e in entries:
                check_entry(e.app, e.proto, e.direction, e.host, e.port)
        except FileNotFoundError:
            return [], "empty"
        except (ValueError, TypeError, KeyError, FirewallError, OSError):
            return [], "tampered"
        if not hmac.compare_digest(mac, _mac(key, entries)):
            return [], "tampered"
        return entries, "ok"

    def _save(self, key: bytes, entries: list[Entry]) -> None:
        self.file.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.file.parent, 0o700)
        atomic_write(self.file, json.dumps({"rules": [asdict(e) for e in entries],
                                            "mac": _mac(key, entries)}, indent=1).encode())

    def add(self, key: bytes, entry: Entry) -> bool:
        entries, state = self.load(key)
        if state == "tampered":
            raise FirewallError("the rule file does not match its seal; remove it "
                                f"({self.file}) to start from deny-all, then add rules again")
        if entry in entries:
            return False
        if len(entries) >= MAX_ENTRIES:
            raise FirewallError(f"at most {MAX_ENTRIES} rules")
        self._save(key, entries + [entry])
        return True

    def remove(self, key: bytes, entry: Entry) -> bool:
        entries, state = self.load(key)
        if state == "tampered":
            raise FirewallError("the rule file does not match its seal; remove it to start from deny-all")
        if entry not in entries:
            return False
        self._save(key, [e for e in entries if e != entry])
        return True


# ---- launch and exit ------------------------------------------------------------------------

_APPS_LOG_MAX = 1 << 16


def _remember(paths: Paths, app_id: int, name: str) -> None:
    f = paths.state.joinpath("kernel", "apps.log")
    f.parent.mkdir(parents=True, exist_ok=True)
    try:
        if f.stat().st_size > _APPS_LOG_MAX:
            lines = f.read_text().splitlines()[-500:]
            atomic_write(f, ("\n".join(lines) + "\n").encode())
    except OSError:
        pass
    fd = os.open(f, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, f"{app_id} {name}\n".encode())
    finally:
        os.close(fd)


def _names(paths: Paths) -> dict[int, str]:
    out = {}
    try:
        for line in (paths.state.joinpath("kernel", "apps.log")).read_text().splitlines():
            n, _, name = line.partition(" ")
            if n.isdigit() and NAME_RE.match(name):
                out[int(n)] = name
    except OSError:
        pass
    return out


def prepare_launch(paths: Paths, name: str, policy, key: bytes,
                   k: Optional[kernel.Kernel] = None) -> int:
    """Give this launch its app id and its kernel rules, before the fork. Returns the id (0:
    the KOS kernel is not there and nothing requires it).

    Fails closed: if the image requires the KOS kernel and this process cannot use it, no app
    starts."""
    from .sandbox import SandboxError
    k = k or kernel.default()
    if not k.can_confine():
        if k.required():
            raise SandboxError("this boot requires the KOS kernel, and it is missing or this "
                               "process is not its core: KOS refuses to run apps without it")
        return 0
    app_id = kernel.AppIds(paths.state).next()
    _remember(paths, app_id, name)
    policy.kernel_app_id = app_id
    policy.on_exit = lambda: release(paths, app_id, k)
    audit = AuditLog(paths)
    if policy.allow_network:           # the owner said yes to the network at this launch
        entries, state = FirewallStore(paths).load(key)
        if state == "tampered":
            audit.record("firewall.rules", name, "tampered")
        for e in entries:
            if e.app == name:
                k.allow(e.kernel_rule(app_id))
    return app_id


def release(paths: Paths, app_id: int, k: Optional[kernel.Kernel] = None) -> None:
    """The app ended: take its rules away and move the kernel's log into the audit log."""
    if not app_id:
        return
    k = k or kernel.default()
    try:
        k.revoke_app(app_id)
    except kernel.KernelError:
        pass
    collect(paths, k)


def collect(paths: Paths, k: Optional[kernel.Kernel] = None) -> int:
    """Copy the kernel's connection log into the audit log (allowed and blocked alike).
    Returns how many lines. Safe to call when the module is not there."""
    k = k or kernel.default()
    if not k.can_confine():
        return 0
    try:
        lines, dropped = k.drain_log()
    except kernel.KernelError:
        return 0
    audit = AuditLog(paths)
    names = _names(paths)
    for ln in lines:
        audit.record(f"net.{ln.detail.split(' ', 1)[0]}", f"{names.get(ln.app, 'app ' + str(ln.app))}: {ln.detail}",
                     "allowed" if ln.verdict == "allow" else "blocked")
    if dropped:
        audit.record("net.log", "kernel", f"{dropped} lines lost before they were read")
    return len(lines)
