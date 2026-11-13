"""The KOS kernel, as the core sees it (kernel/patches/0001-kos-lsm.patch).

KOS runs on a Linux kernel patched with its own security module. The module is
where enforcement lives: it tells apps from the core, denies every connection
that no rule allows, keeps apps away from device nodes, and logs every allowed
and denied attempt. This file is only the core's door to it, and it is small on
purpose:

    claim_core()          PID 1, once per boot: "this process is the core"
    confine(app_id)       in a child, before it runs app code: "this is app N, for good"
    allow / revoke        firewall rules (one app, one protocol, connect or listen,
                          one typed-out address, one port - the kernel refuses the rest)
    drain_log()           the kernel's record of allowed and denied attempts

Nothing here decides anything. A rule the module would refuse is refused here
first with a clearer message, but the kernel never trusts this check.

Without the module (a stock kernel) ``present()`` is False. The core then falls
back to its own sandbox only, and says so (``kos doctor``); an image that sets
``kos.require_kernel=1`` on its signed command line refuses to run apps at all.
"""

from __future__ import annotations

import ctypes
import fcntl
import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

SECURITYFS = Path("/sys/kernel/security/kos")

PR_CLAIM_CORE = 0x4B4F5301
PR_CONFINE = 0x4B4F5302
PR_STATUS = 0x4B4F5303
STATUS_CORE = 0x40000000
APP_MAX = 0x3FFFFFFF

PROTOCOLS = ("tcp", "udp")
DIRECTIONS = ("connect", "listen")
MAX_RULES = 256                    # the kernel's table size
MAX_LOG_READ = 1 << 16


class KernelError(RuntimeError):
    pass


def _prctl(option: int, arg2: int = 0) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.restype = ctypes.c_long
    r = libc.prctl(ctypes.c_int(option), ctypes.c_ulong(arg2), ctypes.c_ulong(0),
                   ctypes.c_ulong(0), ctypes.c_ulong(0))
    if r < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return r


@dataclass(frozen=True)
class Rule:
    app: int
    proto: str
    direction: str
    host: str
    port: int

    def line(self, verb: str = "allow") -> str:
        return f"{verb} {self.app} {self.proto} {self.direction} {self.host} {self.port}"


@dataclass(frozen=True)
class LogLine:
    seq: int
    verdict: str            # "allow" | "deny"
    app: int
    detail: str


_LOG_RE = re.compile(r"^(\d{1,20}) (allow|deny) app=(\d{1,10}) ([ -~]{1,120})$")


def check_rule(app: int, proto: str, direction: str, host: str, port: int) -> Rule:
    """The one place a rule is validated on this side. Typed out or refused: an IP address
    literal (never a name - the core does not resolve names, resolving is a connection), one
    port, one protocol. Raises KernelError."""
    if type(app) is not int or not 1 <= app <= APP_MAX:
        raise KernelError("rule: app id out of range")
    if proto not in PROTOCOLS:
        raise KernelError(f"rule: protocol must be one of {PROTOCOLS}")
    if direction not in DIRECTIONS:
        raise KernelError(f"rule: direction must be one of {DIRECTIONS}")
    if type(port) is not int or not 1 <= port <= 65535:
        raise KernelError("rule: port must be 1-65535 (there is no 'any port')")
    if not isinstance(host, str) or not host.isascii() or len(host) > 45 or "%" in host or "/" in host:
        raise KernelError("rule: host must be an IP address, typed out (no names, no ranges)")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise KernelError("rule: host must be an IP address, typed out (no names, no ranges)") from None
    if ip.is_unspecified and direction == "connect":
        raise KernelError("rule: connecting to the unspecified address is not a destination")
    if ip.is_multicast:
        raise KernelError("rule: multicast is not a single host")
    return Rule(app, proto, direction, str(ip), port)


class Kernel:
    """``sfs`` and ``prctl`` can be replaced in tests; the real values are the module's
    securityfs directory and prctl(2)."""

    def __init__(self, sfs: Path = SECURITYFS, prctl: Callable[[int, int], int] = _prctl,
                 cmdline: Path = Path("/proc/cmdline"), environ: Optional[dict] = None):
        self.sfs, self._prctl, self._cmdline = Path(sfs), prctl, Path(cmdline)
        self._environ = os.environ if environ is None else environ

    # ---- what kernel is this ----
    def present(self) -> bool:
        return (self.sfs / "status").is_file()

    def status(self) -> dict:
        """The module's own status file: {'core': 'claimed'|'unclaimed', 'rules': N, ...}."""
        try:
            text = (self.sfs / "status").read_text()
        except OSError as e:
            raise KernelError(f"the KOS kernel module is not there: {e.strerror}") from None
        out = {}
        for line in text.splitlines()[1:]:
            k, _, v = line.partition("=")
            out[k] = int(v) if v.isdigit() else v
        return out

    def role(self) -> str:
        """'core' (may confine and write rules), 'app' (confined) or 'none' (no module, or
        this process is neither)."""
        if not self.present():
            return "none"
        try:
            r = self._prctl(PR_STATUS, 0)
        except OSError:
            return "none"
        if r & STATUS_CORE:
            return "core"
        return "app" if r else "none"

    def can_confine(self) -> bool:
        return self.role() == "core"

    def required(self) -> bool:
        """Does this boot refuse to run apps without the KOS kernel? Set on the signed kernel
        command line (``kos.require_kernel=1``). The environment counts too, except for PID 1,
        which must not be steered by it."""
        try:
            if "kos.require_kernel=1" in self._cmdline.read_text().split():
                return True
        except OSError:
            pass
        return os.getpid() != 1 and self._environ.get("KOS_REQUIRE_KERNEL") == "1"

    # ---- the core ----
    def claim_core(self) -> None:
        try:
            self._prctl(PR_CLAIM_CORE, 0)
        except OSError as e:
            raise KernelError(f"cannot claim the core: {e.strerror}") from None

    def confine(self, app_id: int) -> None:
        """Call in the child, after fork and before any app code. One way, inherited."""
        if type(app_id) is not int or not 1 <= app_id <= APP_MAX:
            raise KernelError("app id out of range")
        try:
            self._prctl(PR_CONFINE, app_id)
        except OSError as e:
            raise KernelError(f"cannot confine app {app_id}: {e.strerror}") from None

    # ---- rules ----
    def _write_rule(self, line: str) -> None:
        if not line.isascii() or len(line) > 150:
            raise KernelError("rule line is not plain text")
        try:
            fd = os.open(self.sfs / "rules", os.O_WRONLY | os.O_CLOEXEC)
        except OSError as e:
            raise KernelError(f"cannot open the rule table: {e.strerror}") from None
        try:
            os.write(fd, line.encode())       # the kernel takes one rule per write
        except OSError as e:
            raise KernelError(f"the kernel refused the rule: {e.strerror}") from None
        finally:
            os.close(fd)

    def allow(self, rule: Rule) -> None:
        check_rule(rule.app, rule.proto, rule.direction, rule.host, rule.port)
        self._write_rule(rule.line("allow"))

    def revoke(self, rule: Rule) -> None:
        check_rule(rule.app, rule.proto, rule.direction, rule.host, rule.port)
        self._write_rule(rule.line("revoke"))

    def revoke_app(self, app_id: int) -> None:
        if type(app_id) is not int or not 1 <= app_id <= APP_MAX:
            raise KernelError("app id out of range")
        self._write_rule(f"revoke-app {app_id}")

    def rules(self) -> list[Rule]:
        try:
            text = (self.sfs / "rules").read_text()
        except OSError as e:
            raise KernelError(f"cannot read the rule table: {e.strerror}") from None
        out = []
        for line in text.splitlines():
            w = line.split(" ")
            if len(w) == 6 and w[0] == "allow":
                out.append(check_rule(int(w[1]), w[2], w[3], w[4], int(w[5])))
        return out

    # ---- the log ----
    def drain_log(self) -> tuple[list[LogLine], int]:
        """(lines, dropped): everything the kernel logged since the last drain, and how many
        lines it had to overwrite before anyone read them. Core only."""
        try:
            fd = os.open(self.sfs / "log", os.O_RDONLY | os.O_CLOEXEC)
        except OSError as e:
            raise KernelError(f"cannot open the kernel log: {e.strerror}") from None
        lines: list[LogLine] = []
        dropped = 0
        try:
            while True:
                chunk = os.read(fd, MAX_LOG_READ)
                if not chunk:
                    break
                for raw in chunk.decode("ascii", "replace").splitlines():
                    if raw.startswith("dropped "):
                        dropped += int(raw.split()[1]) if raw.split()[1].isdigit() else 0
                        continue
                    m = _LOG_RE.match(raw)
                    if m:
                        lines.append(LogLine(int(m[1]), m[2], int(m[3]), m[4]))
        except OSError as e:
            raise KernelError(f"cannot read the kernel log: {e.strerror}") from None
        finally:
            os.close(fd)
        return lines, dropped


def default() -> Kernel:
    return Kernel()


class AppIds:
    """Hands out app ids that are never reused: a counter in the state directory. A reused id
    would hand a new app the firewall rules of an old one."""

    def __init__(self, state: Path):
        self.file = Path(state) / "kernel" / "next-app-id"

    def next(self) -> int:
        self.file.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.file.parent, 0o700)
        fd = os.open(self.file, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            raw = os.read(fd, 32).decode("ascii", "replace").strip()
            n = int(raw) if raw.isdigit() else 1
            if n > APP_MAX:
                raise KernelError("app ids are used up")
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, str(n + 1).encode())
            os.fsync(fd)
            return n
        finally:
            os.close(fd)
