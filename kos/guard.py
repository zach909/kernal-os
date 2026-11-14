"""The security system of each layer.

The pipeline (README "The pipeline") has six layers. Each one has its own guard here, so no layer
relies on the one next to it having done its job:

    layer      guard (check)         what it refuses
    ---------  --------------------  -----------------------------------------------------------
    graphics   frame-budget          an app that draws faster than any real app does (it would
                                     starve the OS of the time it needs to draw the password prompt)
    text       page-budget           an app that floods the text transcript
    input      event-shape           a key, click or scroll that is not a well-formed event of the
                                     kind the OS sends (so a hostile or broken device cannot push
                                     control sequences or out-of-screen coordinates into an app);
                                     movement beyond a budget is dropped
    commands   message-budget        an app that sends more messages than any real app does
               prompt-budget         an app that asks for the password too often (prompt fatigue:
                                     being asked until you say yes is how people get tricked)
               failed-requests       an app whose requests keep failing: it is answered "no"
                                     until it exits
    kernel     attest-process        an app process that is NOT confined the way the sandbox says:
                                     running as root, able to gain privileges, holding capabilities,
                                     without its seccomp filter, or sharing the OS's user or network
                                     namespace. Looked at in ``/proc``, from the outside, so it does
                                     not rely on the sandbox code having done what it meant to
    hardware   no-device-handles     an app process that holds a handle on a device, the screen,
                                     the keyboard, KVM or ``/sys``: the one thing that must never
                                     be inside the sandbox

A guard that refuses writes ``guard.LAYER.CHECK`` ``refused`` to the audit log (``kos audit``). A
refusal that means the app is hostile or unconfined (``GuardRefused``, a ``ProtocolError``) ends the
session: the app is killed. A refusal that is about one request or one event only answers that one
(``False``/``None``) and the app lives.

What this is NOT: the sandbox, the protocol validator and the devices still do their own work
(``sandbox.py``, ``protocol.py``, ``devices.py``); a guard only checks, from the outside and again,
that they did. The limits below are guesses well above any real app, not measurements. Nothing here
checks Landlock (``/proc`` does not show it), a cell (a different kernel, no ``/proc`` entry on
this one) or an app that was started by someone else's broker unless its pid is given. Whole numbers
only; standard library only.
"""

from __future__ import annotations

import os
import re
import time
from typing import Callable, Optional

from .protocol import ProtocolError

PIPELINE = ("graphics", "text", "input", "commands", "kernel", "hardware")
CHECKS: dict[str, tuple[str, ...]] = {
    "graphics": ("frame-budget",),
    "text": ("page-budget",),
    "input": ("event-shape",),
    "commands": ("message-budget", "prompt-budget", "failed-requests"),
    "kernel": ("attest-process",),
    "hardware": ("no-device-handles",),
}

# Limits per second unless it says otherwise. Guesses, deliberately far above a real app.
MAX_OPS_PER_SEC = 1_000_000        # draw ops: 200 full frames of 5000 ops a second
MAX_PAGES_PER_SEC = 500            # text pages
MAX_PAGE_LINES_PER_SEC = 200_000
MAX_MESSAGES_PER_SEC = 5_000       # anything an app sends
MAX_MOVES_PER_SEC = 2_000          # pointer moves and scrolls forwarded; the rest are dropped
MAX_PROMPTS_PER_MIN = 6            # requests that make the OS ask for the password
MAX_FAILED_REQUESTS = 5            # per session
ATTEST_EVERY_MS = 2_000
MAX_AUDITED_PER_CHECK = 5          # a flood of bad events must not flood the audit log too

_KEY_NAME = re.compile(r"^(?:[a-z0-9]+(?:-[a-z0-9]+){0,3}|ctrl-[ -~])\Z")
_BUTTONS = ("left", "middle", "right")
# Handles an app may hold: the null/zero/random devices the sandbox itself gives it. Nothing else.
SAFE_DEVICES = ("/dev/null", "/dev/zero", "/dev/urandom", "/dev/random")


class GuardRefused(ProtocolError):
    """A guard said no and the app must end. ``layer`` and ``check`` say which."""

    def __init__(self, layer: str, check: str, why: str):
        super().__init__(f"{layer} layer ({check}): {why}")
        self.layer, self.check, self.why = layer, check, why


class Budget:
    """At most ``limit`` in every ``span_ms`` milliseconds (a fixed window). Whole numbers; the
    clock returns nanoseconds and can be replaced in a test."""

    def __init__(self, limit: int, span_ms: int, clock: Callable[[], int]):
        self.limit, self.span_ms, self.clock = limit, span_ms, clock
        self.start = clock() // 1_000_000
        self.used = 0

    def take(self, n: int = 1) -> bool:
        now = self.clock() // 1_000_000
        if now - self.start >= self.span_ms:
            self.start, self.used = now, 0
        if self.used + n > self.limit:
            return False
        self.used += n
        return True


# --- the kernel and hardware guards read /proc: pure functions, so a test can point them at a fake tree

def _status(pid: int, proc: str) -> dict[str, str]:
    out = {}
    with open(f"{proc}/{pid}/status") as f:
        for line in f:
            key, _, value = line.partition(":")
            out[key] = value.strip()
    return out


def attest_process(pid: int, *, allow_network: Optional[bool] = None, seccomp: bool = True,
                   proc: str = "/proc") -> list[str]:
    """Why this process is not confined as the sandbox promises (an empty list: it is).
    ``allow_network`` None means "not known": the network namespace is then not judged."""
    st = _status(pid, proc)
    why = []
    if any(u == "0" for u in st.get("Uid", "0").split()):
        why.append("it runs as root")
    if st.get("NoNewPrivs") != "1":
        why.append("it could still gain privileges (no_new_privs is off)")
    for key in ("CapEff", "CapPrm"):
        if int(st.get(key, "1"), 16) != 0:
            why.append(f"it holds capabilities ({key} is not empty)")
            break
    if seccomp and st.get("Seccomp") != "2":
        why.append("its seccomp filter is not on")
    for ns, label, wanted in (("user", "user namespace", True),
                              ("net", "network namespace", allow_network is False)):
        if wanted and os.readlink(f"{proc}/{pid}/ns/{ns}") == os.readlink(f"{proc}/self/ns/{ns}"):
            why.append(f"it shares the OS's {label}")
    return why


def device_handles(pid: int, proc: str = "/proc") -> list[str]:
    """What this process holds open that is a device, the kernel's own files or KVM."""
    found = []
    for fd in sorted(os.listdir(f"{proc}/{pid}/fd")):
        try:
            target = os.readlink(f"{proc}/{pid}/fd/{fd}")
        except OSError:
            continue                     # closed while we looked
        if target.endswith(" (deleted)"):
            target = target[:-len(" (deleted)")]
        if target in SAFE_DEVICES:
            continue
        if target.startswith(("/dev/", "/sys/", "anon_inode:kvm", "anon_inode:[uinput")):
            found.append(f"fd {fd} -> {target}")
    return found


class Guard:
    """One session's guards. ``audit`` is an ``AuditLog`` (or None); ``pid`` the app process to look
    at (None: nothing local to look at, as for an app in a cell)."""

    def __init__(self, app: str = "", *, audit=None, clock: Callable[[], int] = time.monotonic_ns,
                 pid: Optional[int] = None, allow_network: Optional[bool] = None,
                 weak: Optional[bool] = None, seccomp: Optional[bool] = None, proc: str = "/proc"):
        from .sandbox import seccomp_supported
        self.app, self.audit, self.clock = app, audit, clock
        self.pid, self.allow_network, self.proc = pid, allow_network, proc
        self.weak = os.environ.get("KOS_DEV_WEAK_SANDBOX") == "1" if weak is None else weak
        self.seccomp = seccomp_supported() if seccomp is None else seccomp
        self.stats: dict[tuple[str, str], dict[str, int]] = {}
        self.failed_requests = 0
        self._last_attest = -ATTEST_EVERY_MS
        self._ops = Budget(MAX_OPS_PER_SEC, 1000, clock)
        self._pages = Budget(MAX_PAGES_PER_SEC, 1000, clock)
        self._page_lines = Budget(MAX_PAGE_LINES_PER_SEC, 1000, clock)
        self._messages = Budget(MAX_MESSAGES_PER_SEC, 1000, clock)
        self._moves = Budget(MAX_MOVES_PER_SEC, 1000, clock)
        self._prompts = Budget(MAX_PROMPTS_PER_MIN, 60_000, clock)

    # --- bookkeeping -------------------------------------------------------------------
    def _count(self, layer: str, check: str, outcome: str) -> int:
        row = self.stats.setdefault((layer, check), {})
        row[outcome] = row.get(outcome, 0) + 1
        return row[outcome]

    def _record(self, layer: str, check: str, outcome: str) -> None:
        if self.audit is not None:
            try:
                self.audit.record(f"guard.{layer}.{check}", self.app, outcome)
            except OSError:
                pass                     # a log that cannot be written must not become a way to stop an app's guard

    def ok(self, layer: str, check: str) -> None:
        self._count(layer, check, "pass")

    def refuse(self, layer: str, check: str, why: str, *, fatal: bool) -> None:
        """Count and audit a refusal (audit only the first few of a kind), then end the app if fatal."""
        if self._count(layer, check, "refused") <= MAX_AUDITED_PER_CHECK:
            self._record(layer, check, "refused")
        if fatal:
            raise GuardRefused(layer, check, why)

    # --- graphics ----------------------------------------------------------------------
    def frame(self, n_ops: int) -> None:
        if not self._ops.take(n_ops):
            self.refuse("graphics", "frame-budget",
                        f"more than {MAX_OPS_PER_SEC} draw ops in one second", fatal=True)
        self.ok("graphics", "frame-budget")

    # --- text --------------------------------------------------------------------------
    def page(self, n_lines: int) -> None:
        if not self._pages.take() or not self._page_lines.take(n_lines):
            self.refuse("text", "page-budget",
                        f"more than {MAX_PAGES_PER_SEC} pages in one second", fatal=True)
        self.ok("text", "page-budget")

    # --- input -------------------------------------------------------------------------
    def input_event(self, ev, width: int, height: int, pointer: bool = True) -> Optional[dict]:
        """The event as the OS should forward it (rebuilt from known fields, coordinates clamped to
        the screen), or None to drop it. Dropping never ends the app: the hardware is the owner's."""
        kind = ev.get("type") if isinstance(ev, dict) else None
        if kind == "interrupt":
            return {"type": "interrupt"}        # Ctrl-C is the OS's; it is never judged or delayed
        bad = None
        if kind == "key":
            key = ev.get("key")
            if isinstance(key, str) and 0 < len(key) <= 16 and \
                    ((len(key) == 1 and key.isprintable()) or _KEY_NAME.match(key)):
                self.ok("input", "event-shape")
                return {"type": "key", "key": key}
            bad = "a key that is not a printable character or a plain key name"
        elif kind in ("pointer", "button", "scroll"):
            if not pointer:
                self._count("input", "event-shape", "dropped")      # no pointer on this layer
                return None
            x, y = ev.get("x"), ev.get("y")
            if type(x) is not int or type(y) is not int:
                bad = "pointer coordinates that are not whole numbers"
            else:
                x, y = max(0, min(max(0, width - 1), x)), max(0, min(max(0, height - 1), y))
                if kind == "button":
                    if ev.get("button") in _BUTTONS and type(ev.get("pressed")) is bool:
                        self.ok("input", "event-shape")
                        return {"type": "button", "button": ev["button"], "pressed": ev["pressed"], "x": x, "y": y}
                    bad = "a button that is not left, middle or right, or no pressed flag"
                elif type(ev.get("dy")) is int and kind == "scroll":
                    if not self._moves.take():
                        self._count("input", "event-shape", "dropped")
                        return None
                    self.ok("input", "event-shape")
                    return {"type": "scroll", "dy": 1 if ev["dy"] > 0 else -1, "x": x, "y": y}
                elif kind == "pointer":
                    if not self._moves.take():
                        self._count("input", "event-shape", "dropped")
                        return None
                    self.ok("input", "event-shape")
                    return {"type": "pointer", "x": x, "y": y}
                else:
                    bad = "a scroll with no direction"
        else:
            bad = f"an event of an unknown kind {str(kind)[:20]!r}"
        self.refuse("input", "event-shape", bad, fatal=False)
        return None

    # --- app commands ------------------------------------------------------------------
    def message(self) -> None:
        """Called for every message an app sends, before it is looked at."""
        if not self._messages.take():
            self.refuse("commands", "message-budget",
                        f"more than {MAX_MESSAGES_PER_SEC} messages in one second", fatal=True)
        self.ok("commands", "message-budget")

    def request(self, action: str) -> Optional[str]:
        """Why this request is not answered, or None. ``apps`` only reads a list and asks for nothing;
        every other request makes the OS ask for the password (or is refused before it does)."""
        if self.failed_requests >= MAX_FAILED_REQUESTS:
            self.refuse("commands", "failed-requests",
                        f"{self.failed_requests} requests failed already", fatal=False)
            return f"refused: {self.failed_requests} of this app's requests have already failed"
        if action != "apps" and not self._prompts.take():
            self.refuse("commands", "prompt-budget",
                        f"more than {MAX_PROMPTS_PER_MIN} password requests in a minute", fatal=False)
            return (f"refused: this app has asked for your password {MAX_PROMPTS_PER_MIN} times in "
                    "a minute; wait, or close it")
        self.ok("commands", "prompt-budget")
        return None

    def request_failed(self) -> None:
        self.failed_requests += 1

    # --- kernel and hardware: looked at from outside, in /proc -------------------------
    def attest(self, force: bool = False) -> None:
        """Check the app's process again, at most every ATTEST_EVERY_MS. Fails closed: a process
        that exists but cannot be read is refused. A process that has gone is not a violation."""
        if self.pid is None:
            return
        now = self.clock() // 1_000_000
        if not force and now - self._last_attest < ATTEST_EVERY_MS:
            return
        first = self._last_attest < 0
        self._last_attest = now
        try:
            if self.weak:
                if first:
                    self._record("kernel", "attest-process", "weak")        # loud, never silent
                self._count("kernel", "attest-process", "weak")
            else:
                why = attest_process(self.pid, allow_network=self.allow_network,
                                     seccomp=self.seccomp, proc=self.proc)
                if why:
                    self.refuse("kernel", "attest-process", "; ".join(why), fatal=True)
                self.ok("kernel", "attest-process")
                if first:
                    self._record("kernel", "attest-process", "pass")
            held = device_handles(self.pid, self.proc)
            if held:
                self.refuse("hardware", "no-device-handles",
                            "the app holds " + ", ".join(held[:3]), fatal=True)
            self.ok("hardware", "no-device-handles")
            if first:
                self._record("hardware", "no-device-handles", "pass")
        except (FileNotFoundError, ProcessLookupError):
            return                       # it exited while we looked
        except OSError as e:
            self.refuse("kernel", "attest-process", f"cannot be checked ({e.strerror or e})", fatal=True)


def describe() -> list[tuple[str, str]]:
    """(layer, check) in pipeline order, for ``kos security`` and the tests."""
    return [(layer, check) for layer in PIPELINE for check in CHECKS[layer]]
