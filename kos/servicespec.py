"""What an app may ask the OS to do with a ``service`` call, and the shape of each question.

An app has no files, no devices, no network and no view of the OS's own state. When one needs
any of that - the audit log, the security check, a directory listing, the firewall - it asks
the OS with ``{"cmd": "service", "id": N, "name": "audit.tail", "args": {...}}`` and the OS
answers with ``{"cmd": "service", "id": N, "ok": ..., "detail": ..., "data": {...}}``.

This file is only the schema: pure data and validators, with nothing imported from the rest
of KOS, so the protocol (which every app loads) can check a call without loading the
implementations. The implementations are in ``services.py``. Every call is hostile input:

* the name must be in ``SPECS`` - there is no way to name anything else;
* every argument must be present with exactly the type and range here, and no other
  argument is accepted;
* an app can only call services of a group its manifest asked for (``service:GROUP``) and the
  owner permitted; the password for each one is typed in the OS's own prompt, at the moment of
  use, by the implementation - never by the app.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MAX_PATH = 1024
MAX_TEXT = 200_000
_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")


class SpecError(ValueError):
    pass


@dataclass(frozen=True)
class Arg:
    kind: str                       # path | name | int | bool | text | choice | words
    default: Any = None
    required: bool = False
    lo: int = 0
    hi: int = 0
    maxlen: int = 0
    choices: tuple = ()

    def check(self, key: str, v: Any) -> Any:
        k = self.kind
        if k == "path":
            if not isinstance(v, str) or not v or len(v) > MAX_PATH or _CONTROL.search(v):
                raise SpecError(f"{key}: expected a path (1-{MAX_PATH} characters, no control characters)")
            return v
        if k == "name":
            if not isinstance(v, str) or not _NAME_RE.match(v):
                raise SpecError(f"{key}: expected a plain lowercase name")
            return v
        if k == "int":
            if type(v) is not int or not self.lo <= v <= self.hi:
                raise SpecError(f"{key}: expected an integer from {self.lo} to {self.hi}")
            return v
        if k == "bool":
            if type(v) is not bool:
                raise SpecError(f"{key}: expected true or false")
            return v
        if k == "text":
            if not isinstance(v, str) or len(v) > (self.maxlen or MAX_TEXT) or "\x00" in v:
                raise SpecError(f"{key}: expected text of at most {self.maxlen or MAX_TEXT} characters")
            return v
        if k == "choice":
            if v not in self.choices or type(v) is not str:
                raise SpecError(f"{key}: expected one of {', '.join(self.choices)}")
            return v
        if k == "words":
            if (not isinstance(v, list) or len(v) > 16
                    or any(not isinstance(w, str) or not w or len(w) > 256 or _CONTROL.search(w) for w in v)):
                raise SpecError(f"{key}: expected at most 16 short words")
            return list(v)
        raise SpecError(f"{key}: unknown argument kind")        # a bug in this table, never the app's


def path(default=None, required=True) -> Arg: return Arg("path", default, required)
def name(default=None, required=True) -> Arg: return Arg("name", default, required)
def num(lo: int, hi: int, default=None, required=False) -> Arg: return Arg("int", default, required, lo=lo, hi=hi)
def flag(default: bool = False) -> Arg: return Arg("bool", default)
def text(maxlen: int = MAX_TEXT, required=True, default=None) -> Arg: return Arg("text", default, required, maxlen=maxlen)
def one_of(*choices: str, default=None, required=False) -> Arg: return Arg("choice", default, required, choices=choices)
def words(required=False, default=None) -> Arg: return Arg("words", default if default is not None else [], required)


@dataclass(frozen=True)
class Spec:
    name: str
    args: dict = field(default_factory=dict)
    doc: str = ""

    @property
    def group(self) -> str:
        return self.name.split(".")[0]

    def check(self, raw: Any) -> dict:
        """The arguments of one call, validated: exactly the keys this service takes."""
        if not isinstance(raw, dict):
            raise SpecError("args must be an object")
        extra = sorted(set(raw) - set(self.args))
        if extra:
            raise SpecError(f"unknown argument {extra[0]!r} for {self.name}")
        out = {}
        for key, arg in self.args.items():
            if key in raw:
                out[key] = arg.check(key, raw[key])
            elif arg.required:
                raise SpecError(f"{self.name} needs {key!r}")
            else:
                out[key] = arg.default
        return out


def _specs(*items: Spec) -> dict[str, Spec]:
    return {s.name: s for s in items}


# The whole surface, in one place. A service is added here (and in services.py, with a test that
# its refusals work) or it does not exist.
SPECS: dict[str, Spec] = _specs(
    # the authorization log
    Spec("audit.tail", {"n": num(1, 500, 100)}, "the newest lines of the authorization log"),
    Spec("audit.verify", {}, "check the log's hash chain and the anchors to the password"),
    # what is happening
    Spec("activity.feed", {"n": num(1, 200, 30)}, "open apps and recent password decisions, newest first"),
    # the OS checking itself
    Spec("security.check", {}, "everything KOS can verify about itself; changes nothing"),
    Spec("system.report", {}, "kernel protections, the KOS kernel, firmware control, password set"),
    Spec("system.firmware", {"plan": flag(False)}, "management processors and the boot gate (plan: advice)"),
    # looking after the disk
    Spec("maintenance.owed", {}, "what earlier writes still owe"),
    Spec("maintenance.settle", {}, "do what is owed: security scan, then disk optimize"),
    Spec("maintenance.optimize", {}, "recompress apps, prune dead state, trim the audit log"),
    # files (browsing needs the password; so does reading)
    Spec("files.list", {"path": path()}, "a directory, or a zip as a directory (never extracted)"),
    Spec("files.read", {"path": path(), "limit": num(1, 262_144, 65_536)}, "the start of a file, as text"),
    Spec("scan.file", {"path": path()}, "scan a file or zip for known-bad patterns"),
    # the firewall
    Spec("firewall.list", {}, "the owner's rules, the kernel's state, the recent connection log"),
    Spec("firewall.allow", {"app": name(), "proto": one_of("tcp", "udp", required=True),
                            "direction": one_of("connect", "listen", required=True),
                            "host": text(45), "port": num(1, 65535, required=True)},
         "let one app make one kind of connection to one address and port"),
    Spec("firewall.remove", {"app": name(), "proto": one_of("tcp", "udp", required=True),
                             "direction": one_of("connect", "listen", required=True),
                             "host": text(45), "port": num(1, 65535, required=True)},
         "take one rule away"),
    # kernel cells
    Spec("cells.list", {}, "kernel cells and whether they are running"),
    Spec("cells.start", {"name": name(), "kernel": path(), "initrd": path(), "memory": num(64, 65536, 256),
                         "cpus": words(required=True)}, "start a cell: its own kernel on its own cores"),
    Spec("cells.stop", {"name": name()}, "stop a cell"),
    # apps and permissions
    Spec("packages.list", {}, "installed apps, versions, permits, add-ons"),
    Spec("packages.install", {"path": path()}, "install a .kapp: scan, password, seal"),
    Spec("packages.update", {"path": path()}, "update to a newer version: scan, password, re-seal"),
    Spec("packages.remove", {"name": name()}, "remove an app"),
    Spec("packages.permit", {"name": name(), "revoke": flag(False)}, "let an app run at all (or take that away)"),
    Spec("packages.convert", {"path": path(), "out": path()}, "convert a Debian package into an app"),
    Spec("permissions.list", {}, "who may use which shared folder"),
    Spec("permissions.grant", {"app": name(), "space": name(), "level": one_of("read", "write", default="read"),
                               "revoke": flag(False)}, "let an app into a shared folder (or take it away)"),
    # making skills
    Spec("skills.make", {}, "agent skills from the installed apps and the commands, as text to preview"),
    # code as a command
    Spec("code.run", {"code": text(20_000), "lang": name(default="python", required=False)},
         "run one line of code as a sandboxed one-shot app"),
)

GROUPS = tuple(sorted({s.group for s in SPECS.values()}))
