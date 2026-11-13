"""The layers: every app action goes through the graphical button clicker, then app commands,
then kernel commands - each one, in that order, no shortcut.

These are the three action layers of AI OS (``aios.LAYERS``: ``gui``, ``app``, ``kernel``;
the fourth, ``skill``, makes new skills and does not act on apps). Here they are real checks,
not labels, and one function - :func:`traverse` - is the only door:

    gui     the graphical button clicker. Is there a button for this? The App Library has a row
            for the app (installed, and it has the mode asked for); the taskbar has an entry for
            the instance. Anything with no button cannot be done at all.
    app     app commands. May this app do it? The standing permit (``kos permit``); for an
            extension or mod, that it is permitted and really is an add-on.
    kernel  kernel commands. The Linux-level truth: the password for exactly this action, the
            seal verified against the zip, the manifest still within what you approved, the
            network question, and the sandbox the app will be held in. For an app already
            running, that its process is alive.

A layer that refuses stops everything behind it: an app with no permit is refused by ``app``
and ``kernel`` never runs, so no password is ever asked for it. Every layer writes ``pass`` or
``refused`` to the audit log (``layer.LAYER.VERB``), so ``kos audit`` shows each action went
through each layer. A refusal carries ``.layer``, the layer that said no.

The verbs are every way of using an app: ``open``/``run`` (start it), ``close``, ``focus``
(switch to it, ``kos attach``), ``extend``/``unextend`` (switch an extension or mod on or off).
Installing, updating, removing, permitting and booting a device are *store and device*
management, not use of an app; they keep their own gates (scan + password) and do not pass here.
A layer can have nothing to object to for a given verb (``app`` has nothing to say about
closing); it is still traversed and still audited.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from .auth import AuditLog
from .kapp import KApp, KAppError, supports_mode
from .permit import PermitStore
from .registry import Instance, Registry
from .sandbox import SandboxPolicy
from .store import AppStore

LAYERS = ("gui", "app", "kernel")
LAUNCH = ("open", "run")
VERBS = (*LAUNCH, "close", "focus", "extend", "unextend")


@dataclass(frozen=True)
class Request:
    verb: str                     # one of VERBS
    target: str                   # an app name, or an instance id for close / focus
    mode: str = "tui"
    sandbox_prompt: bool = True   # False inside a kernel cell, which has no network to ask about


@dataclass
class Passage:
    """What came out the far side: whatever the layers established, and how it went."""
    request: Request
    row: Optional[dict] = None            # the App Library row (gui)
    instance: Optional[Instance] = None   # the taskbar entry (gui)
    app: Optional[KApp] = None            # the verified app (kernel)
    policy: Optional[SandboxPolicy] = None
    trail: list = field(default_factory=list)   # [(layer, what it checked)]


def _gui(paths, get_authority, req: Request, p: Passage) -> str:
    from .system import describe_app
    if req.verb in LAUNCH or req.verb == "extend":
        row = describe_app(paths, req.target)
        if row is None:
            raise KAppError(f"{req.target} has no button: it is not installed (kos install)")
        p.row = row
        if req.verb in LAUNCH:
            if not supports_mode(row["modes"], req.mode):
                raise KAppError(f"{req.target} has no {req.mode} mode (it has: {', '.join(row['modes'])})")
            return f"App Library lists {req.target} [{req.mode}]"
        if row["kind"] == "app":
            raise KAppError(f"{req.target} is an ordinary app: only an extension or a mod can be switched on")
        if describe_app(paths, row["extends"]) is None:
            raise KAppError(f"{req.target} extends {row['extends']}, which is not installed")
        return f"App Library lists {req.target} ({row['kind']} of {row['extends']})"
    if req.verb in ("close", "focus"):
        p.instance = Registry(paths).get(req.target)
        return f"the taskbar lists {p.instance.id}"
    return "nothing to look up"


def _app(paths, get_authority, req: Request, p: Passage) -> str:
    if req.verb in LAUNCH or req.verb == "extend":
        PermitStore(paths).require(req.target)
        return f"{req.target} is permitted to run"
    return "no app rule for this"


def _kernel(paths, get_authority, req: Request, p: Passage) -> str:
    from .system import authorize_app_action
    authority = get_authority()      # only now: a refusal by gui or app never needed a password or a TTY
    store = AppStore(paths)
    if req.verb in LAUNCH:
        action = "app.graphical" if req.mode == "graphical" else \
            ("app.open" if req.verb == "open" else "app.run")
        with authority.authorize(action, req.target) as grant:
            app = store.load_verified(req.target, grant)
        PermitStore(paths).check_declared(req.target, app.manifest.permissions)
        if req.sandbox_prompt:
            policy = authorize_app_action(req.target, app, req.mode, authority, authority.prompter)
        else:
            policy = SandboxPolicy(weak=os.environ.get("KOS_DEV_WEAK_SANDBOX") == "1")
        p.app, p.policy = app, policy
        return "password, seal and sandbox"
    if req.verb == "extend":
        action = "app.mod" if p.row["kind"] == "mod" else "app.extend"
        with authority.authorize(action, req.target) as grant:
            p.app = store.load_verified(req.target, grant)
        if p.app.manifest.kind == "app":
            raise KAppError(f"{req.target} is an ordinary app")
        return "password and seal"
    if req.verb == "unextend":
        authority.authorize("app.unextend", req.target).close()
        return "password"
    if req.verb == "close":
        authority.authorize("app.close", p.instance.id).close()
        return "password"
    # focus: switching is an attach; the kernel's word is whether the process is really there
    if p.instance.status != "running":
        raise KAppError(f"{p.instance.id} is not running")
    return "process is alive"


_STEPS = {"gui": _gui, "app": _app, "kernel": _kernel}


def traverse(paths, authority, req: Request) -> Passage:
    """Send ``req`` through gui, app and kernel, in that order. Returns the :class:`Passage`;
    raises whatever the refusing layer raised (with ``.layer`` set).

    ``authority`` is an :class:`Authority`, or a zero-argument function that makes one. The
    function form is how the command line keeps its old promise that an app with no permit is
    refused without ever touching the terminal: the authority (which opens ``/dev/tty``) is only
    made when the kernel layer is reached."""
    if req.verb not in VERBS:
        raise KAppError(f"unknown app action {req.verb!r}")
    get_authority = authority if callable(authority) else (lambda: authority)
    audit = AuditLog(paths)
    passage = Passage(req)
    for layer in LAYERS:
        try:
            detail = _STEPS[layer](paths, get_authority, req, passage)
        except Exception as e:
            audit.record(f"layer.{layer}.{req.verb}", req.target, "refused")
            try:
                e.layer = layer
            except AttributeError:
                pass
            raise
        audit.record(f"layer.{layer}.{req.verb}", req.target, "pass")
        passage.trail.append((layer, detail))
    return passage
