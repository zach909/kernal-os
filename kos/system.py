"""The system bridge: how an app asks the OS to do something.

KOS is built of apps - the taskbar is an app, the App Library is an app - and
an app never touches a device, the screen, or another app. So when the
taskbar wants to switch to a running app, or the App Library wants to start
one, they *ask* the OS with a ``request`` command (see ``protocol.py``).

An app's request is honoured only when all of these are true:

1. its manifest declares the ``system`` permission (checked once, when it is
   opened, and recorded on the instance by the OS - an app cannot grant it
   to itself);
2. it was permitted to run at all (``kos permit``);
3. for anything that starts or stops something (``open``, ``close``): the
   owner types the password in the OS's own prompt - the same overlay the
   app cannot see or draw over. A request is a question, never an order.

Listing apps and switching the desktop to a running app need no new password:
listing reveals names the owner installed, and switching is an ``attach``
(the devices stay booted from the desktop's own password).
"""

from __future__ import annotations

import contextlib
import os
import signal
import time
from pathlib import Path
from typing import Callable, Optional

from . import ai, backup, cache
from . import cache, layers
from .address import check_launch
from .appdirs import AppDirs
from .auth import AuditLog, AuthError, Authority, AuthorizationDenied
from .broker import spawn
from .kapp import KApp, KAppError
from .permit import PermitError, PermitStore
from .paths import Paths
from .protocol import clean_text
from .registry import Instance, Registry, RegistryError
from .sandbox import SandboxError, SandboxPolicy
from .store import AppStore, TamperedError

MAX_LISTED = 200


def authorize_app_action(name: str, app: KApp, mode: str, authority: Authority,
                         prompter) -> SandboxPolicy:
    """Shared by run / open / the bridge: mode check + optional network grant."""
    m = app.manifest
    if mode not in m.modes:
        raise KAppError(f"{name} has no {mode} mode (it has: {', '.join(m.modes)})")
    allow_net = False
    if "network" in m.permissions:
        if prompter.confirm(f"{name} asks for network access. Allow?"):
            authority.authorize("app.network", name).close()
            allow_net = True
    return SandboxPolicy(allow_network=allow_net,
                         weak=os.environ.get("KOS_DEV_WEAK_SANDBOX") == "1")


@contextlib.contextmanager
def _admin_authority(lease, session_authority: Authority):
    """Who asks for the password of an admin write. A lease on real hardware is *exclusive*: the
    password must be typed on the administrator keyboard, taken for this one action, and if something
    else holds a keyboard the write is refused (fails closed). A WEAK lease (a development terminal,
    ``KOS_DEV_ADMIN_WEAK=1``) has no exclusive keyboard to take, so the session's own prompt is used."""
    from .admin import AdminPrompter, open_admin_devices
    devices = open_admin_devices(lease)      # raises AdminError if it cannot be taken exclusively
    if devices is None:
        yield session_authority
        return
    try:
        yield Authority(session_authority.paths, AdminPrompter(devices))
    finally:
        devices.close()


def _row(paths: Paths, a, permits: PermitStore) -> dict:
    """One App Library row. The description comes from the stored zip's manifest and is
    display-only (nothing runs from this read; the seal is verified at launch)."""
    desc, modes, kind, extends, perms = "", ["tui"], "app", "", []
    try:
        m = KApp.from_file(paths.apps / f"{a.name}.kapp").manifest
        desc, modes, kind, extends = m.description, list(m.modes), m.kind, m.extends
        perms = list(m.permissions)
    except (KAppError, OSError):
        pass
    return {"name": a.name, "version": a.version,
            "description": clean_text(desc, 200), "modes": modes,
            "permitted": permits.is_permitted(a.name), "kind": kind, "extends": extends,
            "permissions": perms}


def list_apps(paths: Paths) -> list[dict]:
    """Installed apps for the App Library."""
    permits = PermitStore(paths)
    return [_row(paths, a, permits) for a in AppStore(paths).installed()[:MAX_LISTED]]


def describe_app(paths: Paths, name: str) -> Optional[dict]:
    """The App Library row for ``name``, or None: no row means no button (see layers.py)."""
    a = next((a for a in AppStore(paths).installed() if a.name == name), None)
    return None if a is None else _row(paths, a, PermitStore(paths))


def list_open(paths: Paths) -> list[dict]:
    return [{"id": i.id, "name": i.name, "mode": i.mode, "status": i.status}
            for i in Registry(paths).list()[:MAX_LISTED]]


def wait_running(registry: Registry, instance_id: str, timeout: float = 5.0) -> Instance:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            inst = registry.get(instance_id)
        except RegistryError:
            raise KAppError(f"{instance_id} exited as soon as it started") from None
        if inst.status == "running":
            return inst
        time.sleep(0.05)
    raise KAppError(f"{instance_id} did not start in time")


def open_background(paths: Paths, authority: Authority, name: str, mode: str = "tui", *,
                    address: str = "", spawner: Callable = spawn,
                    release: Optional[Callable[[], None]] = None, wait: float = 5.0) -> Instance:
    """Start an app under a broker and return its instance. The one code path for ``kos open``,
    ``kos go``, the desktop and an app's ``open`` request. It goes through the layers (gui, app,
    kernel - see layers.py): a button for it, then its permit, then the password, the seal check
    and the sandboxed launch. ``address`` is the path+query the app is told at start."""
    address = check_launch(address)       # a bad address is refused before any password is asked
    passage = layers.traverse(paths, authority, layers.Request("open", name, mode))
    app, policy = passage.app, passage.policy
    if release:
        release()                          # e.g. close the TTY before forking the broker
    paths.ensure()
    cache_dir = cache.alloc(paths, name)
    policy.rw_dirs = [*policy.rw_dirs, str(cache_dir)]
    registry = Registry(paths)
    registry.prune()
    inst_id = registry.new_id(name)
    run_dir = AppDirs(paths, name).ensure().run
    inst = Instance(id=inst_id, name=name, mode=mode, broker_pid=0,
                    sock_path=str(run_dir / f"{inst_id}.sock"),
                    log_path=str(run_dir / f"{inst_id}.log"), started=time.time(),
                    system="system" in app.manifest.permissions,
                    asks=list(app.manifest.asks), admin="admin" in app.manifest.permissions,
                    address=address)
    spawner(inst, app, mode, policy, registry, Path(inst.log_path), cache_dir)
    if wait:
        wait_running(registry, inst_id, wait)
    return inst


def close_instance(paths: Paths, authority: Authority, instance_id: str) -> Instance:
    inst = layers.traverse(paths, authority, layers.Request("close", instance_id)).instance
    registry = Registry(paths)
    if inst.status == "running":
        try:
            os.kill(inst.broker_pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        for _ in range(20):  # give the broker a moment to shut the app down cleanly
            if not registry._file(inst.id).exists():
                break
            time.sleep(0.1)
    registry.remove(inst.id)
    return inst


def bridge_for(paths: Paths, name: str, permissions, spawner: Callable = spawn) -> Optional["SystemBridge"]:
    """The bridge a program gets, from its own manifest permissions and nothing else: every request
    for ``system``, only the named ones for ``ask:ACTION``, the AI for ``ai``, the guarded write for
    ``admin`` (each separate from the others), none at all for none of them. Whatever the
    app it belongs to, or its sibling programs, may do plays no part."""
    perms = tuple(permissions)
    powers = {p for p in perms if p in ("system", "ai", "admin")}
    allowed = None
    if "system" not in powers:
        asks = frozenset(p[len("ask:"):] for p in perms if p.startswith("ask:"))
        if asks:
            powers.add("system")        # the bridge's gate for requests; ``allowed`` narrows it
            allowed = asks
    if not powers:
        return None
    return SystemBridge(paths, spawner, allowed=allowed, who=name, app=name, permissions=powers)


class SystemBridge:
    """Answers one app's ``request`` commands. ``handle`` returns a switch
    target - ``("instance", id)`` - when the request moves the desktop.

    ``allowed`` is the set of request actions this program's manifest names (``ask:ACTION``);
    ``None`` means every action (the ``system`` permission). A request outside it is refused
    before anything happens - no password is asked - and goes in the audit log."""

    def __init__(self, paths: Paths, spawner: Callable = spawn, allowed: Optional[frozenset] = None,
                 who: str = "", *, app: str = "", permissions=None,
                 admin_authority: Optional[Callable] = None):
        self.paths = paths
        self._spawner = spawner
        self.allowed = allowed
        self.who = who
        self.app = app or who
        # None = the original behaviour (system actions only). The 'ai' permission is separate:
        # an app that may ask the AI gets no power to open, close or back up anything.
        self.permissions = frozenset(permissions) if permissions is not None else frozenset({"system"})
        # How the password for an admin write is asked: ``(lease, session_authority) -> context manager
        # yielding an Authority``. The default is the real thing (see _admin_authority).
        self._admin_authority = admin_authority or _admin_authority

    def _admin(self, req: dict, authority: Authority) -> None:
        """``admin`` and ``write``: only with the 'admin' permission, and never more than the guarded
        write. Everything that can be checked without the password is checked before it is asked."""
        from .admin import AdminError, AdminKeyboard, WriteBlocked, write_file
        action = req["action"]

        def result(ok: bool, detail: str) -> None:
            self._reply({"cmd": "result", "action": action, "ok": ok, "detail": clean_text(detail, 300)})

        who = self.app or self.who or "?"
        audit = AuditLog(self.paths)
        if "admin" not in self.permissions:
            audit.record("bridge.admin", f"{who}:{action}", "refused")
            return result(False, "this app does not have the 'admin' permission")
        kb = AdminKeyboard(self.paths)
        if action == "admin":
            status = kb.status()
            return result(status.startswith("administrator keyboard: ON"), status)
        try:
            lease = kb.require_booted()          # refuse before any password
            data = req["text"].encode("utf-8")
            with self._admin_authority(lease, authority) as auth:
                report = write_file(self.paths, auth, kb, req["path"], data, who=who)
        except WriteBlocked as e:
            audit.record("bridge.admin", f"{who}:write", "scan-failed")
            return result(False, str(e))
        except (AdminError, AuthorizationDenied, AuthError, OSError) as e:
            audit.record("bridge.admin", f"{who}:write", "refused")
            return result(False, str(e))
        audit.record("bridge.admin", f"{who}:write", "written")
        result(True, f"wrote {report.bytes_written} bytes to {report.path}; "
                     f"scan: {report.scan.summary()}")

    def _kernel(self) -> None:
        """What the Linux kernel protects, as data. Read-only: it changes nothing and needs no password,
        like ``kos doctor``. Cells are listed by name, not by anything that could start one."""
        from .admin import AdminKeyboard
        from .cells import CellManager
        from .sandbox import report
        try:
            cells = [{"name": clean_text(str(c.get("name", "")), 32), "cid": int(c.get("cid", 0)),
                      "cpus": [int(x) for x in c.get("cpus", [])][:64],
                      "memory_mb": int(c.get("memory_mb", 0)), "running": bool(c.get("running"))}
                     for c in CellManager(self.paths).cells()[:MAX_LISTED]]
        except (OSError, ValueError, TypeError, KeyError):
            cells = []
        prot = {}
        for k, v in report().items():
            # the kernel check is a small nested report: flatten its yes/no and number entries
            # (``kos_kernel.present``); text entries are not part of the protocol's {name: bool|int}
            for name, val in (((f"{k}.{kk}", vv) for kk, vv in v.items()) if isinstance(v, dict) else [(k, v)]):
                if isinstance(val, bool):
                    prot[name] = val
                elif isinstance(val, int) or val is None:
                    prot[name] = int(val or 0)
        self._reply({"cmd": "kernel", "protections": prot, "cells": cells,
                     "admin": clean_text(AdminKeyboard(self.paths).status(), 200)})

    def _ask(self, req: dict, authority: Authority) -> None:
        """One question to the AI. Order matters: permission, then is there an endpoint at all
        (blocked by default), then the password naming what leaves, then the connection."""
        def refuse(detail: str) -> None:
            self._answer(False, [], detail=detail)
        if "ai" not in self.permissions:
            return refuse("this app does not have the 'ai' permission")
        try:
            question, context, source = ai.prepare(req["text"], req.get("context", ""), req.get("source", ""))
            ep = ai.load(self.paths)
        except ai.AIError as e:
            ai.log(self.paths, self.app or "?", "-", "blocked")
            return refuse(str(e))
        sent = len(question) + len(context) + len(source)
        target = f"{self.app or '?'}: send {sent} characters to {ep.host}"
        try:
            authority.authorize("ai.ask", target).close()
        except (AuthorizationDenied, AuthError) as e:
            return refuse(str(e))
        try:
            lines = ai.send(ep, question, context, source)
        except ai.AIError as e:
            ai.log(self.paths, self.app or "?", ep.host, "failed")
            return refuse(str(e))
        ai.log(self.paths, self.app or "?", ep.host, "allowed")
        self._answer(True, lines, model=ep.model)

    def _answer(self, ok: bool, lines: list, *, detail: str = "", model: str = "") -> None:
        self._reply({"cmd": "answer", "ok": ok, "lines": lines, "model": clean_text(model, 100),
                     "detail": clean_text(detail, 300)})
    def handle(self, req: dict, reply: Callable[[dict], None],
               authority: Authority) -> Optional[tuple[str, str]]:
        action = req["action"]
        self._reply = reply
        if action == "ask":
            self._ask(req, authority)
            return None
        if action in ("admin", "write"):
            self._admin(req, authority)
            return None
        if "system" not in self.permissions:
            reply({"cmd": "result", "action": action, "ok": False,
                   "detail": "this app does not have the 'system' permission"})
            return None

        def result(ok: bool, detail: str, **extra) -> None:
            reply({"cmd": "result", "action": action, "ok": ok,
                   "detail": clean_text(detail, 300), **extra})

        if self.allowed is not None and action not in self.allowed:
            AuditLog(self.paths).record("bridge.ask", f"{self.who}:{action}", "refused")
            result(False, f"{self.who or 'this program'} has no permission to ask for {action} "
                          f"(its manifest would need ask:{action})")
            return None
        try:
            if action == "apps":
                reply({"cmd": "apps", "installed": list_apps(self.paths),
                       "open": list_open(self.paths)})
                return None
            if action == "open":
                inst = open_background(self.paths, authority, req["app"], req["mode"],
                                       address=req.get("address", ""), spawner=self._spawner)
                result(True, f"opened {inst.name}", id=inst.id)
                return None
            if action == "close":
                inst = close_instance(self.paths, authority, req["id"])
                result(True, f"closed {inst.id}", id=inst.id)
                return None
            if action == "kernel":
                self._kernel()
                return None
            if action == "backup":
                items, stats = backup.snapshot(self.paths, authority, "backup.list", "app")
                reply({"cmd": "backup",
                       "stats": {"items": stats.items, "unique": stats.unique_blobs,
                                 "logical": stats.logical_bytes, "stored": stats.stored_bytes,
                                 "saved": stats.saved_bytes},
                       "items": [{"id": i.id, "path": clean_text(i.path, 200), "size": i.size,
                                  "sha256": i.sha256[:12]}
                                 for i in reversed(items[-MAX_LISTED:])]})
                return None
            if action == "backup_add":
                report = backup.add(self.paths, authority, [req["path"]])
                result(not report.flagged, report.summary())
                return None
            if action == "backup_remove":
                item, gone = backup.remove(self.paths, authority, req["id"])
                result(True, f"removed {item.id}" + (" and its body" if gone else ""), id=item.id)
                return None
            if action == "focus":
                inst = layers.traverse(self.paths, authority,
                                       layers.Request("focus", req["id"])).instance
                result(True, f"switching to {inst.id}", id=inst.id)
                return ("instance", inst.id)
        except (AuthorizationDenied, AuthError, PermitError, KAppError, SandboxError,
                RegistryError, TamperedError, OSError) as e:
            layer = getattr(e, "layer", "")      # which of gui / app / kernel said no
            result(False, f"{layer} layer: {e}" if layer else str(e))
        return None
