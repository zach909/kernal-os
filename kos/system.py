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

import os
import signal
import time
from pathlib import Path
from typing import Callable, Optional

from . import cache
from .auth import AuthError, Authority, AuthorizationDenied
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


def list_apps(paths: Paths) -> list[dict]:
    """Installed apps for the App Library. The description comes from the
    stored zip's manifest and is display-only (nothing runs from this read;
    the seal is verified at launch)."""
    permits = PermitStore(paths)
    out = []
    for a in AppStore(paths).installed()[:MAX_LISTED]:
        desc, modes = "", ["tui"]
        try:
            m = KApp.from_file(paths.apps / f"{a.name}.kapp").manifest
            desc, modes = m.description, list(m.modes)
        except (KAppError, OSError):
            pass
        out.append({"name": a.name, "version": a.version,
                    "description": clean_text(desc, 200), "modes": modes,
                    "permitted": permits.is_permitted(a.name)})
    return out


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
                    spawner: Callable = spawn, release: Optional[Callable[[], None]] = None,
                    wait: float = 5.0) -> Instance:
    """Start an app under a broker and return its instance. The one code path
    for ``kos open`` and for an app's ``open`` request: permit check, then the
    password, then the seal check, then the sandboxed launch."""
    PermitStore(paths).require(name)      # refused before we even ask for the password
    store = AppStore(paths)
    action = "app.graphical" if mode == "graphical" else "app.open"
    with authority.authorize(action, name) as grant:
        app = store.load_verified(name, grant)
    policy = authorize_app_action(name, app, mode, authority, authority.prompter)
    if release:
        release()                          # e.g. close the TTY before forking the broker
    paths.ensure()
    cache_dir = cache.alloc(paths, name)
    policy.rw_dirs = [*policy.rw_dirs, str(cache_dir)]
    registry = Registry(paths)
    registry.prune()
    inst_id = registry.new_id(name)
    inst = Instance(id=inst_id, name=name, mode=mode, broker_pid=0,
                    sock_path=str(paths.state / "instances" / f"{inst_id}.sock"),
                    log_path=str(paths.logs / f"{inst_id}.log"), started=time.time(),
                    system="system" in app.manifest.permissions)
    spawner(inst, app, mode, policy, registry, Path(inst.log_path), cache_dir)
    if wait:
        wait_running(registry, inst_id, wait)
    return inst


def close_instance(paths: Paths, authority: Authority, instance_id: str) -> Instance:
    registry = Registry(paths)
    inst = registry.get(instance_id)
    with authority.authorize("app.close", inst.id):
        if inst.status == "running":
            try:
                os.kill(inst.broker_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            for _ in range(20):  # give the broker a moment to shut the app down cleanly
                if not (paths.state / "instances" / f"{inst.id}.json").exists():
                    break
                time.sleep(0.1)
        registry.remove(inst.id)
    return inst


class SystemBridge:
    """Answers one app's ``request`` commands. ``handle`` returns a switch
    target - ``("instance", id)`` - when the request moves the desktop."""

    def __init__(self, paths: Paths, spawner: Callable = spawn):
        self.paths = paths
        self._spawner = spawner

    def handle(self, req: dict, reply: Callable[[dict], None],
               authority: Authority) -> Optional[tuple[str, str]]:
        action = req["action"]

        def result(ok: bool, detail: str, **extra) -> None:
            reply({"cmd": "result", "action": action, "ok": ok,
                   "detail": clean_text(detail, 300), **extra})

        try:
            if action == "apps":
                reply({"cmd": "apps", "installed": list_apps(self.paths),
                       "open": list_open(self.paths)})
                return None
            if action == "open":
                inst = open_background(self.paths, authority, req["app"], req["mode"],
                                       spawner=self._spawner)
                result(True, f"opened {inst.name}", id=inst.id)
                return None
            if action == "close":
                inst = close_instance(self.paths, authority, req["id"])
                result(True, f"closed {inst.id}", id=inst.id)
                return None
            if action == "focus":
                inst = Registry(self.paths).get(req["id"])
                if inst.status != "running":
                    result(False, f"{inst.id} is not running")
                    return None
                result(True, f"switching to {inst.id}", id=inst.id)
                return ("instance", inst.id)
        except (AuthorizationDenied, AuthError, PermitError, KAppError, SandboxError,
                RegistryError, TamperedError, OSError) as e:
            result(False, str(e))
        return None
