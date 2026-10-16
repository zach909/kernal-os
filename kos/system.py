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

import json
import os
import signal
import time
from pathlib import Path
from typing import Callable, Optional

from . import backup as backups_mod
from . import loader
from . import fschange, osinfo, proctl
from . import cache, sysinfo
from .admin import AdminError, AdminKeyboard, write_file
from .auth import AuthError, Authority, AuthorizationDenied
from .broker import spawn
from .kapp import KApp, KAppError
from .permit import PermitError, PermitStore
from .paths import Paths
from .protocol import clean_text
from .registry import Instance, Registry, RegistryError
from .sandbox import SandboxError, SandboxPolicy
from .store import AppStore, TamperedError
from .vfs import VFSError

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
    devices: list[str] = []
    if m.devices:                                    # hardware: named, asked for at every launch, never remembered
        import glob
        nodes = sorted({n for pat in m.devices for n in glob.glob(pat)})
        if nodes and prompter.confirm(f"{name} asks to use: {', '.join(nodes)}. Allow?"):
            authority.authorize("app.device", name).close()
            devices = nodes
    return SandboxPolicy(allow_network=allow_net, device_paths=devices,
                         weak=os.environ.get("KOS_DEV_WEAK_SANDBOX") == "1")


def list_apps(paths: Paths) -> list[dict]:
    """Installed apps for the App Library. The description comes from the
    stored zip's manifest and is display-only (nothing runs from this read;
    the seal is verified at launch)."""
    permits = PermitStore(paths)
    out = []
    for a in AppStore(paths).installed()[:MAX_LISTED]:
        desc, modes, commands, slot = "", ["tui"], [], ""
        try:
            m = KApp.from_file(paths.apps / f"{a.name}.kapp").manifest
            desc, modes, slot = m.description, list(m.modes), m.slot
            commands = [{"id": c.id, "title": clean_text(c.title, 70), "keywords": list(c.keywords)}
                        for c in m.commands]
        except (KAppError, OSError):
            pass
        out.append({"name": a.name, "version": a.version,
                    "description": clean_text(desc, 200), "modes": modes, "commands": commands, "slot": slot,
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
                    wait: float = 5.0, grant=None) -> Instance:
    """Start an app under a broker and return its instance. The one code path
    for ``kos open`` and for an app's ``open`` request: permit check, then the
    password, then the seal check, then the sandboxed launch."""
    PermitStore(paths).require(name)      # refused before we even ask for the password
    store = AppStore(paths)
    action = "app.graphical" if mode == "graphical" else "app.open"
    if grant is not None:                  # typed already, as part of a batch (see desktop.boot_core)
        with grant:
            app = store.load_verified(name, grant)
    else:
        with authority.authorize(action, name) as grant:
            app = store.load_verified(name, grant)
    policy = authorize_app_action(name, app, mode, authority, authority.prompter)
    if release:
        release()                          # e.g. close the TTY before forking the broker
    paths.ensure()
    cache_dir = cache.alloc(paths, name, ram=app.manifest.runtime in ("npm", "bundle"))
    loader.apply_to_policy(policy, app, cache_dir, paths.data_dir(name))
    registry = Registry(paths)
    registry.prune()
    inst_id = registry.new_id(name)
    inst = Instance(id=inst_id, name=name, mode=mode, broker_pid=0,
                    sock_path=str(paths.state / "instances" / f"{inst_id}.sock"),
                    log_path=str(paths.logs / f"{inst_id}.log"), started=time.time(),
                    system="system" in app.manifest.permissions,
                    ticks="ticks" in app.manifest.permissions,
                    shell="shell" in app.manifest.permissions,
                    pointer="pointer" in app.manifest.permissions,
                    animate="animate" in app.manifest.permissions,
                    neural="neural" in app.manifest.permissions)
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
            if action == "quantum":
                from . import qdev, qjob
                if req["op"] == "devices":
                    devs = qdev.with_drivers(qdev.detect(), self.paths)
                    reply({"cmd": "quantum", "devices": [{**d.as_dict(), "name": clean_text(d.name, 120)} for d in devs]})
                    return None
                driver = req["driver"]
                if not driver:                                   # pick the driver for the named device, else the emulator
                    devs = qdev.with_drivers(qdev.detect(), self.paths)
                    d = next((x for x in devs if x.id == req["device"] and x.drivers), None) or next((x for x in devs if x.drivers), None)
                    driver = d.drivers[0] if d else ""
                if not driver:
                    return result(False, "no quantum driver is installed")
                try:
                    res = qjob.run_job(self.paths, authority, driver, {k: req.get(k) for k in ("program", "shots", "seed", "device")})
                except qjob.JobError as e:
                    return result(False, str(e))
                reply({"cmd": "quantum", "result": json.loads(clean_text(json.dumps(res), 20000))})
                return None
            if action == "autoupdate":
                from .autoupdate import AutoUpdate
                au = AutoUpdate(self.paths)
                if req["op"] == "set":
                    au.set(authority, **{k: v for k, v in req.items() if k in ("enabled", "mode", "every_hours")})
                if req["op"] == "run":
                    res = au.run(authority, scheduled=req["scheduled"])
                    reply({"cmd": "autoupdate", "status": au.status(), "ran": res["ran"],
                           "lines": [clean_text(x, 300) for x in res.get("lines", [])], "reason": res.get("reason", "")})
                    return None
                msg = {"cmd": "autoupdate", "status": au.status()}
                if req["op"] == "refresh":
                    from . import osupdate
                    o = osupdate.pending()
                    msg["os"] = {"manager": o["manager"], "counts": o["counts"], "apply": o["apply"], "note": clean_text(o["note"], 200)}
                reply(msg)
                return None
            if action == "heal":
                from . import heal
                from .desktop import SYSTEM_APPS
                rep = heal.check(self.paths, builtin=SYSTEM_APPS) if req["op"] == "check" else heal.repair(self.paths, authority, builtin=SYSTEM_APPS)
                found = [f.as_dict() for f in rep.findings]
                summary = (", ".join(rep.fixed + rep.left) if (rep.fixed or rep.left) else
                           ("nothing wrong" if not found else f"{len(found)} problem(s): " + "; ".join(f["kind"] + " " + f["subject"] for f in found[:4])))
                reply({"cmd": "heal", "findings": found, "fixed": rep.fixed, "left": rep.left, "summary": clean_text(summary, 300)})
                return None
            if action == "mods":
                from .mods import Mods, ModError
                mods = Mods(self.paths)
                try:
                    if req["op"] == "enable":
                        with authority.authorize("mod.enable", req["name"]):
                            mods.enable(req["name"])
                            PermitStore(self.paths).grant(req["name"])
                    elif req["op"] == "disable":
                        with authority.authorize("mod.disable", req["name"]):
                            mods.disable(req["name"])
                except ModError as e:
                    return result(False, str(e))
                reply({"cmd": "mods", "mods": mods.installed(), "note": "restart the desktop to use the change" if req["op"] != "list" else ""})
                return None
            if action == "sudo":
                from .auth import sudo_status
                if req["op"] == "open":
                    authority.sudo_open(req.get("minutes", 5), tuple(req.get("layers", ("interface", "app", "command"))))
                elif req["op"] == "close":
                    authority.sudo_close()
                reply({"cmd": "sudo", **sudo_status(self.paths)})
                return None
            if action == "policy":
                from .auth import Policy
                if req["op"] == "set":
                    authority.authorize("policy.change", f"interface={req['interface']}").close()
                    Policy(self.paths).set_interface(req["interface"])
                reply({"cmd": "policy", "interface": Policy(self.paths).interface()})
                return None
            if action == "info":
                reply({"cmd": "info", "admin": sysinfo.admin_line(self.paths),
                       "kernel": sysinfo.doctor_lines(), "owed": sysinfo.owed_lines(self.paths),
                       "audit": sysinfo.audit_lines(self.paths),
                       "permits": [p.name for p in PermitStore(self.paths).list()]})
                return None
            if action == "ls":
                reply({"cmd": "listing", "path": clean_text(req["path"], 300),
                       "entries": sysinfo.list_path(req["path"])})
                return None
            if action == "scan":
                self._text(reply, action, req["path"], sysinfo.scan_lines(req["path"]))
                return None
            if action == "view":
                path = os.path.abspath(req["path"])
                authority.authorize("file.view", path).close()
                lines, lossy = sysinfo.view_text(path)
                self._text(reply, action, path, lines, lossy=lossy)
                return None
            if action == "save":
                rep = write_file(self.paths, authority, AdminKeyboard(self.paths),
                                 req["path"], req["text"].encode())
                self._text(reply, action, rep.path, rep.summary().splitlines())
                return None
            if action == "backup":
                info = backups_mod.create(self.paths, authority, req["path"])
                self._text(reply, action, info["name"],
                           [f"backed up {info['files']} file(s) -> {info['name']} ({info['size']:,} bytes)",
                            "security scan: clean"])
                return None
            if action == "backups":
                from .offsite import Offsite
                reply({"cmd": "backups", "backups": backups_mod.list_backups(self.paths),
                       "remote": clean_text(Offsite(self.paths).remote() or "", 300)})
                return None
            if action == "remote":
                from .offsite import Offsite
                url = Offsite(self.paths).set_remote(authority, req["url"])
                result(True, f"off-site repository: {url}")
                return None
            if action == "sys":
                reply({"cmd": "sys", "kind": req["kind"], "data": osinfo.KINDS[req["kind"]](self.paths, req["arg"])})
                return None
            if action == "signal":
                result(True, proctl.signal_process(authority, req["pid"], req["sig"]))
                return None
            if action == "renice":
                result(True, proctl.renice(authority, req["pid"], req["nice"]))
                return None
            if action == "fschange":
                result(True, fschange.change(self.paths, authority, AdminKeyboard(self.paths), req["op"],
                                             req["path"], to=req.get("to"), mode=req.get("mode")))
                return None
            if action == "updates":
                return self._updates(req, reply, result, authority)
            if action == "netcheck":
                authority.authorize("net.check", "1.1.1.1:443").close()
                ok, detail = osinfo.net_check()
                result(ok, detail)
                return None
            if action == "push":
                from .offsite import Offsite
                self._text(reply, action, req["backup"],
                           [Offsite(self.paths).push(authority, req["backup"])])
                return None
            if action == "restore":
                data = backups_mod.read_member(self.paths, req["backup"], req["member"])
                rep = write_file(self.paths, authority, AdminKeyboard(self.paths), req["to"], data)
                self._text(reply, action, rep.path, ["restored " + req["member"]] + rep.summary().splitlines())
                return None
            if action == "optimize":
                from .optimize import optimize
                self._text(reply, action, "disk optimize", [optimize(self.paths, authority).summary()])
                return None
            if action == "settle":
                from .admin import settle
                self._text(reply, action, "settle", settle(self.paths, authority))
                return None
            if action in ("permit", "revoke"):
                name = req["app"]
                if name not in {a.name for a in AppStore(self.paths).installed()}:
                    result(False, f"{name} is not installed")
                    return None
                with authority.authorize("app.revoke" if action == "revoke" else "app.permit", name):
                    getattr(PermitStore(self.paths), "revoke" if action == "revoke" else "grant")(name)
                result(True, f"{name} {'may no longer run' if action == 'revoke' else 'may now run'}")
                return None
            if action == "line":
                self._text(reply, action, req["text"], self._line(req["text"], authority))
                return None
            if action == "focus":
                inst = Registry(self.paths).get(req["id"])
                if inst.status != "running":
                    result(False, f"{inst.id} is not running")
                    return None
                result(True, f"switching to {inst.id}", id=inst.id)
                return ("instance", inst.id)
        except (AuthorizationDenied, AuthError, PermitError, KAppError, SandboxError,
                RegistryError, TamperedError, VFSError, AdminError, OSError, FileNotFoundError) as e:
            result(False, str(e))
        return None

    def _updates(self, req, reply, result, authority) -> None:
        from . import provenance
        from .sources import Sources
        src, op = Sources(self.paths), req["op"]
        if op == "provenance":
            reply({"cmd": "updates", "op": op, "data": {**provenance.components(self.paths),
                                                        "sources": src.list(), "last": src.last_report()}})
        elif op == "check":
            reply({"cmd": "updates", "op": op, "data": src.check(authority)})
        elif op == "install":
            result(True, src.install(authority, req["name"], allow_new_permissions=req.get("permissions", False)))
        elif op == "install_all":
            self._text(reply, "updates", "install all", src.install_all(authority))
        elif op == "core":
            result(True, src.core_update(authority))
        elif op == "source_add":
            src.add(authority, req["name"], req["kind"], req["location"])
            result(True, f"added source {req['name']}")
        elif op == "source_remove":
            src.remove(authority, req["name"])
            result(True, f"removed source {req['name']}")

    @staticmethod
    def _text(reply, action: str, title: str, lines: list[str], **extra) -> None:
        reply({"cmd": "text", "action": action, "title": clean_text(title, 120),
               "lines": [clean_text(l, 300) for l in lines[:sysinfo.MAX_VIEW_LINES]], **extra})

    def _line(self, text: str, authority: Authority) -> list[str]:
        """The line shell, inside the desktop. Same words, same gates - the
        commands that need the real terminal say so instead of half-working."""
        from .lang import HELP, interpret
        r = interpret(text)
        if r.kind == "empty":
            return []
        if r.kind == "help":
            return HELP.splitlines()
        if r.kind == "exit":
            return ["Ctrl-C leaves this app."]
        if r.kind == "unknown":
            return ["I don't know that command." + (f" Did you mean '{r.hint}'?" if r.hint else "")]
        if r.kind == "code":
            from .coderun import run_code
            out: list[str] = []
            status = run_code(self.paths, lambda: authority, text, r.language, out=out.append)
            return [l for chunk in out for l in chunk.splitlines()] or [f"(exit {status})"]
        argv, verb = list(r.argv), r.argv[0]
        if verb == "list":
            return [f"{a['name']:<14} {a['version']:<8} {'permitted' if a['permitted'] else 'needs: permit'}"
                    for a in list_apps(self.paths)] or ["no apps installed"]
        if verb == "ps":
            return [f"{i['id']:<24} {i['name']:<14} {i['mode']:<9} {i['status']}"
                    for i in list_open(self.paths)] or ["no apps open"]
        if verb == "scan" and len(argv) >= 3:
            return sysinfo.scan_lines(argv[2])
        if verb == "ls" and len(argv) >= 2:
            return [f"{e['name']}{'/' if e['kind'] == 'dir' else ''}" for e in sysinfo.list_path(argv[1])]
        if verb == "view" and len(argv) >= 2:
            path = os.path.abspath(argv[1])
            authority.authorize("file.view", path).close()
            return sysinfo.view_lines(path)
        if verb == "optimize":
            from .optimize import optimize
            return [optimize(self.paths, authority).summary()]
        if verb == "settle":
            from .admin import settle
            return settle(self.paths, authority)
        if verb == "owed":
            return sysinfo.owed_lines(self.paths)
        if verb == "audit":
            return sysinfo.audit_lines(self.paths, 30)
        if verb == "activity":
            from .activity import build_feed, render_feed
            return render_feed(build_feed(self.paths, limit=30)).splitlines()
        if verb == "doctor":
            return sysinfo.doctor_lines()
        if verb == "admin" and len(argv) == 1:
            return [sysinfo.admin_line(self.paths)]
        if verb == "open" and len(argv) >= 2:
            mode = argv[1] if len(argv) == 3 else "tui"
            inst = open_background(self.paths, authority, argv[-1], mode, spawner=self._spawner)
            return [f"opened {inst.name} as {inst.id}"]
        if verb == "close" and len(argv) == 2:
            return [f"closed {close_instance(self.paths, authority, argv[1]).id}"]
        if verb == "permit" and len(argv) >= 2:
            revoke = argv[1] == "--revoke"
            name = argv[-1]
            with authority.authorize("app.revoke" if revoke else "app.permit", name):
                getattr(PermitStore(self.paths), "revoke" if revoke else "grant")(name)
            return [f"{name} {'may no longer run' if revoke else 'may now run'}"]
        if verb == "backup":
            if len(argv) < 2:
                return [f"{b['name']}  {b['files']} file(s)  {b['size']:,} bytes"
                        for b in backups_mod.list_backups(self.paths)] or ["no backups yet"]
            info = backups_mod.create(self.paths, authority, argv[1])
            return [f"backed up {info['files']} file(s) -> {info['name']}"]
        if verb == "boot":
            return ["you are already on the desktop"]
        return [f"'{r.word}' needs the real terminal (it takes over the screen or the "
                "administrator keyboard) - use it there, or open the app from the App Library."]
