"""The OS side of ``service`` calls: what an app gets when it asks (see servicespec.py).

Apps cannot read the audit log, run the security check, list a directory, touch the firewall
or install anything. They ask, and this file answers - after four checks that no handler can
skip, because ``ServiceHost.call`` runs them before the handler is even looked up:

1. the call is one of the specs in ``servicespec.SPECS`` with exactly its arguments (the
   protocol already checked; checked again here, because this is the door);
2. the app's manifest asked for the service's group (``service:GROUP``), and the owner
   permitted it to run with that manifest (kos/permit.py pins the declared permissions);
3. the password for the action is typed in the OS's own prompt, now, for this call - a
   handler that shows or changes private state calls ``authorize`` before it reads anything;
4. whatever the handler returns is scrubbed: every string loses its control and bidi
   characters (an app cannot be handed a way to move the owner's cursor), and the reply is
   size-limited.

This is where the OS's own commands live now. ``kos audit``, ``kos security``, ``kos ls``,
``kos scan``, ``kos cell`` and the rest are apps (kos/office/pack_system.py) that call these;
the command line only launches them. What is still in the core, and why, is in the README.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import firewall, kernel
from .auth import AUDIT_KEY_LABEL, AuditLog, AuthError, Authority, AuthorizationDenied
from .kapp import KApp, KAppError
from .paths import Paths
from .permit import PermitError, PermitStore
from .protocol import escape_text
from .servicespec import SPECS, SpecError
from .store import AppStore, TamperedError
from .vfs import VFSError, resolve_mixed

MAX_REPLY = 700_000
MAX_ENTRIES = 500
MAX_STR = 400_000          # per string; MAX_REPLY bounds the whole answer


class ServiceError(Exception):
    """A refusal with a reason the app may show."""


@dataclass
class Ctx:
    paths: Paths
    authority: Authority
    caller: str


HANDLERS: dict[str, Callable[..., dict]] = {}


def service(name: str):
    if name not in SPECS:
        raise AssertionError(f"{name} has no spec in servicespec.py")

    def register(fn):
        HANDLERS[name] = fn
        return fn
    return register


def scrub(v: Any, limit: int = MAX_STR) -> Any:
    """Make everything in a reply safe to print: control characters become visible \\xNN."""
    if isinstance(v, str):
        return escape_text(v, limit)
    if isinstance(v, dict):
        return {escape_text(str(k), 100): scrub(x, limit) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [scrub(x, limit) for x in v]
    if isinstance(v, (bool, int, float)) or v is None:
        return v
    return escape_text(str(v), limit)


# ---- the authorization log ---------------------------------------------------------------------

@service("audit.tail")
def _audit_tail(ctx: Ctx, n: int) -> dict:
    with ctx.authority.authorize("audit.read"):
        rows = AuditLog(ctx.paths).tail(n)
    return {"entries": [{"t": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["t"])),
                         "outcome": e["outcome"], "action": e["action"], "target": e["target"]} for e in rows]}


@service("audit.verify")
def _audit_verify(ctx: Ctx) -> dict:
    with ctx.authority.authorize("audit.verify") as grant:
        rep = AuditLog(ctx.paths).verify(grant.key(AUDIT_KEY_LABEL))
    return {"ok": rep.ok, "entries": rep.entries, "chained": rep.chained, "anchored": rep.anchored,
            "legacy": rep.legacy, "trimmed": bool(rep.trimmed), "bad_line": rep.bad_line or 0,
            "problem": rep.problem or ""}


@service("activity.feed")
def _activity(ctx: Ctx, n: int) -> dict:
    from .activity import build_feed
    with ctx.authority.authorize("activity.read"):
        items = build_feed(ctx.paths, limit=n)
    return {"items": [{"t": time.strftime("%H:%M:%S", time.localtime(i.t)), "live": i.live, "text": i.text}
                      for i in items]}


# ---- the OS checking itself ---------------------------------------------------------------------

@service("security.check")
def _security(ctx: Ctx) -> dict:
    from .secure import FAIL, WARN, run_checks
    with ctx.authority.authorize("security.check"):
        checks = run_checks(ctx.paths)
    return {"checks": [{"level": c.level, "name": c.name, "detail": c.detail} for c in checks],
            "failed": sum(c.level == FAIL for c in checks), "warned": sum(c.level == WARN for c in checks)}


@service("system.report")
def _system(ctx: Ctx) -> dict:
    from . import firmware
    from .auth import PasswordStore
    from .sandbox import report
    with ctx.authority.authorize("system.read"):
        r = report()
        fw = firmware.probe()
    return {**{k: v for k, v in r.items() if k != "kos_kernel"}, "kos_kernel": r["kos_kernel"],
            "firmware": {"ok": fw.ok, "blocking": [f.name for f in fw.blocking], "reason": fw.reason() or ""},
            "password_configured": PasswordStore(ctx.paths).exists()}


@service("system.firmware")
def _firmware(ctx: Ctx, plan: bool) -> dict:
    from . import firmware
    with ctx.authority.authorize("system.read"):
        v = firmware.probe()
        out: dict = {"policy": v.policy, "lines": v.lines(), "ok": v.ok, "reason": v.reason() or "",
                     "protections": [{"name": n, "status": s, "note": t} for n, s, t in firmware.protections()]}
        if plan:
            items = firmware.plan(verdict=v)
            out["platform"] = firmware.platform_firmware()
            out["plan"] = [{"name": i.name, "state": i.state, "open": i.open_replacement, "advice": i.advice}
                           for i in items]
            out["summary"] = firmware.plan_summary(items)
    return out


# ---- looking after the disk ---------------------------------------------------------------------

@service("maintenance.owed")
def _owed(ctx: Ctx) -> dict:
    from .requires import Ledger
    with ctx.authority.authorize("system.read"):
        owed = Ledger(ctx.paths).owed()
    return {"owed": [{"target": e["target"], "trigger": e["trigger"], "pending": list(e["pending"])} for e in owed]}


@service("maintenance.settle")
def _settle(ctx: Ctx) -> dict:
    from .admin import settle
    return {"lines": settle(ctx.paths, ctx.authority)}


@service("maintenance.optimize")
def _optimize(ctx: Ctx) -> dict:
    from .optimize import optimize
    return {"summary": optimize(ctx.paths, ctx.authority).summary()}


# ---- files --------------------------------------------------------------------------------------

@service("files.list")
def _files_list(ctx: Ctx, path: str) -> dict:
    with ctx.authority.authorize("file.view", os.path.abspath(path)):
        vfs, last = resolve_mixed(path)
        if last:
            vfs.cd(last)
        entries = vfs.list()
    return {"path": vfs.pwd(), "truncated": len(entries) > MAX_ENTRIES,
            "entries": [{"name": e.name, "dir": bool(e.is_dir), "zip": bool(e.is_archive)}
                        for e in entries[:MAX_ENTRIES]]}


@service("files.read")
def _files_read(ctx: Ctx, path: str, limit: int) -> dict:
    with ctx.authority.authorize("file.view", os.path.abspath(path)):
        vfs, last = resolve_mixed(path)
        if not last:
            raise ServiceError("that is a directory, not a file")
        data = vfs.read_bytes(last)
    head = data[:limit]
    binary = b"\x00" in head
    text = head.decode("utf-8", errors="replace").replace("\t", "    ")
    return {"size": len(data), "shown": len(head), "binary": binary, "text": text}


@service("scan.file")
def _scan_file(ctx: Ctx, path: str) -> dict:
    from .scan import scan_file
    with ctx.authority.authorize("file.view", os.path.abspath(path)):
        res = scan_file(Path(path))
    return {"clean": res.clean, "summary": res.summary(), "sha256": res.sha256,
            "findings": [{"path": f.path, "rule": f.rule, "severity": f.severity, "note": f.note}
                         for f in res.findings[:200]]}


# ---- the firewall -------------------------------------------------------------------------------

def _rule_dict(e: firewall.Entry) -> dict:
    return {"app": e.app, "proto": e.proto, "direction": e.direction, "host": e.host, "port": e.port}


@service("firewall.list")
def _fw_list(ctx: Ctx) -> dict:
    with ctx.authority.authorize("firewall.read") as grant:
        entries, state = firewall.FirewallStore(ctx.paths).load(grant.key(firewall.KEY_LABEL))
    firewall.collect(ctx.paths)                      # move the kernel's newest lines into the audit log
    k = kernel.default()
    log = [e for e in AuditLog(ctx.paths).tail(400) if e["action"].startswith("net.")][-60:]
    info: dict = {"present": k.present(), "role": k.role(), "required": k.required()}
    if k.present():
        try:
            info.update(k.status())
        except kernel.KernelError:
            pass
    return {"rules": [_rule_dict(e) for e in entries], "state": state, "kernel": info,
            "log": [{"t": time.strftime("%H:%M:%S", time.localtime(e["t"])), "outcome": e["outcome"],
                     "action": e["action"], "target": e["target"]} for e in log]}


def _fw_entry(app: str, proto: str, direction: str, host: str, port: int) -> firewall.Entry:
    try:
        return firewall.check_entry(app, proto, direction, host, port)
    except firewall.FirewallError as e:
        raise ServiceError(str(e)) from None


@service("firewall.allow")
def _fw_allow(ctx: Ctx, app: str, proto: str, direction: str, host: str, port: int) -> dict:
    e = _fw_entry(app, proto, direction, host, port)          # refused before any password is asked
    with ctx.authority.authorize("firewall.change", f"allow {app} {proto} {direction} {e.host}:{port}") as g:
        added = firewall.FirewallStore(ctx.paths).add(g.key(firewall.KEY_LABEL), e)
    return {"added": added, "rule": _rule_dict(e), "note": "takes effect the next time the app is opened"}


@service("firewall.remove")
def _fw_remove(ctx: Ctx, app: str, proto: str, direction: str, host: str, port: int) -> dict:
    e = _fw_entry(app, proto, direction, host, port)
    with ctx.authority.authorize("firewall.change", f"remove {app} {proto} {direction} {e.host}:{port}") as g:
        removed = firewall.FirewallStore(ctx.paths).remove(g.key(firewall.KEY_LABEL), e)
    return {"removed": removed, "rule": _rule_dict(e), "note": "takes effect the next time the app is opened"}


# ---- kernel cells -------------------------------------------------------------------------------

@service("cells.list")
def _cells_list(ctx: Ctx) -> dict:
    from .cells import CellManager
    with ctx.authority.authorize("cell.list"):
        cells = CellManager(ctx.paths).cells()
    return {"cells": [{"name": c["name"], "cid": c["cid"], "cpus": c["cpus"], "memory_mb": c["memory_mb"],
                       "running": bool(c["running"])} for c in cells]}


@service("cells.start")
def _cells_start(ctx: Ctx, name: str, kernel: str, initrd: str, memory: int, cpus: list) -> dict:
    from .cells import CellManager, CellSpec
    if not all(c.isdigit() and len(c) <= 4 for c in cpus):
        raise ServiceError("cpus must be core numbers")
    rec = CellManager(ctx.paths).start(CellSpec(name=name, kernel=kernel, initrd=initrd, memory_mb=memory,
                                                cpus=[int(c) for c in cpus]), ctx.authority)
    return {"name": rec["name"], "cpus": rec["cpus"], "cid": rec["cid"]}


@service("cells.stop")
def _cells_stop(ctx: Ctx, name: str) -> dict:
    from .cells import CellManager
    CellManager(ctx.paths).stop(name, ctx.authority)
    return {"stopped": name}


# ---- apps and permissions -----------------------------------------------------------------------

@service("packages.list")
def _pkg_list(ctx: Ctx) -> dict:
    from .system import list_apps
    with ctx.authority.authorize("app.list"):
        rows = list_apps(ctx.paths)
        grants = PermitStore(ctx.paths).perms
        for r in rows:
            e = grants.get(r["name"], "run")
            r["approved_permissions"] = list((e or {}).get("declared") or [])
    return {"apps": rows}


@service("packages.install")
def _pkg_install(ctx: Ctx, path: str) -> dict:
    m = AppStore(ctx.paths).install(Path(path), ctx.authority)
    return {"name": m.name, "version": m.version, "modes": list(m.modes)}


@service("packages.update")
def _pkg_update(ctx: Ctx, path: str) -> dict:
    old, m = AppStore(ctx.paths).update(Path(path), ctx.authority)
    return {"name": m.name, "from": old, "to": m.version}


@service("packages.remove")
def _pkg_remove(ctx: Ctx, name: str) -> dict:
    AppStore(ctx.paths).remove(name, ctx.authority)
    return {"removed": name}


@service("packages.permit")
def _pkg_permit(ctx: Ctx, name: str, revoke: bool) -> dict:
    action = "app.revoke" if revoke else "app.permit"
    with ctx.authority.authorize(action, name):
        if revoke:
            PermitStore(ctx.paths).revoke(name)
            return {"name": name, "permitted": False}
        declared = KApp.from_file(ctx.paths.apps / f"{name}.kapp").manifest.permissions
        PermitStore(ctx.paths).grant(name, declared)
    return {"name": name, "permitted": True, "approved_permissions": list(declared)}


@service("packages.convert")
def _pkg_convert(ctx: Ctx, path: str, out: str, exe: str) -> dict:
    from .debconv import MAX_DEB, DebError, convert
    if os.path.lexists(out):
        raise ServiceError(f"{out} already exists; refusing to overwrite it")
    with open(path, "rb") as f:
        data = f.read(MAX_DEB + 1)
    try:
        kapp, report = convert(data, exe or None)
    except DebError as e:
        raise ServiceError(str(e)) from None
    ctx.authority.authorize("app.convert", report.kapp_name).close()
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(kapp)
    return {"summary": report.summary(), "wrote": out}


@service("permissions.list")
def _perm_list(ctx: Ctx) -> dict:
    from .permissions import Permissions
    with ctx.authority.authorize("space.list"):
        entries = Permissions(ctx.paths).list("space:")
    return {"grants": [{"space": e["resource"][6:], "app": e["app"], "level": e["level"]} for e in entries]}


@service("permissions.grant")
def _perm_grant(ctx: Ctx, app: str, space: str, level: str, revoke: bool) -> dict:
    from .permissions import Permissions
    resource = f"space:{space}"
    with ctx.authority.authorize("space.revoke" if revoke else "space.grant", f"{app}:{resource}"):
        perms = Permissions(ctx.paths)
        if revoke:
            return {"revoked": bool(perms.revoke(app, resource))}
        cur = perms.get(app, resource)
        if cur and cur["level"] == "own":
            raise ServiceError(f"{app} owns {resource}")
        perms.grant(app, resource, level)
    return {"app": app, "space": space, "level": level}


# ---- skills and code ----------------------------------------------------------------------------

@service("skills.make")
def _skills(ctx: Ctx) -> dict:
    from .cli import build_parser
    from .skillmaker import collect_apps, command_inventory, make_skills
    manifests, skipped = collect_apps(ctx.paths, ctx.authority)
    files, refused = make_skills(command_inventory(build_parser()), manifests)
    total, kept = 0, {}
    for rel, txt in files.items():
        total += len(txt)
        if total > 400_000:
            skipped.append("the rest was left out: too large to show")
            break
        kept[rel] = txt
    return {"files": kept, "skipped": skipped + refused}


@service("code.run")
def _code_run(ctx: Ctx, code: str, lang: str) -> dict:
    from .coderun import run_code
    lines: list[str] = []
    status = run_code(ctx.paths, lambda: ctx.authority, code, lang, out=lambda s: lines.append(str(s)[:2000]))
    return {"status": status, "output": lines[:200]}


# ---- linked devices, sync, migration, the local agent -------------------------------------------------
# The logic lives in kos/linkdev.py, syncer.py, migrate.py and agentrun.py (each has its own tests). What is
# here is only the door: the password is asked *before* anything is read, opened or connected, the caller's
# manifest already asked for the group, and a domain error becomes a refusal the app can show.

def _domain(fn):
    import functools

    @functools.wraps(fn)
    def run(ctx, **args):
        from .agentrun import AgentError
        from .linkdev import LinkError, Refusal
        from .migrate import MigrateError
        try:
            return fn(ctx, **args)
        except (LinkError, Refusal, MigrateError, AgentError) as e:
            raise ServiceError(str(e)) from None
    return run


def _when(t: int) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(t))


def _peer_view(p) -> dict:
    return {"name": p.name, "platform": p.platform, "id": p.device_id[:16], "scope": p.scope, "since": _when(p.linked_at)}


def _find_peer(peers: list, ident: str):
    hit = [p for p in peers if p.device_id.startswith(ident)]
    if len(hit) != 1:
        raise ServiceError("no linked device matches that id" if not hit else "that id matches more than one device: type more of it")
    return hit[0]


@service("link.list")
@_domain
def _link_list(ctx: Ctx) -> dict:
    from . import linkdev
    with ctx.authority.authorize("link.list") as grant:
        peers = linkdev.LinkStore(ctx.paths).peers(grant.key("link-store"))
        me = None
        if linkdev.Identity.exists(ctx.paths):
            i = linkdev.Identity.load(ctx.paths, grant)
            me = {"name": i.name, "platform": i.platform, "id": i.device_id[:16]}
    return {"me": me, "peers": [_peer_view(p) for p in peers]}


@service("link.identify")
@_domain
def _link_identify(ctx: Ctx, name: str, platform: str) -> dict:
    from . import linkdev
    with ctx.authority.authorize("link.identity", name) as grant:
        i = linkdev.Identity.create(ctx.paths, grant, name, platform)
    return {"me": {"name": i.name, "platform": i.platform, "id": i.device_id[:16]}}


def _accept_one(paths: Paths, authority: Authority, host: str, port: int):
    """Wait (at most two minutes) for one connection on an address the firewall allows."""
    import socket
    from . import linkdev
    srv = linkdev.open_listener(paths, authority, host, port)
    try:
        srv.settimeout(120)
        try:
            conn, _ = srv.accept()
        except OSError:
            raise ServiceError("nobody connected within two minutes") from None
    finally:
        srv.close()
    return conn


@service("link.pair")
@_domain
def _link_pair(ctx: Ctx, role: str, host: str, port: int) -> dict:
    from . import linkdev
    with ctx.authority.authorize("link.identity", "to pair") as grant:
        ident = linkdev.Identity.load(ctx.paths, grant)
    if role == "connect":
        sock = linkdev.open_client(ctx.paths, ctx.authority, host, port)
    else:
        sock = _accept_one(ctx.paths, ctx.authority, host, port)
    offer = linkdev.start_pairing(sock, ident, initiator=(role == "connect"))
    p = ctx.authority.prompter
    p.info(f"Pairing with '{offer.peer_name}' ({offer.session.peer_public.hex()[:8]}...). Code: {offer.sas}")
    same = p.confirm(f"Does the other device show exactly {offer.sas}? Say no if it differs: that means someone is in between")
    peer = linkdev.finish_pairing(ctx.paths, ctx.authority, offer, bool(same))
    return {"linked": _peer_view(peer), "code": offer.sas}


@service("link.scope")
@_domain
def _link_scope(ctx: Ctx, device: str, scope: str) -> dict:
    from . import linkdev
    with ctx.authority.authorize("link.scope", f"{device} -> {scope}") as grant:
        key = grant.key("link-store")
        store = linkdev.LinkStore(ctx.paths)
        peer = _find_peer(store.peers(key), device)
        store.set_scope(key, peer.device_id, scope)
    AuditLog(ctx.paths).record("link.scope", f"{peer.name} {peer.device_id[:8]}", scope)
    return {"device": peer.name, "scope": scope}


@service("link.unlink")
@_domain
def _link_unlink(ctx: Ctx, device: str) -> dict:
    from . import linkdev
    with ctx.authority.authorize("link.remove", device) as grant:
        key = grant.key("link-store")
        store = linkdev.LinkStore(ctx.paths)
        peer = _find_peer(store.peers(key), device)
        store.remove(key, peer.device_id)
    AuditLog(ctx.paths).record("link.remove", f"{peer.name} {peer.device_id[:8]}", "unlinked")
    return {"unlinked": peer.name}


def _folders(ctx: Ctx):
    from .syncer import FolderStore
    return FolderStore(ctx.paths.state, forbidden=(ctx.paths.etc,))


@service("sync.folders")
@_domain
def _sync_folders(ctx: Ctx) -> dict:
    with ctx.authority.authorize("sync.read") as grant:
        folders = _folders(ctx).folders(grant.key("sync-folders"))
    return {"folders": [{"name": n, "path": p} for n, p in sorted(folders.items())]}


@service("sync.share")
@_domain
def _sync_share(ctx: Ctx, name: str, path: str) -> dict:
    from .syncer import SyncError
    try:
        with ctx.authority.authorize("sync.run", f"share {path} as {name}") as grant:
            real = _folders(ctx).add(grant.key("sync-folders"), name, path)
    except SyncError as e:
        raise ServiceError(str(e)) from None
    return {"name": name, "path": str(real)}


@service("sync.unshare")
@_domain
def _sync_unshare(ctx: Ctx, name: str) -> dict:
    with ctx.authority.authorize("sync.run", f"stop syncing {name}") as grant:
        gone = _folders(ctx).remove(grant.key("sync-folders"), name)
    if not gone:
        raise ServiceError(f"no shared folder called {name!r}")
    return {"name": name}


@service("sync.run")
@_domain
def _sync_run(ctx: Ctx, device: str, folder: str, host: str, port: int, dry: bool) -> dict:
    from . import linkdev, syncer
    log = AuditLog(ctx.paths)
    with ctx.authority.authorize("sync.run", f"{folder} with {device}") as grant:
        peer = _find_peer(linkdev.LinkStore(ctx.paths).peers(grant.key("link-store")), device)
        try:
            root = _folders(ctx).resolve(grant.key("sync-folders"), folder)
        except syncer.SyncError as e:
            raise ServiceError(str(e)) from None
        ident = linkdev.Identity.load(ctx.paths, grant)
    sock = linkdev.open_client(ctx.paths, ctx.authority, host, port)
    client = linkdev.connect_linked(sock, ident, peer)
    try:
        base = syncer.load_base(ctx.paths.state, peer.device_id, folder)
        try:
            rep, new_base = syncer.sync_once(client, folder, root, base, peer.device_id, peer.platform, dry)
        except syncer.SyncError as e:
            log.record("sync.run", f"{folder} with {peer.name}", "failed")
            raise ServiceError(str(e)) from None
        if not dry:
            syncer.save_base(ctx.paths.state, peer.device_id, folder, new_base)
    finally:
        client.close()
    log.record("sync.run", f"{folder} with {peer.name}", "dry-run" if dry else ("done" if rep.ok() else "partial"))
    return {"pulled": rep.pulled[:40], "pushed": rep.pushed[:40], "trashed": rep.trashed[:40],
            "conflicts": rep.conflicts[:40], "refused": [f"{p}: {why}" for p, why in rep.refused[:40]],
            "skipped": rep.skipped[:40], "counts": [len(rep.pulled), len(rep.pushed), len(rep.trashed),
                                                    len(rep.conflicts), len(rep.refused)], "dry": dry}


@service("sync.serve")
@_domain
def _sync_serve(ctx: Ctx, host: str, port: int) -> dict:
    from . import linkdev, syncer
    with ctx.authority.authorize("sync.read", "to share folders with a linked device") as grant:
        folders = _folders(ctx).folders(grant.key("sync-folders"))
        ident = linkdev.Identity.load(ctx.paths, grant)
        store_key = grant.key("link-store")           # so a stranger at the port cannot make the owner type a password
    store = _folders(ctx)

    def resolve(name: str):
        if name not in folders:
            raise syncer.SyncError(f"no shared folder called {name!r}")
        return store.check_path(folders[name])
    conn = _accept_one(ctx.paths, ctx.authority, host, port)
    handled = linkdev.serve_socket(ctx.paths, ctx.authority, ident, conn, syncer.make_handlers(resolve), store_key)
    return {"requests_handled": handled}


@service("migrate.export")
@_domain
def _migrate_export(ctx: Ctx, roots: list, out: str, apps: bool) -> dict:
    from . import migrate
    label = f"{out} (reads {', '.join(roots)[:150]}{' and your apps' if apps else ''})"
    s = migrate.export_bundle(ctx.paths, ctx.authority, [Path(r) for r in roots], Path(out), include_kos=apps, label=label)
    return {"files": s.files, "bytes": s.bytes, "left_behind": s.skipped[:40], "out": out}


@service("migrate.import")
@_domain
def _migrate_import(ctx: Ctx, bundle: str, dest: str, target: str) -> dict:
    from . import migrate
    r = migrate.import_bundle(ctx.paths, ctx.authority, Path(bundle), Path(dest), target)
    return {"written": len(r.written), "identical": len(r.identical), "kept_both": len(r.kept_both),
            "renamed": [f"{a} -> {b} ({why})" for a, b, why in r.renamed[:40]], "staged": r.staged[:40],
            "left_behind": r.skipped_at_source[:40], "bytes": r.bytes}


@service("agent.run")
@_domain
def _agent_run(ctx: Ctx, task: str, workspace: str, steps: int) -> dict:
    from . import agentrun
    ep = agentrun.local_endpoint(ctx.paths)
    res = agentrun.run_agent(ctx.paths, ctx.authority, task, Path(workspace), agentrun.http_model(ctx.paths, ep),
                             max_steps=steps)
    return {"stopped": res.stopped, "final": res.final,
            "steps": [{"n": s.n, "kind": s.kind, "tool": s.tool, "detail": s.detail[:200]} for s in res.steps]}


# ---- the door -----------------------------------------------------------------------------------

_ERRORS = (AuthorizationDenied, AuthError, KAppError, PermitError, TamperedError, VFSError, OSError,
           ServiceError, firewall.FirewallError, kernel.KernelError, ValueError)


class ServiceHost:
    """One per running app: who it is, and which groups its manifest asked for."""

    def __init__(self, paths: Paths, caller: str, groups: frozenset[str]):
        self.paths, self.caller, self.groups = paths, caller, frozenset(groups)

    def call(self, msg: dict, authority: Authority) -> dict:
        """``msg`` is a validated service message. Always returns a reply; never raises."""
        reply = {"cmd": "service", "id": msg.get("id", 0), "ok": False, "detail": "", "data": {}}
        try:
            spec = SPECS.get(msg.get("name"))
            if spec is None:
                raise ServiceError("no such service")
            if spec.group not in self.groups:
                raise ServiceError(f"this app did not ask for 'service:{spec.group}' in its manifest")
            try:
                args = spec.check(msg.get("args", {}))
            except SpecError as e:
                raise ServiceError(str(e)) from None
            fn = HANDLERS.get(spec.name)
            if fn is None:
                raise ServiceError("this service is not implemented")
            data = scrub(fn(Ctx(self.paths, authority, self.caller), **args))
            if len(json.dumps(data)) > MAX_REPLY:
                raise ServiceError("the answer is too large to send")
            reply.update(ok=True, data=data)
        except _ERRORS as e:
            reply["detail"] = escape_text(str(e) or type(e).__name__, 300)
        except Exception as e:      # a handler bug must not take the session down, nor leak a traceback
            reply["detail"] = f"internal error in {msg.get('name')}: {type(e).__name__}"
        return reply
