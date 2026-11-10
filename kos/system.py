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

import base64
import copy

from . import assistant, backup, cache, credentials, crypto, firewall, netfetch, sysinfo
from . import cache, layers
from .address import check_launch
from .appdirs import AppDirs
from .auth import AuditLog, AuthError, Authority, AuthorizationDenied
from .broker import spawn
from .kapp import KApp, KAppError
from .permit import PermitError, PermitStore
from .paths import Paths
from .protocol import clean_text, escape_text
from .registry import Instance, Registry, RegistryError
from .sandbox import SandboxError, SandboxPolicy
from .store import AppStore, TamperedError

MAX_LISTED = 200
MAX_CRED_DENIALS = 2        # denied password prompts for credential requests per app instance before it is not asked again
MAX_FW_DENIALS = 2          # denied password prompts for firewall changes per app instance before they stop being asked


def authorize_app_action(name: str, app: KApp, mode: str, authority: Authority,
                         prompter) -> SandboxPolicy:
    """Shared by run / open / the bridge: mode check, then the sandbox. An app is NEVER given the host
    network, whatever its manifest says: ``network`` only means "may ask the OS to fetch over https as
    the firewall allows" (netfetch.py). There is no prompt for it here."""
    m = app.manifest
    if mode not in m.modes:
        raise KAppError(f"{name} has no {mode} mode (it has: {', '.join(m.modes)})")
    return SandboxPolicy(weak=os.environ.get("KOS_DEV_WEAK_SANDBOX") == "1")


def _row(paths: Paths, a, permits: PermitStore) -> dict:
    """One App Library row. The description comes from the stored zip's manifest and is
    display-only (nothing runs from this read; the seal is verified at launch)."""
    desc, modes, kind, extends = "", ["tui"], "app", ""
    try:
        m = KApp.from_file(paths.apps / f"{a.name}.kapp").manifest
        desc, modes, kind, extends = m.description, list(m.modes), m.kind, m.extends
    except (KAppError, OSError):
        pass
    return {"name": a.name, "version": a.version,
            "description": clean_text(desc, 200), "modes": modes,
            "permitted": permits.is_permitted(a.name), "kind": kind, "extends": extends}


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
                    system="system" in app.manifest.permissions, address=address)
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


class SystemBridge:
    """Answers one app's ``request`` commands. ``handle`` returns a switch
    target - ``("instance", id)`` - when the request moves the desktop."""

    def __init__(self, paths: Paths, spawner: Callable = spawn, *, app: str = "",
                 system: bool = True, assistant: bool = False, opener=None,
                 sysinfo: bool = False, network: bool = False, fetch_context=None,
                 firewall: bool = False, credentials: bool = False):
        self.paths = paths
        self._spawner = spawner
        self.app = app or "app"
        self.system = system             # manifest 'system' permission (set by the OS)
        self.assistant = assistant       # manifest 'assistant' permission: ONLY the assistant request
        self.sysinfo = sysinfo           # manifest 'sysinfo' permission: ONLY the sysinfo request
        self.network = network           # manifest 'network' permission: ONLY the fetch request (OS-brokered https)
        self.firewall = firewall         # manifest 'firewall' permission: ONLY the firewall request
        self.credentials = credentials   # manifest 'credentials' permission: ONLY the credential request
        self._cred_denied = 0            # denied/cancelled credential prompts this instance; at MAX_CRED_DENIALS it is latched off
        self._cred_rows: Optional[list] = None    # list rows (no secrets) once the owner allowed `list` for this instance
        self._asst_key: Optional[tuple] = None    # (fingerprint, decrypted API key): memory only, this instance only
        self._fw_granted = False         # list/log: one password per app instance; allow/remove: every time
        self._fw_refused = False
        self._fw_denied = 0              # denied/cancelled allow/remove prompts this instance; at MAX_FW_DENIALS it is latched off
        self._opener = opener            # tests only; the real one is assistant.make_opener()
        self._fetch_context = fetch_context   # tests only: an SSLContext that still verifies; real one is netfetch's
        # The assistant grant lasts for this app instance (this session) only. It is bound to the
        # endpoint it was given for: switching the backend asks again. A refusal is remembered too,
        # so an app cannot nag the owner with password prompts.
        self._granted: Optional[tuple] = None
        self._refused: Optional[tuple] = None
        # sysinfo: ONE grant per app instance covers every topic (all of them are the same kind of
        # non-identifying read-only fact, and 4 prompts for one screen would only train the owner to
        # type the password without reading). A refusal is remembered for the session too.
        self._si_granted = False
        self._si_refused = False

    def _fetch(self, req: dict, reply: Callable[[dict], None], authority: Authority) -> None:
        def fail(code: str) -> None:
            reply({"cmd": "fetch", "ok": False, "error": code})

        if not self.network:
            return fail("refused")              # no 'network' permission: nothing, not even a firewall lookup
        try:
            got = netfetch.fetch(self.paths, f"app:{self.app}", req["url"], req["method"], req["headers"],
                                 req["body"], context=self._fetch_context)
        except netfetch.FetchError as e:
            return fail(e.code)
        reply({"cmd": "fetch", "ok": True, "status": got["status"], "content_type": got["content_type"],
               "body_b64": base64.b64encode(got["body"]).decode("ascii")})

    def _firewall(self, req: dict, reply: Callable[[dict], None], authority: Authority) -> None:
        op = req.get("op")
        op = op if isinstance(op, str) and op in ("list", "log", "allow", "remove") else "-"   # never audit app text

        def fail(code: str) -> None:
            reply({"cmd": "firewall", "ok": False, "error": code})

        def audit(outcome: str) -> bool:
            try:
                authority.audit.record("firewall.request", f"{self.app} {op}", outcome)
                return True
            except OSError:
                return False

        if not self.firewall or op == "-":
            audit("refused")
            return fail("refused")
        try:
            if op in ("list", "log") and set(req) != {"cmd", "action", "op"}:
                audit("refused")
                return fail("refused")
            if op in ("allow", "remove"):
                if set(req) != {"cmd", "action", "op", "who", "host", "port"} | ({"proto"} if op == "allow" else set()) \
                        or req.get("host") == firewall.WILDCARD:
                    audit("refused")
                    return fail("refused")
                if op == "allow":
                    rule = firewall.check_rule(req["who"], req["host"], req["port"], req["proto"])
                    key, text = (rule["who"], rule["host"], rule["port"]), "allow " + firewall.describe(rule)
                else:
                    key = firewall.check_key(req["who"], req["host"], req["port"])
                    rule, text = None, f"remove {key[0]} {key[1]}:{key[2]}"
                if key[1] == firewall.WILDCARD:
                    audit("refused")
                    return fail("refused")
                if key[0].startswith("app:") and op == "allow" and \
                        key[0][4:] not in {a.name for a in AppStore(self.paths).installed()}:
                    audit("refused")
                    return fail("refused")
        except (firewall.FirewallError, KeyError, TypeError):
            audit("refused")
            return fail("refused")
        if op in ("allow", "remove"):
            if self._fw_denied >= MAX_FW_DENIALS:      # an app must not be able to nag for a password
                audit("refused")
                return fail("refused")
            try:
                with authority.authorize("firewall.change", text):      # EVERY time; audits itself
                    done = (firewall.add_rule(self.paths, **rule) and 1) if op == "allow" else \
                        firewall.remove_rule(self.paths, *key)
            except (AuthorizationDenied, AuthError, OSError):
                self._fw_denied += 1
                return fail("refused")
            except firewall.FirewallError:
                audit("failed:refused")
                return fail("refused")
            audit("allowed")
            detail = "rule added" if op == "allow" else ("rule removed" if done else "no such rule")
            return reply({"cmd": "firewall", "ok": True, "detail": detail})
        if self._fw_refused:
            audit("refused")
            return fail("refused")
        if not self._fw_granted:
            try:
                authority.authorize("firewall.read", f"{self.app} (rules and log)").close()
            except (AuthorizationDenied, AuthError):
                self._fw_refused = True
                return fail("refused")
            except OSError:
                return fail("refused")
            self._fw_granted = True
        if not audit("allowed"):
            return fail("refused")
        try:
            if op == "list":
                reply({"cmd": "firewall", "ok": True, "rules": [dict(r) for r in firewall.load(self.paths)]})
            else:
                reply({"cmd": "firewall", "ok": True, "log": self._fw_log()})
        except Exception:
            audit("failed:unavailable")
            fail("unavailable")

    def _fw_log(self) -> list:
        import time as _t
        out = []
        rows = [e for e in AuditLog(self.paths).tail(5000) if e.get("action") == "firewall.connect"]
        for e in rows:
            parts = str(e.get("target", "")).split(" ")
            if len(parts) != 3 or ":" not in parts[1]:
                continue
            host, _, port = parts[1].rpartition(":")
            out.append({"who": escape_text(parts[0]), "host": escape_text(host), "port": int(port) if port.isdigit() else 0,
                        "proto": escape_text(parts[2]), "outcome": escape_text(str(e.get("outcome", ""))[:16]),
                        "time": _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(e.get("t", 0)))})
        return out[-100:]

    def _sysinfo(self, req: dict, reply: Callable[[dict], None], authority: Authority) -> None:
        topic = req.get("topic")
        topic = topic if isinstance(topic, str) and topic in sysinfo.TOPICS else "-"   # never audit app text

        def fail(code: str) -> None:
            reply({"cmd": "sysinfo", "ok": False, "error": code})

        def audit(outcome: str) -> bool:
            try:
                authority.audit.record("sysinfo.read", f"{self.app} {topic}", outcome)   # target: never the data
                return True
            except OSError:
                return False                 # cannot log it, so it does not happen

        if not self.sysinfo or topic == "-":
            audit("refused")
            return fail("refused")
        if self._si_refused:
            audit("refused")
            return fail("refused")
        if not self._si_granted:
            try:
                authority.authorize("sysinfo.read", f"{self.app} (any topic)").close()   # audits itself
            except (AuthorizationDenied, AuthError):
                self._si_refused = True
                return fail("refused")
            except OSError:                  # the audit record could not be written: nothing happens
                return fail("refused")
            self._si_granted = True
        if not audit("allowed"):
            return fail("refused")
        try:
            data = sysinfo.read(topic, paths=self.paths)
        except Exception:
            audit("failed:unavailable")
            return fail("unavailable")
        reply({"cmd": "sysinfo", "ok": True, "data": data})

    def _assistant(self, req: dict, reply: Callable[[dict], None], authority: Authority) -> None:
        def fail(code: str) -> None:
            reply({"cmd": "assistant", "ok": False, "error": code})

        def audit(kind: str, outcome: str) -> bool:
            try:
                authority.audit.record("assistant.ask", f"{self.app} {kind}", outcome)
                return True
            except OSError:
                return False                 # cannot log it, so it does not happen

        if not self.assistant:
            audit("-", "refused")
            return fail("refused")
        cfg = assistant.load(self.paths)
        kind = cfg["active"]
        if kind == "off":
            audit(kind, "refused")
            return fail("not-configured")
        try:
            assistant.build_request(assistant.precheck_cfg(cfg), "", [{"role": "user", "content": "x"}])   # policy + completeness, no network
        except assistant.AssistantError as e:
            audit(kind, "refused")
            return fail(e.code)
        tgt = assistant.firewall_target(cfg)
        if tgt is None or not firewall.allows_now(self.paths, "os:assistant", *tgt):
            # no rule: no password prompt either. decide() writes the blocked attempt to the audit log.
            if tgt is not None:
                firewall.decide(self.paths, "os:assistant", *tgt)
            audit(kind, "blocked")
            return fail("blocked")
        fp = assistant.fingerprint(cfg)
        if self._refused == fp:
            audit(kind, "refused")
            return fail("refused")
        if self._granted != fp:
            try:
                with authority.authorize("assistant.ask", f"{self.app} ({kind})") as g:   # audits itself
                    self._asst_key = None
                    if kind == "api":      # the key is opened here, while the password was just typed
                        try:
                            assistant.migrate(self.paths, g)
                            cfg = assistant.load(self.paths)
                            self._asst_key = (fp, assistant.with_key(self.paths, g, cfg)["api"]["key"])
                        except (assistant.AssistantError, assistant.ConfigError):
                            audit(kind, "failed:key")
                            return fail("refused")
            except (AuthorizationDenied, AuthError):
                self._refused = fp
                return fail("refused")
            self._granted = fp
        if not audit(kind, "allowed"):
            return fail("refused")
        try:
            if kind == "api":
                if not self._asst_key or self._asst_key[0] != fp:
                    return fail("refused")
                cfg = copy.deepcopy(cfg)
                cfg["api"].pop("key_enc", None)
                cfg["api"]["key"] = self._asst_key[1]
            text = assistant.ask(cfg, req["system"], req["messages"], opener=self._opener, paths=self.paths)
        except assistant.AssistantError as e:
            audit(kind, "failed:" + e.code)
            return fail(e.code)
        reply({"cmd": "assistant", "ok": True, "text": text})

    def _credential(self, req: dict, reply: Callable[[dict], None], authority: Authority) -> None:
        op = req.get("op")
        op = op if isinstance(op, str) and op in credentials.OPS else "-"     # never audit app text

        def fail(code: str) -> None:
            reply({"cmd": "credential", "ok": False, "error": code})

        def audit(outcome: str) -> bool:
            try:       # app and operation only: never the label, a secret or any value
                authority.audit.record("credential.request", f"{self.app} {op}", outcome)
                return True
            except OSError:
                return False

        if not self.credentials or op == "-":
            audit("refused")
            return fail("refused")
        if self._cred_denied >= MAX_CRED_DENIALS:       # an app must not be able to nag for a password
            audit("refused")
            return fail("refused")
        if op == "list" and self._cred_rows is not None:
            if not audit("allowed"):
                return fail("refused")
            return reply({"cmd": "credential", "ok": True, "entries": [dict(r) for r in self._cred_rows]})
        shown = f"{op} '{req['label']}' for {self.app}" if op in ("get", "delete") else \
            (f"add '{req['label']}' for {self.app}" if op == "add" else f"list names for {self.app}")
        out: dict = {}
        try:
            with authority.authorize("credential." + op, self.app, shown=shown) as g:    # EVERY time except list
                try:
                    dek = crypto.dek_for(self.paths, g, create=(op == "add"))
                except crypto.CryptoError:
                    if op == "list" and not credentials.exists(self.paths) and not crypto.keyring_exists(self.paths):
                        dek = None            # nothing stored yet
                    else:
                        raise
                try:
                    if op == "list":
                        out = {"entries": credentials.list_rows(self.paths, dek) if dek is not None else []}
                        self._cred_rows = out["entries"]
                    elif op == "get":
                        out = {"entry": credentials.get(self.paths, dek, req["label"])}
                    elif op == "add":
                        rows = credentials.add(self.paths, dek, {k: req[k] for k in credentials.FIELDS})
                        self._cred_rows = rows if self._cred_rows is not None else None   # list stays password-gated
                        out = {"detail": "stored"}
                    else:
                        rows = credentials.delete(self.paths, dek, req["label"])
                        self._cred_rows = rows if self._cred_rows is not None else None
                        out = {"detail": "deleted"}
                finally:
                    if dek is not None:
                        crypto.wipe(dek)
        except (AuthorizationDenied, AuthError):
            self._cred_denied += 1
            return fail("refused")
        except credentials.CredentialError as e:
            audit("failed:" + e.code)
            return fail(e.code)
        except (crypto.CryptoError, OSError):
            audit("failed:unavailable")
            return fail("unavailable")
        if not audit("allowed"):
            return fail("refused")
        reply({"cmd": "credential", "ok": True, **out})

    def handle(self, req: dict, reply: Callable[[dict], None],
               authority: Authority) -> Optional[tuple[str, str]]:
        action = req["action"]
        if action == "assistant":
            self._assistant(req, reply, authority)
            return None
        if action == "sysinfo":
            self._sysinfo(req, reply, authority)
            return None
        if action == "firewall":
            self._firewall(req, reply, authority)
            return None
        if action == "fetch":
            self._fetch(req, reply, authority)
            return None
        if action == "credential":
            self._credential(req, reply, authority)
            return None

        def result(ok: bool, detail: str, **extra) -> None:
            reply({"cmd": "result", "action": action, "ok": ok,
                   "detail": clean_text(detail, 300), **extra})

        if not self.system:
            result(False, "this app does not have the 'system' permission")
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
