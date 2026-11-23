"""No reboot: kos/norestart.py, the norestart.* services (the door) and apps/norestart.

What is proved and how. Nothing here is maths a prover needs (no Z3 proof in kos/proofs.py); every claim has a
test that tries to break it, and each refusal sits next to the allowance that shows the rule, not a broken
fixture, said no:

* the lease: it holds exactly three derived keys, serves nothing else, ends on time and when wiped, can
  authorize only app.open and app.close of one named app, once, and never prompts;
* detection: current / stale / in-use / needs-you / unknown, from what each instance recorded when it started;
* a real swap with real brokers and sandboxed apps: make before break, nothing widened, nothing swapped on a
  tampered file or a wrong key, the old copy left alone when anything goes wrong;
* the real watcher process: keys handed over a pipe, found nowhere on disk, wiped when it ends;
* the reasons a reboot is still real (kernel, firmware) and the ones that are not.

What is not tested, because it cannot be here: a real kernel or firmware update, a real desktop with a person
attached, and anything about memory beyond the buffers the lease owns (Python can copy immutable bytes)."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kos import norestart, rulecheck, sdk, servicespec  # noqa: E402
from kos.auth import (ACTIONS, AUDIT_KEY_LABEL, AuditLog, Authority, AuthorizationDenied, KdfParams,  # noqa: E402
                      PasswordStore, Throttle, derive_master, subkey)
from kos.broker import spawn  # noqa: E402
from kos.kapp import KApp, Manifest, pack  # noqa: E402
from kos.norestart import (CURRENT, IN_USE, KEPT, NEEDS_YOU, STALE, SWAPPED, UNKNOWN, Lease,  # noqa: E402
                           LeaseAuthority, NoRestartError)
from kos.paths import Paths  # noqa: E402
from kos.permit import PermitStore  # noqa: E402
from kos.prompt import ScriptedPrompter  # noqa: E402
from kos.registry import Instance, Registry  # noqa: E402
from kos.secret import SecretBytes  # noqa: E402
from kos.services import HANDLERS, ServiceHost  # noqa: E402
from kos.store import SEAL_KEY_LABEL, AppStore  # noqa: E402
from kos.system import open_background  # noqa: E402
from kos import firewall  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "apps" / "norestart"
PW = "no reboot owner password"
BILLION = norestart.BILLION

APP_SRC = '''from kos.sdk import App


def main():
    app = App()
    for _ in app.events():
        pass
'''


def wait_for(pred, timeout=30):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = pred()
        if v:
            return v
        time.sleep(0.1)
    return pred()


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:                                  # a zombie is not running
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


class FakeClock:
    def __init__(self):
        self.now = 10 * BILLION

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds * BILLION


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o755)
        self.paths = Paths(self.root)
        PasswordStore(self.paths).create(PW.encode(), KdfParams.fresh(n=2**10), throttle_base=0)
        self.store = AppStore(self.paths)
        self.addCleanup(self.stop_everything)

    # -- fixtures
    def authority(self, *answers):
        return Authority(self.paths, ScriptedPrompter(answers), Throttle(self.paths, base=0))

    def build(self, name, version, perms=()):
        d = self.root / "src" / f"{name}-{version}"
        d.mkdir(parents=True)
        (d / "app.py").write_text(APP_SRC)
        (d / "manifest.json").write_text(json.dumps({
            "name": name, "version": version, "runtime": "python", "entry": "app:main", "modes": ["tui"],
            "permissions": list(perms), "description": "a test app"}))
        out = self.root / f"{name}-{version}.kapp"
        pack(d, out)
        return out

    def permit(self, name):
        app = KApp.from_file(self.paths.apps / f"{name}.kapp")
        PermitStore(self.paths).grant(name, app.manifest.permissions, pin=app.sha256)

    def install(self, name, version="1.0", perms=(), permit=True):
        self.store.install(self.build(name, version, perms), self.authority(PW))
        if permit:
            self.permit(name)

    def update(self, name, version, perms=(), permit=True):
        self.store.update(self.build(name, version, perms), self.authority(PW))
        if permit:
            self.permit(name)

    def open(self, name):
        return open_background(self.paths, self.authority(PW), name)

    def installed_sha(self, name):
        return next(a.sha256 for a in self.store.installed() if a.name == name)

    def lease(self, seconds=300, clock=time.monotonic_ns):
        with self.authority(PW).authorize("norestart.refresh") as g:
            lease = Lease.from_grant(g, seconds, clock)
        self.addCleanup(lease.wipe)
        return lease

    def running(self, name):
        return [i for i in Registry(self.paths).list() if i.name == name and i.status == "running"]

    def audit(self):
        return [(e["action"], e["outcome"]) for e in AuditLog(self.paths).entries()]

    def stop_everything(self):
        try:
            norestart.stop_watcher(self.paths)
        except Exception:
            pass
        insts = Registry(self.paths).list() if self.paths.state.exists() else []
        for i in insts:
            for pid in (i.broker_pid, i.app_pid):
                if pid > 1 and pid != os.getpid():
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except (ProcessLookupError, PermissionError):
                        pass
        wait_for(lambda: not any(alive(i.broker_pid) for i in insts if i.broker_pid != os.getpid()), 5)

    def record(self, name, sha="", version="", **kw):
        """A running-instance record, written by hand (a live pid, no process) for the detection tests."""
        reg = Registry(self.paths)
        iid = reg.new_id(name)
        run = self.paths.state / "appdata" / name / "run"
        inst = Instance(id=iid, name=name, mode="tui", broker_pid=os.getpid(), sock_path=str(run / f"{iid}.sock"),
                        log_path=str(run / f"{iid}.log"), started=time.time(), app_pid=1, status="running",
                        sha256=sha, version=version, **kw)
        reg.write(inst)
        return inst

    def row(self, inst):
        return next(r for r in norestart.scan(self.paths) if r.id == inst.id)


# ---- the lease -----------------------------------------------------------------------------------

def keys(n=32):
    return {label: SecretBytes(bytes([i + 1]) * n) for i, label in enumerate(norestart.LEASE_LABELS)}


class TestLease(Env):
    def test_a_lease_holds_exactly_the_three_keys_and_lasts_a_bounded_whole_number_of_seconds(self):
        Lease(keys(), 60)
        Lease(keys(), norestart.MAX_LEASE_S)
        for bad in (0, -1, norestart.MAX_LEASE_S + 1, True, 1.5, "60", None):
            with self.assertRaises(NoRestartError, msg=repr(bad)):
                Lease(keys(), bad)
        some = keys()
        some.pop(AUDIT_KEY_LABEL)
        with self.assertRaises(NoRestartError):
            Lease(some, 60)
        more = keys()
        more["backup-index"] = SecretBytes(b"x" * 32)
        with self.assertRaises(NoRestartError):
            Lease(more, 60)

    def test_it_holds_keys_derived_from_the_password_and_never_the_password_or_the_master(self):
        lease = self.lease()
        master = derive_master(PW.encode(), PasswordStore(self.paths).params())
        for label in norestart.LEASE_LABELS:
            self.assertEqual(lease.key(label), subkey(master, label))
            self.assertNotIn(PW.encode(), lease.key(label))
            self.assertNotEqual(lease.key(label), bytes(master.raw))
        self.assertEqual(set(norestart.LEASE_LABELS), {SEAL_KEY_LABEL, firewall.KEY_LABEL, AUDIT_KEY_LABEL})

    def test_it_serves_no_other_key_a_key_for_anything_else_is_refused(self):
        lease = self.lease()
        for label in ("backup-index", "applink-index", "verifier", "", "kapp-seal ", "audit-chain\0"):
            with self.assertRaises(AuthorizationDenied, msg=repr(label)):
                lease.key(label)
        self.assertTrue(lease.alive)            # a refused ask does not end it

    def test_it_ends_on_time_and_an_ended_lease_is_wiped_and_serves_nothing(self):
        clock = FakeClock()
        raw = keys()
        lease = Lease(raw, 10, clock)
        clock.advance(9)
        self.assertTrue(lease.alive)
        self.assertEqual(lease.left(), 1)
        self.assertEqual(len(lease.key(SEAL_KEY_LABEL)), 32)
        clock.advance(1)
        self.assertFalse(lease.alive)
        self.assertEqual(lease.left(), 0)
        with self.assertRaises(AuthorizationDenied):
            lease.key(SEAL_KEY_LABEL)
        self.assertTrue(all(len(k) == 0 for k in raw.values()))     # the buffers are zeroed, not just forgotten

    def test_wipe_zeroes_the_buffers_and_is_final(self):
        raw = keys()
        lease = Lease(raw, 60)
        lease.wipe()
        lease.wipe()
        for k in raw.values():
            self.assertEqual(len(k), 0)
            with self.assertRaises(ValueError):
                k.raw
        with self.assertRaises(AuthorizationDenied):
            lease.key(SEAL_KEY_LABEL)
        self.assertFalse(lease.alive)

    def test_the_grant_it_came_from_is_closed_and_the_lease_still_works(self):
        with self.authority(PW).authorize("norestart.refresh") as g:
            lease = Lease.from_grant(g, 60)
        self.addCleanup(lease.wipe)
        with self.assertRaises(AuthorizationDenied):
            g.key(SEAL_KEY_LABEL)
        self.assertEqual(len(lease.key(SEAL_KEY_LABEL)), 32)

    def test_a_forked_child_does_not_keep_the_keys_but_the_parent_does(self):
        lease = self.lease()
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.write(w, b"1" if (not lease.alive and lease._keys == {}) else b"0")
            finally:
                os._exit(0)
        os.close(w)
        out = os.read(r, 1)
        os.close(r)
        os.waitpid(pid, 0)
        self.assertEqual(out, b"1")
        self.assertTrue(lease.alive)
        self.assertEqual(len(lease.key(SEAL_KEY_LABEL)), 32)

    def test_a_hex_handoff_round_trips_and_a_bad_one_is_refused(self):
        lease = self.lease()
        copy = Lease.from_hex(lease.hex_keys(), 60)
        self.addCleanup(copy.wipe)
        for label in norestart.LEASE_LABELS:
            self.assertEqual(copy.key(label), lease.key(label))
        for bad in ({}, {SEAL_KEY_LABEL: "zz", firewall.KEY_LABEL: "00", AUDIT_KEY_LABEL: "00"},
                    {SEAL_KEY_LABEL: 5, firewall.KEY_LABEL: "00", AUDIT_KEY_LABEL: "00"}):
            with self.assertRaises(NoRestartError):
                Lease.from_hex(bad, 60)


class TestLeaseAuthority(Env):
    def test_it_authorizes_nothing_that_was_not_allowed_and_says_so_in_the_log(self):
        auth = LeaseAuthority(self.paths, self.lease())
        for action, target in (("app.open", "x"), ("app.close", "x-1a2b3c"), ("app.update", "x"),
                               ("norestart.auto", "8h"), ("file.write", "")):
            with self.assertRaises(AuthorizationDenied, msg=action):
                auth.authorize(action, target)
        self.assertEqual({o for a, o in self.audit() if a.startswith("lease:")}, {"refused"})
        self.assertFalse([1 for a, o in self.audit() if o == "granted" and a.startswith("lease:")])

    def test_only_app_open_and_app_close_can_ever_be_allowed(self):
        self.assertEqual(norestart.LEASE_ACTIONS, ("app.open", "app.close"))
        auth = LeaseAuthority(self.paths, self.lease())
        for action in sorted(ACTIONS):
            if action in norestart.LEASE_ACTIONS:
                auth.allow(action, "t")
            else:
                with self.assertRaises(NoRestartError, msg=action):
                    auth.allow(action, "t")

    def test_one_permission_is_one_use_for_one_target(self):
        auth = LeaseAuthority(self.paths, self.lease())
        auth.allow("app.open", "a")
        with self.assertRaises(AuthorizationDenied):
            auth.authorize("app.open", "b")             # another app
        with self.assertRaises(AuthorizationDenied):
            auth.authorize("app.close", "a")            # another action
        grant = auth.authorize("app.open", "a")
        self.assertEqual((grant.action, grant.target), ("app.open", "a"))
        with self.assertRaises(AuthorizationDenied):
            auth.authorize("app.open", "a")             # used

    def test_what_it_logs_is_named_lease_and_is_anchored_to_the_password_key(self):
        auth = LeaseAuthority(self.paths, self.lease())
        auth.allow("app.open", "a")
        auth.authorize("app.open", "a")
        self.assertEqual(self.audit()[-1], ("lease:app.open", "granted"))
        self.assertNotIn(("app.open", "granted"), self.audit())     # never mistakable for a typed password
        with self.authority(PW).authorize("audit.verify") as g:
            rep = AuditLog(self.paths).verify(g.key(AUDIT_KEY_LABEL))
        self.assertTrue(rep.ok, rep.problem)
        self.assertGreaterEqual(rep.anchored, 2)

    def test_a_grant_from_a_lease_serves_only_the_leases_keys_and_gives_up_no_master(self):
        lease = self.lease()
        auth = LeaseAuthority(self.paths, lease)
        auth.allow("app.open", "a")
        grant = auth.authorize("app.open", "a")
        self.assertEqual(grant.key(SEAL_KEY_LABEL), lease.key(SEAL_KEY_LABEL))
        with self.assertRaises(AuthorizationDenied):
            grant.key("backup-index")
        with self.assertRaises(AuthorizationDenied):
            grant.chip_master(b"x" * 32)
        grant.check("app.open", "a")
        with self.assertRaises(AuthorizationDenied):
            grant.check("app.open", "b")
        grant.close()
        self.assertTrue(lease.alive)                    # closing a grant does not end the lease
        lease.wipe()
        with self.assertRaises(AuthorizationDenied):
            grant.check("app.open", "a")

    def test_it_never_prompts_a_question_or_a_password_prompt_is_a_refusal(self):
        auth = LeaseAuthority(self.paths, self.lease())
        with self.assertRaises(AuthorizationDenied) as c:
            auth.prompter.confirm("shop asks for network access. Allow?")
        self.assertIn("only you can make", str(c.exception))
        with self.assertRaises(AuthorizationDenied):
            auth.prompter.password("Password: ")
        auth.prompter.info("ignored")
        auth.prompter.close()

    def test_an_ended_lease_authorizes_nothing_even_if_allowed(self):
        clock = FakeClock()
        lease = self.lease(60, clock)
        auth = LeaseAuthority(self.paths, lease)
        auth.allow("app.open", "a")
        clock.advance(61)
        with self.assertRaises(AuthorizationDenied):
            auth.authorize("app.open", "a")
        self.assertNotIn(("lease:app.open", "granted"), self.audit())


# ---- what is out of date --------------------------------------------------------------------------

class TestRegistryRecord(Env):
    def test_a_record_made_before_this_existed_still_loads_and_is_never_swapped(self):
        self.install("old-rec")
        inst = self.record("old-rec")
        f = Registry(self.paths)._file(inst.id)
        d = json.loads(f.read_text())
        for k in ("sha256", "version", "attached"):
            d.pop(k)
        f.write_text(json.dumps(d))
        got = next(i for i in Registry(self.paths).list() if i.id == inst.id)
        self.assertEqual((got.sha256, got.version, got.attached), ("", "", False))
        r = self.row(got)
        self.assertEqual(r.state, UNKNOWN)
        self.assertIn("restart it once", r.why)

    def test_the_os_records_what_it_launched(self):
        self.install("rec-app", "1.4")
        inst = self.open("rec-app")
        self.assertEqual((inst.sha256, inst.version), (self.installed_sha("rec-app"), "1.4"))
        stored = Registry(self.paths).get(inst.id)
        self.assertEqual((stored.sha256, stored.version, stored.attached), (inst.sha256, "1.4", False))

    def test_the_broker_says_when_someone_attaches_and_when_they_leave(self):
        self.install("watched")
        inst = self.open("watched")
        reg = Registry(self.paths)
        self.assertFalse(reg.get(inst.id).attached)
        s = socket.socket(socket.AF_UNIX)
        s.connect(inst.sock_path)
        self.assertTrue(wait_for(lambda: reg.get(inst.id).attached, 10))
        self.assertEqual(self.row(inst).state, CURRENT)
        s.close()
        self.assertTrue(wait_for(lambda: not reg.get(inst.id).attached, 10))


class TestScan(Env):
    def test_a_running_copy_of_the_installed_file_is_current(self):
        self.install("calm")
        inst = self.record("calm", self.installed_sha("calm"), "1.0")
        self.assertEqual(self.row(inst).state, CURRENT)

    def test_an_updated_and_permitted_file_makes_the_running_copy_stale(self):
        self.install("aging")
        inst = self.record("aging", self.installed_sha("aging"), "1.0")
        self.update("aging", "1.1")
        r = self.row(inst)
        self.assertEqual((r.state, r.running, r.installed), (STALE, "1.0", "1.1"))

    def test_scanning_needs_no_password_and_changes_nothing(self):
        self.install("quiet")
        inst = self.record("quiet", self.installed_sha("quiet"), "1.0")
        self.update("quiet", "1.1")
        before = (AuditLog(self.paths).entries(), sorted(p.name for p in self.paths.apps.iterdir()))
        with mock.patch.object(Authority, "authorize", side_effect=AssertionError("asked for a password")):
            self.assertEqual(self.row(inst).state, STALE)
        self.assertEqual((AuditLog(self.paths).entries(), sorted(p.name for p in self.paths.apps.iterdir())), before)

    def test_a_new_file_the_owner_has_not_permitted_needs_the_owner(self):
        self.install("unpermitted")
        inst = self.record("unpermitted", self.installed_sha("unpermitted"), "1.0")
        self.update("unpermitted", "1.1", permit=False)
        r = self.row(inst)
        self.assertEqual(r.state, NEEDS_YOU)
        self.assertIn("kos permit unpermitted", r.why)

    def test_an_app_that_now_asks_for_the_network_needs_the_owner_even_if_it_was_permitted(self):
        self.install("greedy")
        inst = self.record("greedy", self.installed_sha("greedy"), "1.0")
        self.update("greedy", "1.1", perms=("network",))
        r = self.row(inst)
        self.assertEqual(r.state, NEEDS_YOU)
        self.assertIn("network", r.why)

    def test_an_app_that_now_asks_for_more_than_the_owner_approved_needs_the_owner(self):
        self.install("creeping")
        inst = self.record("creeping", self.installed_sha("creeping"), "1.0")
        self.update("creeping", "1.1", perms=("ask:kernel",), permit=False)
        PermitStore(self.paths).grant("creeping", [], pin=self.installed_sha("creeping"))   # pinned, but not approved
        r = self.row(inst)
        self.assertEqual(r.state, NEEDS_YOU)
        self.assertIn("never approved", r.why)

    def test_a_permitted_widening_the_running_copy_did_not_have_still_needs_the_owner(self):
        for perm, flag in (("system", "system"), ("admin", "admin"), ("ask:kernel", "asks")):
            name = "wider-" + perm.replace(":", "-")
            self.install(name)
            inst = self.record(name, self.installed_sha(name), "1.0")
            self.update(name, "1.1", perms=(perm,))
            r = self.row(inst)
            self.assertEqual(r.state, NEEDS_YOU, perm)
            self.assertTrue(r.why, perm)
            # the same widening is fine once the running copy already had it
            same = replace(inst, **({"system": True} if flag == "system" else {"admin": True} if flag == "admin"
                                    else {"asks": ["kernel"]}))
            Registry(self.paths).write(same)
            self.assertEqual(self.row(same).state, STALE, perm)

    def test_an_installed_version_older_than_the_running_one_is_never_swapped_in(self):
        self.install("rewound", "1.0")
        inst = self.record("rewound", "f" * 64, "2.0")
        r = self.row(inst)
        self.assertEqual(r.state, NEEDS_YOU)
        self.assertIn("older", r.why)

    def test_an_instance_someone_is_attached_to_waits(self):
        self.install("busy")
        inst = self.record("busy", self.installed_sha("busy"), "1.0", attached=True)
        self.update("busy", "1.1")
        r = self.row(inst)
        self.assertEqual(r.state, IN_USE)
        self.assertIn("leave it", r.why)

    def test_what_cannot_be_judged_is_reported_and_not_touched(self):
        self.install("blank")
        no_sha = self.record("blank", "", "1.0")
        self.assertEqual(self.row(no_sha).state, UNKNOWN)
        gone = self.record("removed-app", "a" * 64, "1.0")
        r = self.row(gone)
        self.assertEqual((r.state, r.why), (UNKNOWN, "it is no longer installed"))

    def test_only_running_instances_are_listed(self):
        self.install("starting")
        inst = self.record("starting", self.installed_sha("starting"), "1.0")
        Registry(self.paths).write(replace(inst, status="starting"))
        self.assertEqual([r for r in norestart.scan(self.paths) if r.id == inst.id], [])


# ---- a real swap ----------------------------------------------------------------------------------

class TestRefresh(Env):
    def stale_app(self, name="swapme", **update):
        self.install(name)
        old = self.open(name)
        self.update(name, "1.1", **update)
        return old

    def test_a_stale_app_is_replaced_by_the_new_file_and_the_old_copy_is_closed(self):
        old = self.stale_app()
        old_app_pid = Registry(self.paths).get(old.id).app_pid
        lease = self.lease()                                  # the one typed password, recorded as such
        first_audit = len(self.audit())
        res = norestart.refresh(self.paths, lease)
        self.assertEqual([(r.name, r.outcome, r.old, r.new) for r in res], [("swapme", SWAPPED, "1.0", "1.1")], res)
        now = self.running("swapme")
        self.assertEqual([(i.sha256, i.version) for i in now], [(self.installed_sha("swapme"), "1.1")])
        self.assertNotEqual(now[0].id, old.id)
        self.assertTrue(wait_for(lambda: not alive(old.broker_pid) and not alive(old_app_pid), 15))
        self.assertTrue(alive(now[0].broker_pid))
        self.assertEqual(self.row(now[0]).state, CURRENT)
        trail = self.audit()[first_audit:]
        for item in (("lease:app.open", "granted"), ("lease:app.close", "granted"),
                     ("lease:norestart.swap", "granted"), ("layer.kernel.open", "pass"), ("layer.kernel.close", "pass")):
            self.assertIn(item, trail)
        # not one line in the unattended part says a password was typed for an ordinary action
        self.assertFalse([a for a, o in trail if o == "granted" and not a.startswith("lease:")])
        with self.authority(PW).authorize("audit.verify") as g:
            rep = AuditLog(self.paths).verify(g.key(AUDIT_KEY_LABEL))
        self.assertTrue(rep.ok, rep.problem)

    def test_a_second_pass_finds_nothing_left_to_swap(self):
        self.stale_app()
        lease = self.lease()
        self.assertEqual([r.outcome for r in norestart.refresh(self.paths, lease)], [SWAPPED])
        self.assertEqual(norestart.refresh(self.paths, lease), [])

    def test_the_old_copy_is_left_running_when_the_new_one_cannot_start(self):
        old = self.stale_app()

        def boom(*a, **k):
            raise OSError("no room to start")
        res = norestart.refresh(self.paths, self.lease(), spawner=boom)
        self.assertEqual([r.outcome for r in res], [KEPT])
        self.assertIn("no room to start", res[0].why)
        self.assertEqual([i.id for i in self.running("swapme")], [old.id])
        self.assertTrue(alive(old.broker_pid))
        self.assertTrue([1 for a, o in self.audit() if a == "lease:norestart.swap" and o.startswith("kept")])
        self.assertNotIn(("lease:norestart.swap", "granted"), self.audit())

    def test_a_copy_that_is_not_the_installed_file_is_closed_and_the_old_copy_is_left(self):
        old = self.stale_app()

        def lying(inst, app, mode, policy, registry, log_path, cache_dir=None):
            inst.sha256 = "0" * 64
            return spawn(inst, app, mode, policy, registry, log_path, cache_dir)
        res = norestart.refresh(self.paths, self.lease(), spawner=lying)
        self.assertEqual([r.outcome for r in res], [KEPT])
        self.assertIn("not the installed file", res[0].why)
        self.assertTrue(wait_for(lambda: [i.id for i in self.running("swapme")] == [old.id], 15), self.running("swapme"))
        self.assertTrue(alive(old.broker_pid))

    def test_an_instance_someone_attached_to_is_not_touched(self):
        old = self.stale_app()
        reg = Registry(self.paths)
        reg.write(replace(reg.get(old.id), attached=True))
        self.assertEqual(norestart.refresh(self.paths, self.lease()), [])
        self.assertEqual([i.id for i in self.running("swapme")], [old.id])
        reg.write(replace(reg.get(old.id), attached=False))      # they leave: now it can be swapped
        self.assertEqual([r.outcome for r in norestart.refresh(self.paths, self.lease())], [SWAPPED])

    def test_someone_attaching_between_the_check_and_the_swap_is_left_on_the_old_copy(self):
        old = self.stale_app()
        reg = Registry(self.paths)

        def attach_then_start(inst, app, mode, policy, registry, log_path, cache_dir=None):
            spawn(inst, app, mode, policy, registry, log_path, cache_dir)
            reg.write(replace(reg.get(old.id), attached=True))          # they attach while the new copy starts
        res = norestart.refresh(self.paths, self.lease(), spawner=attach_then_start)
        self.assertEqual([r.outcome for r in res], [KEPT])
        self.assertIn("attached", res[0].why)
        self.assertTrue(wait_for(lambda: [i.id for i in self.running("swapme")] == [old.id], 15), self.running("swapme"))

    def test_an_app_that_now_wants_the_network_is_not_swapped_and_nobody_is_asked(self):
        old = self.stale_app("netty", perms=("network",))
        lease = self.lease()
        self.assertEqual(norestart.scan(self.paths)[0].state, NEEDS_YOU)
        self.assertEqual(norestart.refresh(self.paths, lease), [])
        self.assertEqual([i.id for i in self.running("netty")], [old.id])
        self.assertNotIn("lease:app.open", [a for a, o in self.audit()])

    def test_a_new_file_the_owner_has_not_permitted_is_not_swapped(self):
        old = self.stale_app("unsure", permit=False)
        self.assertEqual(norestart.refresh(self.paths, self.lease()), [])
        self.assertEqual([i.id for i in self.running("unsure")], [old.id])

    def test_a_file_swapped_in_without_the_password_fails_the_seal_and_the_old_copy_stays(self):
        old = self.stale_app()
        d = self.root / "src" / "attacker"
        d.mkdir()
        (d / "app.py").write_text(APP_SRC + "\n# not what the owner installed\n")
        (d / "manifest.json").write_text(json.dumps({"name": "swapme", "version": "1.1", "runtime": "python",
                                                    "entry": "app:main", "modes": ["tui"], "permissions": [],
                                                    "description": "a test app"}))
        evil = self.root / "evil.kapp"
        pack(d, evil)
        shutil.copy(evil, self.paths.apps / "swapme.kapp")          # whoever can write the file cannot write the seal
        self.assertEqual(norestart.scan(self.paths)[0].state, STALE)    # it looks stale from the seal file alone
        res = norestart.refresh(self.paths, self.lease())
        self.assertEqual([r.outcome for r in res], [KEPT])
        self.assertIn("seal check FAILED", res[0].why)
        self.assertEqual([i.id for i in self.running("swapme")], [old.id])

    def test_a_lease_made_from_the_wrong_password_cannot_launch_anything(self):
        old = self.stale_app()
        wrong = Lease({label: SecretBytes(os.urandom(32)) for label in norestart.LEASE_LABELS}, 60)
        self.addCleanup(wrong.wipe)
        res = norestart.refresh(self.paths, wrong)
        self.assertEqual([r.outcome for r in res], [KEPT])
        self.assertIn("seal check FAILED", res[0].why)
        self.assertEqual([i.id for i in self.running("swapme")], [old.id])

    def test_an_ended_lease_swaps_nothing(self):
        old = self.stale_app()
        clock = FakeClock()
        lease = self.lease(30, clock)
        clock.advance(31)
        res = norestart.refresh(self.paths, lease)
        self.assertEqual([r.outcome for r in res], [KEPT])
        self.assertIn("lease has ended", res[0].why)
        self.assertEqual([i.id for i in self.running("swapme")], [old.id])

    def test_only_the_named_app_is_swapped(self):
        a, b = self.stale_app("alpha"), self.stale_app("beta")
        res = norestart.refresh(self.paths, self.lease(), only="alpha")
        self.assertEqual([(r.name, r.outcome) for r in res], [("alpha", SWAPPED)])
        self.assertNotEqual([i.id for i in self.running("alpha")], [a.id])
        self.assertEqual([i.id for i in self.running("beta")], [b.id])

    def test_the_unattended_code_never_reaches_the_real_authority(self):
        src = (ROOT / "kos" / "norestart.py").read_text()
        self.assertEqual([l for l in src.splitlines() if ".authorize(" in l and "def authorize" not in l
                          and not l.lstrip().startswith(("#", '"', "'"))], [])
        plain = src.replace("LeaseAuthority", "")
        for forbidden in ("from .prompt", "import prompt", "Authority(", "PasswordStore", "derive_master"):
            self.assertNotIn(forbidden, plain, forbidden)


# ---- the watcher ----------------------------------------------------------------------------------

class TestWatchLoop(Env):
    def run_watch(self, lease, **kw):
        t = {"slept": 0}

        def sleep(n):
            t["slept"] += n
            if isinstance(lease._clock, FakeClock):
                lease._clock.advance(n)
        return norestart.watch(self.paths, lease, sleep=sleep, **kw), t

    def test_it_ends_when_the_lease_runs_out_and_wipes_everything(self):
        clock = FakeClock()
        lease = self.lease(5, clock)
        why, t = self.run_watch(lease, interval=2)
        self.assertEqual(why, "the lease ran out")
        self.assertFalse(lease.alive)
        self.assertEqual(lease._keys, {})
        self.assertIsNone(norestart.watcher_state(self.paths))
        self.assertFalse((self.paths.state / "norestart" / "watcher.json").exists())
        self.assertEqual(self.audit()[-1], ("lease:norestart.watch", "ended: the lease ran out"))

    def test_it_ends_when_told_to_and_wipes(self):
        lease = self.lease(300)
        flag = {"n": 0}

        def stopped():
            flag["n"] += 1
            return flag["n"] > 3
        why, _ = self.run_watch(lease, interval=1, stopped=stopped)
        self.assertEqual(why, "stopped")
        self.assertEqual(lease._keys, {})

    def test_it_stops_itself_rather_than_start_programs_with_old_os_code(self):
        lease = self.lease(300)
        stamps = iter(["a", "a", "b", "b", "b"])
        why, _ = self.run_watch(lease, interval=1, stamp=lambda: next(stamps))
        self.assertIn("OS's own code changed", why)
        self.assertEqual(lease._keys, {})

    def test_it_ends_after_the_rounds_asked_for(self):
        why, _ = self.run_watch(self.lease(300), interval=1, rounds=2)
        self.assertEqual(why, "finished")

    def test_it_swaps_stale_apps_by_itself(self):
        self.install("auto-app")
        old = self.open("auto-app")
        self.update("auto-app", "1.1")
        lease = self.lease(300)
        seen = []
        real = norestart.refresh

        def recording(*a, **k):
            seen.append(real(*a, **k))
            return seen[-1]
        with mock.patch.object(norestart, "refresh", recording):
            why, _ = self.run_watch(lease, interval=1, rounds=1)
        self.assertEqual(why, "finished")
        self.assertEqual([i.version for i in self.running("auto-app")], ["1.1"], f"results: {seen}")
        self.assertNotIn(old.id, [i.id for i in self.running("auto-app")])

    def test_a_swap_that_failed_is_not_tried_again_for_the_same_file(self):
        self.install("stuck")
        self.open("stuck")
        self.update("stuck", "1.1")
        calls = []

        def boom(*a, **k):
            calls.append(1)
            raise OSError("cannot start")
        seen = {}

        def sleep(n):
            raw = (self.paths.state / "norestart" / "watcher.json").read_bytes()
            seen["state"] = json.loads(raw)
            seen["raw"] = raw
        lease = self.lease(300)
        hexes = [h.encode() for h in lease.hex_keys().values()]
        why = norestart.watch(self.paths, lease, interval=1, sleep=sleep, rounds=3, spawner=boom)
        self.assertEqual(why, "finished")
        self.assertEqual(len(calls), 1)
        self.assertEqual((seen["state"]["kept"], seen["state"]["swapped"]), (1, 0))
        for h in hexes:
            self.assertNotIn(h, seen["raw"])                     # the public state holds no key
        self.assertEqual(sorted(seen["state"]), ["kept", "last", "pid", "started", "swapped", "until"])


class TestWatcherProcess(Env):
    def test_a_real_watcher_swaps_by_itself_holds_no_key_on_disk_and_ends_clean(self):
        self.install("live")
        old = self.open("live")
        lease = self.lease(600)
        secrets_ = [lease.key(l) for l in norestart.LEASE_LABELS]
        pid = norestart.start_watcher(self.paths, lease, 600, interval=1)
        lease.wipe()                                          # the caller's copy goes at once
        self.assertEqual(norestart.watcher_state(self.paths)["pid"], pid)
        self.assertTrue(norestart._is_watcher(pid))
        self.assertNotEqual(pid, os.getpid())
        self.update("live", "1.1")
        self.assertTrue(wait_for(lambda: [i.version for i in self.running("live")] == ["1.1"], 40),
                        [(i.id, i.version) for i in Registry(self.paths).list()])
        now = self.running("live")[0]
        self.assertNotEqual(now.id, old.id)
        self.assertTrue(wait_for(lambda: not alive(old.broker_pid), 15))
        self.assertTrue(wait_for(lambda: (norestart.watcher_state(self.paths) or {}).get("swapped") == 1, 15))
        # the keys are nowhere on disk: not in the state, the registry, the audit log, nor any file
        for p in self.root.rglob("*"):
            if p.is_file() and not p.is_symlink():
                data = p.read_bytes()
                for k in secrets_:
                    self.assertNotIn(k, data, str(p))
                    self.assertNotIn(k.hex().encode(), data, str(p))
        self.assertTrue(norestart.stop_watcher(self.paths))
        self.assertIsNone(norestart.watcher_state(self.paths))
        self.assertTrue(wait_for(lambda: not alive(pid), 10))
        self.assertTrue(alive(now.broker_pid))                # stopping it does not close what it started
        self.assertIn(("lease:norestart.watch", "ended: stopped"), self.audit())

    def test_the_key_scan_can_see_a_key_in_a_process_and_a_broker_it_started_holds_none(self):
        """A positive control first: the scan finds the key in the watcher. Then the broker the watcher forked."""
        self.install("scanned")
        self.open("scanned")
        lease = self.lease(600)
        seal = lease.key(SEAL_KEY_LABEL)
        pid = norestart.start_watcher(self.paths, lease, 600, interval=1)
        lease.wipe()

        def in_memory(target):
            hits = 0
            try:
                maps = Path(f"/proc/{target}/maps").read_text().splitlines()
                with open(f"/proc/{target}/mem", "rb", 0) as mem:
                    for line in maps:
                        rng, perms = line.split()[:2]
                        if "r" not in perms or "w" not in perms:
                            continue
                        lo, hi = (int(x, 16) for x in rng.split("-"))
                        try:
                            mem.seek(lo)
                            chunk = mem.read(hi - lo)
                        except (OSError, ValueError, OverflowError):
                            continue
                        hits += chunk.count(seal)
            except (OSError, PermissionError):
                return None
            return hits
        found = in_memory(pid)
        if found is None:
            self.skipTest("this process may not read another process's memory here")
        self.assertGreaterEqual(found, 1, "the scan cannot see the key in the watcher: it proves nothing")
        self.update("scanned", "1.1")
        self.assertTrue(wait_for(lambda: [i.version for i in self.running("scanned")] == ["1.1"], 40))
        broker = self.running("scanned")[0].broker_pid
        self.assertNotEqual(broker, pid)
        live_copies = in_memory(broker)
        # the buffers the lease owns are wiped in the child; Python's own transient copies of immutable bytes it
        # made while using the key are not ours to zero (kos/secret.py says the same), so count, don't pretend
        self.assertIsNotNone(live_copies)
        print(f"\n  key copies found in the watcher: {found}; in the broker it started: {live_copies}")


# ---- the reasons a reboot is real -------------------------------------------------------------------

class TestReboot(Env):
    def root_with(self, *files):
        r = Path(tempfile.mkdtemp(dir=self.root))
        for f in files:
            p = r / f
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("")
        return r

    def test_a_newer_installed_kernel_is_a_real_reason(self):
        r = self.root_with("boot/vmlinuz-6.12.117-kos", "boot/vmlinuz-6.12.116-kos")
        why = norestart.pending_kernel(r, "6.12.116-kos")
        self.assertIn("6.12.117-kos", why)
        self.assertIn("only at boot", why)

    def test_an_equal_older_or_unreadable_kernel_is_not_a_reason(self):
        r = self.root_with("boot/vmlinuz-6.12.116-kos", "boot/vmlinuz-6.1.0", "lib/modules/6.12.116-kos",
                           "boot/vmlinuz-rescue", "lib/modules/readme")
        self.assertEqual(norestart.pending_kernel(r, "6.12.116-kos"), "")
        self.assertEqual(norestart.pending_kernel(r, ""), "")
        self.assertEqual(norestart.pending_kernel(r, "weird"), "")
        self.assertEqual(norestart.pending_kernel(self.root_with(), "6.12.116"), "")

    def test_modules_for_a_newer_kernel_count_too_and_numbers_compare_as_numbers(self):
        r = self.root_with("lib/modules/6.13.0")
        self.assertIn("6.13.0", norestart.pending_kernel(r, "6.12.116"))
        r2 = self.root_with("boot/vmlinuz-6.9.0")
        self.assertEqual(norestart.pending_kernel(r2, "6.12.116"), "")      # 6.9 < 6.12, not "6.9" > "6.12"

    def test_a_note_is_kept_for_this_boot_and_dropped_after_a_reboot(self):
        norestart.note_reboot_needed(self.paths, "the firmware of spi-flash:bios was rewritten")
        self.assertEqual(norestart.reboot_reasons(self.paths, running=""), ["the firmware of spi-flash:bios was rewritten"])
        f = self.paths.state / "norestart" / "reboot-needed.json"
        notes = json.loads(f.read_text())
        notes.append({"why": "from an earlier boot", "boot": "some-other-boot-id"})
        f.write_text(json.dumps(notes))
        self.assertEqual(norestart.reboot_reasons(self.paths, running=""), ["the firmware of spi-flash:bios was rewritten"])
        f.write_text("not json")
        self.assertEqual(norestart.reboot_reasons(self.paths, running=""), [])

    def test_a_note_is_plain_text_and_bounded(self):
        norestart.note_reboot_needed(self.paths, "bad\x1b[31m\nreason" + "x" * 500)
        (why,) = norestart.reboot_reasons(self.paths, running="")
        self.assertLessEqual(len(why), 200)
        self.assertFalse([c for c in why if ord(c) < 32 or ord(c) > 126])
        self.assertEqual(oct((self.paths.state / "norestart").stat().st_mode & 0o777), "0o700")

    def test_a_dropped_in_note_cannot_inject_other_shapes(self):
        f = self.paths.state / "norestart" / "reboot-needed.json"
        f.parent.mkdir(parents=True)
        here = norestart._boot_id()
        f.write_text(json.dumps([{"why": 5, "boot": here}, "x", {"boot": here}, {"why": "ok", "boot": here}, None]))
        self.assertEqual(norestart.reboot_reasons(self.paths, running=""), ["ok"])
        f.write_text(json.dumps({"why": "ok", "boot": here}))
        self.assertEqual(norestart.reboot_reasons(self.paths, running=""), [])

    def test_a_stale_app_alone_is_not_a_reason_to_reboot(self):
        self.install("only-apps")
        inst = self.record("only-apps", self.installed_sha("only-apps"), "1.0")
        self.update("only-apps", "1.1")
        rep = norestart.report(self.paths, running="", root=self.root_with())
        self.assertFalse(rep.reboot_needed)
        self.assertEqual([r.state for r in rep.apps if r.id == inst.id], [STALE])

    def test_a_new_kernel_is_a_reason_and_apps_still_do_not_hide_it(self):
        rep = norestart.report(self.paths, running="6.12.116-kos", root=self.root_with("boot/vmlinuz-6.12.200"))
        self.assertTrue(rep.reboot_needed)
        self.assertIn("6.12.200", rep.reboot[0])

    def test_apps_started_before_the_os_code_changed_are_advice_not_a_swap(self):
        self.install("before")
        old = self.record("before", self.installed_sha("before"), "1.0")
        Registry(self.paths).write(replace(old, started=1))
        reasons = norestart.session_reasons(self.paths)
        self.assertEqual(len(reasons), 1)
        self.assertIn("before", reasons[0])
        self.assertIn("not the machine", reasons[0])
        Registry(self.paths).write(replace(old, started=4_000_000_000))
        self.assertEqual(norestart.session_reasons(self.paths), [])
        self.assertEqual(self.row(old).state, CURRENT)                       # advice only: nothing is stale for it

    def test_the_code_stamp_changes_when_an_os_file_changes(self):
        a = norestart.code_stamp()
        self.assertEqual(a, norestart.code_stamp())
        with tempfile.TemporaryDirectory() as t:
            pkg = Path(t) / "kos"
            pkg.mkdir()
            (pkg / "a.py").write_text("x = 1\n")
            with mock.patch.object(norestart, "PKG", pkg):
                one = norestart.code_stamp()
                (pkg / "a.py").write_text("x = 22\n")
                self.assertNotEqual(one, norestart.code_stamp())


# ---- the door ---------------------------------------------------------------------------------------

def call(host, authority, name, **args):
    return host.call({"cmd": "service", "id": 7, "name": name, "args": args}, authority)


class TestServices(Env):
    def host(self, groups=("norestart",)):
        return ServiceHost(self.paths, "norestart", frozenset(groups))

    def test_every_service_has_a_spec_a_handler_and_an_action_that_exists(self):
        names = ["norestart.status", "norestart.refresh", "norestart.auto", "norestart.stop"]
        for n in names:
            self.assertIn(n, servicespec.SPECS)
            self.assertIn(n, HANDLERS)
            self.assertEqual(servicespec.SPECS[n].group, "norestart")
        for a in ("norestart.read", "norestart.refresh", "norestart.auto", "norestart.stop"):
            self.assertIn(a, ACTIONS)
        self.assertIn("norestart", servicespec.GROUPS)

    def test_an_app_that_did_not_ask_for_the_group_is_refused_before_anything_happens(self):
        for name in ("norestart.status", "norestart.refresh", "norestart.auto", "norestart.stop"):
            r = call(self.host(("compute",)), self.authority(), name)       # no answers: any prompt would raise
            self.assertFalse(r["ok"], name)
            self.assertIn("service:norestart", r["detail"])

    def test_hostile_arguments_are_refused_before_a_password_is_asked(self):
        h = self.host()
        for name, args in (("norestart.auto", {"hours": 0}), ("norestart.auto", {"hours": 25}),
                           ("norestart.auto", {"hours": True}), ("norestart.auto", {"hours": "8"}),
                           ("norestart.auto", {"hours": 8, "extra": 1}), ("norestart.refresh", {"app": "../x"}),
                           ("norestart.refresh", {"app": "A"}), ("norestart.refresh", {"app": 5}),
                           ("norestart.refresh", {"all": True}), ("norestart.status", {"app": "x"}),
                           ("norestart.stop", {"now": 1})):
            r = call(h, self.authority(), name, **args)
            self.assertFalse(r["ok"], (name, args))
            self.assertEqual(r["data"], {})

    def test_what_the_protocol_hands_the_host_survives_the_hosts_second_check(self):
        """The real path: the protocol checks and fills in defaults, then the host checks that again. A default
        that fails the check the second time (an empty name) would refuse the call every time in production."""
        from kos.protocol import validate_app_message
        self.install("via-protocol")
        old = self.open("via-protocol")
        self.update("via-protocol", "1.1")
        for args in ({}, {"app": None}, {"app": "via-protocol"}):
            normalised = validate_app_message({"cmd": "service", "id": 3, "name": "norestart.refresh", "args": args}, "tui")
            self.assertEqual(servicespec.SPECS["norestart.refresh"].check(normalised.get("args", {})),
                             servicespec.SPECS["norestart.refresh"].check(args))
        normalised = validate_app_message({"cmd": "service", "id": 3, "name": "norestart.refresh", "args": {}}, "tui")
        r = self.host().call(normalised, self.authority(PW))
        self.assertTrue(r["ok"], r)
        self.assertEqual([(x["name"], x["outcome"]) for x in r["data"]["results"]], [("via-protocol", SWAPPED)])
        self.assertNotIn(old.id, [i.id for i in self.running("via-protocol")])
        for name, args in (("norestart.status", {}), ("norestart.stop", {}), ("norestart.auto", {})):
            n = validate_app_message({"cmd": "service", "id": 4, "name": name, "args": args}, "tui")
            servicespec.SPECS[name].check(n.get("args", {}))

    def test_the_defaults_are_the_cautious_ones(self):
        self.assertEqual(servicespec.SPECS["norestart.auto"].check({}), {"hours": 8})
        self.assertEqual(servicespec.SPECS["norestart.refresh"].check({}), {"app": None})

    def test_status_asks_for_the_password_and_a_wrong_one_gives_no_data(self):
        r = call(self.host(), self.authority("wrong", "wrong", "wrong"), "norestart.status")
        self.assertFalse(r["ok"])
        self.assertEqual(r["data"], {})
        self.assertIn("not authorized", r["detail"])
        r = call(self.host(), self.authority(None), "norestart.status")
        self.assertFalse(r["ok"])
        self.assertIn("cancelled", r["detail"])

    def test_status_says_what_is_stale_and_that_no_reboot_is_needed(self):
        self.install("shown")
        self.record("shown", self.installed_sha("shown"), "1.0")
        self.update("shown", "1.1")
        r = call(self.host(), self.authority(PW), "norestart.status")
        self.assertTrue(r["ok"], r)
        d = r["data"]
        self.assertEqual(sorted(d), ["apps", "auto", "reboot", "reboot_needed", "session"])
        self.assertIsNone(d["auto"])
        row = next(a for a in d["apps"] if a["name"] == "shown")
        self.assertEqual((row["state"], row["running"], row["installed"]), (STALE, "1.0", "1.1"))
        self.assertIn(("norestart.read", "granted"), self.audit())

    def test_refresh_swaps_after_the_password_and_a_cancelled_prompt_swaps_nothing(self):
        self.install("svc-swap")
        old = self.open("svc-swap")
        self.update("svc-swap", "1.1")
        r = call(self.host(), self.authority(None), "norestart.refresh", app="svc-swap")
        self.assertFalse(r["ok"])
        self.assertEqual([i.id for i in self.running("svc-swap")], [old.id])
        r = call(self.host(), self.authority(PW), "norestart.refresh", app="svc-swap")
        self.assertTrue(r["ok"], r)
        self.assertEqual([(x["name"], x["outcome"], x["from"], x["to"]) for x in r["data"]["results"]],
                         [("svc-swap", SWAPPED, "1.0", "1.1")])
        self.assertEqual([i.version for i in self.running("svc-swap")], ["1.1"])
        self.assertIn(("norestart.refresh", "granted"), self.audit())

    def test_refresh_with_nothing_stale_says_so_and_still_needs_the_password(self):
        a = self.authority(PW)
        r = call(self.host(), a, "norestart.refresh")
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["results"], [])
        self.assertEqual(len(a.prompter.asked), 1)

    def test_auto_already_on_is_said_before_the_password_is_asked(self):
        state = {"pid": os.getpid(), "started": 1, "until": 2, "swapped": 0, "kept": 0, "last": []}
        f = self.paths.state / "norestart" / "watcher.json"
        f.parent.mkdir(parents=True)
        f.write_text(json.dumps(state))
        with mock.patch.object(norestart, "_is_watcher", return_value=True):
            r = call(self.host(), self.authority(), "norestart.auto", hours=2)     # no answers: a prompt would raise
        self.assertFalse(r["ok"])
        self.assertIn("already on", r["detail"])

    def test_auto_and_stop_run_a_real_watcher_with_the_password_typed_once_each(self):
        self.install("by-service")
        old = self.open("by-service")
        a = self.authority(PW)
        r = call(self.host(), a, "norestart.auto", hours=1)
        self.assertTrue(r["ok"], r)
        self.assertEqual(len(a.prompter.asked), 1)
        self.assertIn("swap out-of-date apps by itself", a.prompter.asked[0])     # the OS's own prompt says what it is for
        self.assertEqual(norestart.watcher_state(self.paths)["pid"], r["data"]["pid"])
        self.assertIn(("norestart.auto", "granted"), self.audit())
        r2 = call(self.host(), self.authority(), "norestart.auto", hours=1)         # a second start: no prompt, refused
        self.assertFalse(r2["ok"])
        r = call(self.host(), self.authority(PW), "norestart.status")
        self.assertEqual(r["data"]["auto"]["pid"], norestart.watcher_state(self.paths)["pid"])
        self.assertLessEqual(r["data"]["auto"]["minutes_left"], 60)
        self.assertGreaterEqual(r["data"]["auto"]["minutes_left"], 58)
        r = call(self.host(), self.authority(PW), "norestart.stop")
        self.assertEqual((r["ok"], r["data"]), (True, {"stopped": True}))
        self.assertIsNone(norestart.watcher_state(self.paths))
        r = call(self.host(), self.authority(PW), "norestart.stop")
        self.assertEqual((r["ok"], r["data"]), (True, {"stopped": False}))
        self.assertEqual([i.id for i in self.running("by-service")], [old.id])

    def test_a_pid_in_a_dropped_in_state_file_that_is_not_a_watcher_is_never_signalled(self):
        victim = subprocess.Popen(["sleep", "30"])
        self.addCleanup(victim.kill)
        f = self.paths.state / "norestart" / "watcher.json"
        f.parent.mkdir(parents=True)
        f.write_text(json.dumps({"pid": victim.pid, "started": 1, "until": 2, "swapped": 0, "kept": 0, "last": []}))
        self.assertIsNone(norestart.watcher_state(self.paths))
        self.assertFalse(norestart.stop_watcher(self.paths))
        self.assertIsNone(victim.poll())
        for junk in ("[]", '{"pid": "5"}', '{"pid": -1}', '{"pid": 0}', "nope", '{"pid": true}'):
            f.write_text(junk)
            self.assertIsNone(norestart.watcher_state(self.paths), junk)


# ---- the app ----------------------------------------------------------------------------------------

class FakeApp:
    def __init__(self, events, replies=None):
        self._events, self.replies = events, replies or {}
        self.width, self.height = 80, 24
        self.screens, self.calls, self.exited = [], [], None

    def events(self):
        yield from self._events

    def screen(self, title, lines, status=""):
        self.screens.append((title, list(lines), status))

    def service(self, name, /, **args):
        self.calls.append((name, args))
        r = self.replies.get(name, {"ok": True, "detail": "", "data": {}})
        return r(args) if callable(r) else r

    def exit(self, code=0):
        self.exited = code

    @property
    def last(self):
        return "\n".join(self.screens[-1][1])


def run_app(keys, replies=None):
    fake = FakeApp([{"cmd": "hello", "mode": "tui", "width": 80, "height": 24},
                    *[{"cmd": "key", "key": k} for k in keys]], replies)
    with mock.patch.object(sdk, "App", lambda *a, **k: fake):
        spec = importlib.util.spec_from_file_location("norestart_app_under_test", APP / "app.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.main()
    return fake


STATUS = {"ok": True, "detail": "", "data": {
    "reboot_needed": False, "reboot": [], "session": ["2 open app(s) started before the OS's own code changed (a, b): "
                                                      "restart the desktop (not the machine) to run the new OS code"],
    "apps": [{"id": "a-1", "name": "a", "mode": "tui", "running": "1.0", "installed": "1.0", "state": "current", "why": ""},
             {"id": "b-1", "name": "web", "mode": "tui", "running": "1.0", "installed": "1.1", "state": "stale",
              "why": "a newer file is installed"},
             {"id": "c-1", "name": "shop", "mode": "tui", "running": "2.0", "installed": "2.1", "state": "needs-you",
              "why": "it asks for network access, which only you can allow"}],
    "auto": {"pid": 5, "started": 1, "until": 9, "swapped": 3, "kept": 1, "last": [], "minutes_left": 42}}}


class TestTheApp(unittest.TestCase):
    def test_it_packs_through_the_proof_gate_and_asks_for_one_service_group_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = pack(APP, Path(tmp) / "n.kapp")
            self.assertEqual(m.name, "norestart")
            self.assertIn("proof.json", KApp.from_file(Path(tmp) / "n.kapp").names())
        self.assertEqual(list(Manifest.parse((APP / "manifest.json").read_bytes()).permissions), ["service:norestart"])

    def test_it_asks_the_os_nothing_until_the_owner_presses_a_key(self):
        f = run_app(["+", "-", "q", "z"])
        self.assertEqual(f.calls, [])
        self.assertIn("Press s", f.last)

    def test_s_asks_for_status_and_shows_it_plainly(self):
        f = run_app(["s"], {"norestart.status": STATUS})
        self.assertEqual(f.calls, [("norestart.status", {})])
        out = f.last
        self.assertIn("No reboot is needed.", out)
        self.assertIn("3 open app(s): 1 up to date.", out)
        self.assertIn("web  1.0 -> 1.1  stale", out)
        self.assertIn("shop  2.0 -> 2.1  needs-you", out)
        self.assertIn("only you can allow", out)
        self.assertIn("not the machine", out)
        self.assertIn("ON: 42 minute(s) left, 3 swapped, 1 left alone", out)

    def test_a_reboot_that_is_really_needed_is_said_first_and_not_hidden(self):
        data = {**STATUS["data"], "reboot_needed": True, "reboot": ["kernel 6.12.116 is running and 6.12.200 is installed"]}
        f = run_app(["s"], {"norestart.status": {"ok": True, "detail": "", "data": data}})
        self.assertIn("A reboot IS needed:", f.last)
        self.assertIn("6.12.200", f.last)
        self.assertNotIn("No reboot is needed", f.last)

    def test_r_swaps_and_sends_only_the_arguments_the_spec_takes(self):
        reply = {"ok": True, "detail": "", "data": {
            "results": [{"name": "web", "from": "1.0", "to": "1.1", "outcome": "swapped", "why": "now running web-1"}],
            "apps": STATUS["data"]["apps"]}}
        f = run_app(["r"], {"norestart.refresh": reply})
        self.assertEqual(f.calls, [("norestart.refresh", {})])
        self.assertEqual(servicespec.SPECS["norestart.refresh"].check(f.calls[0][1]), {"app": None})   # the OS reads "all"
        self.assertIn("SWAPPED  web  1.0 -> 1.1", f.last)
        self.assertIn("shop is needs-you", f.last)
        empty = run_app(["r"], {"norestart.refresh": {"ok": True, "detail": "", "data": {"results": [], "apps": []}}})
        self.assertIn("Nothing to swap", empty.last)

    def test_a_chooses_hours_within_one_to_twenty_four_and_says_the_password_is_not_kept(self):
        reply = {"ok": True, "detail": "", "data": {"pid": 5, "hours": 11, "until": 9}}
        f = run_app(["+", "+", "+", "a"], {"norestart.auto": reply})
        self.assertEqual(f.calls, [("norestart.auto", {"hours": 11})])
        servicespec.SPECS["norestart.auto"].check(f.calls[0][1])
        self.assertIn("not kept", f.last)
        self.assertIn("wiped when the time is up", f.last)
        f = run_app(["-"] * 20 + ["a"], {"norestart.auto": reply})
        self.assertEqual(f.calls[0][1], {"hours": 1})
        f = run_app(["+"] * 40 + ["a"], {"norestart.auto": reply})
        self.assertEqual(f.calls[0][1], {"hours": 24})
        f = run_app(["a"], {"norestart.auto": reply})
        self.assertEqual(f.calls[0][1], {"hours": 8})

    def test_x_stops_it_and_says_whether_anything_was_running(self):
        f = run_app(["x"], {"norestart.stop": {"ok": True, "detail": "", "data": {"stopped": True}}})
        self.assertEqual(f.calls, [("norestart.stop", {})])
        self.assertIn("stopped", f.last)
        f = run_app(["x"], {"norestart.stop": {"ok": True, "detail": "", "data": {"stopped": False}}})
        self.assertIn("was not running", f.last)

    def test_a_refusal_is_shown_as_a_refusal_and_nothing_is_claimed_changed(self):
        f = run_app(["r"], {"norestart.refresh": {"ok": False, "detail": "cancelled", "data": {}}})
        self.assertIn("Refused: cancelled", f.last)
        self.assertIn("Nothing was changed", f.last)
        self.assertNotIn("SWAPPED", f.last)

    def test_an_answer_of_the_wrong_shape_does_not_crash_it(self):
        for name, key in (("norestart.status", "s"), ("norestart.refresh", "r")):
            for bad in ({"ok": True, "data": {"apps": 5}}, {"ok": True, "data": {"results": [5]}},
                        {"ok": True, "data": {"apps": [None]}}):
                f = run_app([key], {name: bad})
                self.assertTrue(f.screens)

    def test_escape_leaves_and_nothing_after_it_runs(self):
        f = run_app(["escape", "s"], {"norestart.status": STATUS})
        self.assertEqual(f.exited, 0)
        self.assertEqual(f.calls, [])


# ---- the rules ---------------------------------------------------------------------------------------

class TestRules(unittest.TestCase):
    def test_the_new_code_has_no_decimals_by_either_checker(self):
        from kos import proof
        for p in (ROOT / "kos" / "norestart.py", APP / "app.py"):
            self.assertEqual(rulecheck.scan_file(p), [], p.name)
            self.assertEqual(proof.decimal_uses(p.read_bytes()), 0, p.name)    # the ratchet counts every "/" too

    def test_the_app_imports_only_the_sdk_and_uses_no_clock(self):
        import ast
        tree = ast.parse((APP / "app.py").read_text())
        mods = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)] + \
               [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        self.assertEqual(mods, ["kos.sdk"])

    def test_the_unattended_swap_goes_through_the_one_door(self):
        src = (ROOT / "kos" / "norestart.py").read_text()
        self.assertIn("open_background(", src)
        self.assertIn("close_instance(", src)
        for banned in ("loader.launch", "sandbox.", "SandboxPolicy(", "compute_seal", "load_verified", "_read_sealed"):
            self.assertNotIn(banned, src, banned)       # no second way to start an app, and no way to make a seal

    def test_the_firmware_flasher_leaves_a_reboot_note(self):
        src = (ROOT / "kos" / "fwflash.py").read_text()
        self.assertIn("note_reboot_needed", src)


if __name__ == "__main__":
    unittest.main()
