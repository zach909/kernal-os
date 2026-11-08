"""Apps made of programs: ``apps/backup/list`` is the program ``backup.list``.

Run with: python3 -m unittest discover -s tests -v
"""

import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from kos import cli as kcli  # noqa: E402
from kos import loader  # noqa: E402
from kos.sandbox import SandboxPolicy  # noqa: E402
from kos import layers as klayers  # noqa: E402
from kos.address import AddressError, parse as parse_address  # noqa: E402
from kos.appdirs import AppDirs  # noqa: E402
from kos.auth import AuditLog, Authority, KdfParams, PasswordStore, Throttle  # noqa: E402
from kos.kapp import (ASK_ACTIONS, ID_RE, MAX_DEPTH, KApp, KAppError, Manifest,  # noqa: E402
                      find_programs, pack, pack_tree)
from kos.paths import Paths  # noqa: E402
from kos.permit import PermitError, PermitStore  # noqa: E402
from kos.prompt import ScriptedPrompter  # noqa: E402
from kos.protocol import ProtocolError, validate_app_message  # noqa: E402
from kos.registry import Instance, Registry  # noqa: E402
from kos.scan import scan_bytes  # noqa: E402
from kos.store import AppStore  # noqa: E402
from kos.system import SystemBridge, bridge_for, open_background  # noqa: E402

PW = "correct horse battery"
BACKUP_TREE = REPO / "apps" / "backup"


def manifest(name, permissions=(), **extra):
    d = {"name": name, "version": "1.0", "runtime": "python", "entry": "app:main",
         "permissions": list(permissions), **extra}
    return json.dumps(d)


def program(folder: Path, name, permissions=(), **extra):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "manifest.json").write_text(manifest(name, permissions, **extra))
    (folder / "app.py").write_text("def main():\n    return 0\n")


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.chmod(self.tmp.name, 0o755)
        self.root = Path(self.tmp.name)
        self.paths = Paths(self.root / "state")
        PasswordStore(self.paths).create(PW.encode(), KdfParams.fresh(n=2**10), throttle_base=0)
        self.dist = self.root / "dist"

    def tearDown(self):
        self.tmp.cleanup()

    def authority(self, *answers):
        self.prompter = ScriptedPrompter(answers)
        return Authority(self.paths, self.prompter, Throttle(self.paths, base=0))

    def audit(self):
        return [(e["action"], e["target"], e["outcome"]) for e in AuditLog(self.paths).entries()]


class TestProgramIds(unittest.TestCase):
    def test_ids_are_folder_paths_joined_with_dots(self):
        for ok in ("backup", "backup.add", "a.b.c.d", "web-2.page"):
            self.assertTrue(ID_RE.match(ok), ok)

    def test_hostile_or_malformed_ids_are_refused_everywhere_an_id_is_taken(self):
        too_deep = ".".join("a" * (MAX_DEPTH + 1))
        bad = ["a..b", ".a", "a.", "A.b", "a.1b", "a b", "a/b", "../x", "a.b/../c", "a\x00b",
               "a.b\n", too_deep, "a." + "x" * 33, ""]
        for b in bad:
            self.assertFalse(ID_RE.match(b), repr(b))
            with self.assertRaises(KAppError, msg=repr(b)):
                Manifest.parse(manifest(b).encode())
            with self.assertRaises(KAppError, msg=repr(b)):
                AppDirs(Paths(Path("/nonexistent")), b)
            with self.assertRaises(KAppError, msg=repr(b)):
                PermitStore(Paths(Path("/nonexistent"))).grant(b)
            with self.assertRaises(KAppError, msg=repr(b)):
                AppStore(Paths(Path("/nonexistent")))._files(b)
        with self.assertRaises(Exception):
            Registry(Paths(Path("/nonexistent"))).get("../../etc-aaaaaa")

    def test_a_reserved_word_is_only_reserved_as_a_whole_name(self):
        with self.assertRaises(KAppError):
            Manifest.parse(manifest("system").encode())
        self.assertEqual(Manifest.parse(manifest("settings.system").encode()).parent, "settings")

    def test_a_dotted_name_cannot_collide_with_a_plain_app_name(self):
        # 'backup-add' (an ordinary app) and 'backup.add' (a program) are different apps with
        # different files, folders and permits.
        paths = Paths(Path("/nonexistent"))
        self.assertNotEqual(AppDirs(paths, "backup-add").root, AppDirs(paths, "backup.add").root)
        self.assertNotEqual(AppStore(paths)._files("backup-add"), AppStore(paths)._files("backup.add"))

    def test_only_an_ordinary_app_can_be_a_program(self):
        for kind, extends in (("extension", "hello"), ("mod", "taskbar")):
            with self.assertRaises(KAppError):
                Manifest.parse(manifest("hello.thing", kind=kind, extends=extends).encode())

    def test_an_address_names_a_program_with_a_dot_and_a_path_with_a_slash(self):
        a = parse_address("kos://backup.add/some/page")
        self.assertEqual((a.app, a.path), ("backup.add", "/some/page"))
        b = parse_address("kos://backup/add")          # the app 'backup', told to start at /add
        self.assertEqual((b.app, b.path), ("backup", "/add"))
        for bad in ("kos://backup..add", "kos://.backup", "kos://backup.add./x"):
            with self.assertRaises(AddressError, msg=bad):
                parse_address(bad)

    def test_requests_and_instance_ids_take_program_ids(self):
        req = validate_app_message({"cmd": "request", "action": "open", "app": "backup.list"}, "tui")
        self.assertEqual(req["app"], "backup.list")
        for bad in ("backup..list", "backup/list", "../backup"):
            with self.assertRaises(ProtocolError, msg=bad):
                validate_app_message({"cmd": "request", "action": "open", "app": bad}, "tui")
        ok = validate_app_message({"cmd": "request", "action": "close", "id": "backup.list-0a1b2c"}, "tui")
        self.assertEqual(ok["id"], "backup.list-0a1b2c")
        with self.assertRaises(ProtocolError):
            validate_app_message({"cmd": "request", "action": "close", "id": "backup..list-0a1b2c"}, "tui")


class TestAskPermissions(unittest.TestCase):
    def test_ask_permissions_name_one_request_each(self):
        m = Manifest.parse(manifest("backup.remove", ["ask:backup", "ask:backup_remove"]).encode())
        self.assertEqual(m.asks, ("backup", "backup_remove"))
        self.assertEqual(Manifest.parse(manifest("hello").encode()).asks, ())

    def test_open_close_focus_and_unknown_actions_are_not_askable_one_by_one(self):
        for bad in ("ask:open", "ask:close", "ask:focus", "ask:", "ask:backup_add2", "ask:*", "ask"):
            with self.assertRaises(KAppError, msg=bad):
                Manifest.parse(manifest("backup.x", [bad]).encode())
        for a in ASK_ACTIONS:
            Manifest.parse(manifest("backup.x", [f"ask:{a}"]).encode())

    def test_an_add_on_cannot_ask_the_os_for_anything(self):
        with self.assertRaises(KAppError):
            Manifest.parse(manifest("ext-x", ["ask:backup"], kind="extension", extends="hello").encode())
        with self.assertRaises(KAppError):
            Manifest.parse(manifest("mod-x", ["ask:apps"], kind="mod", extends="taskbar").encode())


class TestTreeLayout(Env):
    def test_the_backup_app_is_made_of_programs_and_has_no_permissions_itself(self):
        self.assertFalse((BACKUP_TREE / "manifest.json").exists())
        ms = {m.name: m for m in pack_tree(BACKUP_TREE, self.dist)}
        self.assertEqual(sorted(ms), ["backup.add", "backup.list", "backup.remove"])
        self.assertEqual(ms["backup.list"].permissions, ("ask:backup",))
        self.assertEqual(ms["backup.add"].permissions, ("ask:backup_add",))
        self.assertEqual(ms["backup.remove"].permissions, ("ask:backup", "ask:backup_remove"))
        for m in ms.values():
            self.assertEqual(m.parent, "backup")
            self.assertNotIn("system", m.permissions)
            data = (self.dist / f"{m.name}.kapp").read_bytes()
            self.assertTrue(scan_bytes(data, m.name).clean)

    def test_each_program_zip_holds_only_its_own_folder(self):
        pack_tree(BACKUP_TREE, self.dist)
        for ident in ("backup.list", "backup.add", "backup.remove"):
            self.assertEqual(KApp.from_file(self.dist / f"{ident}.kapp").names(), ["app.py", "manifest.json"])

    def test_packing_is_reproducible(self):
        pack_tree(BACKUP_TREE, self.dist)
        again = self.root / "again"
        pack_tree(BACKUP_TREE, again)
        for f in sorted(self.dist.glob("*.kapp")):
            self.assertEqual(f.read_bytes(), (again / f.name).read_bytes())

    def test_sub_programs_nest_and_are_left_out_of_their_parent(self):
        t = self.root / "mail"
        program(t / "compose", "mail.compose", ["network"])
        (t / "compose" / "assets").mkdir()
        (t / "compose" / "assets" / "icon.txt").write_text("keep me")
        program(t / "compose" / "attach", "mail.compose.attach", ["storage"])
        program(t / "compose" / "attach" / "inline", "mail.compose.attach.inline")
        program(t / "read", "mail.read")
        ms = {m.name: m for m in pack_tree(t, self.dist)}
        self.assertEqual(sorted(ms), ["mail.compose", "mail.compose.attach", "mail.compose.attach.inline",
                                      "mail.read"])
        self.assertEqual(KApp.from_file(self.dist / "mail.compose.kapp").names(),
                         ["app.py", "assets/icon.txt", "manifest.json"])
        self.assertEqual(KApp.from_file(self.dist / "mail.compose.attach.kapp").names(), ["app.py", "manifest.json"])
        # nothing is inherited: the child has the child's permissions only
        self.assertEqual(ms["mail.compose.attach"].permissions, ("storage",))
        self.assertEqual(ms["mail.compose.attach.inline"].permissions, ())
        self.assertEqual(ms["mail.compose"].permissions, ("network",))

    def test_a_program_folder_may_sit_under_a_folder_with_no_manifest(self):
        t = self.root / "docs"
        program(t / "editor" / "spell", "docs.editor.spell")
        self.assertEqual([i for i, _ in find_programs(t)], ["docs.editor.spell"])

    def test_a_name_that_does_not_match_its_folder_is_refused(self):
        t = self.root / "mail"
        program(t / "read", "mail.write")                 # tries to be a sibling
        with self.assertRaises(KAppError):
            pack_tree(t, self.dist)
        t2 = self.root / "evil"
        program(t2 / "x", "backup.add")                   # tries to be another app's program
        with self.assertRaises(KAppError):
            pack_tree(t2, self.dist)
        self.assertEqual(list(self.dist.glob("*.kapp")) if self.dist.exists() else [], [])

    def test_the_app_folder_cannot_hold_code(self):
        t = self.root / "mail"
        program(t / "read", "mail.read")
        (t / "app.py").write_text("print('I would run with no permissions listed anywhere')")
        with self.assertRaises(KAppError) as cm:
            pack_tree(t, self.dist)
        self.assertIn("no permissions", str(cm.exception))
        (t / "app.py").unlink()
        (t / "README.md").write_text("docs are fine")
        self.assertEqual(len(pack_tree(t, self.dist)), 1)
        self.assertEqual(sorted(p.name for p in self.dist.iterdir()), ["mail.read.kapp"])

    def test_too_deep_an_empty_tree_and_symlinks_are_refused(self):
        t = self.root / "a"
        deep = t
        for part in "bcde":
            deep = deep / part
        program(deep, "a.b.c.d.e")
        with self.assertRaises(KAppError):
            pack_tree(t, self.dist)
        with self.assertRaises(KAppError):
            pack_tree(self.root / "nothing-here-yet", self.dist)
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaises(KAppError):
            pack_tree(empty, self.dist)
        s = self.root / "s"
        program(s / "one", "s.one")
        (s / "link").symlink_to(self.root)
        self.assertEqual([i for i, _ in find_programs(s)], ["s.one"])      # a symlink is never followed
        with self.assertRaises(KAppError):
            pack_tree(self.root / "s" / "link", self.dist)

    def test_a_plain_single_app_is_packed_exactly_as_before(self):
        one = self.root / "one"
        program(one, "one", ["network"])
        pack(one, self.root / "one.kapp")
        out = io.StringIO()
        with redirect_stdout(out):
            kcli.cmd_pack(types.SimpleNamespace(dir=str(one), output=str(self.root / "one2.kapp")), self.paths)
        self.assertEqual((self.root / "one.kapp").read_bytes(), (self.root / "one2.kapp").read_bytes())


class TestCommandLine(Env):
    def setUp(self):
        super().setUp()
        self.store = AppStore(self.paths)

    def pack_and_install(self, *answers):
        out = io.StringIO()
        with redirect_stdout(out):
            kcli.cmd_pack(types.SimpleNamespace(dir=str(BACKUP_TREE), output=str(self.dist)), self.paths)
        self.assertIn("backup itself is not a program and has no permissions", out.getvalue())
        with mock.patch.object(kcli, "_authority", lambda paths: (self.authority(*answers), None)):
            with redirect_stdout(io.StringIO()):
                kcli.cmd_install(types.SimpleNamespace(file=str(self.dist)), self.paths)

    def test_pack_of_an_app_wants_a_folder_not_one_file(self):
        with self.assertRaises(KAppError):
            kcli.cmd_pack(types.SimpleNamespace(dir=str(BACKUP_TREE), output=str(self.root / "b.kapp")), self.paths)

    def test_installing_the_folder_installs_every_program_with_its_own_password(self):
        self.pack_and_install(PW, PW, PW)
        self.assertEqual([a.name for a in self.store.installed()], ["backup.add", "backup.list", "backup.remove"])
        installs = [t for a, t, o in self.audit() if a == "app.install" and o == "granted"]
        self.assertEqual(sorted(installs), ["backup.add", "backup.list", "backup.remove"])

    def test_one_wrong_password_installs_that_program_not_the_rest(self):
        with self.assertRaises(Exception):
            self.pack_and_install(PW, "no", "no", "no")
        self.assertEqual(len(self.store.installed()), 1)

    def test_permitting_the_app_is_refused_and_names_its_programs(self):
        self.pack_and_install(PW, PW, PW)
        asked = []
        with mock.patch.object(kcli, "_authority", lambda paths: asked.append(1) or (self.authority(PW), None)):
            with self.assertRaises(KAppError) as cm:
                kcli.cmd_permit(types.SimpleNamespace(list=False, name="backup", revoke=False), self.paths)
        self.assertIn("backup.add", str(cm.exception))
        self.assertIn("no permission of its own", str(cm.exception))
        self.assertEqual(asked, [])                       # refused before any password
        self.assertFalse(PermitStore(self.paths).is_permitted("backup"))

    def test_each_program_is_permitted_alone_and_nothing_spreads_to_siblings(self):
        self.pack_and_install(PW, PW, PW)
        with mock.patch.object(kcli, "_authority", lambda paths: (self.authority(PW), None)):
            with redirect_stdout(io.StringIO()) as out:
                kcli.cmd_permit(types.SimpleNamespace(list=False, name="backup.list", revoke=False), self.paths)
        self.assertIn("ask:backup", out.getvalue())
        permits = PermitStore(self.paths)
        self.assertTrue(permits.is_permitted("backup.list"))
        for other in ("backup.add", "backup.remove", "backup"):
            self.assertFalse(permits.is_permitted(other), other)
        # the permitted program passes the app layer; its sibling is refused before any password
        klayers.traverse(self.paths, self.authority(PW), klayers.Request("run", "backup.list", "tui"))
        with self.assertRaises(PermitError):
            klayers.traverse(self.paths, self.authority(), klayers.Request("run", "backup.add", "tui"))
        self.assertEqual(self.prompter.asked, [])

    def test_a_program_that_later_asks_for_more_is_refused_until_permitted_again(self):
        self.pack_and_install(PW, PW, PW)
        permits = PermitStore(self.paths)
        permits.grant("backup.add", ["ask:backup_add"])
        permits.check_declared("backup.add", ["ask:backup_add"])
        with self.assertRaises(PermitError):
            permits.check_declared("backup.add", ["ask:backup_add", "ask:backup_remove"])

    def test_list_shows_each_programs_own_permissions(self):
        self.pack_and_install(PW, PW, PW)
        out = io.StringIO()
        with redirect_stdout(out):
            kcli.cmd_list(types.SimpleNamespace(), self.paths)
        text = out.getvalue()
        self.assertIn("[program of backup; permissions: ask:backup_add]", text)
        self.assertIn("[program of backup; permissions: ask:backup, ask:backup_remove]", text)


class TestBridgeIsPerProgram(Env):
    def setUp(self):
        super().setUp()
        self.sent = []
        self.spawned = []

    def ask(self, bridge, req, *answers):
        msg = validate_app_message(dict(req, cmd="request"), "tui")
        bridge.handle(msg, self.sent.append, self.authority(*answers))
        return self.sent[-1]

    def test_the_bridge_is_built_from_the_programs_own_permissions(self):
        self.assertIsNone(bridge_for(self.paths, "backup.x", []))
        self.assertIsNone(bridge_for(self.paths, "backup.x", ["network", "owns:notes"]))
        self.assertEqual(bridge_for(self.paths, "backup.x", ["ask:backup"]).allowed, frozenset({"backup"}))
        self.assertIsNone(bridge_for(self.paths, "x", ["system"]).allowed)         # every request
        self.assertEqual(bridge_for(self.paths, "x", ["ask:backup", "ask:apps"]).allowed,
                         frozenset({"backup", "apps"}))

    def test_a_program_gets_its_one_request_and_is_refused_all_others_without_a_password(self):
        bridge = bridge_for(self.paths, "backup.list", ["ask:backup"])
        reply = self.ask(bridge, {"action": "backup"}, "no", "no", "no")          # allowed: reaches the OS prompt
        self.assertFalse(reply["ok"])
        self.assertGreater(len(self.prompter.asked), 0)
        for req in ({"action": "backup_add", "path": "/etc/passwd"},
                    {"action": "backup_remove", "id": "0123456789ab"},
                    {"action": "apps"},
                    {"action": "open", "app": "taskbar", "mode": "tui"},
                    {"action": "close", "id": "taskbar-0a1b2c"},
                    {"action": "focus", "id": "taskbar-0a1b2c"}):
            reply = self.ask(bridge, req, PW)
            self.assertFalse(reply["ok"], req)
            self.assertIn("no permission to ask for", reply["detail"])
            self.assertEqual(self.prompter.asked, [], req)                         # no password was even asked
        refused = [t for a, t, o in self.audit() if a == "bridge.ask" and o == "refused"]
        self.assertEqual(refused, [f"backup.list:{a}" for a in
                                   ("backup_add", "backup_remove", "apps", "open", "close", "focus")])

    def test_two_programs_of_one_app_hold_different_powers(self):
        add = bridge_for(self.paths, "backup.add", ["ask:backup_add"])
        lst = bridge_for(self.paths, "backup.list", ["ask:backup"])
        f = self.root / "a.txt"
        f.write_text("hello")
        self.assertFalse(self.ask(lst, {"action": "backup_add", "path": str(f)}, PW)["ok"])
        self.assertEqual(self.prompter.asked, [])
        self.assertIn("no permission", self.ask(add, {"action": "backup"}, PW)["detail"])

    def test_system_is_still_every_request(self):
        bridge = bridge_for(self.paths, "taskbar", ["system"])
        reply = self.ask(bridge, {"action": "apps"})
        self.assertEqual(reply["cmd"], "apps")

    def test_the_os_records_what_a_program_may_ask_when_it_opens_it(self):
        out = io.StringIO()
        with redirect_stdout(out):
            kcli.cmd_pack(types.SimpleNamespace(dir=str(BACKUP_TREE), output=str(self.dist)), self.paths)
        store = AppStore(self.paths)
        for f in sorted(self.dist.glob("*.kapp")):
            store.install(f, self.authority(PW))
        PermitStore(self.paths).grant("backup.remove", ["ask:backup", "ask:backup_remove"])

        def spawner(inst, app, mode, policy, registry, log_path, cache_dir=None):
            self.spawned.append(inst)
            inst.status, inst.broker_pid = "running", os.getpid()
            registry.write(inst)

        inst = open_background(self.paths, self.authority(PW), "backup.remove", spawner=spawner)
        self.assertEqual((inst.name, inst.system, inst.asks), ("backup.remove", False, ["backup", "backup_remove"]))
        stored = Registry(self.paths).get(inst.id)
        self.assertEqual((stored.name, stored.asks), ("backup.remove", ["backup", "backup_remove"]))
        self.assertTrue(inst.id.startswith("backup.remove-"))
        self.assertTrue((AppDirs(self.paths, "backup.remove").run / f"{inst.id}.json").exists())
        # an attach rebuilds exactly that bridge from the record, not from anything the app says
        b = bridge_for(self.paths, stored.name, ["system"] if stored.system else [f"ask:{a}" for a in stored.asks])
        self.assertEqual(b.allowed, frozenset({"backup", "backup_remove"}))


class TestProgramRunsInTheRealSandbox(Env):
    def test_backup_list_runs_sealed_in_the_sandbox_and_only_asks_for_the_list(self):
        pack_tree(BACKUP_TREE, self.dist)
        store = AppStore(self.paths)
        store.install(self.dist / "backup.list.kapp", self.authority(PW))
        with self.authority(PW).authorize("app.run", "backup.list") as g:
            app = store.load_verified("backup.list", g)
        self.assertEqual(app.manifest.name, "backup.list")
        a, b = socket.socketpair()
        proc = loader.launch(loader.plan(app, b.fileno(), "tui"), SandboxPolicy(), None)
        b.close()
        a.settimeout(10)
        f = a.makefile("rw", encoding="utf-8")
        try:
            f.write('{"cmd":"hello","mode":"tui","width":80,"height":20}\n')
            f.flush()
            first = json.loads(f.readline())
            self.assertEqual(first["cmd"], "screen")
            self.assertIn("Backup - list", first["title"])
            f.write('{"cmd":"key","key":"a"}\n{"cmd":"key","key":"d"}\n{"cmd":"key","key":"r"}\n')
            f.flush()
            seen = []
            while True:
                msg = json.loads(f.readline())
                if msg["cmd"] == "request":
                    seen.append(msg)
                    break
            self.assertEqual(seen, [{"cmd": "request", "action": "backup"}])
            f.write('{"cmd":"key","key":"escape"}\n')
            f.flush()
            proc.wait(10)
        finally:
            f.close()
            a.close()
            if proc.poll() is None:
                proc.kill()


class TestBackupPrograms(unittest.TestCase):
    """The three programs only ever ask; the OS does the work (see TestBackupApp in test_kos)."""

    def load(self, program):
        spec = importlib.util.spec_from_file_location(f"backup_{program}", BACKUP_TREE / program / "app.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    class Fake:
        def __init__(self):
            self.calls = []
        def request_backup(self): self.calls.append(("list",))
        def request_backup_add(self, p): self.calls.append(("add", p))
        def request_backup_remove(self, i): self.calls.append(("rm", i))

    def test_list_only_lists(self):
        mod, app = self.load("list"), self.Fake()
        state = {"items": [], "stats": None, "loaded": False, "note": ""}
        for k in ("r", "a", "d", "enter", "x"):
            self.assertFalse(mod.handle_key(app, state, k))
        self.assertEqual(app.calls, [("list",)])
        self.assertTrue(mod.handle_key(app, state, "escape"))

    def test_add_only_adds(self):
        mod, app = self.load("add"), self.Fake()
        state = {"path": "", "note": ""}
        for ch in "/x/y":
            mod.handle_key(app, state, ch)
        mod.handle_key(app, state, "enter")
        for k in ("r", "d"):
            mod.handle_key(app, state, k)
        mod.handle_key(app, state, "enter")                  # empty path asks nothing
        self.assertEqual(app.calls[0], ("add", "/x/y"))
        self.assertNotIn(("list",), app.calls[:1])
        state["path"] = "partial"
        self.assertFalse(mod.handle_key(app, state, "escape"))   # escape cancels typing, not the program
        self.assertTrue(mod.handle_key(app, state, "escape"))

    def test_remove_lists_to_pick_and_removes_only_the_selected_item(self):
        mod, app = self.load("remove"), self.Fake()
        state = {"items": [{"id": "0123456789ab", "path": "/x", "size": 5, "sha256": "ab"},
                           {"id": "ba9876543210", "path": "/y", "size": 5, "sha256": "cd"}],
                 "loaded": True, "sel": 0, "note": ""}
        mod.handle_key(app, state, "down")
        mod.handle_key(app, state, "d")
        mod.handle_key(app, state, "r")
        mod.handle_key(app, state, "a")                      # no add in this program
        self.assertEqual(app.calls, [("rm", "ba9876543210"), ("list",)])
        self.assertTrue(mod.handle_key(app, state, "escape"))


if __name__ == "__main__":
    unittest.main()
