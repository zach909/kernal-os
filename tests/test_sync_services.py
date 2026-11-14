"""The service door for linked devices, sync, migration and the agent (kos/servicespec.py, kos/services.py).

An app gets nothing its manifest did not ask for, nothing without the password typed in the OS's own prompt,
and a refusal changes nothing. The last test runs the whole stack: two devices pair, then sync real files."""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kos import firewall, linkdev, migrate, servicespec, services  # noqa: E402
from kos.services import HANDLERS, ServiceHost  # noqa: E402
from test_linkdev import Device  # noqa: E402

PW = "service owner password"
PASS = "a long enough passphrase"
NEW = {n for n in servicespec.SPECS if n.split(".")[0] in ("link", "sync", "migrate", "agent")}


def msg(_name, /, **args):                      # positional-only: services have arguments called "name"
    return {"cmd": "service", "id": 1, "name": _name, "args": args}


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Base(unittest.TestCase):
    def setUp(self):
        self.d = Device(self, "box", PW)
        self.t = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.t, ignore_errors=True))

    def call(self, _name, _groups, /, *answers, **args):
        host = ServiceHost(self.d.paths, "test-app", frozenset(_groups))
        return host.call(msg(_name, **args), self.d.authority(*answers))

    def ok(self, _name, _groups, /, *answers, **args):
        r = self.call(_name, _groups, *answers, **args)
        self.assertTrue(r["ok"], r["detail"])
        return r["data"]


class TestTheSpecs(unittest.TestCase):
    def test_every_new_service_has_a_handler_and_every_handler_a_spec(self):
        self.assertEqual({"link.list", "link.identify", "link.pair", "link.scope", "link.unlink", "sync.folders",
                          "sync.share", "sync.unshare", "sync.run", "sync.serve", "migrate.export", "migrate.import",
                          "agent.run"}, NEW)
        for n in NEW:
            self.assertIn(n, HANDLERS, n)

    def test_the_constants_the_pure_spec_repeats_match_the_code_that_enforces_them(self):
        self.assertEqual(servicespec.PLATFORMS, linkdev.PLATFORMS)
        self.assertEqual(servicespec.TARGETS, migrate.TARGETS)

    def test_arguments_are_exact_no_extras_no_wrong_types_no_wrong_ranges(self):
        S = servicespec.SPECS
        S["sync.run"].check({"device": "ab", "folder": "docs", "host": "10.0.0.2", "port": 7007})
        for bad in ({"device": "ab", "folder": "docs", "host": "h", "port": 0},
                    {"device": "ab", "folder": "docs", "host": "h", "port": 65536},
                    {"device": "ab", "folder": "docs", "host": "h", "port": "7007"},
                    {"device": "ab", "folder": "Docs", "host": "h", "port": 1},
                    {"device": "ab", "folder": "docs", "host": "h", "port": 1, "sudo": True},
                    {"device": "ab", "folder": "docs", "host": "h", "port": 1, "dry": "yes"},
                    {"device": "ab", "folder": "docs", "host": "h"}):
            with self.assertRaises(servicespec.SpecError, msg=str(bad)):
                S["sync.run"].check(bad)
        for bad in ({"role": "both", "host": "h", "port": 1}, {"role": "connect", "host": "h" * 50, "port": 1}):
            with self.assertRaises(servicespec.SpecError):
                S["link.pair"].check(bad)
        with self.assertRaises(servicespec.SpecError):
            S["link.identify"].check({"name": "x", "platform": "toaster"})
        with self.assertRaises(servicespec.SpecError):
            S["agent.run"].check({"task": "t", "workspace": "/w", "steps": 21})
        with self.assertRaises(servicespec.SpecError):
            S["agent.run"].check({"task": "t", "workspace": "/w", "steps": 2.5})
        with self.assertRaises(servicespec.SpecError):
            S["migrate.export"].check({"roots": ["a"] * 17, "out": "/o"})

    def test_an_app_can_only_call_the_groups_its_manifest_asked_for(self):
        d = Device(self, "box", PW)
        host = ServiceHost(d.paths, "just-links", frozenset({"link"}))
        for name, args in (("sync.folders", {}), ("migrate.import", {"bundle": "/b", "dest": "/d"}),
                           ("agent.run", {"task": "t", "workspace": "/w"})):
            r = host.call(msg(name, **args), d.authority(PW))
            self.assertFalse(r["ok"], name)
            self.assertIn("did not ask for", r["detail"])
        self.assertEqual(d.prompter.asked, [])                                  # refused before any prompt


class TestNothingHappensWithoutThePassword(Base):
    def test_every_new_service_refuses_when_the_owner_says_no_and_changes_nothing(self):
        src = self.t / "docs"
        src.mkdir()
        calls = [("link.list", "link", {}), ("link.identify", "link", {"name": "x", "platform": "linux"}),
                 ("link.pair", "link", {"role": "listen", "host": "127.0.0.1", "port": 1}),
                 ("link.scope", "link", {"device": "ab", "scope": "paused"}), ("link.unlink", "link", {"device": "ab"}),
                 ("sync.folders", "sync", {}), ("sync.share", "sync", {"name": "docs", "path": str(src)}),
                 ("sync.unshare", "sync", {"name": "docs"}),
                 ("sync.run", "sync", {"device": "ab", "folder": "docs", "host": "127.0.0.1", "port": 1}),
                 ("sync.serve", "sync", {"host": "127.0.0.1", "port": 1}),
                 ("migrate.export", "migrate", {"roots": [str(src)], "out": str(self.t / "o.kmig")}),
                 ("migrate.import", "migrate", {"bundle": str(self.t / "o.kmig"), "dest": str(self.t)}),
                 ("agent.run", "agent", {"task": "t", "workspace": str(src)})]
        for name, group, args in calls:
            r = self.call(name, [group], None, **args)                          # cancel at the first prompt
            self.assertFalse(r["ok"], name)
        self.assertFalse((self.d.paths.state / "links").exists())
        self.assertFalse((self.d.paths.state / "sync").exists())
        self.assertFalse((self.t / "o.kmig").exists())

    def test_wrong_passwords_do_the_same(self):
        r = self.call("link.identify", ["link"], "bad one", "bad two", "bad three", name="x", platform="linux")
        self.assertFalse(r["ok"])
        self.assertFalse(Path(self.d.paths.state / "links" / "identity.bin").exists())


class TestLinks(Base):
    def test_identify_then_list_then_a_second_identity_is_refused(self):
        d = self.ok("link.identify", ["link"], PW, name="laptop", platform="linux")
        self.assertEqual(d["me"]["name"], "laptop")
        listed = self.ok("link.list", ["link"], PW)
        self.assertEqual((listed["me"]["name"], listed["peers"]), ("laptop", []))
        r = self.call("link.identify", ["link"], PW, name="again", platform="linux")
        self.assertFalse(r["ok"])
        self.assertIn("already has an identity", r["detail"])

    def test_pausing_and_unlinking_by_id_prefix_and_ambiguity_is_refused(self):
        self.ok("link.identify", ["link"], PW, name="laptop", platform="linux")
        other = Device(self, "phone", "phone owner password", "android")
        other.make_identity()
        key = self.d.key()
        store = linkdev.LinkStore(self.d.paths)
        for i in range(2):                                                       # two peers whose ids start alike is unlikely;
            pub = (bytes([i]) + os.urandom(31))                                  # force it by hand instead
            store.add(key, linkdev.Peer(linkdev.device_id(pub), f"peer{i}", "ios", pub.hex(), "all", 1_700_000_000))
        peers = self.ok("link.list", ["link"], PW)["peers"]
        self.assertEqual(len(peers), 2)
        r = self.call("link.scope", ["link"], PW, device="", scope="paused")      # an empty prefix matches both
        self.assertFalse(r["ok"])
        self.assertIn("more than one", r["detail"])
        first = peers[0]["id"]
        self.assertTrue(self.ok("link.scope", ["link"], PW, device=first, scope="paused")["scope"] == "paused")
        self.assertEqual([p["scope"] for p in self.ok("link.list", ["link"], PW)["peers"]].count("paused"), 1)
        self.assertEqual(self.ok("link.unlink", ["link"], PW, device=first)["unlinked"], peers[0]["name"])
        self.assertEqual(len(self.ok("link.list", ["link"], PW)["peers"]), 1)
        self.assertFalse(self.call("link.unlink", ["link"], PW, device="ffffffffffff")["ok"])

    def test_what_a_peer_called_itself_can_never_reach_the_screen_as_an_escape_code(self):
        self.ok("link.identify", ["link"], PW, name="laptop", platform="linux")
        pub = os.urandom(32)
        linkdev.LinkStore(self.d.paths).add(self.d.key(), linkdev.Peer(
            linkdev.device_id(pub), "evil\x1b[2J\x1b]0;pwned\x07name", "linux", pub.hex(), "all", 1))
        raw = json.dumps(self.ok("link.list", ["link"], PW))
        self.assertNotIn("\x1b", raw)
        self.assertNotIn("\\u001b", raw)
        self.assertIn("evil", raw)


class TestSharedFolders(Base):
    def test_a_folder_is_shared_by_name_and_resolves_only_through_the_sealed_list(self):
        src = self.t / "docs"
        src.mkdir()
        self.ok("sync.share", ["sync"], PW, name="docs", path=str(src))
        self.assertEqual(self.ok("sync.folders", ["sync"], PW)["folders"], [{"name": "docs", "path": str(src.resolve())}])
        f = self.d.paths.state / "sync" / "folders.json"
        d = json.loads(f.read_text())
        d["folders"]["docs"] = "/etc"                                              # someone edits the file to point at /etc
        f.write_text(json.dumps(d))
        r = self.call("sync.folders", ["sync"], PW)
        self.assertFalse(r["ok"])
        self.assertIn("seal", r["detail"])
        f.unlink()
        self.assertEqual(self.ok("sync.folders", ["sync"], PW)["folders"], [])

    def test_folders_that_must_never_be_shared_are_refused(self):
        real = self.t / "real"
        real.mkdir()
        os.symlink(real, self.t / "alias")
        inside_state = self.d.paths.state / "spaces"
        inside_state.mkdir(parents=True, exist_ok=True)
        for path in ("relative/path", str(self.t / "alias"), str(self.t / "missing"), "/", str(self.d.paths.state),
                     str(inside_state), str(self.d.paths.state.parent), str(real / "x" / ".." )):
            r = self.call("sync.share", ["sync"], PW, name="docs", path=path)
            self.assertFalse(r["ok"], path)

    def test_names_are_plain_and_the_list_is_capped_and_unsharing_keeps_the_files(self):
        src = self.t / "docs"
        src.mkdir()
        (src / "keep.txt").write_text("k")
        for bad in ("Docs", "a b", "../x", "1abc", "a" * 33, ""):
            self.assertFalse(self.call("sync.share", ["sync"], PW, name=bad, path=str(src))["ok"], bad)
        self.ok("sync.share", ["sync"], PW, name="docs", path=str(src))
        self.ok("sync.unshare", ["sync"], PW, name="docs")
        self.assertTrue((src / "keep.txt").exists())
        self.assertFalse(self.call("sync.unshare", ["sync"], PW, name="docs")["ok"])


class TestMigrateThroughTheDoor(Base):
    def test_export_and_import_ask_for_the_password_and_say_what_will_be_read(self):
        src = self.t / "docs"
        src.mkdir()
        (src / "a.txt").write_text("hello")
        out, dest = self.t / "o.kmig", self.t / "dest"
        dest.mkdir()
        d = self.ok("migrate.export", ["migrate"], PW, PASS, PASS, roots=[str(src)], out=str(out), apps=False)
        self.assertEqual(d["files"], 1)
        self.assertIn(str(src), self.d.prompter.asked[0])                          # the prompt names what is read
        self.assertIn(str(out), self.d.prompter.asked[0])
        d = self.ok("migrate.import", ["migrate"], PW, PASS, bundle=str(out), dest=str(dest), target="linux")
        self.assertEqual((d["written"], d["identical"]), (1, 0))
        self.assertEqual((dest / "docs" / "a.txt").read_text(), "hello")

    def test_a_bad_bundle_is_a_refusal_the_app_can_show(self):
        out = self.t / "junk.kmig"
        out.write_bytes(os.urandom(300))
        r = self.call("migrate.import", ["migrate"], PW, PASS, bundle=str(out), dest=str(self.t), target="linux")
        self.assertFalse(r["ok"])
        self.assertNotIn("Traceback", r["detail"])


class TestAgentThroughTheDoor(Base):
    def test_no_local_model_set_up_means_a_clear_refusal(self):
        ws = self.t / "ws"
        ws.mkdir()
        r = self.call("agent.run", ["agent"], PW, task="hi", workspace=str(ws))
        self.assertFalse(r["ok"])
        self.assertIn("no AI is set up", r["detail"])


class TestTwoDevicesThroughTheWholeStack(unittest.TestCase):
    """Pair two devices with link.pair, then sync a folder with sync.serve and sync.run. Everything real:
    sockets on loopback, the firewall rules, the password on each side for each step."""

    def test_pair_then_sync(self):
        a, b = Device(self, "laptop", "laptop owner password"), Device(self, "phone", "phone owner password", "android")
        ra, rb = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp())
        for r in (ra, rb):
            self.addCleanup(lambda r=r: __import__("shutil").rmtree(r, ignore_errors=True))
        (ra / "from-laptop.txt").write_text("hello from the laptop")
        (rb / "from-phone.txt").write_text("hello from the phone")
        port = free_port()
        for dev, direction in ((a, "connect"), (b, "listen")):
            with dev.authority(dev.pw).authorize("firewall.change") as g:
                firewall.FirewallStore(dev.paths).add(g.key(firewall.KEY_LABEL),
                                                      firewall.check_entry("sync", "tcp", direction, "127.0.0.1", port))
        ha = ServiceHost(a.paths, "devices.pair", frozenset({"link", "sync"}))
        hb = ServiceHost(b.paths, "devices.pair", frozenset({"link", "sync"}))
        # each owner names their device
        self.assertTrue(ha.call(msg("link.identify", name="laptop", platform="linux"), a.authority(a.pw))["ok"])
        self.assertTrue(hb.call(msg("link.identify", name="phone", platform="android"), b.authority(b.pw))["ok"])

        # ---- pair: b listens, a connects. Prompts, in order: unlock identity, the connection, the code, link.add
        out = {}
        ready = threading.Event()
        real_listen = linkdev.open_listener

        def listening(*args):
            s = real_listen(*args)
            ready.set()
            return s
        with mock.patch.object(linkdev, "open_listener", listening):
            tb = threading.Thread(target=lambda: out.update(b=hb.call(
                msg("link.pair", role="listen", host="127.0.0.1", port=port), b.authority(b.pw, b.pw, True, b.pw))))
            tb.start()
            self.assertTrue(ready.wait(20))
            out["a"] = ha.call(msg("link.pair", role="connect", host="127.0.0.1", port=port),
                               a.authority(a.pw, a.pw, True, a.pw))
            tb.join(30)
        self.assertTrue(out["a"]["ok"], out["a"]["detail"])
        self.assertTrue(out["b"]["ok"], out["b"]["detail"])
        self.assertEqual(out["a"]["data"]["code"], out["b"]["data"]["code"])
        self.assertEqual(out["a"]["data"]["linked"]["name"], "phone")
        self.assertEqual(out["b"]["data"]["linked"]["name"], "laptop")

        # ---- share a folder on each device and sync
        for dev, h, root in ((a, ha, ra), (b, hb, rb)):
            self.assertTrue(h.call(msg("sync.share", name="docs", path=str(root)), dev.authority(dev.pw))["ok"])
        port2 = free_port()
        for dev, direction in ((a, "connect"), (b, "listen")):
            with dev.authority(dev.pw).authorize("firewall.change") as g:
                firewall.FirewallStore(dev.paths).add(g.key(firewall.KEY_LABEL),
                                                      firewall.check_entry("sync", "tcp", direction, "127.0.0.1", port2))
        ready.clear()
        peer_id = ha.call(msg("link.list"), a.authority(a.pw))["data"]["peers"][0]["id"]
        with mock.patch.object(linkdev, "open_listener", listening):
            tb = threading.Thread(target=lambda: out.update(serve=hb.call(
                msg("sync.serve", host="127.0.0.1", port=port2), b.authority(*[b.pw] * 8))))
            tb.start()
            self.assertTrue(ready.wait(20))
            run = ha.call(msg("sync.run", device=peer_id, folder="docs", host="127.0.0.1", port=port2),
                          a.authority(*[a.pw] * 8))
            tb.join(30)
        self.assertTrue(run["ok"], run["detail"])
        self.assertTrue(out["serve"]["ok"], out["serve"]["detail"])
        self.assertEqual(run["data"]["pushed"], ["from-laptop.txt"])
        self.assertEqual(run["data"]["pulled"], ["from-phone.txt"])
        self.assertEqual((rb / "from-laptop.txt").read_text(), "hello from the laptop")
        self.assertEqual((ra / "from-phone.txt").read_text(), "hello from the phone")
        # the receiving phone's owner was asked for the folder, by name, and the laptop was named
        asked = [q for pr in b.prompters for q in pr.asked if "space docs" in q]
        self.assertTrue(asked and all("laptop" in q for q in asked), asked)
        # both sides audited it
        for dev in (a, b):
            self.assertIn("sync.run" if dev is a else "link.request", {r["action"] for r in dev.audit(100)})


if __name__ == "__main__":
    unittest.main()
