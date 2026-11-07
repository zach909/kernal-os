"""Pack apps in the real machinery: real AppStorage enforcing shared folders, and a real sealed-zip Landlock launch."""

import os
import socket
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from kos import loader  # noqa: E402
from kos.appdirs import AppDirs  # noqa: E402
from kos.auth import Authority, Throttle  # noqa: E402
from kos.devices import ScriptedDevices  # noqa: E402
from kos.kapp import KApp  # noqa: E402
from kos.office.packkit import shared_add, shared_items  # noqa: E402
from kos.office.ui import FakeHost  # noqa: E402
from kos.permissions import Permissions  # noqa: E402
from kos.protocol import Channel  # noqa: E402
from kos.sandbox import SandboxPolicy  # noqa: E402
from kos.session import Session  # noqa: E402
from kos.spaces import AppStorage  # noqa: E402
from kos.store import AppStore  # noqa: E402
from kos.tui import TUISurface  # noqa: E402
from test_kos import Env, PW  # noqa: E402


class TestSharedFoldersAreEnforcedByTheRealStorage(Env):
    def _perms(self, name):
        from suite import gen
        d = Path(self.tmp.name) / "k"
        if not (d / f"{name}.kapp").exists(): gen.build(d)
        return KApp.from_file(d / f"{name}.kapp").manifest.permissions

    def _host(self, name):
        return FakeHost([], storage=AppStorage(self.paths, name, self._perms(name)))

    def test_an_app_sees_a_shared_folder_only_when_it_declared_it_and_the_owner_granted_it(self):
        owner, user, stranger = self._host("places"), self._host("route-planner"), self._host("clock")
        self.assertIn("owns:places", self._perms("places"))
        self.assertIn("uses:places", self._perms("route-planner"))
        self.assertNotIn("uses:places", self._perms("clock"))

        self.assertTrue(shared_add(owner, "places", {"name": "Home", "lat": "51.5", "lon": "-0.12"}))     # first write creates the space
        self.assertEqual(Permissions(self.paths).owner_of("space:places"), "places")

        self.assertEqual(shared_items(user, "places"), [])                      # declared, but not granted yet
        self.assertFalse(shared_add(user, "places", {"name": "Evil"}))

        Permissions(self.paths).grant("route-planner", "space:places", "read")
        self.assertEqual([r["name"] for r in shared_items(user, "places")], ["Home"])
        self.assertFalse(shared_add(user, "places", {"name": "Evil"}))          # read is not write
        self.assertEqual(len(shared_items(owner, "places")), 1)

        Permissions(self.paths).grant("route-planner", "space:places", "write")
        self.assertTrue(shared_add(user, "places", {"name": "Work", "lat": "51.6", "lon": "-0.1"}))
        self.assertEqual([r["name"] for r in shared_items(owner, "places")], ["Home", "Work"])

        Permissions(self.paths).grant("clock", "space:places", "write")         # a grant alone is not enough: the app never asked
        self.assertEqual(shared_items(stranger, "places"), [])
        self.assertFalse(shared_add(stranger, "places", {"name": "Evil"}))

    def test_revoking_takes_access_away(self):
        owner, user = self._host("places"), self._host("map-tools")
        shared_add(owner, "places", {"name": "Home"})
        Permissions(self.paths).grant("map-tools", "space:places", "read")
        self.assertEqual(len(shared_items(user, "places")), 1)
        Permissions(self.paths).revoke("map-tools", "space:places")
        self.assertEqual(shared_items(user, "places"), [])


class TestAPackAppInTheRealSandbox(Env):
    def _launch(self, name, keys):
        from suite import gen
        gen.build(Path(self.tmp.name) / "k")
        store = AppStore(self.paths)
        store.install(Path(self.tmp.name) / "k" / f"{name}.kapp", self.authority(PW))
        with self.authority(PW).authorize("app.run", name) as g:
            app = store.load_verified(name, g)
        a, b = socket.socketpair()
        proc = loader.launch(loader.plan(app, b.fileno(), "tui"), SandboxPolicy(), None); b.close()
        devices = ScriptedDevices()
        devnull = os.open(os.devnull, os.O_WRONLY)
        s = Session(name=name, mode="tui", channel=Channel(a), proc=proc, surface=TUISurface(devnull, 100, 30, name),
                    devices=devices, authority=Authority(self.paths, None, Throttle(self.paths, base=0)), boot_devices=("keyboard",),
                    vault=AppStorage(self.paths, name, app.manifest.permissions))
        send = lambda *names: devices.push(*[{"type": "key", "key": n} for n in names])
        send("y", *PW, "enter")                                                    # boot the keyboard with the password
        send(*keys)
        code = s.run(first_frame_timeout=5)
        os.close(devnull)
        return code, app

    def test_clock_runs_sealed_and_sandboxed_imports_only_its_pack_and_exits_cleanly(self):
        code, app = self._launch("clock", ["escape"])
        self.assertEqual(code, 0)
        self.assertEqual(app.manifest.entry, "app:main")
        self.assertFalse(list(AppDirs(self.paths, "clock").cache.glob("*")))      # scratch wiped

    def test_the_agent_opens_inside_the_sandbox_with_ctrl_n(self):
        code, _ = self._launch("calculator", ["ctrl-n", *"/about", "enter", "escape", "escape"])
        self.assertEqual(code, 0)
        from kos.vault import Vault
        chat = Vault(self.paths, "calculator").get("agent-chat") or ""
        self.assertIn("/about", chat)                       # the agent really ran in the sandbox and saved to its own prefix
        self.assertIn("Single-user and local", chat)
        self.assertEqual([k for k in Vault(self.paths, "calculator").keys() if not k.startswith(("agent-", "export-"))], [])


if __name__ == "__main__":
    unittest.main()
