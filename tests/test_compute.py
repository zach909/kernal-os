"""The device chooser: kos/compute.py (the decision), the compute.* services (the door) and store/apps/device-chooser.

What is proved and how. The decision has no maths a prover needs, so it is not in kos/proofs.py; instead the
exhaustive test below tries every task against every subset of a device set and checks the two properties that
matter (a chosen device passes every hard check; nothing is chosen only when everything is refused). Every
refusal sits next to the allowance that shows the rule, not a broken fixture, said no."""

from __future__ import annotations

import importlib.util
import itertools
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kos import compute, sdk, servicespec  # noqa: E402
from kos.auth import AuditLog  # noqa: E402
from kos.compute import AFFINITY, EXECUTORS, KINDS, TASKS, ComputeError, Device, Task, choose  # noqa: E402
from kos.kapp import KApp, Manifest, pack  # noqa: E402
from kos.services import HANDLERS, ServiceHost  # noqa: E402
from test_linkdev import Device as TestDevice  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "store" / "apps" / "device-chooser"
PW = "compute owner password"

CPU = Device("cpu", "cpu", "host", units=8, memory_mb=16_384)
GPU = Device("gpu:card0", "gpu", "a gpu")
NPU = Device("npu:accel0", "npu", "an npu")
CELL = Device("cell:iso", "cell", "cell", units=2, memory_mb=1024, isolated=True)
LINK = Device("link:ab", "linked", "phone", remote=True, isolated=True)
ALL = [CPU, GPU, NPU, CELL, LINK]


def decide(task, devices=ALL):
    return choose(task, devices)


class TestTheTables(unittest.TestCase):
    def test_every_kind_has_an_executor_entry_and_an_affinity_for_every_task(self):
        self.assertEqual(set(EXECUTORS), set(KINDS))
        for task in TASKS:
            self.assertEqual(set(AFFINITY[task]), set(KINDS), task)
            for v in AFFINITY[task].values():
                self.assertIs(type(v), int)
                self.assertTrue(0 <= v <= 100)

    def test_size_can_never_outweigh_fit(self):
        biggest = Device("x", "cpu", "x", units=10**9, memory_mb=10**12)
        smallest = Device("y", "cell", "y", units=0, memory_mb=0, isolated=True)
        for task in TASKS:
            t = Task(task)
            gap = AFFINITY[task]["cpu"] - AFFINITY[task]["cell"]
            if gap < 0:
                self.assertLess(compute.score(biggest, t), compute.score(smallest, t))
            elif gap > 0:
                self.assertGreater(compute.score(smallest, Task(task)) + 1000 * gap, compute.score(smallest, t))
        self.assertLess(compute.score(biggest, Task("general")) - 1000 * AFFINITY["general"]["cpu"], 1000)


class TestChoosing(unittest.TestCase):
    def test_a_plain_task_goes_to_the_host_processor(self):
        d = decide(Task("general"))
        self.assertEqual(d.device.id, "cpu")

    def test_a_gpu_is_listed_and_refused_because_nothing_in_kos_can_run_work_on_one(self):
        d = decide(Task("parallel"))
        self.assertEqual(d.device.id, "cpu")                               # not the gpu the task would suit best
        why = dict((x.id, w) for x, w in d.refused)
        self.assertIn("no GPU executor", why["gpu:card0"])
        self.assertIn("no NPU executor", why["npu:accel0"])

    def test_the_executor_table_is_the_only_thing_that_lets_a_gpu_be_chosen(self):
        with mock.patch.dict(EXECUTORS, {"gpu": ""}):
            self.assertEqual(decide(Task("parallel")).device.id, "gpu:card0")
            self.assertEqual(decide(Task("general")).device.id, "cpu")      # fit still decides
        self.assertEqual(decide(Task("parallel")).device.id, "cpu")

    def test_a_task_that_must_be_isolated_never_falls_back_to_the_host(self):
        d = decide(Task("general", isolate=True), [CPU, GPU])
        self.assertIsNone(d.device)
        self.assertEqual(d.ranked, ())
        self.assertIn("apart from the main kernel", dict((x.id, w) for x, w in d.refused)["cpu"])

    def test_an_isolated_task_goes_to_a_running_cell(self):
        self.assertEqual(decide(Task("general", isolate=True)).device.id, "cell:iso")

    def test_a_cell_that_is_not_running_is_refused_with_its_reason(self):
        down = Device("cell:iso", "cell", "cell", units=2, memory_mb=1024, online=False,
                      why_offline="the cell is not running", isolated=True)
        d = decide(Task("general", isolate=True), [CPU, down])
        self.assertIsNone(d.device)
        self.assertEqual(dict((x.id, w) for x, w in d.refused)["cell:iso"], "the cell is not running")

    def test_private_data_never_leaves_this_machine_and_a_linked_device_needs_it_said_out_loud(self):
        with mock.patch.dict(EXECUTORS, {"linked": ""}):
            d = decide(Task("parallel"), [CPU, LINK])
            self.assertEqual(d.device.id, "cpu")
            self.assertIn("may not leave this machine", dict((x.id, w) for x, w in d.refused)["link:ab"])
            self.assertEqual(decide(Task("parallel", private=False), [CPU, LINK]).device.id, "link:ab")

    def test_memory_must_fit_and_an_unknown_size_is_not_assumed_to_fit(self):
        self.assertEqual(decide(Task("general", memory_mb=16_384)).device.id, "cpu")
        d = decide(Task("general", memory_mb=16_385), [CPU])
        self.assertIsNone(d.device)
        self.assertIn("16384 MB", d.refused[0][1])
        unknown = Device("cpu", "cpu", "host", units=4, memory_mb=0)
        self.assertIsNone(decide(Task("general", memory_mb=1), [unknown]).device)
        self.assertEqual(decide(Task("general"), [unknown]).device.id, "cpu")   # no size stated: nothing to fit

    def test_no_devices_means_no_device(self):
        self.assertIsNone(decide(Task("general"), []).device)

    def test_the_same_input_gives_the_same_answer_and_ties_go_to_the_lower_id(self):
        a = Device("cpu:b", "cpu", "b", units=2, memory_mb=2048)
        b = Device("cpu:a", "cpu", "a", units=2, memory_mb=2048)
        first = decide(Task("general"), [a, b])
        self.assertEqual(first.device.id, "cpu:a")
        self.assertEqual(decide(Task("general"), [b, a]).as_dict(), first.as_dict())

    def test_two_devices_with_one_id_are_refused_not_merged(self):
        with self.assertRaises(ComputeError):
            decide(Task("general"), [CPU, CPU])

    def test_every_number_in_the_answer_is_a_whole_number(self):
        raw = json.dumps(decide(Task("inference", memory_mb=512)).as_dict())
        self.assertNotRegex(raw, r"\d\.\d")
        for r in decide(Task("inference")).as_dict()["ranked"]:
            self.assertIs(type(r["score"]), int)


class TestExhaustive(unittest.TestCase):
    """Every task, every memory, both flags, every subset of the five devices: 3 * 3 * 2 * 2 * 32 cases."""

    def test_a_chosen_device_passes_every_hard_check_and_beats_every_other_allowed_one(self):
        cases = 0
        for kind, mem, private, isolate in itertools.product(TASKS, (0, 1024, 20_000), (True, False), (True, False)):
            task = Task(kind, mem, private, isolate)
            for mask in range(1 << len(ALL)):
                devices = [d for i, d in enumerate(ALL) if mask >> i & 1]
                got = choose(task, devices)
                cases += 1
                allowed = [d for d in devices if not compute.refusal(d, task)]
                self.assertEqual(got.device is None, not allowed, (task, mask))      # none only if all refused
                self.assertEqual({d.id for d, _ in got.ranked}, {d.id for d in allowed})
                if got.device is None:
                    continue
                self.assertEqual(compute.refusal(got.device, task), "")
                self.assertTrue(got.device.runs)                                      # never a device without an executor
                if private:
                    self.assertFalse(got.device.remote)
                if isolate:
                    self.assertTrue(got.device.isolated)
                if mem:
                    self.assertGreaterEqual(got.device.memory_mb, mem)
                best = max(compute.score(d, task) for d in allowed)
                self.assertEqual(compute.score(got.device, task), best)
                self.assertEqual({d.id for d, _ in got.ranked} | {d.id for d, _ in got.refused}, {d.id for d in devices})
        self.assertEqual(cases, 3 * 3 * 2 * 2 * 32)


class TestInputIsChecked(unittest.TestCase):
    def test_a_task_is_whole_numbers_and_known_kinds_only(self):
        for bad in ({"kind": "mine-bitcoin"}, {"memory_mb": -1}, {"memory_mb": 1.5}, {"memory_mb": True},
                    {"memory_mb": 10**9}, {"private": "no"}, {"isolate": 1}):
            with self.assertRaises(ComputeError, msg=str(bad)):
                Task(**bad)

    def test_a_device_is_whole_numbers_only(self):
        for bad in ({"units": 1.5}, {"memory_mb": 2.5}, {"units": -1}, {"units": True}):
            with self.assertRaises(ComputeError, msg=str(bad)):
                Device("x", "cpu", "x", **bad)
        with self.assertRaises(ComputeError):
            Device("x", "quantum", "x")


class TestProbing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, rel, text):
        p = self.root.joinpath(*rel.split("/"))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def test_the_processor_reads_available_memory_in_whole_megabytes(self):
        self.write("proc/meminfo", "MemTotal:  9999999 kB\nMemAvailable:   2099200 kB\n")
        cpu = compute.host_cpu(self.root)
        self.assertEqual(cpu.memory_mb, 2050)
        self.assertGreaterEqual(cpu.units, 1)

    def test_a_missing_or_broken_meminfo_gives_unknown_not_a_crash(self):
        self.assertEqual(compute.host_cpu(self.root).memory_mb, 0)
        self.write("proc/meminfo", "MemAvailable: lots kB\n")
        self.assertEqual(compute.host_cpu(self.root).memory_mb, 0)

    def test_gpus_and_npus_are_found_and_connector_entries_are_not_devices(self):
        self.write("sys/class/drm/card0/device/vendor", "0x10de\n")
        self.write("sys/class/drm/card0-HDMI-A-1/status", "connected\n")
        self.write("sys/class/drm/renderD128/device/vendor", "0x10de\n")
        self.write("sys/class/accel/accel0/device/vendor", "0x8086\n")
        found = {d.id: d for d in compute.accelerators(self.root)}
        self.assertEqual(set(found), {"gpu:card0", "npu:accel0"})
        self.assertIn("NVIDIA", found["gpu:card0"].name)
        self.assertIn("Intel", found["npu:accel0"].name)
        self.assertEqual(compute.accelerators(Path(self.tmp.name) / "nowhere"), [])

    def test_a_hostile_vendor_string_cannot_move_a_terminal(self):
        self.write("sys/class/drm/card1/device/vendor", "\x1b[2J\x1b]0;pwned\x07\n")
        for d in compute.accelerators(self.root):
            self.assertNotRegex(d.name, r"[\x00-\x1f\x7f-\x9f]")

    def test_cells_come_from_the_manager_and_a_broken_record_is_skipped(self):
        cells = [{"name": "a", "cpus": [2, 3], "memory_mb": 512, "running": True},
                 {"name": "b\x1b[2J", "cpus": [4], "memory_mb": 64, "running": False},
                 {"cpus": [1]}, {"name": "c", "memory_mb": "lots"}, "junk"]
        got = {d.id: d for d in compute.cell_devices(cells)}
        self.assertEqual(len(got), 2)
        self.assertTrue(got["cell:a"].isolated and got["cell:a"].online and got["cell:a"].units == 2)
        for d in got.values():
            self.assertNotRegex(d.id + d.name, r"[\x00-\x1f\x7f-\x9f]")
        self.assertFalse([d for d in got.values() if d.id != "cell:a"][0].online)

    def test_a_paused_link_is_offline_and_every_linked_device_is_remote(self):
        peers = [SimpleNamespace(device_id="a" * 64, name="phone", scope="all"),
                 SimpleNamespace(device_id="b" * 64, name="tablet\x1b[2J", scope="paused"), object()]
        got = compute.linked_devices(peers)
        self.assertEqual(len(got), 2)
        self.assertTrue(all(d.remote for d in got))
        self.assertEqual([d.online for d in got], [True, False])
        self.assertTrue(all(len(d.id) == len("link:") + 16 for d in got))
        for d in got:
            self.assertNotRegex(d.name, r"[\x00-\x1f\x7f-\x9f]")

    def test_probe_returns_every_kind_in_id_order(self):
        self.write("proc/meminfo", "MemAvailable: 1048576 kB\n")
        self.write("sys/class/drm/card0/device/vendor", "0x1002\n")
        out = compute.probe(self.root, cells=[{"name": "a", "cpus": [1], "memory_mb": 64, "running": True}],
                            peers=[SimpleNamespace(device_id="c" * 64, name="p", scope="all")])
        self.assertEqual([d.id for d in out], sorted(d.id for d in out))
        self.assertEqual({d.kind for d in out}, set(KINDS) - {"npu"})


class TestTheServices(unittest.TestCase):
    def setUp(self):
        self.d = TestDevice(self, "box", PW)

    def call(self, name, answers=(PW,), groups=("compute",), **args):
        msg = {"cmd": "service", "id": 1, "name": name, "args": args}
        return ServiceHost(self.d.paths, "test-app", frozenset(groups)).call(msg, self.d.authority(*answers))

    def choices(self):
        """What the OS recorded as chosen: the audit entries my handler writes (outcome = the device)."""
        return [e["outcome"] for e in AuditLog(self.d.paths).tail(100)
                if e["action"] == "compute.choose" and e["outcome"] not in ("cancelled", "granted", "bad-password", "denied")]

    def test_the_specs_and_handlers_exist_and_the_group_is_known_to_manifests(self):
        for n in ("compute.list", "compute.choose"):
            self.assertIn(n, servicespec.SPECS)
            self.assertIn(n, HANDLERS)
        self.assertIn("compute", servicespec.GROUPS)

    def test_an_app_that_did_not_ask_for_the_group_is_refused_before_any_prompt(self):
        for name, args in (("compute.list", {}), ("compute.choose", {"task": "general"})):
            r = self.call(name, groups=("audit",), **args)
            self.assertFalse(r["ok"])
            self.assertIn("did not ask for", r["detail"])
        self.assertEqual(self.d.prompter.asked, [])

    def test_the_owner_saying_no_reads_nothing_and_logs_no_choice(self):
        for name, args in (("compute.list", {}), ("compute.choose", {"task": "general"})):
            r = self.call(name, answers=(None,), **args)
            self.assertFalse(r["ok"], name)
            self.assertEqual(r["data"], {})
        self.assertEqual(self.choices(), [])                  # the cancels are logged; no choice is

    def test_a_wrong_password_three_times_is_the_same_refusal(self):
        r = self.call("compute.choose", answers=("bad one", "bad two", "bad three"), task="general")
        self.assertFalse(r["ok"])

    def test_list_names_the_host_processor_and_says_what_can_run(self):
        r = self.call("compute.list")
        self.assertTrue(r["ok"], r["detail"])
        by = {d["id"]: d for d in r["data"]["devices"]}
        self.assertIn("cpu", by)
        self.assertTrue(by["cpu"]["runs"])
        for d in r["data"]["devices"]:
            self.assertEqual(d["runs"], not EXECUTORS[d["kind"]])

    def test_choose_answers_logs_the_choice_and_says_it_ran_nothing(self):
        r = self.call("compute.choose", task="general", memory=0, private=True, isolate=False)
        self.assertTrue(r["ok"], r["detail"])
        self.assertEqual(r["data"]["device"], "cpu")
        self.assertEqual(r["data"]["task"], {"kind": "general", "memory_mb": 0, "private": True, "isolate": False})
        self.assertEqual(self.choices(), ["cpu"])
        self.call("compute.choose", task="general", isolate=True)
        self.assertEqual(self.choices(), ["cpu", "no device"])         # a refusal to place is logged too

    def test_choose_with_isolation_and_no_cell_says_no_device_instead_of_using_the_host(self):
        r = self.call("compute.choose", task="general", isolate=True)
        self.assertTrue(r["ok"], r["detail"])
        self.assertIsNone(r["data"]["device"])
        self.assertIn("cpu", [x["id"] for x in r["data"]["refused"]])

    def test_a_running_cell_on_this_machine_is_chosen_for_an_isolated_task(self):
        self.d.paths.ensure()
        self.d.paths.cells.mkdir(parents=True, exist_ok=True)
        import os
        self.d.paths.cells.joinpath("iso.json").write_text(json.dumps(
            {"name": "iso", "cid": 3, "cpus": [1, 2], "memory_mb": 512, "pid": os.getpid()}))
        r = self.call("compute.choose", task="general", isolate=True, memory=256)
        self.assertEqual(r["data"]["device"], "cell:iso")

    def test_hostile_arguments_are_refused_by_the_spec(self):
        for args in ({"task": "gpu"}, {"task": "general", "memory": -1}, {"task": "general", "memory": 2**40},
                     {"task": "general", "memory": 1.5}, {"task": "general", "private": "no"},
                     {"task": "general", "isolate": 1}, {"task": "general", "device": "gpu:card0"}, {}):
            r = self.call("compute.choose", **args)
            self.assertFalse(r["ok"], str(args))
        self.assertFalse(self.call("compute.list", extra=1)["ok"])
        self.assertEqual(self.d.prompter.asked, [])                      # all refused before the password was asked

    def test_a_cell_name_cannot_move_the_owners_terminal(self):
        self.d.paths.ensure()
        self.d.paths.cells.mkdir(parents=True, exist_ok=True)
        self.d.paths.cells.joinpath("x.json").write_text(json.dumps(
            {"name": "x\x1b[2J\x1b]0;pwned\x07", "cid": 4, "cpus": [1], "memory_mb": 64, "pid": 0}))
        r = self.call("compute.list")
        self.assertTrue(r["ok"], r["detail"])
        self.assertNotRegex(json.dumps(r["data"], ensure_ascii=False), r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

    def test_a_link_list_that_does_not_match_its_seal_lists_no_linked_device_and_says_so(self):
        store = self.d.paths.state / "links"
        store.mkdir(parents=True, exist_ok=True)
        (store / "links.json").write_text("{not json")
        r = self.call("compute.list")
        self.assertTrue(r["ok"], r["detail"])
        self.assertIn("seal", r["data"]["note"])
        self.assertEqual([d for d in r["data"]["devices"] if d["kind"] == "linked"], [])


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


def key(k):
    return {"cmd": "key", "key": k}


def run_app(keys, replies=None):
    fake = FakeApp([{"cmd": "hello", "mode": "tui", "width": 80, "height": 24}, *[key(k) for k in keys]], replies)
    with mock.patch.object(sdk, "App", lambda *a, **k: fake):
        spec = importlib.util.spec_from_file_location("device_chooser_under_test", APP / "app.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.main()
    return fake


ANSWER = {"ok": True, "detail": "", "data": {
    "device": "cpu", "task": {}, "note": "",
    "ranked": [{"id": "cpu", "kind": "cpu", "name": "host processor", "score": 60320}],
    "refused": [{"id": "gpu:card0", "kind": "gpu", "name": "g", "why": "KOS has no GPU executor"}]}}


class TestTheApp(unittest.TestCase):
    def test_it_packs_through_the_proof_gate_and_asks_for_one_service_group_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = pack(APP, Path(tmp) / "c.kapp")
            self.assertEqual(m.name, "device-chooser")
            self.assertIn("proof.json", KApp.from_file(Path(tmp) / "c.kapp").names())
        self.assertEqual(list(Manifest.parse((APP / "manifest.json").read_bytes()).permissions), ["service:compute"])

    def test_it_does_not_ask_the_os_until_the_owner_presses_enter(self):
        f = run_app(["2", "m", "d", "i", "x"])
        self.assertEqual(f.calls, [])

    def test_it_sends_exactly_the_arguments_the_spec_takes_and_shows_the_answer(self):
        f = run_app(["3", "m", "m", "d", "i", "enter"], {"compute.choose": ANSWER})
        self.assertEqual(f.calls, [("compute.choose", {"task": "inference", "memory": 2048, "private": False, "isolate": True})])
        servicespec.SPECS["compute.choose"].check(f.calls[0][1])
        self.assertIn("Chosen: cpu", f.last)
        self.assertIn("no GPU executor", f.last)
        self.assertIn("does not start anything", f.last)

    def test_the_defaults_are_the_cautious_ones(self):
        f = run_app(["enter"], {"compute.choose": ANSWER})
        self.assertEqual(f.calls[0][1], {"task": "general", "memory": 0, "private": True, "isolate": False})

    def test_a_refusal_is_shown_as_a_refusal_and_nothing_is_claimed_chosen(self):
        f = run_app(["enter"], {"compute.choose": {"ok": False, "detail": "the password was not accepted", "data": {}}})
        self.assertIn("Refused: the password was not accepted", f.last)
        self.assertIn("Nothing was chosen", f.last)
        self.assertNotIn("Chosen", f.last)

    def test_no_device_is_said_plainly(self):
        none = {"ok": True, "detail": "", "data": {"device": None, "ranked": [], "refused": [
            {"id": "cpu", "kind": "cpu", "name": "h", "why": "not apart from the main kernel"}]}}
        f = run_app(["i", "enter"], {"compute.choose": none})
        self.assertIn("No device", f.last)
        self.assertIn("nothing was run", f.last)

    def test_an_answer_in_a_shape_it_does_not_know_does_not_crash_it(self):
        f = run_app(["enter"], {"compute.choose": {"ok": True, "detail": "", "data": {"ranked": "nope", "refused": 3}}})
        self.assertTrue(f.screens)

    def test_escape_leaves(self):
        f = run_app(["escape"])
        self.assertEqual(f.exited, 0)


class TestTheRealAppInTheRealSandbox(unittest.TestCase):
    """The packed app, confined by the real sandbox, asking the real service host; the password is typed into the
    OS's own prompt, which the app cannot see. Nothing here is faked except the keyboard."""

    def run_chooser(self, extra_keys=()):
        import re
        import socket
        import threading
        import time
        from test_services import ENTER, keys
        from kos import loader
        from kos.auth import Authority, KdfParams, PasswordStore, Throttle
        from kos.cli import _services_for
        from kos.devices import ScriptedDevices
        from kos.paths import Paths
        from kos.permit import PermitStore
        from kos.protocol import Channel
        from kos.sandbox import SandboxPolicy
        from kos.session import Session
        from kos.store import AppStore
        from kos.tui import TUISurface

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        root.chmod(0o755)
        paths = Paths(root)
        PasswordStore(paths).create(PW.encode(), KdfParams.fresh(n=2**10), throttle_base=0)

        def authority(*answers):
            from kos.prompt import ScriptedPrompter
            return Authority(paths, ScriptedPrompter(answers), Throttle(paths, base=0))
        kapp = root / "device-chooser.kapp"
        pack(APP, kapp)
        store = AppStore(paths)
        store.install(kapp, authority(PW))
        PermitStore(paths).grant("device-chooser")
        with authority(PW).authorize("app.run", "device-chooser") as g:
            app = store.load_verified("device-chooser", g)
        a, b = socket.socketpair()
        proc = loader.launch(loader.plan(app, b.fileno(), "tui", None, ""), SandboxPolicy(), None)
        b.close()
        devices = ScriptedDevices()
        out = tempfile.TemporaryFile()
        self.addCleanup(out.close)
        session = Session(name="device-chooser", mode="tui", channel=Channel(a), proc=proc,
                          surface=TUISurface(out.fileno(), 100, 30, "device-chooser"), devices=devices,
                          authority=Authority(paths, None, Throttle(paths, base=0)),
                          log=SimpleNamespace(write=lambda s: None, flush=lambda: None), preboot=("mouse", "keyboard"),
                          services=_services_for(paths, "device-chooser", ["service:compute"]))
        seen = {}

        def watch():
            end = time.monotonic() + 30
            while time.monotonic() < end and not session.surface.has_content:
                time.sleep(0.02)                                        # keys sent before the first frame are dropped
            time.sleep(0.3)
            devices.push(*keys(extra_keys), ENTER)                      # set the task, then ask the OS
            while time.monotonic() < end:
                m = session.surface.modal
                if m is not None and m.title.startswith("Password to choose a device"):
                    seen["prompt"] = m.title
                    devices.push(*keys(PW), ENTER)                      # the owner types the password in the OS prompt
                    break
                time.sleep(0.02)
            while time.monotonic() < end and session.surface.modal is not None:
                time.sleep(0.02)
            time.sleep(0.5)
            devices.push({"type": "key", "key": "escape"})
        t = threading.Thread(target=watch, daemon=True)
        t.start()
        code = session.run()
        t.join(2)
        out.seek(0)
        screen = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", out.read().decode("utf-8", "replace"))
        return code, screen, seen, AuditLog(paths)

    def test_the_owner_types_the_password_in_the_os_prompt_and_the_app_shows_the_choice(self):
        code, screen, seen, audit = self.run_chooser()
        self.assertEqual(code, 0)
        self.assertIn("choose a device for a task", seen.get("prompt", ""))   # the OS's own prompt
        self.assertIn("Chosen: cpu", screen)
        self.assertIn("does not start anything", screen)
        self.assertIn("cpu", [e["outcome"] for e in audit.tail(50) if e["action"] == "compute.choose"])

    def test_a_task_that_must_be_isolated_gets_no_device_because_this_machine_has_no_cell_running(self):
        code, screen, seen, audit = self.run_chooser("i")
        self.assertEqual(code, 0)
        self.assertIn("No device", screen)
        self.assertNotIn("Chosen:", screen)
        self.assertIn("no device", [e["outcome"] for e in audit.tail(50) if e["action"] == "compute.choose"])


if __name__ == "__main__":
    unittest.main()
