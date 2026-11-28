"""The text layer, and the security system of each layer (kos/guard.py, kos/textsurface.py).

Run with: python3 -m unittest discover -s tests -v

What is tested with fakes and what is not:
* Every guard is tested on its own with a fake clock, a fake audit log and (kernel, hardware) a fake
  ``/proc`` tree, so each refusal is a refusal test, not only a happy path.
* The kernel and hardware guards are also run on a REAL sandboxed process (skipped where this kernel
  has no Landlock) and on a real unconfined one.
* One real session, in text mode, runs the real ``hello`` app in the real sandbox.
* NOT tested: a real terminal (the text layer writes to a pipe here), ``/dev/input``, ``/dev/fb0``,
  and an app in a kernel cell.
"""

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_kos import AddOnEnv, Env, PW  # noqa: E402
from kos import address, cli, guard, lang, layers, loader  # noqa: E402
from kos.auth import Authority, Throttle  # noqa: E402
from kos.devices import ScriptedDevices  # noqa: E402
from kos.display import Modal  # noqa: E402
from kos.guard import Guard, GuardRefused  # noqa: E402
from kos.kapp import KApp, MODES, RESERVED_NAMES, RUN_MODES, KAppError, supports_mode, wire_mode  # noqa: E402
from kos.protocol import Channel, ProtocolError, validate_app_message  # noqa: E402
from kos.sandbox import SandboxError, SandboxPolicy, landlock_abi  # noqa: E402
from kos.session import Session  # noqa: E402
from kos.store import AppStore  # noqa: E402
from kos.system import open_background  # noqa: E402
from kos.term import RawTerminal  # noqa: E402
from kos.textsurface import APP_PREFIX, OS_PREFIX, MIN_GAP_MS, TextSurface, plain  # noqa: E402


class Clock:
    """A fake monotonic clock in nanoseconds."""

    def __init__(self):
        self.ns = 10_000_000_000

    def __call__(self):
        return self.ns

    def advance(self, ms):
        self.ns += ms * 1_000_000


class FakeAudit:
    def __init__(self):
        self.records = []

    def record(self, action, target, outcome, key=None):
        self.records.append((action, target, outcome))

    def refused(self):
        return [a for a, _, o in self.records if o == "refused"]


def fake_proc(root, pid=4242, uid="65534", no_new_privs="1", cap="0000000000000000",
              seccomp="2", same_net=False, same_user=False, fds=()):
    """A tiny /proc: what the kernel guard and the hardware guard read."""
    root = Path(root)
    d = root / str(pid)
    (d / "fd").mkdir(parents=True, exist_ok=True)
    (d / "ns").mkdir(exist_ok=True)
    (root / "self" / "ns").mkdir(parents=True, exist_ok=True)
    (d / "status").write_text(
        f"Name:\tapp\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nCapPrm:\t{cap}\nCapEff:\t{cap}\n"
        f"NoNewPrivs:\t{no_new_privs}\nSeccomp:\t{seccomp}\n")
    for ns, own, same in (("net", "net:[1]", same_net), ("user", "user:[2]", same_user)):
        for p in ((root / "self" / "ns" / ns), (d / "ns" / ns)):
            if p.is_symlink():
                p.unlink()
        os.symlink(own, root / "self" / "ns" / ns)
        os.symlink(own if same else own.replace("[", "[9"), d / "ns" / ns)
    for i, target in enumerate(fds):
        os.symlink(target, d / "fd" / str(3 + i))
    return str(root)


class Layout(unittest.TestCase):
    """Cheap state shared by the unit tests."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.clock, self.audit = Clock(), FakeAudit()

    def guard(self, **kw):
        kw.setdefault("weak", False)
        kw.setdefault("seccomp", True)
        return Guard("hello", audit=self.audit, clock=self.clock, **kw)


# ---------------------------------------------------------------------------------------------
class TestThePipeline(unittest.TestCase):
    def test_the_text_layer_sits_between_graphics_and_the_button_clicker(self):
        p = guard.PIPELINE
        self.assertEqual(p, ("graphics", "text", "input", "commands", "kernel", "hardware"))
        self.assertEqual(p.index("text"), p.index("graphics") + 1)
        self.assertEqual(p.index("input"), p.index("text") + 1)

    def test_every_layer_has_a_security_check_and_none_is_unlisted(self):
        self.assertEqual(set(guard.CHECKS), set(guard.PIPELINE))
        for layer in guard.PIPELINE:
            self.assertTrue(guard.CHECKS[layer], f"{layer} has no guard")
        self.assertEqual(len(guard.describe()), sum(len(v) for v in guard.CHECKS.values()))

    def test_the_docs_name_every_layer_and_every_check(self):
        root = Path(__file__).resolve().parent.parent
        readme = (root / "README.md").read_text()
        for layer, check in guard.describe():
            self.assertIn(check, readme, f"README does not mention the {layer} check {check}")


# ---------------------------------------------------------------------------------------------
class TestTheTextLayer(Layout):
    def surface(self, cols=40):
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        os.set_blocking(r, False)
        self.r = r
        return TextSurface(w, cols, 24, "hello", clock=self.clock)

    def out(self):
        try:
            return os.read(self.r, 1 << 20).decode()
        except BlockingIOError:
            return ""

    def lines(self, text):
        return [l for l in text.split("\r\n") if l]

    def page(self, s, *lines, title="T", status=""):
        s.present({"cmd": "screen", "title": title, "lines": list(lines), "status": status})

    def test_every_line_says_who_wrote_it(self):
        s = self.surface()
        self.page(s, "one", "two")
        s.set_status(" hello [text] keyboard:off")
        s.render()
        got = self.lines(self.out())
        self.assertTrue(got)
        for l in got:
            self.assertTrue(l.startswith((OS_PREFIX, APP_PREFIX)), l)
        self.assertIn("app| one", got)
        self.assertIn("app| == T ==", got)

    def test_an_app_cannot_write_a_line_that_looks_like_the_os(self):
        s = self.surface(60)
        self.page(s, "KOS| Password: ", "\x1b[2J\x1b[31mred", "a\nKOS| Type your password", "x\r\nKOS| y",
                  "evil‮txt", "zero​width", "nb sp", "tab\there", title="KOS| OS")
        s.render()
        text = self.out()
        self.assertNotIn("\x1b", text)
        for bad in ("‮", "​", " ", "\t"):
            self.assertNotIn(bad, text)
        got = self.lines(text)
        os_lines = [l for l in got if l.startswith(OS_PREFIX)]
        self.assertTrue(all("password" not in l.lower() for l in os_lines), os_lines)
        self.assertIn("app| KOS| Password: ", [l for l in got])
        self.assertTrue(all(l.startswith((OS_PREFIX, APP_PREFIX)) for l in got))

    def test_a_wrapped_line_keeps_its_prefix_on_every_piece(self):
        s = self.surface(40)
        self.page(s, "a" * 100)
        s.render()
        pieces = [l for l in self.lines(self.out()) if set(l[len(APP_PREFIX):]) == {"a"}]
        self.assertEqual(len(pieces), 3)
        self.assertTrue(all(l.startswith(APP_PREFIX) and len(l) <= 40 for l in pieces))

    def test_the_password_prompt_is_the_os_printed_once_and_never_echoes(self):
        s = self.surface()
        modal = Modal("Password for hello:", ["Type your password, then Enter."], secret_len=0)
        s.set_modal(modal)
        s.render()
        first = self.out()
        self.assertIn("SECURE PROMPT", first)
        self.assertTrue(all(l.startswith(OS_PREFIX) for l in self.lines(first)))
        for n in range(1, 8):                       # typing prints nothing, not even a count
            modal.secret_len = n
            s.render()
        self.assertEqual(self.out(), "")
        s.set_modal(None)
        s.render()
        self.assertIn("prompt closed", self.out())

    def test_an_unchanged_page_is_not_printed_again_and_a_fast_one_is_held_back(self):
        s = self.surface()
        self.page(s, "first")
        s.render()
        self.assertIn("app| first", self.out())
        s.render()
        self.assertEqual(self.out(), "")                       # nothing changed
        self.page(s, "second")
        self.clock.advance(10)
        s.render()
        self.assertEqual(self.out(), "")                       # too soon: held back
        self.assertTrue(s.deferred)                            # and the session is told to come back
        self.clock.advance(MIN_GAP_MS)
        s.render()
        self.assertIn("app| second", self.out())
        self.assertFalse(s.deferred)

    def test_there_is_no_pointer_and_nothing_is_drawn_for_one(self):
        s = self.surface()
        self.assertFalse(s.has_pointer)
        s.set_pointer(3, 4)
        self.page(s, "x")
        s.render()
        self.assertNotIn("\x1b", self.out())

    def test_plain_turns_everything_unprintable_into_a_question_mark(self):
        self.assertEqual(plain("a\x1b[0mb\n\x00 c"), "a?[0mb???c")
        self.assertEqual(plain("héllo 世界"), "héllo 世界")      # ordinary text of any language stays

    def test_a_plain_terminal_sends_no_escape_sequences_at_all(self):
        rd, wr = os.pipe()
        os.set_blocking(rd, False)
        pty_in = os.open(os.devnull, os.O_RDONLY)
        try:
            term = RawTerminal(in_fd=pty_in, out_fd=wr, plain=True)
            term.write = lambda s: os.write(wr, s.encode())     # record what it would have said
            import termios
            term._saved = None
            # entering and leaving write nothing; the mouse is refused outright
            term.enable_mouse()
            self.assertFalse(term.mouse)
            term.__exit__(None, None, None)
            with self.assertRaises(BlockingIOError):
                os.read(rd, 100)
        finally:
            for fd in (rd, wr, pty_in):
                os.close(fd)


# ---------------------------------------------------------------------------------------------
class TestModePlumbing(AddOnEnv):
    def test_text_is_a_way_to_show_an_app_not_a_kind_of_app(self):
        self.assertNotIn("text", MODES)               # a manifest cannot declare it
        self.assertIn("text", RUN_MODES)
        self.assertIn("text", RESERVED_NAMES)         # and no app can be called "text"
        self.assertTrue(supports_mode(("tui",), "text"))
        self.assertTrue(supports_mode(("tui", "graphical"), "text"))
        for modes in (("cmd",), ("graphical",), ()):
            self.assertFalse(supports_mode(modes, "text"))
        self.assertEqual((wire_mode("text"), wire_mode("tui"), wire_mode("graphical"), wire_mode("cmd")),
                         ("tui", "tui", "graphical", "cmd"))

    def test_the_app_is_told_tui(self):
        app = KApp(self.kapp.read_bytes())
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        plan = loader.plan(app, b.fileno(), "text")
        try:
            self.assertEqual(plan.env["KOS_MODE"], "tui")
        finally:
            plan.close()
            b.close()

    def test_the_protocol_takes_screen_in_text_mode_and_refuses_frames(self):
        ok = validate_app_message({"cmd": "screen", "title": "t", "lines": ["a\x1bb"], "status": ""}, "text")
        self.assertEqual(ok["lines"], ["ab"])
        with self.assertRaises(ProtocolError):
            validate_app_message({"cmd": "frame", "ops": []}, "text")
        req = validate_app_message({"cmd": "request", "action": "open", "app": "hello", "mode": "text"}, "text")
        self.assertEqual(req["mode"], "text")
        with self.assertRaises(ProtocolError):
            validate_app_message({"cmd": "request", "action": "open", "app": "hello", "mode": "plain"}, "text")

    def test_an_address_and_the_command_line_can_ask_for_text(self):
        self.assertEqual(address.parse("kos://hello?mode=text").mode, "text")
        self.assertEqual(cli._parse_run_target(["text", "hello"]), ("text", "hello"))
        with self.assertRaises(KAppError):
            cli._parse_run_target(["plain", "hello"])
        for words in ("run text hello", "ejecuta texto hello"):
            self.assertEqual(list(lang.interpret(words).argv)[:2], ["run", "text"], words)
        # a lone word is the app's name, never a mode
        self.assertEqual(list(lang.interpret("run raw").argv), ["run", "raw"])

    def test_the_layers_let_a_tui_app_run_as_text_and_still_refuse_what_it_cannot(self):
        spawned = []

        def spawner(inst, app, mode, policy, registry, log_path, cache_dir=None):
            spawned.append(inst.mode)
            inst.status, inst.broker_pid = "running", os.getpid()
            registry.write(inst)
        inst = open_background(self.paths, self.authority(PW), "hello", "text", spawner=spawner)
        self.assertEqual((spawned, inst.mode), (["text"], "text"))
        with self.assertRaises(KAppError) as cm:       # ext-hello has no graphical mode
            open_background(self.paths, self.authority(), "ext-hello", "graphical", spawner=spawner)
        self.assertEqual(cm.exception.layer, "gui")


# ---------------------------------------------------------------------------------------------
class TestGraphicsGuard(Layout):
    def test_a_normal_frame_passes_and_a_flood_ends_the_app(self):
        g = self.guard()
        for _ in range(200):
            g.frame(5000)                              # 200 full frames in a second: allowed
        with self.assertRaises(GuardRefused) as cm:
            g.frame(1)
        self.assertEqual((cm.exception.layer, cm.exception.check), ("graphics", "frame-budget"))
        self.assertIsInstance(cm.exception, ProtocolError)         # so the session kills the app
        self.assertEqual(self.audit.refused(), ["guard.graphics.frame-budget"])
        self.clock.advance(1000)
        g.frame(5000)                                  # a new second

    def test_the_budget_is_per_guard_so_one_app_cannot_spend_anothers(self):
        a, b = self.guard(), self.guard()
        for _ in range(200):
            a.frame(5000)
        b.frame(5000)


class TestTextGuard(Layout):
    def test_pages_are_budgeted(self):
        g = self.guard()
        for _ in range(guard.MAX_PAGES_PER_SEC):
            g.page(3)
        with self.assertRaises(GuardRefused) as cm:
            g.page(3)
        self.assertEqual((cm.exception.layer, cm.exception.check), ("text", "page-budget"))

    def test_lines_are_budgeted_too(self):
        g = self.guard()
        for _ in range(guard.MAX_PAGE_LINES_PER_SEC // 500):
            g.page(500)
        with self.assertRaises(GuardRefused):
            g.page(500)


class TestInputGuard(Layout):
    def ev(self, g, e, pointer=True, w=80, h=24):
        return g.input_event(e, w, h, pointer)

    def test_a_well_formed_key_passes_and_nothing_extra_comes_through(self):
        g = self.guard()
        for k in ("a", "Z", " ", "é", "世", "enter", "up", "pagedown", "f5", "ctrl-x", "ctrl-]"):
            self.assertEqual(self.ev(g, {"type": "key", "key": k, "evil": 1}), {"type": "key", "key": k}, k)

    def test_a_hostile_key_is_dropped_and_audited_and_the_app_lives(self):
        g = self.guard()
        for k in ("\x1b[2J", "ab c", "", "\x00", "a" * 17, "‮", 5, None, ["a"], "UP", "up\n"):
            self.assertIsNone(self.ev(g, {"type": "key", "key": k}), repr(k))
        self.assertIsNone(self.ev(g, {"type": "key"}))
        self.assertEqual(self.audit.refused(), ["guard.input.event-shape"] * guard.MAX_AUDITED_PER_CHECK)
        self.assertEqual(g.stats[("input", "event-shape")]["refused"], 12)    # all counted, few audited

    def test_unknown_and_malformed_events_are_dropped(self):
        g = self.guard()
        for e in ("key", None, 5, [], {}, {"type": "launch"}, {"type": "pointer", "x": "1", "y": 2},
                  {"type": "pointer", "x": True, "y": 2}, {"type": "pointer", "x": 1}, {"type": "button", "x": 1, "y": 1},
                  {"type": "button", "button": "x", "pressed": True, "x": 1, "y": 1},
                  {"type": "button", "button": "left", "pressed": 1, "x": 1, "y": 1},
                  {"type": "scroll", "x": 1, "y": 1}, {"type": "scroll", "dy": "1", "x": 1, "y": 1}):
            self.assertIsNone(self.ev(g, e), repr(e))

    def test_coordinates_are_clamped_to_the_screen(self):
        g = self.guard()
        self.assertEqual(self.ev(g, {"type": "pointer", "x": -50, "y": 10 ** 9}), {"type": "pointer", "x": 0, "y": 23})
        self.assertEqual(self.ev(g, {"type": "button", "button": "left", "pressed": False, "x": 999, "y": -1}),
                         {"type": "button", "button": "left", "pressed": False, "x": 79, "y": 0})
        self.assertEqual(self.ev(g, {"type": "scroll", "dy": -7, "x": 5, "y": 5}), {"type": "scroll", "dy": -1, "x": 5, "y": 5})

    def test_a_layer_with_no_pointer_drops_every_pointer_event_but_not_keys(self):
        g = self.guard()
        for e in ({"type": "pointer", "x": 1, "y": 1}, {"type": "scroll", "dy": 1, "x": 1, "y": 1},
                  {"type": "button", "button": "left", "pressed": True, "x": 1, "y": 1}):
            self.assertIsNone(self.ev(g, e, pointer=False))
        self.assertEqual(g.stats[("input", "event-shape")]["dropped"], 3)
        self.assertEqual(self.ev(g, {"type": "key", "key": "a"}, pointer=False), {"type": "key", "key": "a"})

    def test_pointer_movement_beyond_the_budget_is_dropped_but_a_click_never_is(self):
        g = self.guard()
        moves = [self.ev(g, {"type": "pointer", "x": 1, "y": 1}) for _ in range(guard.MAX_MOVES_PER_SEC + 10)]
        self.assertEqual(sum(m is None for m in moves), 10)
        click = {"type": "button", "button": "left", "pressed": False, "x": 1, "y": 1}
        self.assertIsNotNone(self.ev(g, click))      # a dropped release would leave a button stuck down
        self.clock.advance(1000)
        self.assertIsNotNone(self.ev(g, {"type": "pointer", "x": 1, "y": 1}))

    def test_ctrl_c_is_never_judged_or_delayed(self):
        g = self.guard()
        for _ in range(guard.MAX_MOVES_PER_SEC * 3):
            self.ev(g, {"type": "pointer", "x": 1, "y": 1})
        self.assertEqual(self.ev(g, {"type": "interrupt", "junk": 1}), {"type": "interrupt"})


class TestCommandsGuard(Layout):
    def test_a_message_flood_ends_the_app(self):
        g = self.guard()
        for _ in range(guard.MAX_MESSAGES_PER_SEC):
            g.message()
        with self.assertRaises(GuardRefused) as cm:
            g.message()
        self.assertEqual((cm.exception.layer, cm.exception.check), ("commands", "message-budget"))
        self.assertEqual(self.audit.refused(), ["guard.commands.message-budget"])

    def test_an_app_cannot_ask_for_the_password_over_and_over(self):
        g = self.guard()
        for _ in range(guard.MAX_PROMPTS_PER_MIN):
            self.assertIsNone(g.request("open"))
        why = g.request("close")
        self.assertIn("asked for your password", why)
        self.assertEqual(self.audit.refused(), ["guard.commands.prompt-budget"])
        self.assertIsNone(g.request("apps"))                 # reading a list asks for nothing
        self.clock.advance(60_000)
        self.assertIsNone(g.request("open"))                 # the owner has had a minute

    def test_after_enough_failures_every_request_is_refused_until_the_app_exits(self):
        g = self.guard()
        for _ in range(guard.MAX_FAILED_REQUESTS):
            self.assertIsNone(g.request("apps"))
            g.request_failed()
        self.assertIn("already failed", g.request("apps"))
        self.assertIn("already failed", g.request("open"))
        self.clock.advance(10 * 60_000)
        self.assertIn("already failed", g.request("open"))   # time does not forgive a hostile app
        self.assertIn("guard.commands.failed-requests", self.audit.refused())


class TestKernelAndHardwareGuards(Layout):
    def tree(self, **kw):
        return fake_proc(self.tmp.name, **kw)

    def attest(self, **kw):
        net = kw.pop("allow_network", False)
        proc = self.tree(**kw)
        return guard.attest_process(4242, allow_network=net, proc=proc)

    def test_a_confined_process_passes(self):
        self.assertEqual(self.attest(), [])
        g = self.guard(pid=4242, allow_network=False, proc=self.tree())
        g.attest(force=True)
        self.assertEqual(self.audit.records, [("guard.kernel.attest-process", "hello", "pass"),
                                              ("guard.hardware.no-device-handles", "hello", "pass")])

    def test_each_way_of_not_being_confined_is_refused_on_its_own(self):
        for kw, word in (({"uid": "0"}, "root"), ({"no_new_privs": "0"}, "privileges"),
                         ({"cap": "0000000000000400"}, "capabilities"), ({"seccomp": "0"}, "seccomp"),
                         ({"same_net": True}, "network namespace"), ({"same_user": True}, "user namespace")):
            with self.subTest(kw=kw):
                why = self.attest(**kw)
                self.assertEqual(len(why), 1, why)
                self.assertIn(word, why[0])

    def test_an_app_the_owner_let_onto_the_network_may_share_it_and_nothing_else_is_relaxed(self):
        self.assertEqual(self.attest(same_net=True, allow_network=True), [])
        self.assertEqual(self.attest(same_net=True, allow_network=None), [])        # not known: not judged
        self.assertTrue(self.attest(same_net=True, allow_network=True, uid="0"))

    def test_a_refusal_ends_the_app_and_is_audited(self):
        g = self.guard(pid=4242, allow_network=False, proc=self.tree(uid="0", same_net=True))
        with self.assertRaises(GuardRefused) as cm:
            g.attest(force=True)
        self.assertEqual((cm.exception.layer, cm.exception.check), ("kernel", "attest-process"))
        self.assertIn("root", str(cm.exception))
        self.assertEqual(self.audit.refused(), ["guard.kernel.attest-process"])

    def test_a_process_that_cannot_be_read_is_refused_but_one_that_has_gone_is_not(self):
        proc = self.tree()
        (Path(proc) / "4242" / "status").write_text("Name:\tx\n")           # unreadable fields: fail closed
        with self.assertRaises(GuardRefused):
            self.guard(pid=4242, allow_network=False, proc=proc).attest(force=True)
        self.guard(pid=999999, allow_network=False, proc=proc).attest(force=True)    # no such process: it exited
        os.chmod(Path(proc) / "4242" / "status", 0)
        if os.geteuid() != 0:                                                  # root reads anything
            with self.assertRaises(GuardRefused):
                self.guard(pid=4242, allow_network=False, proc=proc).attest(force=True)

    def test_the_check_is_repeated_but_not_more_than_every_two_seconds(self):
        proc = self.tree()
        g = self.guard(pid=4242, allow_network=False, proc=proc)
        g.attest()
        fake_proc(self.tmp.name, uid="0")                                      # the process changes under us
        g.attest()                                                             # too soon: not looked at
        self.clock.advance(guard.ATTEST_EVERY_MS)
        with self.assertRaises(GuardRefused):
            g.attest()

    def test_a_weak_sandbox_is_never_called_confined(self):
        g = self.guard(pid=4242, allow_network=False, weak=True, proc=self.tree(uid="0"))
        g.attest(force=True)                                                   # the kernel check is skipped ...
        self.assertEqual(self.audit.records[0], ("guard.kernel.attest-process", "hello", "weak"))   # ... loudly
        self.assertNotIn(("guard.kernel.attest-process", "hello", "pass"), self.audit.records)

    def test_no_pid_means_nothing_local_to_look_at(self):
        g = self.guard(pid=None)
        g.attest(force=True)
        self.assertEqual(self.audit.records, [])

    def test_a_device_handle_is_refused_even_under_a_weak_sandbox(self):
        for target in ("/dev/input/event3", "/dev/fb0", "/dev/kvm", "/dev/vhost-vsock", "/dev/mem",
                       "/dev/tty1", "/sys/class/gpio/export", "anon_inode:kvm-vm", "/dev/input/mice (deleted)"):
            with self.subTest(target=target):
                proc = fake_proc(self.tmp.name, fds=("/dev/null", "/dev/urandom", "socket:[7]", target))
                self.assertEqual(len(guard.device_handles(4242, proc)), 1)
                for weak in (False, True):
                    g = self.guard(pid=4242, allow_network=False, weak=weak, proc=proc)
                    with self.assertRaises(GuardRefused) as cm:
                        g.attest(force=True)
                    self.assertEqual((cm.exception.layer, cm.exception.check), ("hardware", "no-device-handles"))
                for f in (Path(proc) / "4242" / "fd").iterdir():
                    f.unlink()

    def test_the_handles_the_sandbox_itself_gives_are_fine(self):
        proc = fake_proc(self.tmp.name, fds=("/dev/null", "/dev/zero", "/dev/urandom", "/dev/random",
                                             "/memfd:hello (deleted)", "socket:[5]", "pipe:[6]", "/tmp/x/hello.log"))
        self.assertEqual(guard.device_handles(4242, proc), [])


@unittest.skipUnless(landlock_abi(), "this kernel has no Landlock: the sandbox would refuse to start")
class TestOnRealProcesses(Layout):
    def child(self, code, policy=None):
        kw = {"preexec_fn": policy.preexec()} if policy else {}
        p = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", code], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, **kw)
        self.addCleanup(lambda: (p.kill(), p.wait()))
        return p

    def test_a_process_in_the_real_sandbox_is_attested_and_holds_no_device(self):
        try:
            p = self.child("import time; time.sleep(30)", SandboxPolicy())
        except SandboxError as e:
            self.skipTest(f"cannot sandbox here: {e}")
        self.assertEqual(guard.attest_process(p.pid, allow_network=False, seccomp=guard.Guard("x").seccomp), [])
        self.assertEqual(guard.device_handles(p.pid), [])

    @unittest.skipUnless(os.path.exists("/dev/full"), "no /dev/full to hold open")
    def test_a_process_holding_a_device_is_refused(self):
        p = self.child("f = open('/dev/full', 'wb'); import time; time.sleep(30)")
        for _ in range(100):
            if guard.device_handles(p.pid):
                break
            time.sleep(0.05)
        self.assertEqual(len(guard.device_handles(p.pid)), 1)
        with self.assertRaises(GuardRefused) as cm:
            self.guard(pid=p.pid, allow_network=False).attest(force=True)
        self.assertIn(cm.exception.layer, ("kernel", "hardware"))

    def test_an_unconfined_process_is_refused(self):
        if os.geteuid() != 0:
            self.skipTest("a non-root test process is not root: the root check cannot be shown")
        p = self.child("import time; time.sleep(30)")
        why = guard.attest_process(p.pid, allow_network=False, seccomp=True)
        self.assertTrue(any("root" in w for w in why) and any("seccomp" in w for w in why), why)


# ---------------------------------------------------------------------------------------------
class AppThread:
    """Plays an app on the far end of a socket: ``script(send, event)`` is called for every message."""

    def __init__(self, sock, script, first=None):
        self.sock, self.script, self.got, self.first = sock, script, [], first
        self.t = threading.Thread(target=self.run, daemon=True)
        self.t.start()

    def send(self, obj):
        import json
        try:
            self.sock.sendall(json.dumps(obj).encode() + b"\n")
        except OSError:
            pass

    def run(self):
        import json
        f = self.sock.makefile("rb")
        try:
            for line in f:
                ev = json.loads(line)
                self.got.append(ev)
                if ev.get("cmd") == "hello" and self.first:
                    self.first(self.send)
                self.script(self.send, ev)
                if ev.get("cmd") == "quit":
                    return
        except (OSError, ValueError):
            pass


class SessionEnv(Env):
    def session(self, mode="text", surface=None, devices=None, bridge=None, **kw):
        a, b = socket.socketpair()
        self.addCleanup(b.close)
        self.devices = devices or ScriptedDevices()
        self.auth = Authority(self.paths, None, Throttle(self.paths, base=0))
        if surface is None:
            r, w = os.pipe()
            os.set_blocking(r, False)
            self.addCleanup(os.close, r)
            self.addCleanup(os.close, w)
            self.rfd = r
            surface = TextSurface(w, 80, 24, "hello")
        s = Session(name="hello", mode=mode, channel=Channel(a), proc=kw.pop("proc", None), surface=surface,
                    devices=self.devices, authority=self.auth, bridge=bridge, **kw)
        # A watchdog: if a guard under test fails to end the app, the session still ends (with code 0,
        # which the test then fails on) instead of hanging the whole suite.
        dog = threading.Timer(5.0, lambda: setattr(s, "stop_requested", True))
        dog.daemon = True
        dog.start()
        self.addCleanup(dog.cancel)
        return s, b

    def audit_actions(self):
        return [(e["action"], e["outcome"]) for e in self.auth.audit.entries()]

    def transcript(self):
        out = b""
        while True:
            try:
                chunk = os.read(self.rfd, 1 << 16)
            except BlockingIOError:
                break
            if not chunk:
                break
            out += chunk
        return out.decode()


class TestGuardsInASession(SessionEnv):
    def test_a_flood_of_messages_ends_the_app_and_is_in_the_audit_log(self):
        s, far = self.session(boot_devices=())
        app = AppThread(far, lambda send, ev: None,
                        first=lambda send: [send({"cmd": "log", "msg": "x"}) for _ in range(guard.MAX_MESSAGES_PER_SEC + 50)])
        self.assertEqual(s.run(first_frame_timeout=0.1), 125)
        self.assertIn(("guard.commands.message-budget", "refused"), self.audit_actions())

    def test_a_flood_of_pages_ends_the_app(self):
        s, far = self.session(boot_devices=())
        page = {"cmd": "screen", "title": "", "lines": ["x"], "status": ""}
        AppThread(far, lambda send, ev: None, first=lambda send: [send(page) for _ in range(guard.MAX_PAGES_PER_SEC + 20)])
        self.assertEqual(s.run(first_frame_timeout=0.1), 125)
        self.assertIn(("guard.text.page-budget", "refused"), self.audit_actions())

    def test_a_process_that_is_not_confined_ends_the_session_before_it_is_trusted(self):
        proc = fake_proc(self.tmp.name, uid="0")
        g = Guard("hello", pid=4242, allow_network=False, weak=False, seccomp=True, proc=proc)
        s, far = self.session(boot_devices=(), guard=g)
        g.audit = self.auth.audit
        AppThread(far, lambda send, ev: None)
        self.assertEqual(s.run(first_frame_timeout=0.1), 125)
        self.assertIn(("guard.kernel.attest-process", "refused"), self.audit_actions())

    def test_requests_that_keep_failing_stop_reaching_the_bridge(self):
        calls = []

        class Bridge:
            def handle(self, msg, reply, authority):
                calls.append(msg["action"])
                reply({"cmd": "result", "action": msg["action"], "ok": False, "detail": "no"})

        s, far = self.session(boot_devices=(), bridge=Bridge())
        req = {"cmd": "request", "action": "close", "id": "hello-abcdef"}

        def first(send):
            for _ in range(guard.MAX_FAILED_REQUESTS + 4):
                send(req)
            send({"cmd": "exit", "code": 0})
        app = AppThread(far, lambda send, ev: None, first=first)
        self.assertEqual(s.run(first_frame_timeout=0.1), 0)
        app.t.join(2)
        self.assertEqual(len(calls), guard.MAX_FAILED_REQUESTS)
        results = [e for e in app.got if e.get("cmd") == "result"]
        self.assertEqual(len(results), guard.MAX_FAILED_REQUESTS + 4)
        self.assertIn("already failed", results[-1]["detail"])

    def test_a_sixth_password_request_in_a_minute_is_not_asked(self):
        calls = []

        class Bridge:
            def handle(self, msg, reply, authority):
                calls.append(1)
                reply({"cmd": "result", "action": msg["action"], "ok": True, "detail": "done"})

        s, far = self.session(boot_devices=(), bridge=Bridge())

        def first(send):
            for _ in range(guard.MAX_PROMPTS_PER_MIN + 3):
                send({"cmd": "request", "action": "close", "id": "hello-abcdef"})
            send({"cmd": "exit", "code": 0})
        app = AppThread(far, lambda send, ev: None, first=first)
        self.assertEqual(s.run(first_frame_timeout=0.1), 0)
        app.t.join(2)
        self.assertEqual(len(calls), guard.MAX_PROMPTS_PER_MIN)
        self.assertIn("asked for your password", [e for e in app.got if e.get("cmd") == "result"][-1]["detail"])

    def test_a_bad_event_from_a_device_never_reaches_the_app(self):
        s, far = self.session(boot_devices=(), preboot=())
        s.booted.update(("keyboard", "mouse"))
        got = []
        app = AppThread(far, lambda send, ev: got.append(ev))
        self.devices.push({"type": "key", "key": "\x1b[2J"}, {"type": "key", "key": "a"},
                          {"type": "bogus"}, {"type": "key", "key": "escape"})
        threading.Timer(0.6, lambda: self.devices.push({"type": "interrupt"})).start()
        s.run(first_frame_timeout=0.1)
        app.t.join(2)
        keys = [e["key"] for e in app.got if e.get("cmd") == "key"]
        self.assertEqual(keys, ["a", "escape"])
        self.assertEqual(s.guard.stats[("input", "event-shape")]["refused"], 2)


class TestTextSession(SessionEnv):
    def test_text_mode_boots_only_the_keyboard_and_never_offers_the_mouse(self):
        s, far = self.session()
        self.assertFalse(s.has_pointer)
        self.assertEqual((s.device_names, s.boot_queue), (("keyboard",), ["keyboard"]))
        self.assertEqual(self.session(mode="tui", surface=__import__("kos.tui", fromlist=["x"]).TUISurface(1, 80, 24, "h"))[0].boot_queue,
                         ["mouse", "keyboard"])                                  # the other layers still offer it

    def test_the_whole_session_a_real_app_in_the_real_sandbox(self):
        if not landlock_abi():
            self.skipTest("no Landlock: the sandbox would refuse to start")
        store = AppStore(self.paths)
        store.install(self.kapp, self.authority(PW))
        with self.authority(PW).authorize("app.run", "hello") as g:
            app = store.load_verified("hello", g)
        a, b = socket.socketpair()
        proc = loader.launch(loader.plan(app, b.fileno(), "text"), SandboxPolicy(), None)
        b.close()
        r, w = os.pipe()
        os.set_blocking(r, False)
        self.rfd = r
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        devices = ScriptedDevices()
        self.auth = Authority(self.paths, None, Throttle(self.paths, base=0))
        s = Session(name="hello", mode="text", channel=Channel(a), proc=proc,
                    surface=TextSurface(w, 80, 24, "hello"), devices=devices, authority=self.auth,
                    allow_network=False)
        keys = lambda text: [{"type": "key", "key": c} for c in text]
        devices.push(*keys("y"), *keys(PW), {"type": "key", "key": "enter"})        # boot the keyboard
        devices.push({"type": "button", "button": "left", "pressed": True, "x": 3, "y": 3},
                     {"type": "pointer", "x": 4, "y": 4}, *keys("hi"))
        threading.Timer(3.0, lambda: devices.push({"type": "key", "key": "escape"})).start()
        code = s.run(first_frame_timeout=5)
        self.assertEqual(code, 0)
        self.assertEqual(devices.booted, ["keyboard"])                              # never the mouse
        text = self.transcript()
        self.assertNotIn("\x1b", text)
        self.assertNotIn(PW, text)                                                  # the password is never printed
        self.assertIn("SECURE PROMPT", text)
        self.assertIn("app| " + "  Welcome to KOS", text)
        self.assertIn("You typed             : hi", text)
        self.assertIn("Mouse clicks          : 0", text)                           # the click went nowhere
        for line in text.split("\r\n"):
            self.assertTrue(line == "" or line.startswith((OS_PREFIX, APP_PREFIX)), repr(line))
        # every layer's guard really ran on this session, and the real process was found confined
        for layer, check in guard.describe():
            if (layer, check) in (("graphics", "frame-budget"), ("commands", "prompt-budget"),
                                  ("commands", "failed-requests")):
                continue            # a text session draws no frames and asks for nothing
            self.assertIn("pass", s.guard.stats.get((layer, check), {}), f"{layer}/{check} never ran")
        self.assertNotIn("refused", s.guard.stats.get(("kernel", "attest-process"), {}))
        self.assertIn(("guard.kernel.attest-process", "pass"), self.audit_actions())
        self.assertIn(("guard.hardware.no-device-handles", "pass"), self.audit_actions())
        self.assertEqual(s.guard.stats[("input", "event-shape")]["dropped"], 2)     # the click and the move


if __name__ == "__main__":
    unittest.main()
