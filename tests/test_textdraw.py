"""``text`` mode: the same draw commands drawn with characters (kos/textdraw.py), and the rule that a system
app ships both text and graphical.

What is proved by a test that tries to break it (not by Z3): what is drawn is what a click hits; an app's text can
never put an escape sequence on the terminal; one frame can only do a bounded amount of work; the protocol and the
manifest refuse what they should; every OS app really draws in both frame modes; a click reaches the app as a
command at the centre of the cell."""

from __future__ import annotations

import json
import random
import re
import socket
import sys
import time
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos import font  # noqa: E402
from kos.address import parse as parse_address  # noqa: E402
from kos.display import Modal, render_text_modal  # noqa: E402
from kos.kapp import MODES, SYSTEM_MODES, KAppError, Manifest, is_system_app  # noqa: E402
from kos.office import pack_os, pack_system, ui  # noqa: E402
from kos.office.ui import FakeHost, Screen, button_at, page_canvas, run  # noqa: E402
from kos.protocol import Channel, ProtocolError, validate_app_message  # noqa: E402
from kos.session import Session  # noqa: E402
from kos.textdraw import (CELL_H, CELL_W, MAX_COLS, MAX_ROWS, WORK_BUDGET, TextDrawSurface,  # noqa: E402
                          luminance, safe_char)

WHITE, BLACK = "#ffffff", "#000000"
CSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def surface(cols=40, rows=12, ascii_only=True):
    return TextDrawSurface(-1, cols, rows, "hello", ascii_only=ascii_only)


def frame(ops):
    return {"cmd": "frame", "ops": ops}


def manifest(**kw):
    d = {"name": "x", "version": "1", "runtime": "python", "entry": "app:main"}
    d.update(kw)
    return Manifest.parse(json.dumps(d).encode())


class TestDrawing(unittest.TestCase):
    def test_a_frame_is_drawn_with_text(self):
        s = surface()
        s.present(frame([["clear", BLACK],
                         ["rect", 12, 12, 36, 36, WHITE],
                         ["text", 18, 26, "HI", BLACK, 1],
                         ["line", 0, 108, 119, 108, WHITE],
                         ["line", 60, 0, 60, 119, WHITE]]))
        rows = s.rows_text()
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(len(r) == 40 for r in rows))
        self.assertEqual(rows[1][:10], "  +----+  ")                    # a big rectangle gets a box ...
        self.assertEqual(rows[2][:10], "  |HI##|  ")                    # ... shaded inside, with its text on it
        self.assertEqual(rows[3][:10], "  +----+  ")
        self.assertEqual(rows[9][:20], "----------+---------")          # a horizontal rule, crossed by ...
        self.assertEqual([r[10] for r in rows[:9]], ["|"] * 9)           # ... a vertical one: + where they meet
        self.assertIn("\x1b[7mHI", s.compose())                          # dark text on a bright fill is reversed

    def test_the_unicode_alphabet_is_used_unless_ascii_is_asked_for(self):
        s = surface(ascii_only=False)
        s.present(frame([["clear", BLACK], ["rect", 12, 12, 36, 36, WHITE], ["line", 0, 108, 119, 108, WHITE]]))
        rows = s.rows_text()
        self.assertEqual(rows[1][2:8], "┌────┐")
        self.assertEqual(rows[2][2:8], "│████│")
        self.assertEqual(rows[9][:3], "───")

    def test_a_frame_changes_the_last_one_and_clear_starts_blank(self):
        s = surface()
        s.present(frame([["text", 0, 0, "ONE", WHITE, 1]]))
        s.present(frame([["text", 0, 12, "TWO", WHITE, 1]]))
        self.assertEqual([r[:3] for r in s.rows_text()[:2]], ["ONE", "TWO"])
        s.present(frame([["clear", BLACK]]))
        self.assertEqual(set("".join(s.rows_text())), {" "})

    def test_a_space_is_transparent_like_the_graphical_font(self):
        s = surface()
        s.present(frame([["rect", 0, 0, 60, 12, WHITE], ["text", 0, 0, "a b", BLACK, 1]]))
        self.assertEqual(s.rows_text()[0][:5], "a#b##")

    def test_thin_rectangles_are_rules_and_tiny_ones_still_show(self):
        s = surface()
        s.present(frame([["rect", 0, 24, 120, 1, WHITE],        # a 1-pixel-high divider: ----
                         ["rect", 30, 36, 1, 60, WHITE],        # a 1-pixel-wide divider: |||
                         ["rect", 90, 108, 2, 2, WHITE],        # a dot
                         ["rect", 100, 10, 6, 8, WHITE]]))      # too small to hold a cell centre: still seen
        rows = s.rows_text()
        self.assertEqual(rows[2][:20], "-" * 20)
        self.assertEqual([rows[r][5] for r in (3, 4, 5, 6)], ["|"] * 4)
        self.assertEqual(rows[9][15], ".")
        self.assertEqual(rows[1][17], "#")                               # in the one cell around its middle

    def test_what_is_drawn_is_what_a_click_hits(self):
        """The button clicker's whole promise in text mode: a click is reported at the centre of its cell, and a
        rectangle fills a cell exactly when that centre is inside it."""
        rng = random.Random(20260713)
        for n in range(300):
            x, y = rng.randint(-30, 250), rng.randint(-30, 130)
            w, h = rng.randint(CELL_W, 200), rng.randint(CELL_H, 100)
            s = surface(40, 12)
            s.present(frame([["rect", x, y, w, h, WHITE]]))
            for r in range(s.body):
                for c in range(s.cols):
                    px, py = s.to_app_coords(c, r + 1)
                    inside = x <= px < x + w and y <= py < y + h
                    self.assertEqual(s.grid[r][c][1] == 255, inside, (n, (x, y, w, h), (c, r)))

    def test_a_rectangle_off_any_edge_never_damages_the_grid(self):
        for rect in ((-500, 0, 100, 50), (-500, -500, 100, 100), (500, 0, 50, 50), (0, -500, 50, 100),
                     (0, 500, 50, 50), (-10 ** 6, -10 ** 6, 10, 10), (10 ** 6, 10 ** 6, 10, 10)):
            s = surface(40, 12)
            s.present(frame([["clear", BLACK], ["rect", *rect, WHITE]]))
            self.assertEqual({len(r) for r in s.grid}, {40}, rect)
            self.assertEqual(len(s.grid), 10, rect)
            self.assertEqual(set("".join(s.rows_text())), {" "}, rect)       # and nothing is drawn

    def test_cell_centres_map_both_ways(self):
        s = surface(40, 12)
        self.assertEqual(s.hello_size(), (40 * CELL_W, 10 * CELL_H))
        for c, r in ((0, 0), (5, 3), (39, 9)):
            px, py = s.to_app_coords(c, r + 1)                   # terminal row 0 is the OS's title bar
            self.assertEqual((px // CELL_W, py // CELL_H), (c, r))
            self.assertEqual((px % CELL_W, py % CELL_H), (CELL_W // 2, CELL_H // 2))

    def test_a_letter_is_one_cell_wide_so_text_lines_up_with_the_pixels_apps_use(self):
        self.assertEqual((CELL_W, CELL_H), (font.ADVANCE, 12))
        s = surface()
        s.present(frame([["text", 6 * 7, 12 * 3, "ABC", WHITE, 1], ["text", 0, 0, "AB", WHITE, 3]]))
        self.assertEqual(s.rows_text()[3][7:10], "ABC")
        self.assertEqual(s.rows_text()[0][:6], "A  B  ")                 # scale 3 spaces letters 3 cells apart


class TestTheOsStaysInControl(unittest.TestCase):
    def test_the_bars_the_pointer_and_the_password_overlay_are_the_oss(self):
        s = surface()
        s.set_status(" hello [text] mouse | Ctrl-C quits")
        s.set_pointer(5, 3)
        s.present(frame([["text", 0, 12 * 40, "FAKE STATUS", WHITE, 1], ["text", 0, -12, "FAKE TITLE", WHITE, 1]]))
        out = s.compose()
        self.assertIn(" KOS > hello [text]", out)                       # the title bar names the app, always
        self.assertIn("mouse | Ctrl-C quits", out)             # the status bar says which devices it has
        self.assertNotIn("FAKE", out)                                   # text outside the drawing area goes nowhere
        self.assertIn("\x1b[4;6H\x1b[7m", out)                          # the pointer: row 3 -> terminal row 4
        modal = Modal("Password for hello", ["type it"], secret_len=3)
        s.set_modal(modal)
        shown = s.compose()
        self.assertTrue(shown.endswith(render_text_modal(modal, s.cols, s.rows)))      # drawn last, over everything
        s.present(frame([["clear", WHITE], ["rect", 0, 0, 999, 999, WHITE], ["text", 0, 0, "PASSWORD", BLACK, 1]]))
        self.assertTrue(s.compose().endswith(render_text_modal(modal, s.cols, s.rows)))  # an app cannot cover it

    def test_hostile_text_can_never_put_an_escape_sequence_on_the_terminal(self):
        evil = ("\x1b[2J\x1b]0;pwned\x07\x1bc \x9b31m ‮reversed⁦ é 漢字 "
                "\x00\x08\x7f  ﻿ ퟿ \U0010ffff \U0001f600")
        for ascii_only in (True, False):
            s = surface(ascii_only=ascii_only)
            s.present(frame([["text", 0, 0, evil, WHITE, 1], ["text", 0, 12, "x" + evil, BLACK, 2]]))
            out = s.compose()
            rest = CSI.sub("", out)                                     # take away the OS's own sequences ...
            self.assertNotIn("\x1b", rest)                              # ... and no other one is left
            for bad in ("\x07", "\x9b", "\x00", "\x08", "\x7f", "‮", "⁦", " ", "﻿", "́",
                        "漢"):
                self.assertNotIn(bad, rest)
            if ascii_only:
                self.assertTrue(rest.isascii())                         # the serial-console alphabet is ASCII only

    def test_safe_char(self):
        self.assertEqual([safe_char(c) for c in "a\x1b\x00\x7f\x9b‮́漢\ud800 "],
                         ["a", "?", "?", "?", "?", "?", "?", "?", "?", " "])
        self.assertEqual(safe_char("é"), "é")
        self.assertEqual(safe_char("é", ascii_only=True), "?")
        self.assertEqual(safe_char("ab"), "?")                           # exactly one character or nothing
        self.assertEqual(safe_char(""), "?")

    def test_the_app_name_in_the_title_bar_is_vetted_too(self):
        s = TextDrawSurface(-1, 40, 12, "a\x1b[31mb", ascii_only=True)
        self.assertNotIn("\x1b[31m", s.compose())

    def test_a_frame_can_only_do_a_bounded_amount_of_work(self):
        s = TextDrawSurface(-1, MAX_COLS, MAX_ROWS, "hello", ascii_only=True)
        per_clear = s.cols * s.body
        started = time.monotonic()
        s.present(frame([["clear", WHITE]] * 5000))
        took = time.monotonic() - started
        done = WORK_BUDGET // per_clear
        self.assertEqual(s.last_dropped, 5000 - done)                    # the rest are dropped, and counted
        self.assertLess(took, 5.0)
        self.assertIn("draw op(s) dropped", s.compose())                 # and the OS says so on its status bar
        s2 = TextDrawSurface(-1, MAX_COLS, MAX_ROWS, "hello", ascii_only=True)
        started = time.monotonic()
        s2.present(frame([["line", -16384, -16384, 16384, 16384, WHITE]] * 5000))
        self.assertLess(time.monotonic() - started, 10.0)

    def test_the_grid_is_bounded_whatever_the_terminal_says(self):
        s = TextDrawSurface(-1, 10 ** 6, 10 ** 6, "hello")
        self.assertEqual((s.cols, s.rows), (MAX_COLS, MAX_ROWS))
        tiny = TextDrawSurface(-1, 0, 0, "hello")
        self.assertGreaterEqual(tiny.cols, 8)
        self.assertGreaterEqual(tiny.body, 2)

    def test_malformed_ops_and_extreme_coordinates_are_dropped_not_fatal(self):
        s = surface()
        bad = [[], ["bogus"], ["rect", "a", 1, 2, 3, WHITE], ["rect", 1, 2], ["line", None, 0, 0, 0, WHITE],
               ["text", 0, 0, 5, WHITE, 1], ["text", 0, 0, "ok", 12345, 1], ["text", 0, 0, "ok", WHITE, -4],
               "rect", 7, None]
        good = [["rect", -10 ** 9, -10 ** 9, 2 * 10 ** 9, 2 * 10 ** 9, WHITE], ["rect", 0, 0, -5, 10, WHITE],
                ["text", -10 ** 9, 0, "off", WHITE, 1], ["text", 10 ** 9, 0, "off", WHITE, 1]]
        s.present(frame(bad + good))
        self.assertGreaterEqual(s.dropped, 8)
        self.assertEqual(len(s.rows_text()), 10)
        self.assertEqual(luminance("not a colour"), 0)
        self.assertEqual(luminance("#fff"), 0)
        self.assertEqual(luminance(WHITE), 255)


class TestProtocol(unittest.TestCase):
    def test_a_text_app_draws_with_frames_and_not_with_a_text_page(self):
        ok = {"cmd": "frame", "ops": [["clear", "#101820"], ["rect", 0, 0, 10, 10, WHITE],
                                      ["line", 0, 0, 5, 5, WHITE], ["text", 1, 1, "hi", WHITE, 2]]}
        self.assertEqual(validate_app_message(ok, "text")["ops"][3], ["text", 1, 1, "hi", WHITE, 2])
        self.assertEqual(validate_app_message(ok, "graphical")["cmd"], "frame")
        with self.assertRaises(ProtocolError):
            validate_app_message({"cmd": "screen", "title": "t", "lines": [], "status": ""}, "text")
        with self.assertRaises(ProtocolError):
            validate_app_message(ok, "tui")
        with self.assertRaises(ProtocolError):
            validate_app_message(ok, "cmd")

    def test_frames_in_text_mode_are_as_hostile_proof_as_in_graphical_mode(self):
        for ops in ([["rect", 0, 0, 1.5, 1, WHITE]], [["rect", 0, 0, 1, 1, "red"]], [["rect", 10 ** 6, 0, 1, 1, WHITE]],
                    [["rect", True, 0, 1, 1, WHITE]], [["teleport"]], [["clear"]], [["text", 0, 0, "x", WHITE, 99]],
                    [["clear", WHITE]] * 5001, "ops", None):
            with self.subTest(ops=str(ops)[:40]), self.assertRaises(ProtocolError):
                validate_app_message({"cmd": "frame", "ops": ops}, "text")
        cleaned = validate_app_message({"cmd": "frame", "ops": [["text", 0, 0, "a\x1b[2Jb‮", WHITE]]}, "text")
        self.assertEqual(cleaned["ops"][0][3], "a[2Jb")                  # the protocol strips controls first

    def test_open_accepts_the_text_mode_and_nothing_made_up(self):
        for mode in ("tui", "graphical", "text", "cmd"):
            msg = validate_app_message({"cmd": "request", "action": "open", "app": "hello", "mode": mode}, "tui")
            self.assertEqual(msg["mode"], mode)
        for mode in ("texty", "TEXT", "", None, 3, ["text"]):
            with self.subTest(mode=mode), self.assertRaises(ProtocolError):
                validate_app_message({"cmd": "request", "action": "open", "app": "hello", "mode": mode}, "tui")
        self.assertEqual(parse_address("kos://hello?mode=text").mode, "text")


class TestSystemAppsShipTextAndGraphical(unittest.TestCase):
    def test_text_is_a_mode(self):
        self.assertIn("text", MODES)
        self.assertEqual(manifest(modes=["text"]).modes, ("text",))
        with self.assertRaises(KAppError):
            manifest(modes=["texts"])

    def test_an_ordinary_app_may_ship_any_modes(self):
        for modes in (["tui"], ["text"], ["graphical"], ["cmd"]):
            self.assertEqual(manifest(modes=modes).modes, tuple(modes))
        manifest(permissions=["network", "storage"])
        manifest(name="backup.add", permissions=["ask:backup_add", "storage"], modes=["tui"])   # a program, not a system app

    def test_a_system_app_without_both_is_refused_when_its_manifest_is_read(self):
        cases = [dict(name="taskbar"), dict(permissions=["system"]), dict(permissions=["service:audit"]),
                 dict(permissions=["storage", "service:files", "uses:notes"])]
        for extra in cases:
            for modes in (["tui"], ["tui", "graphical"], ["tui", "text"], ["text"], ["graphical"], ["cmd"]):
                with self.subTest(extra=extra, modes=modes):
                    with self.assertRaises(KAppError) as cm:
                        manifest(modes=modes, **extra)
                    self.assertIn("text and graphical", str(cm.exception))
            self.assertEqual(set(manifest(modes=["tui", "text", "graphical"], **extra).modes),
                             {"tui", "text", "graphical"})
            self.assertEqual(manifest(modes=["graphical", "text"], **extra).modes, ("graphical", "text"))

    def test_the_default_modes_do_not_slip_a_system_app_through(self):
        with self.assertRaises(KAppError):
            manifest(permissions=["system"])                              # no "modes" key: the default is tui only

    def test_which_apps_are_system_apps(self):
        self.assertTrue(is_system_app("taskbar", []))
        self.assertTrue(is_system_app("anything", ["system"]))
        self.assertTrue(is_system_app("anything", ["service:audit"]))
        self.assertFalse(is_system_app("notes", ["storage", "network", "ai", "owns:x", "ask:apps"]))
        self.assertEqual(SYSTEM_MODES, ("text", "graphical"))

    def test_the_shipped_system_apps_say_so_in_their_manifests(self):
        for path in ("examples/system/taskbar", "examples/system/app-library", "examples/backup"):
            m = Manifest.parse((ROOT / path / "manifest.json").read_bytes())
            self.assertTrue(set(SYSTEM_MODES) <= set(m.modes), path)
        from kos import sysapps
        for e in sysapps.entries():
            m = Manifest.parse(json.dumps(sysapps.manifest(e)).encode())
            self.assertTrue(set(SYSTEM_MODES) <= set(m.modes), e.name)

    def test_every_os_app_really_draws_in_text_and_in_graphical_mode(self):
        """Not just a manifest line: build every OS app's first screen and check it is sent as validated draw ops,
        never as a text page (which the protocol would refuse in these modes)."""
        from kos import sysapps
        entries = sysapps.entries()
        self.assertGreaterEqual(len(entries), 14)
        for mode in ("text", "graphical"):
            for e in entries:
                with self.subTest(app=e.name, mode=mode):
                    h = FakeHost([], mode=mode, width=480, height=192)
                    run(h, e.args["make"](h, e))
                    self.assertEqual(h.frames, [])                      # nothing was sent as a text page
                    self.assertTrue(h.canvases)
                    msg = validate_app_message({"cmd": "frame", "ops": h.canvases[-1]}, mode)
                    self.assertGreater(len(msg["ops"]), 4)


class Pager(Screen):
    title = "Pager"

    def __init__(self):
        self.keys = []

    def render(self, w, h):
        return ["line one", "line two"]

    def key(self, k):
        self.keys.append(k)


class TestTheButtonClicker(unittest.TestCase):
    W, H = 80 * CELL_W, 16 * CELL_H

    def buttons(self, fill=True):
        return page_canvas(self.W, self.H, "Pager", ["a"], "", fill_buttons=fill)[1]

    def click(self, x, y):
        return {"cmd": "button", "button": "left", "pressed": True, "x": x, "y": y}

    def centre(self, key, fill=True):
        bx, by, bw, bh, _ = next(b for b in self.buttons(fill) if b[4] == key)
        return bx + bw // 2, by + bh // 2

    def test_clicking_a_button_is_pressing_its_key_in_both_frame_modes(self):
        for mode in ("graphical", "text"):
            with self.subTest(mode=mode):
                pager = Pager()
                script = [self.click(*self.centre(k, mode == "graphical")) for k in ("down", "down", "up", "enter")]
                h = FakeHost(script, mode=mode, width=self.W, height=self.H)
                run(h, pager)
                self.assertEqual(pager.keys, ["down", "down", "up", "enter"])
                self.assertEqual(len(h.canvases), 1 + 4)                 # drawn after hello and after every click
                self.assertEqual(h.frames, [])

    def test_the_back_button_leaves_the_app_like_escape(self):
        h = FakeHost([self.click(*self.centre("escape"))], mode="text", width=self.W, height=self.H)
        run(h, Pager())
        self.assertEqual(h.exited, 0)

    def test_only_a_left_press_on_a_button_counts(self):
        pager = Pager()
        x, y = self.centre("down")
        script = [{**self.click(x, y), "button": "right"}, {**self.click(x, y), "pressed": False},
                  self.click(x + 500, y), self.click(x, y - 100), self.click(-5, -5),
                  {"cmd": "button", "button": "left", "pressed": True, "x": "7", "y": None},
                  {"cmd": "button", "button": "left", "pressed": True, "x": True, "y": True},
                  {"cmd": "pointer", "x": x, "y": y}]
        run(FakeHost(script, mode="text", width=self.W, height=self.H), pager)
        self.assertEqual(pager.keys, [])
        self.assertIsNone(button_at(self.buttons(), 1.5, 2.5))

    def test_what_is_drawn_as_a_button_in_text_mode_is_exactly_what_a_click_on_it_hits(self):
        h = FakeHost([], mode="text", width=self.W, height=self.H)
        run(h, Pager())
        s = TextDrawSurface(-1, 80, 18, "pager", ascii_only=True)
        self.assertEqual(s.hello_size(), (self.W, self.H))
        s.present(frame(h.canvases[-1]))
        rows = s.rows_text()
        bar = next(r for r, line in enumerate(rows) if "[ Back ]" in line)
        buttons = self.buttons(False)
        for label, key in ui.BUTTONS:
            col = rows[bar].index(f"[ {label} ]")
            for c in range(col, col + len(label) + 4):                   # every cell of "[ Label ]", brackets too
                px, py = s.to_app_coords(c, bar + 1)
                self.assertEqual(button_at(buttons, px, py), key, (label, c))
            for c in (col - 1, col + len(label) + 4):                    # the cell either side is not part of it
                px, py = s.to_app_coords(c, bar + 1)
                self.assertIsNone(button_at(buttons, px, py), (label, c))

    def test_a_screen_with_its_own_canvas_keeps_it_and_gets_no_buttons(self):
        class Own(Pager):
            def canvas(self, w, h):
                from kos.sdk import Canvas
                return Canvas().clear("#000000").text(0, 0, "mine", WHITE)
        own = Own()
        x, y = self.centre("down")
        h = FakeHost([self.click(x, y)], mode="text", width=self.W, height=self.H)
        run(h, own)
        self.assertEqual(own.keys, [])                                   # no buttons were drawn, so none were hit
        self.assertEqual(h.canvases[0][1], ["text", 0, 0, "mine", WHITE, 1])

    def test_the_page_is_drawn_from_the_lines_within_what_validates(self):
        cv, buttons = page_canvas(self.W, self.H, "T" * 500, ["x" * 900] * 400, "s" * 900)
        msg = validate_app_message({"cmd": "frame", "ops": cv.ops}, "text")
        self.assertEqual(len(msg["ops"]), len(cv.ops))
        self.assertEqual(len(buttons), 4)
        self.assertTrue(all(bx % CELL_W == 0 and by % CELL_H == 0 and bw % CELL_W == 0 for bx, by, bw, _, _ in buttons))


class TestInASession(unittest.TestCase):
    """The OS side: a click becomes a command at the centre of the cell, and the app's frame lands on the grid."""

    def setUp(self):
        self.a, self.b = socket.socketpair()
        self.addCleanup(self.a.close)
        self.addCleanup(self.b.close)
        self.surface = TextDrawSurface(-1, 40, 12, "hello", ascii_only=True)
        self.session = Session(name="hello", mode="text", channel=Channel(self.a), proc=None, surface=self.surface,
                               devices=None, authority=types.SimpleNamespace(prompter=None))
        self.session.booted = {"mouse", "keyboard"}

    def sent(self):
        self.b.settimeout(1)
        return [json.loads(line) for line in self.b.recv(65536).decode().splitlines()]

    def test_hello_tells_the_app_the_size_of_the_drawing_area(self):
        self.session._send({"cmd": "hello", "mode": self.session.mode, "width": self.surface.hello_size()[0],
                            "height": self.surface.hello_size()[1]})
        self.assertEqual(self.sent(), [{"cmd": "hello", "mode": "text", "width": 240, "height": 120}])

    def test_a_click_reaches_the_app_at_the_centre_of_its_cell(self):
        self.session.route({"type": "button", "button": "left", "pressed": True, "x": 5, "y": 4})
        self.session.route({"type": "pointer", "x": 0, "y": 1})
        self.session.route({"type": "scroll", "dy": 1, "x": 39, "y": 10})
        self.assertEqual(self.sent(), [
            {"cmd": "button", "button": "left", "pressed": True, "x": 5 * 6 + 3, "y": 3 * 12 + 6},
            {"cmd": "pointer", "x": 3, "y": 6},
            {"cmd": "scroll", "dy": 1, "x": 39 * 6 + 3, "y": 9 * 12 + 6}])

    def test_the_app_sends_a_frame_and_the_os_draws_it(self):
        self.b.sendall((json.dumps({"cmd": "frame", "ops": [["clear", BLACK], ["text", 6, 12, "OK", WHITE, 1]]})
                        + "\n").encode())
        time.sleep(0.05)
        self.session.handle_app()
        self.assertTrue(self.surface.has_content)
        self.assertEqual(self.surface.rows_text()[1][:4], " OK ")
        self.b.sendall((json.dumps({"cmd": "screen", "title": "t", "lines": [], "status": ""}) + "\n").encode())
        time.sleep(0.05)
        with self.assertRaises(ProtocolError):                           # a text page is not a thing in text mode
            self.session.handle_app()

    def test_no_mouse_booted_means_no_click_reaches_the_app(self):
        self.session.booted = {"keyboard"}
        self.session.route({"type": "button", "button": "left", "pressed": True, "x": 5, "y": 4})
        self.b.setblocking(False)
        with self.assertRaises(BlockingIOError):
            self.b.recv(100)


class TestTheCommandLine(unittest.TestCase):
    def test_run_and_open_take_text(self):
        from kos import cli
        self.assertEqual(cli._parse_run_target(["text", "hello"]), ("text", "hello"))
        self.assertEqual(cli._parse_run_target(["hello"]), ("tui", "hello"))
        with self.assertRaises(KAppError):
            cli._parse_run_target(["texty", "hello"])
        args = cli.build_parser().parse_args(["open", "text", "hello"])
        self.assertEqual((args.mode, args.name), ("text", "hello"))
        self.assertTrue(cli.build_parser().parse_args(["boot", "desktop", "--text"]).text)

    def test_the_surface_for_text_mode_is_the_text_drawing_one_with_terminal_input(self):
        from kos import cli
        term = types.SimpleNamespace(size=lambda: (100, 30))
        surf, devices = cli._build_surface("text", "hello", term)
        self.assertIsInstance(surf, TextDrawSurface)
        self.assertEqual((surf.cols, surf.rows), (100, 30))
        self.assertFalse(devices.cell_to_pixels)             # clicks arrive as cells; the surface maps them to pixels


if __name__ == "__main__":
    unittest.main()
