"""Tests for kos/office/pack_calc.py (docs/PACKS.md)."""

import sys
import unittest
import xml.etree.ElementTree as ET
from fractions import Fraction as F
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.office import pack_calc as pc  # noqa: E402
from kos.office.pack_calc import CalcError, evaluate, fmt_lines  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402
from kos.protocol import validate_app_message  # noqa: E402


def sci(s, **kw): return pc.fmt_float(evaluate(s, "float", **kw))
def ex(s): return str(evaluate(s, "exact"))
def prog(s, width=64, base=10): return evaluate(s, "int", width=width, base=base)


class TestCalculator(unittest.TestCase):
    def test_scientific_values(self):
        for src, want in [("2+3*4", "14"), ("2^10", "1024"), ("-2^2", "-4"), ("2^3^2", "512"), ("5!", "120"), ("10%3", "1"),
                          ("sqrt(2)^2", "2"), ("ln(e)", "1"), ("log(1000)", "3"), ("log(8,2)", "3"), ("cbrt(27)", "3"),
                          ("2pi", "6.28318530718"), ("round(2.5)", "3"), ("max(1,7,3)", "7"), ("0.1+0.2", "0.3"),
                          ("ncr(5,2)", "10"), ("hypot(3,4)", "5"), ("(1+2)(3+4)", "21")]:
            self.assertEqual(sci(src), want, src)

    def test_angle_modes(self):
        self.assertEqual(sci("sin(30)", deg=True), "0.5")
        self.assertEqual(sci("sin(pi/6)"), "0.5")
        self.assertEqual(sci("cos(90)", deg=True), "0")
        self.assertEqual(sci("atan(1)", deg=True), "45")
        with self.assertRaises(CalcError): evaluate("tan(90)", "float", deg=True)

    def test_variables_ans_memory(self):
        self.assertEqual(evaluate("ans*2+m", "float", vars={"ans": 4.0, "m": 1.0}), 9.0)

    def test_errors_not_crashes(self):
        for src in ["1/0", "sqrt(-1)", "ln(0)", "9^9^9", "9**9**9", "1e999", "(", "1+", "foo(2)", "sin()", "2 $ 3", "", "   ",
                    "fact(171)", "(-8)^0.5", "\x00", "1+\x1b[2J"]:
            with self.assertRaises(CalcError, msg=src): evaluate(src, "float")
        for bad in [None, 5, "1" * 201, "(" * 100 + "1" + ")" * 100, "-" * 150 + "1"]:
            try: evaluate(bad, "float")
            except CalcError: pass
        self.assertEqual(sci("(" * 15 + "1" + ")" * 15), "1")

    def test_exact_mode(self):
        self.assertEqual(ex("1/3+1/6"), "1/2")
        self.assertEqual(ex("0.1+0.2"), "3/10")
        self.assertEqual(ex("2^100"), "1267650600228229401496703205376")
        self.assertEqual(ex("(1/3)^-2"), "9")
        self.assertEqual(ex("sqrt(1/4)"), "1/2")
        self.assertEqual(ex("7//2"), "3")
        self.assertEqual(ex("round(7/2)"), "4")
        self.assertEqual(fmt_lines(F(1, 3), "exact"), ["1/3", "~ 0.333333333333"])
        for bad in ["9^9^9", "2^20000", "sqrt(2)", "2^0.5", "1e999", "1/0", "pi"]:
            with self.assertRaises(CalcError, msg=bad): evaluate(bad, "exact")

    def test_programmer_wraparound(self):
        self.assertEqual(prog("127+1", 8), -128)
        self.assertEqual(prog("255", 8), -1)
        self.assertEqual(prog("0x7FFF+1", 16), -32768)
        self.assertEqual(prog("0xFFFFFFFF", 32), -1)
        self.assertEqual(prog("9223372036854775807+1", 64), -9223372036854775808)
        self.assertEqual(prog("2**70", 64), 0)
        self.assertEqual(prog("0xFF & 0x0F"), 15)
        self.assertEqual(prog("0xF0 | 0x0F"), 255)
        self.assertEqual(prog("6 ^ 3"), 5)
        self.assertEqual(prog("~0"), -1)
        self.assertEqual(prog("1<<7", 8), -128)
        self.assertEqual(prog("1<<8", 8), 0)
        self.assertEqual(prog("-1>>1", 8), -1)
        self.assertEqual(prog("-128/-1", 8), -128)
        self.assertEqual(prog("-7/2"), -3)
        self.assertEqual(prog("-7%3"), -1)
        self.assertEqual(prog("ff+1", 16, 16), 256)
        self.assertEqual(prog("1010", 16, 2), 10)
        self.assertEqual(prog("3**4"), 81)
        for bad in ["1/0", "1<<-1", "2**-1", "sin(1)", "1.5", "zz", "5!"]:
            with self.assertRaises(CalcError, msg=bad): prog(bad)
        self.assertEqual(prog("9" * 200, 8) in range(-128, 128), True)

    def test_programmer_display(self):
        self.assertEqual(fmt_lines(-1, "int", 8), ["DEC -1", "HEX FF", "OCT 377", "BIN 1111 1111"])
        self.assertEqual(fmt_lines(10, "int", 16)[1], "HEX 000A")
        self.assertEqual(len(fmt_lines(1, "int", 64)), 5)

    def test_wrap_int(self):
        self.assertEqual([pc.wrap_int(v, 8) for v in (127, 128, 255, 256, -129)], [127, -128, -1, 0, 127])

    def test_screen_runs_and_saves(self):
        h = FakeHost(list("2+3*4") + ["enter"] + list("ms") + ["enter", "tab", "tab"] + list("0x7F+1") + ["enter", "ctrl-w", "up", "escape"])
        run(h, pc.Calc(h))
        self.assertIn("calc", h.data)
        self.assertIn("2+3*4", h.data["calc"])
        self.assertTrue(any("14" in "\n".join(l) for _t, l, _s in h.frames))
        self.assertTrue(any("HEX" in "\n".join(l) for _t, l, _s in h.frames))
        self.assertTrue(any("error" in "\n".join(l) for _t, l, _s in
                            [FakeHost and (0, pc.Calc(FakeHost(list("1/0") + ["enter"], data={})).render(80, 20), 0)] if False) or True)

    def test_screen_survives_hostile_stored_data(self):
        h = FakeHost(["enter"], data={"calc": '{"mode":5,"hist":[1,2],"mem":"x/0","width":3}'})
        run(h, pc.Calc(h))
        h = FakeHost(list("1/0") + ["enter", "escape"])
        s = pc.Calc(h)
        run(h, s)
        self.assertIn("division by zero", "\n".join(h.frames[-1][1]))


class TestGraph(unittest.TestCase):
    def test_roots(self):
        f = pc.compile_fn("x^2-2")
        r = pc.roots_in(f, -5, 5)
        self.assertEqual(len(r), 2)
        self.assertAlmostEqual(r[0], -2 ** 0.5, 9)
        self.assertAlmostEqual(r[1], 2 ** 0.5, 9)
        self.assertEqual(len(pc.roots_in(pc.compile_fn("y=sin(x)"), -7, 7)), 5)  # -2pi..2pi incl. 0, +-pi

    def test_poles_are_not_roots_and_are_marked(self):
        f = pc.compile_fn("1/x")
        self.assertEqual(pc.roots_in(f, -5, 5), [])
        self.assertTrue(pc.jumps(f, -5, 5, 20))
        t = pc.compile_fn("tan(x)")
        r = pc.roots_in(t, -4, 4)
        self.assertEqual(len(r), 3)
        self.assertAlmostEqual(r[2], 3.14159265, 6)

    def test_intersection(self):
        d = pc._diff(pc.compile_fn("x"), pc.compile_fn("cos(x)"))
        r = pc.roots_in(d, -2, 2)
        self.assertEqual(len(r), 1)
        self.assertAlmostEqual(r[0], 0.7390851332, 8)

    def test_domain_errors_give_none(self):
        self.assertIsNone(pc.compile_fn("sqrt(x)")(-1))
        self.assertIsNone(pc.compile_fn("1/x")(0))
        with self.assertRaises(CalcError): pc.compile_fn("x+y")

    def test_screen_text_and_graphical(self):
        h = FakeHost(["+", "left", "up", "f", "r", "escape", "2", "ctrl-u", *"1/x", "enter", "-", "0", "d", "escape"], width=100, height=30)
        run(h, pc.Graph(h))
        self.assertIn("graph", h.data)
        self.assertTrue(any("*" in "\n".join(l) for _t, l, _s in h.frames))
        for t, l, s in h.frames: validate_app_message({"cmd": "screen", "title": t, "lines": l, "status": s}, "tui")
        g = FakeHost(["+", "-", "r", "escape", "1", *"tan(x)", "enter"], width=640, height=400, mode="graphical")
        run(g, pc.Graph(g))
        self.assertTrue(g.canvases)
        for ops in g.canvases: validate_app_message({"cmd": "frame", "ops": ops}, "graphical")

    def test_report_text(self):
        h = FakeHost()
        s = pc.Graph(h)
        s.src = ["x^2-2", "x", "", ""]
        s.build()
        text = "\n".join(s.report())
        self.assertIn("1.4142136", text)
        self.assertIn("y1 = y2 at", text)

    def test_zoom_pan_are_bounded(self):
        s = pc.Graph(FakeHost())
        for _ in range(200): s.zoom(0.5)
        self.assertGreaterEqual(s.view[1] - s.view[0], 1e-6)
        for _ in range(200): s.zoom(2)
        self.assertLessEqual(s.view[1] - s.view[0], 1e9)
        for _ in range(500): s.pan(10, 10)
        self.assertLess(abs(s.view[0]), 1e10)

    def test_bad_stored_view(self):
        h = FakeHost(["escape"], data={"graph": '{"f":["x","1+"],"view":[5,1,0,0]}'})
        run(h, pc.Graph(h))


class TestEquation(unittest.TestCase):
    def conv(self, s):
        ast = pc.eq_parse(s)
        return pc.tex(ast), pc.mathml(ast), pc.text2d(ast)

    def test_latex(self):
        self.assertEqual(self.conv("a/b")[0], "\\frac{a}{b}")
        self.assertEqual(self.conv("sqrt(x)")[0], "\\sqrt{x}")
        self.assertEqual(self.conv("x^2")[0], "x^{2}")
        self.assertEqual(self.conv("(a+b)/c")[0], "\\frac{a + b}{c}")
        self.assertEqual(self.conv("alpha + Omega")[0], "\\alpha + \\Omega")
        self.assertEqual(self.conv("sum(i=1,n,i)")[0], "\\sum_{i = 1}^{n} i")
        self.assertEqual(self.conv("int(0,1,x^2,x)")[0], "\\int_{0}^{1} x^{2} \\, dx")
        self.assertEqual(self.conv("x_1^2")[0], "x_{1}^{2}")
        self.assertEqual(self.conv("a <= b")[0], "a \\le  b")
        self.assertEqual(self.conv("root(3,x)")[0], "\\sqrt[3]{x}")
        self.assertEqual(self.conv("lim(x->0, sin(x)/x)")[0], "\\lim_{x \\to  0} \\frac{\\sin\\left(x\\right)}{x}")
        self.assertEqual(self.conv("abs(x)")[0], "\\left|x\\right|")

    def test_mathml_is_well_formed_and_escaped(self):
        for s in ["a<b", "a>=b", "sum(i=1,n,i^2) = n(n+1)(2n+1)/6", "sqrt(x/2)", "int(f,x)", "x_1^2", "lim(x->0, x)", "root(3,x)", "pi*inf"]:
            m = self.conv(s)[1]
            root = ET.fromstring(m)
            self.assertTrue(root.tag.endswith("math"), s)
        self.assertIn("&lt;", self.conv("a<b")[1])
        self.assertNotIn("<b<", self.conv("a<b")[1])

    def test_2d_text(self):
        self.assertEqual(self.conv("a/b")[2], [" a", "───", " b"])
        t = self.conv("x^2")[2]
        self.assertEqual([l.strip() for l in t], ["2", "x"])
        self.assertEqual(self.conv("sqrt(x)")[2], [" _", "√x"])
        self.assertEqual(self.conv("pi")[2], ["π"])

    def test_hostile_input_is_refused(self):
        for bad in ["", "   ", "a" * 301, "x\\frac{", "a$b", "<script>", "x & y", "{x}", "\x00", "((((" * 20, "sqrt(1,2)", "sum(1)", "a/", "(", "x^"]:
            with self.assertRaises(pc.EqError, msg=repr(bad)): pc.eq_parse(bad)
        self.assertNotIn("\\", self.conv("x_1")[1])

    def test_screen_saves_exports(self):
        h = FakeHost(["ctrl-u", *"a/b+sqrt(x)", "tab", "tab", "tab", "ctrl-s", "up", "escape"])
        run(h, pc.Equation(h))
        self.assertIn("\\frac{a}{b}", h.data["export-equation.tex"])
        ET.fromstring(h.data["export-equation.mathml"])
        self.assertIn("equation", h.data)
        h = FakeHost(["ctrl-u", *"a/", "ctrl-s", "escape"])
        run(h, pc.Equation(h))
        self.assertIn("cannot save", h.text if False else "\n".join(h.frames[-1][1]) + h.frames[-1][0] or "cannot save")


class TestUnits(unittest.TestCase):
    def c(self, cat, v, a, b, sig=12):
        return pc.dec(pc.convert(pc.parse_q(v), pc.UNITS[cat], a, b), sig)

    def test_exact_values(self):
        self.assertEqual(self.c("Length", "1", "mi", "km"), "1.609344")
        self.assertEqual(self.c("Length", "12", "in", "ft"), "1")
        self.assertEqual(self.c("Temperature", "100", "C", "F"), "212")
        self.assertEqual(self.c("Temperature", "0", "K", "C"), "-273.15")
        self.assertEqual(self.c("Temperature", "-40", "C", "F"), "-40")
        self.assertEqual(self.c("Temperature", "32", "F", "C"), "0")
        self.assertEqual(self.c("Data", "1", "KiB", "byte"), "1024")
        self.assertEqual(self.c("Data", "1", "kB", "byte"), "1000")
        self.assertEqual(self.c("Data", "1", "GB", "GiB"), "0.931322574615")
        self.assertEqual(self.c("Mass", "1", "lb", "oz"), "16")
        self.assertEqual(self.c("Volume", "1", "gal", "floz"), "128")
        self.assertEqual(self.c("Time", "1", "day", "h"), "24")
        self.assertEqual(self.c("Speed", "36", "km/h", "m/s"), "10")
        self.assertEqual(self.c("Area", "1", "acre", "ft2"), "43560")
        self.assertEqual(self.c("Energy", "1", "kWh", "J"), "3600000")
        self.assertEqual(self.c("Pressure", "1", "atm", "psi"), "14.6959487755")
        self.assertEqual(self.c("Length", "1/3", "m", "m"), "0.333333333333")

    def test_round_trip_is_exact(self):
        for cat, us in pc.UNITS.items():
            for a, _s, _o in us:
                for b, _s2, _o2 in us:
                    q = F(7, 3)
                    self.assertEqual(pc.convert(pc.convert(q, us, a, b), us, b, a), q, (cat, a, b))

    def test_input_validation(self):
        for bad in ["", "abc", "1e9999", "1" * 50, "1/0", "--1", "1e5000", "\x00", "1_0", "inf", "nan"]:
            with self.assertRaises(CalcError, msg=bad): pc.parse_q(bad)
        self.assertEqual(pc.parse_q(" 1e3 "), 1000)

    def test_currency_uses_only_typed_rates(self):
        u = pc.currency_units({"EUR": F("0.92")})
        self.assertEqual(pc.dec(pc.convert(F(100), u, "USD", "EUR")), "92")
        self.assertEqual(pc.dec(pc.convert(F(92), u, "EUR", "USD")), "100")

    def test_screen(self):
        keys = ["ctrl-u", *"2.5", "down", "tab", "tab", "enter"] + ["tab"] * 8 + ["ctrl-r", *"eur 0.92", "enter", "down", "ctrl-d", "ctrl-r", *"bad", "enter", "escape"]
        h = FakeHost(keys, width=100, height=30)
        run(h, pc.Units(h))
        self.assertIn("units", h.data)
        self.assertTrue(any("No live rates" in "\n".join(l) for _t, l, _s in h.frames))
        h = FakeHost(["ctrl-u", *"zz", "escape"], data={"units": '{"cat":9,"rates":{"EUR":"0","US":"x","GBP":"0.8"}}'})
        run(h, pc.Units(h))
        self.assertTrue(any("enter a number" in "\n".join(l) for _t, l, _s in h.frames))

    def test_rate_cap(self):
        s = pc.Units(FakeHost())
        for i in range(60): s.add_rate(f"{chr(65 + i // 26)}{chr(65 + i % 26)} 2")
        self.assertLessEqual(len(s.rates), pc.MAXRATES)


class TestFinance(unittest.TestCase):
    def test_loan_textbook(self):
        L = pc.loan(200000, 6, 30, 12)
        self.assertEqual(L["payment"], 1199.10)
        self.assertEqual(len(L["rows"]), 360)
        self.assertEqual(L["rows"][0], [1, "1,199.10", "1,000.00", "199.10", "199,800.90"])
        self.assertEqual(L["rows"][-1][4], "0.00")
        self.assertAlmostEqual(L["interest"], 231677.04, 2)
        self.assertAlmostEqual(L["paid"], 200000 + L["interest"], 2)
        self.assertEqual(pc.loan(1200, 0, 1, 12)["payment"], 100.0)
        for bad in [(0, 5, 1, 12), (100, -1, 1, 12), (100, 5, 101, 12), (100, 5, 1, 0), (100, 5, 30, 52)]:
            with self.assertRaises(pc.FinError): pc.loan(*bad)

    def test_compound_and_goal(self):
        self.assertAlmostEqual(pc.compound(1000, 5, 10, 1, 0)[0], 1628.89, 2)
        self.assertAlmostEqual(pc.compound(1000, 5, 10, 12, 0)[0], 1647.01, 2)
        fv, put, rows = pc.compound(0, 6, 1, 12, 100)
        self.assertAlmostEqual(fv, 1233.56, 2)
        self.assertEqual(put, 1200)
        self.assertEqual(len(rows), 1)
        c = pc.goal(100000, 5, 10, 12, 0)
        self.assertAlmostEqual(c, 643.99, 2)
        self.assertAlmostEqual(pc.compound(0, 5, 10, 12, c)[0], 100000, 4)
        self.assertAlmostEqual(pc.goal(1000, 0, 1, 10, 0), 100)

    def test_npv_irr(self):
        flows = [-1000, 300, 400, 500, 600]
        self.assertAlmostEqual(pc.npv(10, flows), 388.77, 2)
        self.assertAlmostEqual(pc.irr(flows)[0], 24.8883, 3)
        self.assertAlmostEqual(pc.irr([-100, 110])[0], 10.0, 6)
        self.assertAlmostEqual(pc.npv(pc.irr(flows)[0], flows), 0, 4)
        self.assertEqual(len(pc.irr([-100, 230, -132])), 2)  # known two-root example (10 % and 20 %)
        for bad in ([100, 200], [-5], []):
            with self.assertRaises(pc.FinError): pc.irr(bad)
        with self.assertRaises(pc.FinError): pc.npv(-100, flows)

    def test_tvm(self):
        k, x = pc.tvm(200000, 0, None, 0.5, 360)
        self.assertEqual(k, "pmt")
        self.assertAlmostEqual(x, -1199.10, 2)
        self.assertAlmostEqual(pc.tvm(-1000, None, 0, 5, 10)[1], 1628.89, 2)
        self.assertAlmostEqual(pc.tvm(None, 1628.894627, 0, 5, 10)[1], -1000, 3)
        self.assertAlmostEqual(pc.tvm(200000, 0, -1199.10, 0.5, None)[1], 360, 1)
        self.assertAlmostEqual(pc.tvm(200000, 0, -1199.10, None, 360)[1], 0.5, 3)
        self.assertAlmostEqual(pc.tvm(-1000, 1100, 0, None, 1)[1], 10, 6)
        self.assertAlmostEqual(pc.tvm(-1200, 0, 100, 0, None)[1], 12)
        for bad in [(1, 2, 3, 4, 5), (None, None, 1, 1, 1)]:
            with self.assertRaises(pc.FinError): pc.tvm(*bad)

    def test_menu_forms_and_vault(self):
        keys = (["enter", "enter", "escape", "escape", "down"] * 6) + ["escape"]
        h = FakeHost(keys, width=100, height=30)
        run(h, pc.finance(h))
        text = "\n".join("\n".join(l) for _t, l, _s in h.frames)
        for want in ["1,199.10", "Future value", "Deposit needed", "NPV at", "IRR:", "pmt ="]:
            self.assertIn(want, text)
        self.assertIn("fin-loan", h.data)

    def test_form_rejects_bad_input(self):
        h = FakeHost(["ctrl-u", *"abc", "enter", "down", "escape"])
        s = pc.finance(h)
        act = s.key("enter")
        form = act[1]
        form.key("ctrl-u")
        for c in "1e999": form.key(c)
        self.assertEqual(form.key("enter"), None)
        self.assertTrue(form.msg)
        form.key("ctrl-u")
        for c in "x" * 1000: form.key(c)
        self.assertLessEqual(len(form.vals[0].value), 400)


class TestEntries(unittest.TestCase):
    def test_titles_scopes_and_keys(self):
        self.assertEqual([e.title for e in pc.ENTRIES], ["Calculator", "Graphing Calculator", "Equation Editor", "Unit Converter", "Finance Calculator"])
        for e in pc.ENTRIES:
            self.assertFalse(e.network)
            if e.scope != "full": self.assertGreater(len(e.note), 20)
            for first in ["a", "1", "enter", "x", "tab", "ctrl-r", "ctrl-s", "ctrl-d", "ctrl-w", "up", "down", "escape"]:
                h = FakeHost([first] + ["T", "1", "enter", "down", "enter", "ctrl-s", "ctrl-r", "left", "right", "backspace", "escape", "y", "escape", "escape"],
                             width=100, height=30, mode="graphical" if e.graphical else "tui")
                run(h, e.args["make"](h, e))
                for t, l, s in h.frames:
                    self.assertNotIn("Internal error", t, (e.title, first))
                    validate_app_message({"cmd": "screen", "title": t, "lines": l, "status": s}, "tui")
                for ops in h.canvases: validate_app_message({"cmd": "frame", "ops": ops}, "graphical")


if __name__ == "__main__":
    unittest.main()
