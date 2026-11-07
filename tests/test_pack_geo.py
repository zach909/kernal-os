import json
import math
import unittest

from kos.office import pack_geo as g
from kos.office.ui import FakeHost, run

LON, PAR, NYC, LAX = (51.5074, -0.1278), (48.8566, 2.3522), (40.7128, -74.0060), (34.0522, -118.2437)
DEG = g.RADIUS_KM * math.pi / 180


def near(t, a, b, tol): t.assertLessEqual(abs(a - b), tol, (a, b))


class Coords(unittest.TestCase):
    def test_formats_agree(self):
        for s in ("40.7128, -74.0060", "40.7128N 74.0060W", "40.7128 N, 74.006 W", "N 40.7128 W 74.006", "74.006W, 40.7128N",
                  "40 42 46.08 N, 74 0 21.6 W", "40°42'46.08\"N 74°0'21.6\"W", "N 40 42 46.08 W 74 0 21.6"):
            la, lo = g.parse_coord(s)
            near(self, la, 40.7128, 1e-6); near(self, lo, -74.006, 1e-6)

    def test_output_forms(self):
        self.assertEqual(g.fmt_dd((40.7128, -74.006)), "40.712800, -74.006000")
        self.assertEqual(g.fmt_hem((-33.5, 151.25)), "33.500000 S, 151.250000 E")
        self.assertEqual(g.fmt_dms((40.7128, -74.006)), "40° 42' 46.08\" N, 74° 0' 21.60\" W")

    def test_bad_input_refused(self):
        for s in ("", "   ", "91, 0", "0, 181", "40 N, 50 N", "1,2,3", "abc", "40, -N 74", "-40 S, 5", "10 75 0 N, 5", "x" * 500,
                  "1\x00, 2", None, 5, "1e5, 2", "--4, 5", "0 E, 0 N, 5"):
            with self.assertRaises(g.GeoError, msg=repr(s)): g.parse_coord(s)


class Geometry(unittest.TestCase):
    def test_city_pairs(self):
        near(self, g.haversine(LON, PAR), 343.5, 343.5 * 0.005)
        near(self, g.haversine(NYC, LAX), 3936, 3936 * 0.005)
        near(self, g.haversine((0, 0), (0, 1)), DEG, 1e-9)
        near(self, g.haversine((0, 0), (90, 0)), g.RADIUS_KM * math.pi / 2, 1e-9)
        self.assertEqual(g.haversine(LON, LON), 0.0)

    def test_bearing_midpoint_destination(self):
        near(self, g.bearing((0, 0), (0, 90)), 90, 1e-9)
        near(self, g.bearing((0, 0), (90, 0)), 0, 1e-9)
        near(self, g.bearing((0, 0), (-10, 0)), 180, 1e-9)
        near(self, g.bearing(NYC, LAX), 273.7, 0.5)
        near(self, g.bearing(LON, PAR), 148.1, 0.5)
        self.assertEqual(g.compass(90), "E")
        m = g.midpoint((0, 0), (0, 90)); near(self, m[0], 0, 1e-9); near(self, m[1], 45, 1e-9)
        d = g.destination((0, 0), 90, math.pi / 2 * g.RADIUS_KM); near(self, d[0], 0, 1e-9); near(self, d[1], 90, 1e-9)
        d = g.destination(LON, 148.1, 343.5); near(self, g.haversine(d, PAR), 0, 3)
        near(self, g.destination((0, 179), 90, DEG * 2)[1], -179, 1e-9)         # wraps the antimeridian

    def test_bbox_area_path(self):
        self.assertEqual(g.bbox([(1, 2), (-3, 5), (0, -7)]), (-3, -7, 1, 5))
        octant = g.sphere_area_km2([(0, 0), (0, 90), (90, 0)])
        near(self, octant, 4 * math.pi * g.RADIUS_KM ** 2 / 8, 1e-3)
        near(self, g.sphere_area_km2([(0, 0), (0, 90), (90, 0), (0, 0)]), octant, 1e-3)    # closed ring too
        near(self, g.sphere_area_km2([(90, 0), (0, 90), (0, 0)]), octant, 1e-3)             # either winding
        box = g.sphere_area_km2([(0, 0), (0, 1), (1, 1), (1, 0)])
        near(self, box, g.RADIUS_KM ** 2 * math.radians(1) * math.sin(math.radians(1)), 12364 * 0.001)
        self.assertEqual(g.sphere_area_km2([(0, 0), (1, 1)]), 0.0)
        near(self, g.path_km([(0, 0), (0, 1), (0, 2)]), 2 * DEG, 1e-9)
        near(self, g.path_km([(0, 0), (0, 1), (1, 1)], True), 2 * DEG + g.haversine((1, 1), (0, 0)), 1e-9)

    def test_tools_text(self):
        self.assertIn("Decimal:      40.712800, -74.006000", g._convert("40 42 46.08 N, 74 0 21.6 W")[0])
        self.assertIn("343.", g._between("51.5074, -0.1278 | 48.8566, 2.3522")[0])
        self.assertEqual(g._dest("0,0 | 90 | %.6f" % DEG)[0], "Destination: 0.000000, 1.000000")
        for bad in ("1,1", "0,0 | x | 5", "0,0 | 90 | -1", "0,0 | 90 | nan", "0,0 | 0 | 99999"):
            with self.assertRaises(g.GeoError): g._dest(bad) if bad.count("|") == 2 else g._between(bad)
        self.assertTrue(any("Area" in l for l in g._polygon("0,0\n0,1\n1,1\n1,0")))
        with self.assertRaises(g.GeoError): g._polygon("0,0\nfoo")
        with self.assertRaises(g.GeoError): g._polygon("\n".join("0,0" for _ in range(g.MAX_POINTS + 1)))


class GeoJson(unittest.TestCase):
    def test_valid_summary(self):
        doc = {"type": "FeatureCollection", "features": [
            {"type": "Feature", "geometry": {"type": "Point", "coordinates": [10, 20]}},
            {"type": "Feature", "geometry": {"type": "LineString", "coordinates": [[0, 0], [1, 0]]}},
            {"type": "Feature", "geometry": None},
            {"type": "Feature", "geometry": {"type": "Polygon", "coordinates": [[[0, 0], [1, 0], [1, 1], [0, 1], [0, 0]]]}}]}
        r = g.geojson_check(json.dumps(doc))
        self.assertEqual(r["errors"], [])
        self.assertEqual(r["types"], {"FeatureCollection": 1, "Feature": 4, "Point": 1, "LineString": 1, "Polygon": 1})
        near(self, r["length"], DEG, 1e-9)
        near(self, r["area"], 12364, 20)
        self.assertEqual(r["n"][0], 8)
        self.assertEqual(g.geojson_report(json.dumps(doc))[0].split()[0], "VALID")

    def test_invalid(self):
        bad = ['', '   ', '{', '[]', '{"type":"Nope"}', '{"type":"Point","coordinates":[200,0]}', '{"type":"Point","coordinates":[1]}',
               '{"type":"Point","coordinates":[true,1]}', '{"type":"Point","coordinates":[NaN,1]}', '{"type":"LineString","coordinates":[[0,0]]}',
               '{"type":"Polygon","coordinates":[[[0,0],[1,0],[0,0]]]}', '{"type":"Polygon","coordinates":[[[0,0],[1,0],[1,1],[0,1],[5,5]]]}',
               '{"type":"FeatureCollection","features":5}', '{"type":"Feature","geometry":{"type":"Point","coordinates":"x"}}',
               '[' * 50000 + ']' * 50000, '{"a":' * 30000, "x" * (g.MAX_TEXT + 1), "\x00", None, 7]
        for b in bad:
            r = g.geojson_check(b)
            self.assertTrue(r["errors"], repr(b)[:40])
            self.assertEqual(g.geojson_report(b)[0], "INVALID")

    def test_deep_collections_bounded(self):
        s = '{"type":"GeometryCollection","geometries":[' * 30 + "]}" * 30
        self.assertTrue(g.geojson_check(s)["errors"])
        many = json.dumps({"type": "GeometryCollection", "geometries": [{"type": "Point", "coordinates": [0, 0]}] * 6000})
        self.assertTrue(g.geojson_check(many)["errors"])


class PlotTests(unittest.TestCase):
    def test_parse_and_project(self):
        sh = g.parse_plot("# c\n0, 0 | A\n0, 10 | B\nline 0,0 | 1,1\npoly 0,0 | 0,1 | 1,1")
        self.assertEqual([s[0] for s in sh], ["point", "point", "line", "poly"])
        self.assertEqual(sh[0][2], "A")
        pr = g.project(sh[:2], 200, 100)
        self.assertEqual(pr[0][1][0][1], pr[1][1][0][1])                 # same latitude -> same y
        self.assertGreater(pr[1][1][0][0], pr[0][1][0][0])               # east is right
        self.assertEqual(pr[1][1][0][0] - pr[0][1][0][0], 180)           # fills the width minus 2*10 margins
        one = g.project([("point", [(5, 5)], "")], 100, 100)             # a single point does not divide by zero
        self.assertEqual(len(one[0][1]), 1)
        near(self, g.project([("point", [(60, 0)], ""), ("point", [(60, 10)], "")], 400, 400)[1][1][0][0]
             - g.project([("point", [(60, 0)], ""), ("point", [(60, 10)], "")], 400, 400)[0][1][0][0], 380, 1)

    def test_bad_plot_input(self):
        for b in ("", "\n\n", "line 1,1", "poly 1,1 | 2,2", "bogus", "line", None, "x" * (g.MAX_TEXT + 1),
                  "\n".join("1,1" for _ in range(g.MAX_POINTS + 1))):
            with self.assertRaises(g.GeoError, msg=repr(b)[:30]): g.parse_plot(b)


class Route(unittest.TestCase):
    def test_eta_and_order(self):
        self.assertEqual(g.fmt_eta(10, 5), "2 h 00 min")
        self.assertEqual(g.fmt_eta(2.5, 5), "30 min")
        pts = [(0, 0), (0, 3), (0, 1), (0, 2)]              # user order zig-zags along the equator
        dm = g.matrix(pts)
        mine = g.order_cost(range(4), dm)
        near(self, mine, DEG * (3 + 2 + 1), 1e-6)
        nn = g.nearest_neighbour(dm, 0)
        self.assertEqual(nn, [0, 2, 3, 1])
        imp = g.two_opt([0, 1, 2, 3], dm)
        self.assertEqual(imp, [0, 2, 3, 1])
        near(self, g.order_cost(imp, dm), 3 * DEG, 1e-6)
        # two_opt repairs a bad start: from the zig-zag it reaches the straight order
        self.assertEqual(g.two_opt([0, 1, 2, 3], dm), [0, 2, 3, 1])
        # round trip: square is already optimal in order 0,1,2,3 and a crossing order is repaired
        sq = [(0, 0), (0, 1), (1, 1), (1, 0)]
        dq = g.matrix(sq)
        crossed = [0, 2, 1, 3]
        fixed = g.two_opt(crossed, dq, closed=True)
        self.assertLess(g.order_cost(fixed, dq, True), g.order_cost(crossed, dq, True))
        near(self, g.order_cost(fixed, dq, True), g.order_cost([0, 1, 2, 3], dq, True), 1e-6)
        self.assertEqual(fixed[0], 0)

    def test_screen_flow_and_persistence(self):
        h = FakeHost(["a", *"A | 0, 0", "enter", "a", *"B | 0, 3", "enter", "a", *"C | 0, 1", "enter", "a", *"D | 0, 2", "enter",
                      "o", "escape", "O", "m", "r", "r"], width=100, height=30)
        e = g.ENTRIES[1]
        run(h, e.args["make"](h, e))
        st = json.loads(h.data["route"])
        self.assertEqual([w[0] for w in st["wps"]], ["A", "C", "D", "B"])
        self.assertEqual(st["mode"], "cycle")
        text = "\n".join(l for f in h.frames for l in f[1])
        self.assertIn("Saves", text)
        self.assertIn("not road", text.replace("(straight lines, not roads)", "not road"))

    def test_bounds_and_hostile(self):
        s = g._route_state({"wps": [["x", 999, 0], ["y", "a", 0], ["z", 1, 2]] + [["w", 1, 1]] * 100, "speeds": {"walk": -1, "cycle": "x", "drive": 80}, "mode": "fly", "round": 1})
        self.assertEqual(len(s["wps"]), g.MAX_WAYPOINTS - 2)
        self.assertLessEqual(len(s["wps"]), g.MAX_WAYPOINTS)
        self.assertEqual(s["speeds"], {"walk": 5.0, "cycle": 15.0, "drive": 80.0})
        self.assertEqual((s["mode"], s["round"]), ("walk", False))
        self.assertEqual(g._route_state("junk")["wps"], [])
        h = FakeHost(["v", *"0 0 0", "enter", "a", *"zzz", "enter", "o", "escape", "<", ">", "d", "y", "O", "p", "escape"], width=100, height=30)
        run(h, g.ENTRIES[1].args["make"](h, g.ENTRIES[1]))
        h = FakeHost(["v", "ctrl-u", *"1 2 3", "enter"], width=100, height=30)
        run(h, g.ENTRIES[1].args["make"](h, g.ENTRIES[1]))
        self.assertEqual(json.loads(h.data["route"])["speeds"], {"walk": 1.0, "cycle": 2.0, "drive": 3.0})
        h = FakeHost(["a"] + list("1,1") + ["enter"] + [], width=100, height=30)
        h.data["route"] = json.dumps({"wps": [["s", 1, 1]] * g.MAX_WAYPOINTS})
        run(h, g.ENTRIES[1].args["make"](h, g.ENTRIES[1]))
        self.assertEqual(len(json.loads(h.data["route"])["wps"]), g.MAX_WAYPOINTS)


class Places(unittest.TestCase):
    ITEMS = [{"_id": 1, "name": "Home", "lat": "51.5074", "lon": "-0.1278"}, {"_id": 2, "name": "Paris", "lat": "48.8566", "lon": "2.3522"},
             {"_id": 3, "name": "NYC", "lat": "40.7128", "lon": "-74.006"}, {"_id": 4, "name": "Bad", "lat": "x", "lon": "1"}, {"_id": 5, "name": "Far", "lat": "999", "lon": "1"}]

    def test_queries(self):
        n = g.nearest(self.ITEMS, (51.5, 0), 2)
        self.assertEqual([r["name"] for _d, r in n], ["Home", "Paris"])
        w = g.within(self.ITEMS, LON, 400)
        self.assertEqual([r["name"] for _d, r in w], ["Home", "Paris"])
        self.assertEqual(g.within(self.ITEMS, LON, 1), [self.ITEMS[0]] and [(0.0, self.ITEMS[0])])
        log = [{"p": 2, "d": "2026-01-01"}, {"p": 1, "d": "2026-01-02"}, {"p": 2, "d": "2026-01-03"}, {"p": 99, "d": "x"}]
        self.assertEqual(g.most_visited(self.ITEMS, log), [("Paris", 2), ("Home", 1)])

    def test_screen_saves_logs_and_queries(self):
        e = g.ENTRIES[2]
        keys = ["a", "enter", *"Home", "enter", "enter", *"51.5074", "enter", "enter", *"-0.1278", "enter", "ctrl-s",
                "a", "enter", *"Paris", "enter", "enter", *"48.8566", "enter", "enter", *"2.3522", "enter", "ctrl-s",
                "a", "enter", *"Void", "enter", "enter", *"95", "enter", "enter", *"0", "enter", "ctrl-s",
                "v", *"2026-02-03 lunch", "enter", "v", "enter",
                "L", "escape", "m", "escape", "n", *"Home", "enter", "escape", "w", *"Home | 400", "enter", "escape"]
        h = FakeHost(keys, width=100, height=30)
        run(h, e.args["make"](h, e))
        recs = json.loads(h.spaces["places"]["records"])
        self.assertEqual([r["name"] for r in recs["items"]], ["Home", "Paris"])      # the out-of-range one was refused
        self.assertEqual((recs["items"][0]["lat"], recs["items"][0]["lon"]), ("51.5074", "-0.1278"))
        self.assertNotIn("records", h.data)                                           # places live only in the shared space
        log = json.loads(h.data["visits"])
        self.assertEqual(len(log), 2)
        self.assertEqual(log[0], {"p": 1, "d": "2026-02-03", "n": "lunch"})
        text = "\n".join(l for f in h.frames for l in f[1] + [f[0]])
        self.assertIn("lunch", text); self.assertIn("Paris", text); self.assertIn("within 400", text)
        self.assertIn("not saved", text)

    def test_visit_bad_date_and_log_bound(self):
        e = g.ENTRIES[2]
        h = FakeHost([], width=100, height=30)
        sc = e.args["make"](h, e)
        sc.data.add({"name": "A", "lat": "1", "lon": "1"})
        rec = sc.data.items[0]
        sc._visit(rec, "2026-13-45 x"); self.assertIn("date", sc.msg)
        self.assertFalse(h.data.get("visits"))
        for _ in range(3): sc._visit(rec, "n" * 500)
        self.assertEqual(len(sc.log()), 3); self.assertEqual(len(sc.log()[0]["n"]), 80)
        sc.store.save("visits", [{"p": 1, "d": "2026-01-01"}] * (g.MAX_VISITS + 5) + ["junk", {"p": "x"}])
        self.assertLessEqual(len(sc.log()), g.MAX_VISITS)
        sc._deleted(rec); self.assertEqual(sc.log(), [])


class SharedFolder(unittest.TestCase):
    def test_declared_permissions(self):
        owns = {e.title: (e.owns, e.uses) for e in g.ENTRIES}
        self.assertEqual(owns["Places"], (["places"], []))
        self.assertEqual(owns["Route Planner"], ([], ["places"]))
        self.assertEqual(owns["Map Tools"], ([], ["places"]))
        self.assertEqual({e.title: e.scope for e in g.ENTRIES}, {"Map Tools": "partial", "Route Planner": "partial", "Places": "full"})

    def test_two_hosts_share_a_space_and_missing_grant_is_explained(self):
        shared = {}
        a, b, c = FakeHost(width=100, height=30), FakeHost(width=100, height=30), FakeHost(width=100, height=30)
        a.spaces = b.spaces = shared
        pl, rp, mt = g.ENTRIES[2], g.ENTRIES[1], g.ENTRIES[0]
        sc = pl.args["make"](a, pl)
        sc.data.add({"name": "Home", "lat": "1", "lon": "2", "category": "home"})
        host = FakeHost(["p", "enter"], width=100, height=30); host.spaces = shared
        run(host, rp.args["make"](host, rp))
        self.assertEqual(json.loads(host.data["route"])["wps"], [["Home", 1.0, 2.0]])
        host = FakeHost(["down", "enter", "enter", "escape"], width=100, height=30); host.spaces = shared
        run(host, mt.args["make"](host, mt))
        self.assertTrue(host.frames)
        # no grant / nothing there: the apps still work and say what to do
        for ent, keys in ((rp, ["p"]), (mt, ["down", "down", "down", "down", "down", "enter"])):
            empty = FakeHost(keys, width=100, height=30)
            run(empty, ent.args["make"](empty, ent))
            self.assertIn("kos grant " + ent.name + " space:places --level read", "\n".join(l for f in empty.frames for l in f[1]))
        self.assertEqual(g.latlon({"lat": "1e999", "lon": "0"}), None)
        self.assertIsNone(g.latlon({"lat": None}))


class EveryAppDraws(unittest.TestCase):
    def test_map_tools_menu_items(self):
        e = g.ENTRIES[0]
        for mode in ("tui", "graphical"):
            for i in range(1, 8):
                h = FakeHost([str(i), "ctrl-r", "escape", "ctrl-l", "escape", "enter", "escape", "escape"], width=100, height=30, mode=mode)
                run(h, e.args["make"](h, e))
                self.assertFalse([t for t, _l, _s in h.frames if "Internal error" in t], (mode, i))
        h = FakeHost(["7", "ctrl-r"], mode="graphical", width=100, height=30)
        run(h, e.args["make"](h, e))
        self.assertTrue(h.canvases)
        ops = h.canvases[-1]
        self.assertTrue(any(o[0] == "line" for o in ops) and any(o[0] == "text" and o[3] == "London" for o in ops))
        h = FakeHost(["5", "ctrl-l"], mode="graphical", width=100, height=30)
        run(h, e.args["make"](h, e))
        self.assertTrue(h.canvases)
        h = FakeHost(["5", "ctrl-s", "1", "enter"], width=100, height=30)
        run(h, e.args["make"](h, e)); self.assertIn("mt-geojson", h.data)

    def test_prompts_show_errors_not_crashes(self):
        e = g.ENTRIES[0]
        h = FakeHost(["1", *"nonsense", "enter", "2", *"1,1", "enter", "3", "enter", "4", "ctrl-r"], width=100, height=30)
        run(h, e.args["make"](h, e))
        self.assertIn("Error", "\n".join(l for f in h.frames for l in f[1]))
        self.assertFalse([t for t, _l, _s in h.frames if "Internal error" in t])


if __name__ == "__main__":
    unittest.main()
