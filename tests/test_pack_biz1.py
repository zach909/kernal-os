import datetime as dt
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.office import pack_biz1 as P  # noqa: E402
from kos.office.packkit import shared_items  # noqa: E402
from kos.office.records import Data, validate  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402

D = dt.date(2026, 11, 7)


class TestCRM(unittest.TestCase):
    deals = [
        {"name": "A", "stage": "proposal", "value": "1000", "opened": "2026-08-01"},
        {"name": "B", "stage": "negotiation", "value": "2000", "opened": "2026-10-20"},
        {"name": "C", "stage": "won", "value": "500", "opened": "2026-01-01"},
        {"name": "D", "stage": "lead", "value": "400", "opened": "2026-10-30"},
        {"name": "E", "stage": "lost", "value": "900", "opened": "2026-01-01"},
    ]
    acts = [{"deal": "a", "date": "2026-09-01"}, {"deal": "A", "date": "2026-08-15"}]

    def test_pipeline_forecast_stale(self):
        t = "\n".join(P.crm_report(self.deals, self.acts, D))
        self.assertIn("FORECAST (open deals x stage probability): 2,040.00", t)   # 500 + 1500 + 40
        self.assertIn("proposal       1 deal(s)       1,000.00  (50%)", t)
        self.assertIn("Won to date: 500.00", t)
        stale = t.split("STALE DEALS")[1]
        self.assertIn("A ", stale)
        self.assertIn("last activity 2026-09-01 (67 days)", stale)
        self.assertNotIn("\n  B ", stale)
        self.assertNotIn("\n  D ", stale)
        self.assertNotIn("\n  C ", stale)          # won deals are never stale

    def test_stale_boundary_and_undated(self):
        d = [{"name": "X", "stage": "lead", "value": "1", "opened": "2026-10-08"}, {"name": "Y", "stage": "lead", "value": "1"}]
        t = "\n".join(P.crm_report(d, [], D))
        self.assertIn("X", t.split("STALE")[1])     # exactly 30 days
        self.assertIn("no date at all", t)
        self.assertIn("none", "\n".join(P.crm_report([], [], D)))

    def test_overdue_followups(self):
        acts = [{"deal": "A", "follow_up": "2026-11-01", "kind": "call"}, {"deal": "B", "follow_up": "2026-11-07"},
                {"deal": "C", "follow_up": "2026-10-01", "done": "yes"}, {"deal": "D", "follow_up": "garbage"}, {"deal": "E"}]
        out = P.overdue_followups(acts, D)
        self.assertEqual(out[0], "OVERDUE FOLLOW-UPS as of 2026-11-07: 1")
        self.assertIn("2026-11-01", out[2])

    def test_weighted_calc(self):
        h = FakeHost()
        d = Data(h, P.R("t", "t", "deal", "name; stage: choice(" + "|".join(P.STAGES) + ")=lead; value: money; weighted: money", calc=(P._W,)))
        self.assertEqual(d.add({"name": "x", "stage": "proposal", "value": "1000"})["weighted"], "500")
        self.assertEqual(d.add({"name": "y", "stage": "lost", "value": "1000"})["weighted"], "0")
        self.assertEqual(d.add({"name": "z", "stage": "won", "value": "250"})["weighted"], "250")


class TestSales(unittest.TestCase):
    def test_quote_total(self):
        h = FakeHost()
        h2 = P._sales(h, type("E", (), {"uses": []})())
        d = Data(h, h2.entries and P.R("q", "q", "q", "qty: number=1; unit_price: money=0; discount_pct: percent=0; tax_pct: percent=0; subtotal: money; total: money",
                                        calc=("subtotal=qty*unit_price", "total=ROUND(qty*unit_price*(1-discount_pct/100)*(1+tax_pct/100),2)")))
        r = d.add({"qty": "2", "unit_price": "100", "discount_pct": "10", "tax_pct": "20"})
        self.assertEqual((r["subtotal"], r["total"]), ("200", "216"))
        self.assertEqual(d.add({"qty": "1", "unit_price": "100", "discount_pct": "20", "tax_pct": "5"})["total"], "84")

    def test_report(self):
        q = [{"status": "won", "rep": "Ann", "date": "2026-11-03", "total": "216"}, {"status": "won", "rep": "Ann", "date": "2026-11-20", "total": "84"},
             {"status": "won", "rep": "Bob", "date": "2026-10-02", "total": "300"}, {"status": "lost", "rep": "Bob", "date": "2026-10-05", "total": "50"},
             {"status": "sent", "rep": "Ann", "date": "2026-11-21", "total": "1000"}, {"status": "draft", "rep": "Ann", "date": "2026-11-22", "total": "bad"}]
        t = [{"rep": "Ann", "month": "2026-11", "target": "600"}, {"rep": "Bob", "month": "2026-10", "target": "200"}, {"rep": "Cy", "month": "2026-11", "target": "100"}]
        out = "\n".join(P.sales_report(q, t))
        self.assertIn("Open pipeline (draft + sent): 1,000.00 in 2 quote(s)", out)
        self.assertIn("Won: 3  Lost: 1  Win rate: 75.0%", out)
        self.assertIn("Average won deal size: 200.00", out)
        self.assertIn("Ann            2026-11        600.00       300.00  50%", out)
        self.assertIn("Bob            2026-10        200.00       300.00  150%", out)
        self.assertIn("Cy             2026-11        100.00         0.00  0%", out)

    def test_empty(self):
        self.assertIn("Win rate: n/a", "\n".join(P.sales_report([], [])))


class TestSupport(unittest.TestCase):
    now = dt.datetime(2026, 11, 7, 12, 0)
    tk = [
        {"subject": "t1", "priority": "urgent", "agent": "Ann", "status": "open", "opened": "2026-11-07 09:00", "first_response": "2026-11-07 09:30"},
        {"subject": "t2", "priority": "high", "agent": "Ann", "status": "open", "opened": "2026-11-07 02:00"},
        {"subject": "t3", "priority": "normal", "agent": "Bob", "status": "resolved", "opened": "2026-11-01 08:00",
         "first_response": "2026-11-01 19:30", "resolved": "2026-11-02 08:00"},
        {"subject": "t4", "priority": "low", "agent": "Bob", "status": "open", "opened": "2026-10-20 12:00"},
        {"subject": "t5", "opened": "nonsense"},
    ]

    def test_report(self):
        out = "\n".join(P.support_report(self.tk, self.now))
        self.assertIn("SLA BREACHES: 4", out)
        self.assertIn("t2: no first response after 10.0h > 4h (high)", out)
        self.assertIn("t3: first response 11.5h > 8h (normal)", out)
        self.assertIn("t4: unresolved after 432.0h > 120h (low)", out)
        self.assertNotIn("t1:", out)
        self.assertIn("Average first response: 6.0 h", out)
        self.assertIn("Average resolution: 24.0 h", out)
        self.assertIn("under 1 day    2", out)
        self.assertIn("over 7 days    1", out)
        self.assertIn("Ann                  2", out)
        self.assertIn("Bob                  1", out)
        self.assertIn("UNREADABLE", out)

    def test_empty(self):
        self.assertIn("SLA BREACHES: 0", "\n".join(P.support_report([], self.now)))


class TestAds(unittest.TestCase):
    def test_calc_and_report(self):
        d = Data(FakeHost(), P.ADS)
        a = d.add({"campaign": "s", "channel": "search", "budget": "80", "spend": "100", "impressions": "10000", "clicks": "200", "conversions": "10", "revenue": "400"})
        self.assertEqual((a["ctr"], a["cpc"], a["cpa"], a["roas"], a["flag"]), ("2", "0.5", "10", "4", "OVER BUDGET"))
        b = d.add({"campaign": "so", "channel": "social", "budget": "300", "spend": "200", "impressions": "20000", "clicks": "100", "conversions": "5", "revenue": "300"})
        self.assertEqual((b["ctr"], b["cpc"], b["cpa"], b["roas"], b["flag"]), ("0.5", "2", "40", "1.5", "ok"))
        z = d.add({"campaign": "zero", "channel": "video", "budget": "0", "spend": "0", "impressions": "0", "clicks": "0", "conversions": "0", "revenue": "0"})       # defaults: no division by zero
        self.assertEqual((z["ctr"], z["cpc"], z["cpa"], z["roas"]), ("0", "0", "0", "0"))
        out = P.ads_report(d.items)
        self.assertTrue(out[2].startswith("  search"))
        self.assertTrue(out[3].startswith("  social"))
        self.assertTrue(out[4].startswith("  video"))
        self.assertIn("search", out[2]); self.assertIn("4.00", out[2])
        self.assertIn("OVER BUDGET: 1", out)
        self.assertIn("  s: spent 100.00 of 80.00", out)

    def test_hostile_input(self):
        self.assertFalse(validate(P.ADS.field("spend"), "abc")[0])
        self.assertFalse(validate(P.ADS.field("channel"), "tv")[0])
        self.assertFalse(validate(P.SALES_TARGETS.fields[2], "x\x00y")[0])
        # malformed stored records never crash the reports
        junk = [{"channel": None, "spend": "x\x00", "budget": [1]}, {}]
        self.assertTrue(P.ads_report(junk))
        self.assertTrue(P.support_report([{"opened": 5}, {"opened": "\x00" * 50}], dt.datetime(2026, 1, 1)))
        self.assertTrue(P.sales_report([{"total": "huge" * 100}], [{"month": None}]))
        self.assertTrue(P.crm_report([{"stage": "??"}, {}], [{"date": 3}, {"deal": None}], D))
        self.assertTrue(P.overdue_followups([{"follow_up": 5}], D))


class TestScreens(unittest.TestCase):
    def test_entries(self):
        self.assertEqual([e.title for e in P.ENTRIES], ["CRM", "Sales Management", "Support Desk", "Advertising Campaign Manager"])
        for e in P.ENTRIES:
            self.assertGreater(len(e.note), 20)

    def test_ads_draws_and_saves(self):
        e = P.ENTRIES[3]
        h = FakeHost(["a", "enter", "Spring", "enter", "ctrl-s", "ctrl-q"])
        run(h, e.args["make"](h, e))
        self.assertEqual(Data(h, P.ADS).items[0]["campaign"], "Spring")
        self.assertIn("Advertising Campaign Manager", h.frames[-1][0])

    def test_support_report_screen(self):
        e = P.ENTRIES[2]
        h = FakeHost(["enter", "R", "escape", "ctrl-q"])
        run(h, e.args["make"](h, e))
        self.assertTrue(any("SLA TARGETS" in "\n".join(f[1]) for f in h.frames))

    def test_crm_menu_saves_deal_in_shared_space(self):
        e = P.ENTRIES[0]
        h = FakeHost(["enter", "a", "enter", "Big deal", "enter", "ctrl-s", "ctrl-q"])
        run(h, e.args["make"](h, e))
        self.assertEqual([r["name"] for r in shared_items(h, "deals")], ["Big deal"])

    def test_manifest_matches_use(self):
        c, s, t, a = P.ENTRIES
        self.assertEqual((c.owns, c.uses), (["deals"], ["contacts", "employees"]))
        self.assertEqual((s.owns, s.uses), ([], ["deals", "invoices"]))
        self.assertEqual(t.uses, ["contacts", "employees"])
        self.assertEqual((a.owns, a.uses), ([], []))

    def test_pickers_prefill_and_say_when_missing(self):
        e = P.ENTRIES[0]
        h = FakeHost()
        h.spaces["contacts"] = {"records": json.dumps({"next": 2, "items": [{"name": "Ann", "company": "Acme", "_id": 1}]})}
        m = e.args["make"](h, e)
        self.assertIn("(1 available)", m.entries[4][0])
        self.assertIn("none: empty or not granted", m.entries[5][0])
        h2 = FakeHost(["5", "enter", "enter", "Big", "enter", "ctrl-s", "ctrl-q"])        # menu item 5: pick Ann, save prefilled deal
        h2.spaces = h.spaces
        run(h2, e.args["make"](h2, e))
        d = shared_items(h2, "deals")[0]
        self.assertEqual((d["contact"], d["account"], d["name"]), ("Ann", "Acme", "Big"))

    def test_pick_empty_screen(self):
        h = FakeHost(["6", "escape", "ctrl-q"])
        run(h, P.ENTRIES[0].args["make"](h, P.ENTRIES[0]))
        self.assertTrue(any("not been granted" in "\n".join(f[1]) for f in h.frames))

    def test_crm_to_sales_through_shared_space(self):
        crm, sales = P.ENTRIES[0], P.ENTRIES[1]
        a, b = FakeHost(["enter", "a", "enter", "Big deal", "enter", "enter", "down", "down", "down", "100", "enter", "ctrl-s", "ctrl-q"]), FakeHost()
        b.spaces = a.spaces                                       # one shared space store
        run(a, crm.args["make"](a, crm))
        got = shared_items(b, "deals")
        self.assertEqual(got[0]["name"], "Big deal")
        out = "\n".join(P.sales_report([], [], got, [{"status": "paid", "total": "50", "due": "2026-11-02"}, {"status": "draft", "total": "9", "due": "2026-11-02"},
                                                         {"status": "sent", "total": "25.5", "due": "2026-11-09"}]))
        self.assertIn("lead", out)
        self.assertIn("2026-11  target         0.00  billed        75.50", out)
        m = sales.args["make"](b, sales)
        m.entries[0][1]()                                          # opens without error
        self.assertIn("not been granted", "\n".join(P.sales_report([], [])))

    def test_support_pickers(self):
        h = FakeHost()
        h.spaces["employees"] = {"records": json.dumps({"next": 2, "items": [{"name": "Eve", "department": "Care", "_id": 1}]})}
        m = P._support(h, P.ENTRIES[2])
        self.assertIn("(none: empty or not granted)", m.entries[1][0])
        self.assertIn("(1 available)", m.entries[2][0])

    def test_sales_menu_draws(self):
        e = P.ENTRIES[1]
        h = FakeHost(["enter", "ctrl-q"])
        run(h, e.args["make"](h, e))
        self.assertIn("Quotes and orders", h.frames[-1][0])


if __name__ == "__main__":
    unittest.main()
