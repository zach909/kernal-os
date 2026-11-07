"""pack_biz2: exact-value tests for the ledger, invoices, stock valuation, three-way match, leave and org chart."""

import datetime as dt
import json
import sys
import unittest
from decimal import Decimal as D
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kos.office import pack_biz2 as b  # noqa: E402
from kos.office.packkit import shared_items  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402

CAP = [("1000", 100000, 0), ("3000", 0, 100000)]


def acct():
    h = FakeHost(); m = b.make_accounting(h); return h, m.ns


class TestAccounting(unittest.TestCase):
    def test_unbalanced_entry_is_refused_and_nothing_is_stored(self):
        h, ns = acct()
        with self.assertRaisesRegex(b.LedgerError, "unbalanced"):
            ns.led.post("2026-01-01", "bad", [("1000", 100, 0), ("4000", 0, 99)])
        self.assertEqual(ns.led.entries, [])
        self.assertNotIn("journal", h.data)
        for bad in ([("1000", 100, 0)], [("9999", 100, 0), ("1000", 0, 100)], [("1000", 0, 0), ("4000", 0, 0)], [("1000", -5, 0), ("4000", 0, -5)], [("1000", 5, 5), ("4000", 0, 0)]):
            with self.assertRaises(b.LedgerError): ns.led.post("2026-01-01", "x", bad)
        with self.assertRaises(ValueError): ns.led.post("2026-13-01", "x", CAP)

    def _books(self):
        h, ns = acct()
        ns.led.post("2026-01-05", "capital", CAP)
        ns.led.post("2026-02-01", "sale", [("1100", 50000, 0), ("4000", 0, 50000)])
        ns.led.post("2026-03-01", "rent", [("6000", 20000, 0), ("1000", 0, 20000)])
        return h, ns

    def test_balance_sheet_equation_and_statements(self):
        _h, ns = self._books()
        t = b.sheet_totals(ns.chart.items, ns.led.entries)
        self.assertEqual(t, {"assets": 130000, "liabilities": 0, "equity": 100000, "earnings": 30000})
        self.assertEqual(t["assets"], t["liabilities"] + t["equity"] + t["earnings"])
        self.assertIn("BALANCED", b.balance_sheet(ns.chart.items, ns.led.entries)[-1])
        self.assertIn("BALANCED", b.trial_balance(ns.chart.items, ns.led.entries)[-1])
        self.assertTrue(any("NET INCOME" in l and "300.00" in l for l in b.income_statement(ns.chart.items, ns.led.entries)))
        # period filter: only February
        inc = b.income_statement(ns.chart.items, ns.led.entries, "2026-02-01", "2026-02-28")
        self.assertTrue(any("NET INCOME" in l and "500.00" in l for l in inc))
        # as at end of January the sale does not exist yet
        self.assertEqual(b.sheet_totals(ns.chart.items, ns.led.entries, "2026-01-31")["assets"], 100000)

    def test_reversal_replaces_deletion(self):
        _h, ns = self._books()
        r = ns.led.reverse(3, "2026-03-02")
        self.assertEqual(r["reverses"], 3)
        self.assertEqual(ns.led.entries[2]["reversed_by"], r["id"])
        self.assertEqual(b.sheet_totals(ns.chart.items, ns.led.entries)["earnings"], 50000)
        self.assertEqual(len(ns.led.entries), 4)
        with self.assertRaises(b.LedgerError): ns.led.reverse(3)
        with self.assertRaises(b.LedgerError): ns.led.reverse(r["id"])
        with self.assertRaises(b.LedgerError): ns.led.reverse(99)

    def test_account_ledger_running_balance_and_chart_protection(self):
        _h, ns = self._books()
        rows = b.account_ledger(ns.chart.items, ns.led.entries, "1000")
        self.assertIn("800.00", rows[-1])
        self.assertTrue(any("opening balance" in l and "1,000.00" in l for l in b.account_ledger(ns.chart.items, ns.led.entries, "1000", "2026-02-01")))
        cash = next(r for r in ns.chart.items if r["code"] == "1000")
        with self.assertRaises(ValueError): ns.chart.remove(cash)
        with self.assertRaises(ValueError): ns.chart.add({"code": "1000", "name": "dup", "type": "asset"})
        self.assertEqual(cash["code"], "1000")

    def test_entry_text_and_screen_run_saves_to_vault(self):
        self.assertEqual(b.parse_entry("2026-01-05 hi\n1000 dr 0.10\n3000 CR 0.10"), ("2026-01-05", "hi", [("1000", 10, 0), ("3000", 0, 10)]))
        for t in ("", "x", "2026-01-01 m\n1000 xx 1\n3000 cr 1", "2026-01-01 m\n1000 dr abc\n3000 cr 1", "2026-01-01 m\n1000 dr nan\n3000 cr 1"):
            with self.assertRaises(ValueError): b.parse_entry(t)
        h = FakeHost("2a<end>cap<enter>1000 dr 5.00<enter>3000 cr 5.00<ctrl-s>6<escape><escape>3", width=100, height=30)
        run(h, b.make_accounting(h))
        self.assertEqual(len(json.loads(h.data["journal"])["entries"]), 1)
        self.assertTrue(any("5.00" in "\n".join(l) for _t, l, _s in h.frames))


class TestInvoicing(unittest.TestCase):
    def setUp(self):
        self.h = FakeHost(); _m, self.ns = b.make_invoicing(self.h)

    def new(self, cust="Acme", lines="Widget | 1 | 100", due="2026-07-01", status="sent", date="2026-06-01", **kw):
        r = self.ns.inv.add({"customer": cust, "date": date, "due": due, "lines": lines, **kw})
        if status != "draft":
            r["status"] = status; self.ns.inv.update(r)
        return r

    def test_totals_discount_tax_exact(self):
        ls = b.parse_lines("Widget | 3 | 19.99\nService | 1.5 | 100")
        self.assertEqual([l[3] for l in ls], [5997, 15000])
        t = b.invoice_totals(ls, "10", "8.25")
        self.assertEqual(t, {"subtotal": 20997, "discount": 2100, "tax": 1559, "total": 20456})
        self.assertTrue(all(type(v) is int for v in t.values()))
        self.assertEqual(b.cents("0.10") + b.cents("0.20"), 30)
        for bad in ("", "x | 1", "x | -1 | 5", "x | 1 | -5", "x | nan | 5", "| 1 | 1", "x | 1e999999 | 1"):
            with self.assertRaises(ValueError): b.parse_lines(bad)
        with self.assertRaises(ValueError): b.invoice_totals(ls, "101", "0")

    def test_numbers_status_locking_and_payments(self):
        a, c = self.new(), self.new(status="draft", lines="x | 2 | 50")
        self.assertEqual((a["number"], c["number"], a["total"], a["balance"]), ("INV-0001", "INV-0002", "100.00", "100.00"))
        a["lines"] = "Widget | 1 | 1"
        with self.assertRaisesRegex(ValueError, "locked"): self.ns.inv.update(a)
        self.assertEqual(a["lines"], "Widget | 1 | 100")           # a refused edit leaves the record unchanged
        self.ns.pay.add({"invoice": "inv-0001", "date": "2026-06-10", "amount": "30"})
        self.assertEqual(a["balance"], "70.00")
        with self.assertRaisesRegex(ValueError, "overpayment"): self.ns.pay.add({"invoice": "INV-0001", "date": "2026-06-10", "amount": "70.01"})
        with self.assertRaisesRegex(ValueError, "only sent"): self.ns.pay.add({"invoice": "INV-0002", "date": "2026-06-10", "amount": "1"})
        self.ns.pay.add({"invoice": "INV-0001", "date": "2026-06-11", "amount": "70"})
        self.assertEqual((a["status"], a["balance"]), ("paid", "0.00"))
        self.ns.pay.remove(self.ns.pay.items[-1])
        self.assertEqual((a["status"], a["balance"]), ("sent", "70.00"))
        with self.assertRaises(ValueError): self.ns.inv.remove(a)
        self.ns.inv.remove(c)
        d = self.new(status="draft")
        self.assertEqual(d["number"], "INV-0003")                  # numbers are never reused
        with self.assertRaises(ValueError): self.ns.inv.add({"customer": "A", "date": "2026-06-01", "due": "2026-05-01", "lines": "x | 1 | 1"})

    def test_ageing_buckets(self):
        for due in ("2026-07-10", "2026-06-10", "2026-04-01", "2026-03-31"):    # 0 / 20 / 90 / 91 days at 2026-06-30
            self.new(due=due, date="2026-01-01")
        self.new(cust="Paid Co", due="2026-01-01", date="2026-01-01", status="draft")                # drafts do not age
        row = next(l for l in b.ageing(self.ns.inv.items, dt.date(2026, 6, 30)) if l.startswith("Acme"))
        self.assertEqual(row.split(), ["Acme", "100.00", "100.00", "100.00", "100.00", "400.00"])
        self.assertEqual(len(b.ageing([], dt.date(2026, 6, 30))), 5)

    def test_export_escapes_everything(self):
        r = self.new(cust="<script>alert(1)</script>", lines="<b>x</b> & y | 2 | 1.50", status="draft")
        h = b.invoice_html(r)
        self.assertNotIn("<script>", h); self.assertIn("&lt;b&gt;x&lt;/b&gt;", h)
        self.assertIn("&lt;script&gt;", h); self.assertIn("&amp;", h)
        txt = "\n".join(b.invoice_text(r))
        self.assertIn("TOTAL", txt); self.assertIn("3.00", txt)

    def test_contacts_picker_when_shared_and_screen_run(self):
        self.h.spaces["contacts"] = {"records": json.dumps({"next": 2, "items": [{"name": "Zed Co", "_id": 1}]})}
        self.assertEqual(self.new(cust="zed co", status="draft")["customer"], "Zed Co")
        with self.assertRaisesRegex(ValueError, "one of"): self.new(cust="Nobody", status="draft")
        h = FakeHost("1pc<escape><escape>", width=100, height=30)
        run(h, b.make_invoicing(h)[0])
        self.assertFalse([t for t, _l, _s in h.frames if "Internal error" in t])


class TestInventory(unittest.TestCase):
    def test_weighted_average_and_fifo_exact(self):
        m = [("receipt", D(10), D(10)), ("receipt", D(10), D(20)), ("issue", D(5), None)]
        self.assertEqual(b.valuate(m, D(0), "wa"), (D(15), D(225)))
        self.assertEqual(b.valuate(m[:2] + [("issue", D(15), None)], D(0), "fifo"), (D(5), D(100)))
        self.assertEqual(b.valuate(m[:2] + [("issue", D(15), None)], D(0), "wa"), (D(5), D(75)))
        self.assertEqual(b.valuate([("receipt", D(4), D(2.5)), ("adjust", D(-1), None), ("adjust", D(2), None)], D(3), "wa"), (D(5), D("12.5")))
        self.assertEqual(b.valuate([("issue", D(5), None)], D(0)), (D(0), D(0)))     # over-issue is clamped, never negative

    def test_movement_ledger_computes_on_hand_and_writes_it_back(self):
        h = FakeHost(); _m, ns = b.make_inventory(h)
        it = ns.items.add({"sku": "w-1", "name": "Widget", "unit_cost": "2", "reorder_point": "5", "on_hand": "999"})
        self.assertEqual((it["sku"], it["on_hand"]), ("W-1", "0"))
        with self.assertRaisesRegex(ValueError, "SKU"): ns.items.add({"sku": "bad sku!", "name": "x"})
        with self.assertRaisesRegex(ValueError, "exists"): ns.items.add({"sku": "w-1", "name": "dup"})
        ns.mov.add({"sku": "w-1", "date": "2026-01-01", "kind": "receipt", "qty": "10", "unit_cost": "10"})
        ns.mov.add({"sku": "W-1", "date": "2026-01-02", "kind": "receipt", "qty": "10", "unit_cost": "20"})
        ns.mov.add({"sku": "W-1", "date": "2026-01-03", "kind": "issue", "qty": "15"})
        self.assertEqual(shared_items(h, "inventory")[0]["on_hand"], "5")
        it["on_hand"] = "100"
        ns.items.update(it); self.assertEqual(it["on_hand"], "5")           # cannot be edited directly
        for bad in ({"kind": "issue", "qty": "6"}, {"kind": "issue", "qty": "-1"}, {"kind": "adjust", "qty": "-6"}, {"kind": "adjust", "qty": "0"}, {"kind": "receipt", "qty": "x"}, {"sku": "NOPE", "kind": "receipt", "qty": "1"}):
            with self.assertRaises(ValueError): ns.mov.add({"sku": "W-1", "date": "2026-01-04", **bad})
        with self.assertRaises(ValueError): ns.mov.update(ns.mov.items[0])
        with self.assertRaises(ValueError): ns.mov.remove(ns.mov.items[0])
        with self.assertRaises(ValueError): ns.items.remove(it)
        st = b.stock_table(ns.items.items, ns.mov.items)[0]
        self.assertEqual((st["on_hand"], st["wa"], st["fifo"]), (D(5), 7500, 10000))
        self.assertTrue(any("W-1" in l for l in b.low_stock(ns.items.items, ns.mov.items)[2:]))   # 5 <= reorder point 5
        ns.mov.add({"sku": "W-1", "date": "2026-01-05", "kind": "adjust", "qty": "3"})
        self.assertEqual(it["on_hand"], "8")
        self.assertEqual(len(b.low_stock(ns.items.items, ns.mov.items)), 2)


class TestProcurement(unittest.TestCase):
    def test_three_way_match_flags(self):
        pos = [{"number": "PO-1", "status": "received", "qty": "10", "unit_price": "5.00", "supplier": "S"},
               {"number": "PO-2", "status": "partial", "qty": "10", "unit_price": "5.00", "supplier": "S"},
               {"number": "PO-3", "status": "draft", "qty": "1", "unit_price": "1"}]
        rec = [{"po": "PO-1", "qty": "10"}, {"po": "PO-2", "qty": "8"}]
        bills = [{"ref": "A", "po": "PO-1", "qty": "10", "unit_price": "5.00"}, {"ref": "B", "po": "PO-2", "qty": "10", "unit_price": "5.50"}, {"ref": "C", "po": "PO-9", "qty": "1", "unit_price": "1"}]
        r = {x["number"]: x["flags"] for x in b.three_way(pos, rec, bills)}
        self.assertEqual(r["PO-1"], [])
        self.assertIn("SHORT-RECEIVED (8 of 10)", r["PO-2"]); self.assertIn("BILLED BUT NOT RECEIVED", r["PO-2"]); self.assertIn("PRICE MISMATCH", r["PO-2"])
        self.assertNotIn("PO-3", r)
        self.assertTrue(r["PO-9"][0].startswith("ORPHAN"))
        self.assertEqual(b.match_report(pos, rec, bills)[0], "Three-way match: 3 PO(s), 2 with mismatches")

    def test_lifecycle_requests_orders_receipts(self):
        h = FakeHost(); _m, ns = b.make_procurement(h)
        ns.sup.add({"name": "Supply Co"})
        rq = ns.req.add({"item": "Bolts", "qty": "10", "requester": "Ann"})
        self.assertEqual((rq["number"], rq["status"]), ("PR-0001", "requested"))
        with self.assertRaisesRegex(ValueError, "approved"): ns.po.add({"supplier": "Supply Co", "request": "PR-0001", "item": "Bolts", "qty": "10", "unit_price": "1", "date": "2026-01-01"})
        rq["status"] = "approved"; ns.req.update(rq)
        po = ns.po.add({"supplier": "supply co", "request": "pr-0001", "item": "Bolts", "qty": "10", "unit_price": "1.5", "date": "2026-01-01"})
        self.assertEqual((po["number"], po["supplier"], rq["status"]), ("PO-0001", "Supply Co", "ordered"))
        with self.assertRaisesRegex(ValueError, "issued|ordered|purchase order"): rq["status"] = "approved"; ns.req.update(rq)
        with self.assertRaisesRegex(ValueError, "one of"): ns.po.add({"supplier": "Nope", "item": "x", "qty": "1", "unit_price": "1", "date": "2026-01-01"})
        with self.assertRaisesRegex(ValueError, "draft"): ns.rec.add({"po": "PO-0001", "date": "2026-01-02", "qty": "1"})
        po["status"] = "partial"
        with self.assertRaises(ValueError): ns.po.update(po)
        self.assertEqual(po["status"], "draft")
        po["status"] = "sent"; ns.po.update(po)
        ns.rec.add({"po": "PO-0001", "date": "2026-01-03", "qty": "4"}); self.assertEqual(po["status"], "partial")
        ns.rec.add({"po": "PO-0001", "date": "2026-01-04", "qty": "6"}); self.assertEqual(po["status"], "received")
        self.assertEqual(b.open_po_value(ns.po.items, ns.rec.items), (0, 0))
        with self.assertRaises(ValueError): ns.po.remove(po)

    def test_reorder_suggestions_use_shared_inventory_and_say_when_missing(self):
        inv = [{"sku": "A", "name": "Alpha", "on_hand": "2", "reorder_point": "5", "unit_cost": "3"}, {"sku": "B", "name": "Beta", "on_hand": "9", "reorder_point": "5"}, {"sku": "C", "on_hand": "0", "reorder_point": "0"}]
        self.assertEqual(b.reorder_suggestions(inv, []), [("A", "Alpha", D(8), 2400)])
        self.assertEqual(b.reorder_suggestions(inv, [{"item": "A - Alpha", "status": "approved"}]), [])
        h = FakeHost("7<escape><escape>", width=100, height=30)
        run(h, b.make_procurement(h)[0])
        self.assertTrue(any("kos grant" in "\n".join(l) for _t, l, _s in h.frames))
        h.spaces["inventory"] = {"records": json.dumps({"next": 2, "items": inv})}
        h2 = FakeHost("8y<escape><escape>", width=100, height=30); h2.spaces = h.spaces
        _m, ns = b.make_procurement(h2); self.assertEqual(len(ns.req.items), 0)
        run(h2, _m)
        self.assertEqual([(r["item"], r["qty"], r["est_cost"]) for r in ns.req.items], [("A - Alpha", "8", "24.00")])


class TestHR(unittest.TestCase):
    def setUp(self):
        self.h = FakeHost(); _m, self.ns = b.make_hr(self.h)

    def emp(self, name, **kw): return self.ns.emp.add({"name": name, **kw})

    def test_org_chart_tree_cycle_guard_and_tampered_cycle(self):
        self.emp("CEO"); self.emp("VP", manager="ceo"); self.emp("Eng", manager="VP"); self.emp("Solo")
        self.assertEqual(b.org_chart(self.ns.emp.items), ["- CEO", "  - VP", "    - Eng", "- Solo"])
        ceo = self.ns.emp.items[0]; ceo["manager"] = "Eng"
        with self.assertRaisesRegex(ValueError, "loop"): self.ns.emp.update(ceo)
        self.assertEqual(ceo["manager"], "")
        with self.assertRaises(ValueError): self.emp("X", manager="ghost")
        with self.assertRaises(ValueError): self.emp("ceo")
        out = b.org_chart([{"name": "A", "manager": "B"}, {"name": "B", "manager": "A"}, {"name": "C"}])
        self.assertEqual(out[0], "- C"); self.assertTrue(any("CYCLE" in l and "A" in l and "B" in l for l in out))
        with self.assertRaises(ValueError): self.ns.emp.remove(self.ns.emp.items[1])    # VP manages Eng
        self.assertEqual(b.headcount([{"department": "X", "status": "active"}, {"department": "X", "status": "left"}, {"status": "on leave"}])[0], "Headcount: 2 current (1 active)")

    def test_accrual_and_approval_against_balance(self):
        self.assertEqual(b.accrued("2020-01-01", D(24), dt.date(2026, 6, 15)), D(10))
        self.assertEqual(b.accrued("2026-03-10", D(24), dt.date(2026, 6, 15)), D(6))
        self.assertEqual(b.accrued("2026-07-01", D(24), dt.date(2026, 6, 15)), D(0))
        self.assertEqual(b.accrued("garbage", D(24), dt.date(2026, 6, 15)), D(0))
        self.assertEqual(b.weekdays(dt.date(2026, 6, 1), dt.date(2026, 6, 14)), 10)
        self.emp("Ann", hire_date="2020-01-01")
        r = self.ns.lr.add({"employee": "ann", "type": "annual", "start": "2026-06-01", "end": "2026-06-05"})
        self.assertEqual((r["days"], r["status"], r["employee"], r["type"]), ("5", "requested", "Ann", "Annual"))
        r["status"] = "approved"; self.ns.lr.update(r)                       # 20/12*5 = 8.33 accrued by 1 June
        r2 = self.ns.lr.add({"employee": "Ann", "type": "Annual", "start": "2026-06-08", "end": "2026-06-12"})
        r2["status"] = "approved"
        with self.assertRaisesRegex(ValueError, "insufficient balance: 3.33"): self.ns.lr.update(r2)
        self.assertEqual(r2["status"], "requested")
        rows = b.make_hr(self.h)[1].balances(dt.date(2026, 6, 15))
        self.assertTrue(any(l.split()[:2] == ["Ann", "Annual"] and "8.33" in l and "3.33" in l for l in rows))
        for bad in ({"start": "2026-06-05", "end": "2026-06-01"}, {"start": "2026-06-06", "end": "2026-06-07"}, {"start": "2026-12-30", "end": "2027-01-02"}, {"employee": "Nobody"}, {"type": "Nope"}):
            with self.assertRaises(ValueError): self.ns.lr.add({"employee": "Ann", "type": "Annual", "start": "2026-07-01", "end": "2026-07-02", **bad})
        with self.assertRaises(ValueError): self.ns.lr.remove(r)

    def test_no_government_id_or_bank_fields_and_employees_shared_fields(self):
        keys = {f.key for f in b.EMP_SPEC.fields}
        self.assertTrue({"name", "department", "manager", "title", "email"} <= keys)
        self.assertFalse([k for k in keys if any(w in k for w in ("ssn", "tax", "passport", "bank", "iban", "account", "national"))])
        self.emp("Zoe", department="Ops")
        self.assertEqual(shared_items(self.h, "employees")[0]["name"], "Zoe")


class TestSharingAndErp(unittest.TestCase):
    def test_two_hosts_share_invoices_invoicing_writes_accounting_reads(self):
        h1, h2 = FakeHost(), FakeHost(); h2.spaces = h1.spaces
        _m, ns = b.make_invoicing(h1)
        r = ns.inv.add({"customer": "Acme", "date": "2026-06-01", "due": "2026-07-01", "lines": "Work | 2 | 50"})
        r["status"] = "sent"; ns.inv.update(r)
        self.assertEqual(shared_items(h2, "invoices")[0]["number"], "INV-0001")
        m = b.make_accounting(h2)
        sug = b.inv_suggestions(m.ns.led, shared_items(h2, "invoices"))
        self.assertEqual(sug[0][3], [("1100", 10000, 0), ("4000", 0, 10000)])
        run(h2, m)                                                            # draws
        h3 = FakeHost("8y<escape><escape>", width=100, height=30); h3.spaces = h1.spaces
        m3 = b.make_accounting(h3)
        run(h3, m3)                                                           # no-op keys; then post via menu
        h4 = FakeHost("9y<enter><escape>", width=100, height=30); h4.spaces = h1.spaces
        m4 = b.make_accounting(h4); run(h4, m4)
        self.assertEqual(b._ar(m4.ns.led), 10000)
        self.assertEqual(m4.ns.led.entries[0]["ref"], "INV-0001")
        self.assertEqual(b.inv_suggestions(m4.ns.led, shared_items(h4, "invoices")), [])      # not posted twice
        h1.spaces["invoices"]["records"] = json.dumps({"next": 1, "items": [{"number": "INV-0001", "status": "paid", "total": "100.00", "customer": "Acme"}]})
        self.assertEqual([s[0] for s in b.inv_suggestions(m4.ns.led, shared_items(h4, "invoices"))], ["INV-0001/paid"])

    def test_missing_grant_is_said_and_apps_still_work(self):
        h = FakeHost("8<escape><escape>", width=100, height=30)             # nothing shared
        run(h, b.make_accounting(h))
        self.assertTrue(any("kos grant accounting space:invoices" in "\n".join(l) for _t, l, _s in h.frames))
        self.assertEqual(shared_items(h, "invoices"), [])

    def test_erp_hub_prefixes_and_summary(self):
        h = FakeHost()
        _m, inv = b.make_invoicing(b.PrefixHost(h, "inv-"))
        r = inv.inv.add({"customer": "Acme", "date": "2026-06-01", "due": "2026-07-01", "lines": "x | 1 | 100"}); r["status"] = "sent"; inv.inv.update(r)
        inv.pay.add({"invoice": "INV-0001", "date": "2026-06-02", "amount": "25"})
        _m, stk = b.make_inventory(b.PrefixHost(h, "stk-"))
        stk.items.add({"sku": "a", "name": "A"}); stk.mov.add({"sku": "a", "date": "2026-01-01", "kind": "receipt", "qty": "4", "unit_cost": "2.50"})
        _m, hr = b.make_hr(b.PrefixHost(h, "hr-")); hr.emp.add({"name": "Ann"}); hr.emp.add({"name": "Bob", "status": "left"})
        _m, pro = b.make_procurement(b.PrefixHost(h, "pro-")); pro.sup.add({"name": "S"})
        po = pro.po.add({"supplier": "S", "item": "x", "qty": "10", "unit_price": "2", "date": "2026-01-01"}); po["status"] = "sent"; pro.po.update(po)
        pro.rec.add({"po": "PO-0001", "date": "2026-01-02", "qty": "4"})
        acc = b.make_accounting(b.PrefixHost(h, "acc-")); acc.ns.led.post("2026-01-01", "c", CAP)
        s = "\n".join(b.erp_summary(h))
        for want in ("Receivables: 75.00 across 1", "Open purchase orders: 1, value still to receive 12.00", "Stock value (weighted average): 10.00", "Headcount: 1 ", "debits 1,000.00 / credits 1,000.00"):
            self.assertIn(want, s)
        self.assertTrue({"inv-payments", "stk-movements", "hr-leave", "pro-orders", "acc-journal"} <= set(h.data) | {"hr-leave"})
        self.assertFalse([k for k in h.data if not k.split("-")[0] in ("inv", "stk", "hr", "pro", "acc")])
        h2 = FakeHost("<enter>6<escape><escape>", width=100, height=30)
        run(h2, b.make_erp(h2))
        self.assertFalse([t for t, _l, _s in h2.frames if "Internal error" in t])

    def test_entries_declare_exactly_the_needed_permissions_and_no_floats(self):
        e = {x.title: x for x in b.ENTRIES}
        self.assertEqual(len(e), 6)
        self.assertEqual((e["Invoicing"].owns, e["Invoicing"].uses), (["invoices"], ["contacts"]))
        self.assertEqual((e["Inventory Management"].owns, e["Inventory Management"].uses), (["inventory"], []))
        self.assertEqual((e["Human Resources"].owns, e["Human Resources"].uses), (["employees"], []))
        self.assertEqual((e["Accounting"].owns, e["Accounting"].uses), ([], ["invoices"]))
        self.assertEqual((e["Procurement"].owns, e["Procurement"].uses), ([], ["inventory", "employees"]))
        self.assertEqual((sorted(e["ERP"].owns), e["ERP"].uses), (["employees", "inventory", "invoices"], ["contacts"]))
        for x in e.values():
            self.assertGreater(len(x.note), 20); self.assertFalse(x.network)
        src = (Path(b.__file__)).read_text()
        self.assertNotIn("float(", src)

    def test_every_app_survives_hostile_keys(self):
        keys = ["enter", "a", "x" * 5, "enter", "down", "ctrl-s", "escape", "\x00", "1", "2", "3", "4", "5", "6", "7", "8", "9", "enter", "a", "\x1b[2J", "enter", "escape", "r", "p", "h", "c", "d", "y", " ", "b", "escape", "escape"]
        for x in b.ENTRIES:
            h = FakeHost(keys, width=100, height=30); run(h, x.args["make"](h, x))
            self.assertFalse([t for t, _l, _s in h.frames if "Internal error" in t], x.title)


if __name__ == "__main__":
    unittest.main()
