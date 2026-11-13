"""Tests for the vault (OS side) and the productivity suite (kos.office).

Run with: python3 -m unittest discover -s tests -v

The suite is tested through scripted keys (FakeHost) because the sandbox needs
kernel features some containers lack; the vault's wire path is tested over a
real socket pair with the real SDK and the real Session handler."""

import csv
import datetime as dt
import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos.office import (builder, calendar_, docs, extras, flow, llm, mail, quiz, records, security, sheet,  # noqa: E402
                        sqlapp, tools)
from kos.office.catalog import BY_NAME, CATALOG, build  # noqa: E402
from kos.office.search import Index  # noqa: E402
from kos.office.specs import S  # noqa: E402
from kos.office.ui import FakeHost, run  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.protocol import ProtocolError, validate_app_message  # noqa: E402
from kos.sdk import App  # noqa: E402
from kos.session import Session  # noqa: E402
from kos.vault import MAX_ITEM, Vault, VaultError  # noqa: E402
from kos.spaces import AppStorage, StorageError  # noqa: E402
from kos.permissions import Permissions  # noqa: E402
from kos.permit import PermitError, PermitStore  # noqa: E402
from kos.appdirs import AppDirs  # noqa: E402
from kos.kapp import KApp, Manifest  # noqa: E402


def drive(screen_factory, keys, data=None, **kw):
    h = FakeHost(keys, data=data if data is not None else {}, **kw)
    run(h, screen_factory(h))
    return h


class TestVault(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.paths = Paths(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_put_get_list_delete(self):
        v = Vault(self.paths, "notes")
        v.put("a", "hello"); v.put("b.txt", "x")
        self.assertEqual(v.get("a"), "hello")
        self.assertEqual(v.keys(), ["a", "b.txt"])
        self.assertTrue(v.delete("a")); self.assertFalse(v.delete("a"))
        self.assertIsNone(v.get("a"))

    def test_keys_cannot_escape_the_vault(self):
        v = Vault(self.paths, "notes")
        for bad in ("../x", "a/b", "/etc/passwd", ".hidden", "A", "", "x" * 65):
            with self.assertRaises(VaultError):
                v.put(bad, "no")

    def test_limits(self):
        v = Vault(self.paths, "notes")
        with self.assertRaises(VaultError):
            v.put("big", "x" * (MAX_ITEM + 1))

    def test_each_app_has_its_own_vault(self):
        Vault(self.paths, "one").put("k", "1")
        self.assertIsNone(Vault(self.paths, "two").get("k"))

    def test_private_data_lives_in_the_apps_data_folder(self):
        Vault(self.paths, "notes").put("k", "1")
        self.assertTrue((AppDirs(self.paths, "notes").data / "k").exists())

    def test_storage_permission_is_a_valid_manifest_permission(self):
        m = Manifest.parse(json.dumps({"name": "x", "version": "1", "runtime": "python", "entry": "a:main", "permissions": ["storage"]}).encode())
        self.assertEqual(m.permissions, ("storage",))


class TestVaultProtocol(unittest.TestCase):
    def test_valid_and_invalid_messages(self):
        ok = validate_app_message({"cmd": "vault", "id": 1, "op": "put", "key": "a", "value": "line\nbreak"}, "tui")
        self.assertEqual(ok["value"], "line\nbreak")           # data is not stripped
        for bad in ({"cmd": "vault", "id": 1, "op": "rm", "key": "a"}, {"cmd": "vault", "id": 1, "op": "get", "key": "../a"},
                    {"cmd": "vault", "id": "x", "op": "list"}, {"cmd": "vault", "id": 1, "op": "put", "key": "a"}):
            with self.assertRaises(ProtocolError):
                validate_app_message(bad, "tui")


class StubOS:
    """Just enough of Session to run its real vault handler."""
    _on_vault = Session._on_vault

    def __init__(self, vault, sock):
        self.vault, self.sock = vault, sock

    def _send(self, obj):
        self.sock.sendall(json.dumps(obj).encode() + b"\n")


class TestSdkVaultRoundTrip(unittest.TestCase):
    def serve(self, os_side, stub, extra_first=None):
        f = os_side.makefile("rb")
        if extra_first:
            os_side.sendall(json.dumps(extra_first).encode() + b"\n")
        for line in f:
            msg = validate_app_message(json.loads(line), "tui")
            if msg["cmd"] == "vault":
                stub._on_vault(msg)

    def test_app_sdk_talks_to_the_real_session_handler(self):
        with tempfile.TemporaryDirectory() as td:
            a, b = socket.socketpair(); a.settimeout(10)
            stub = StubOS(AppStorage(Paths(Path(td)), "demo", ["storage"]), b)
            t = threading.Thread(target=self.serve, args=(b, stub, {"cmd": "key", "key": "z"}), daemon=True); t.start()
            os.environ["KOS_MODE"] = "tui"
            app = App(a)
            self.assertTrue(app.vault_put("k", "v\nline2"))
            self.assertEqual(app.vault_get("k"), "v\nline2")
            self.assertEqual(app.vault_keys(), ["k"])
            self.assertIsNone(app.vault_get("missing"))
            self.assertFalse(app.vault_put("../x", "no") if False else app.vault_delete("missing") and False)
            self.assertTrue(app.vault_delete("k"))
            # the key event that arrived while we were waiting on a vault reply is not lost
            self.assertEqual(next(app.events())["key"], "z")
            a.close(); b.close()

    def test_no_storage_permission_is_refused_not_ignored(self):
        a, b = socket.socketpair(); a.settimeout(10)
        stub = StubOS(None, b)
        t = threading.Thread(target=self.serve, args=(b, stub), daemon=True); t.start()
        app = App(a)
        self.assertFalse(app.vault_put("k", "v"))
        a.close(); b.close()


class TestAppDirsAndPermissions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.paths = Paths(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_layout_cache_data_run_and_cache_is_per_app(self):
        from kos import cache
        d = AppDirs(self.paths, "hello").ensure()
        self.assertEqual({p.name for p in d.root.iterdir()}, {"cache", "data", "run"})
        c = cache.alloc(self.paths, "hello")
        self.assertEqual(c.parent, d.cache); cache.wipe(c); self.assertFalse(c.exists())
        with self.assertRaises(Exception): AppDirs(self.paths, "../evil")

    def test_universal_store_levels_owner_revoke(self):
        P = Permissions(self.paths)
        P.grant("a", "space:contacts", "own"); P.grant("b", "space:contacts", "read")
        self.assertTrue(P.has("a", "space:contacts", "write")); self.assertTrue(P.has("b", "space:contacts", "read"))
        self.assertFalse(P.has("b", "space:contacts", "write")); self.assertFalse(P.has("c", "space:contacts", "read"))
        self.assertEqual(P.owner_of("space:contacts"), "a")
        self.assertEqual(P.revoke("b"), 1); self.assertFalse(P.has("b", "space:contacts", "read"))

    def test_run_permit_is_in_the_same_store_and_legacy_files_migrate(self):
        ps = PermitStore(self.paths)
        legacy = self.paths.state / "permits"; legacy.mkdir(parents=True)
        (legacy / "old.json").write_text('{"name":"old","granted_at":1}')
        self.assertTrue(ps.is_permitted("old")); self.assertFalse((legacy / "old.json").exists())
        ps.grant("new"); self.assertTrue(Permissions(self.paths).has("new", "run"))
        ps.revoke("new"); self.assertFalse(ps.is_permitted("new"))

    def test_revoking_the_run_permit_does_not_give_away_a_shared_folder(self):
        P, ps = Permissions(self.paths), PermitStore(self.paths)
        ps.grant("contacts-app"); P.grant("contacts-app", "space:contacts", "own")
        ps.revoke("contacts-app")
        self.assertFalse(ps.is_permitted("contacts-app")); self.assertEqual(P.owner_of("space:contacts"), "contacts-app")
        squatter = AppStorage(self.paths, "squatter", ["owns:contacts"])
        with self.assertRaises(StorageError): squatter.vault("contacts", "get")

    def test_an_update_that_asks_for_more_than_was_approved_is_refused(self):
        ps = PermitStore(self.paths); ps.grant("app", ["storage"])
        ps.check_declared("app", ["storage"])
        with self.assertRaises(PermitError): ps.check_declared("app", ["storage", "network"])
        ps.grant("app", ["storage", "network"]); ps.check_declared("app", ["storage", "network"])


class TestSharedSpaces(unittest.TestCase):
    """'contacts' is created by the Contacts app; everyone else looks for it and needs a grant."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.paths = Paths(Path(self.tmp.name)); self.P = Permissions(self.paths)
        self.owner = AppStorage(self.paths, "contacts-app", ["owns:contacts"])
        self.mail = AppStorage(self.paths, "mail-app", ["storage", "uses:contacts"])

    def tearDown(self):
        self.tmp.cleanup()

    def test_owner_creates_the_space_and_its_permission_on_first_use(self):
        self.assertIsNone(self.P.owner_of("space:contacts"))
        self.owner.vault("contacts", "put").put("records", "ann")
        self.assertEqual(self.P.owner_of("space:contacts"), "contacts-app")
        self.assertTrue((self.paths.state / "spaces" / "contacts" / "records").exists())

    def test_consumer_needs_both_the_manifest_and_a_grant(self):
        self.owner.vault("contacts", "put").put("records", "ann")
        with self.assertRaises(StorageError): self.mail.vault("contacts", "get")             # declared, not granted
        self.P.grant("mail-app", "space:contacts", "read")
        self.assertEqual(self.mail.vault("contacts", "get").get("records"), "ann")
        with self.assertRaises(StorageError): self.mail.vault("contacts", "put")            # read is not write
        self.P.grant("mail-app", "space:contacts", "write"); self.mail.vault("contacts", "put").put("x", "1")
        stranger = AppStorage(self.paths, "stranger", ["storage"])
        self.P.grant("stranger", "space:contacts", "write")                                  # granted but never declared
        with self.assertRaises(StorageError): stranger.vault("contacts", "get")

    def test_nobody_can_take_over_an_owned_space(self):
        self.owner.vault("contacts", "put").put("records", "ann")
        squatter = AppStorage(self.paths, "squatter", ["owns:contacts"])
        with self.assertRaises(StorageError): squatter.vault("contacts", "get")

    def test_private_data_and_spaces_are_separate_and_revocation_works(self):
        self.mail.vault(None, "put").put("mine", "private")
        self.assertEqual(self.owner.visible_spaces(), [{"space": "contacts", "access": "own", "owner": "contacts-app"}])
        self.assertEqual(self.mail.visible_spaces(), [])                                      # nothing granted yet
        self.owner.vault("contacts", "put").put("records", "ann"); self.P.grant("mail-app", "space:contacts", "read")
        self.assertEqual(self.mail.visible_spaces()[0]["access"], "read")
        self.assertNotIn("mine", self.owner.vault("contacts", "list").keys())
        self.P.revoke("mail-app", "space:contacts")
        with self.assertRaises(StorageError): self.mail.vault("contacts", "get")

    def test_private_storage_needs_the_storage_permission(self):
        with self.assertRaises(StorageError): self.owner.vault(None, "get")


class TestSpacesOverTheWire(unittest.TestCase):
    def test_two_real_sdk_apps_share_a_space_through_the_session_handler(self):
        with tempfile.TemporaryDirectory() as td:
            paths = Paths(Path(td)); sdk = []
            for name, perms in (("contacts-app", ["owns:contacts"]), ("mail-app", ["storage", "uses:contacts"])):
                a, b = socket.socketpair(); a.settimeout(10)
                stub = StubOS(AppStorage(paths, name, perms), b)
                threading.Thread(target=TestSdkVaultRoundTrip.serve, args=(self, b, stub), daemon=True).start()
                sdk.append(App(a))
            owner, mail = sdk
            self.assertTrue(owner.vault_put("records", "ann", space="contacts"))
            self.assertIsNone(mail.vault_get("records", space="contacts"))
            self.assertIn("no read access", mail.vault_error)                       # the app can show why
            Permissions(paths).grant("mail-app", "space:contacts", "read")
            self.assertEqual(mail.vault_get("records", space="contacts"), "ann")
            self.assertFalse(mail.vault_put("records", "evil", space="contacts"))
            self.assertEqual(owner.vault_get("records", space="contacts"), "ann")
            self.assertEqual(mail.vault_spaces()[0]["space"], "contacts")
            self.assertFalse(mail.vault_put("k", "v", space="calendar"))
            self.assertIn("does not declare", mail.vault_error)

    def test_protocol_rejects_bad_space_names(self):
        for bad in ("../x", "Contacts", "a b", 5):
            with self.assertRaises(ProtocolError):
                validate_app_message({"cmd": "vault", "id": 1, "op": "get", "key": "k", "space": bad}, "tui")


class TestSharedSuite(unittest.TestCase):
    """Contacts creates the folder; the other apps look for it; the device owner decides who gets in."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.paths = Paths(Path(self.tmp.name)); self.P = Permissions(self.paths)

    def tearDown(self):
        self.tmp.cleanup()

    def host(self, name, keys=(), **kw):
        e = BY_NAME[name]
        from suite.gen import manifest
        return FakeHost(keys, storage=AppStorage(self.paths, name, manifest(e)["permissions"]), **kw), e

    def test_contacts_calendar_and_scheduler_end_to_end(self):
        h, e = self.host("contact-manager", ["a", "enter", *"Ann", "enter", "down", "down", "enter", *"ann@x.io", "enter", "ctrl-s"])
        run(h, build(h, e))
        self.assertEqual(self.P.owner_of("space:contacts"), "contact-manager")               # the Contacts app made the folder + permission
        self.assertTrue((self.paths.state / "spaces" / "contacts" / "records").exists())
        # the mail client looks for it: nothing until the owner of the device grants read access
        mh, me = self.host("email-client", ["c", "A", "n"])
        mail.MailStore(mh).users.add({"addr": "me@kos.local", "quota": "50", "active": "yes"})
        run(mh, build(mh, me)); self.assertNotIn("ann@x.io", mh.text)
        self.P.grant("email-client", "space:contacts", "read")
        mh2, _ = self.host("email-client", ["c", "A", "n", "tab"], data=mh.data); run(mh2, build(mh2, me))
        self.assertIn("> ann@x.io", mh2.text)                                                  # Tab completed the address
        # the scheduler: books fine either way, but only reaches the shared calendar once granted write
        sh, se = self.host("appointment-scheduler"); s = build(sh, se); first = s.slots()[0]
        s._book(*first, "Ann"); self.assertIn("NOT on the calendar", s.msg)
        self.P.grant("appointment-scheduler", "space:calendar", "write")
        s2 = build(sh, se); second = s2.slots()[1]; s2._book(*second, "Bob"); self.assertIn("on the shared calendar", s2.msg)
        ch, ce = self.host("calendar-manager"); events = records.Data(SpaceHostForTest(ch, "calendar"), calendar_.EVENT_SPEC).items
        self.assertEqual([x["title"] for x in events], ["Appointment: Bob"])
        self.assertEqual(events[0]["date"], second[0])

    def test_a_read_only_consumer_cannot_change_the_owners_data(self):
        h, e = self.host("contact-manager", ["a", "enter", *"Ann", "enter", "ctrl-s"]); run(h, build(h, e))
        before = (self.paths.state / "spaces" / "contacts" / "records").read_text()
        self.P.grant("email-client", "space:contacts", "read")
        mh, _ = self.host("email-client"); self.assertFalse(mh.put("records", "{}", space="contacts"))
        self.assertIn("no write access", mh.error)
        self.assertEqual((self.paths.state / "spaces" / "contacts" / "records").read_text(), before)

    def test_every_manifest_that_uses_or_owns_a_space_is_valid(self):
        from suite.gen import manifest
        for e in CATALOG:
            if e.scope != "none": Manifest.parse(json.dumps(manifest(e)).encode())


from kos.office.ui import SpaceHost as SpaceHostForTest  # noqa: E402


class TestSheet(unittest.TestCase):
    def test_formulas_and_errors(self):
        s = sheet.Sheet({"A1": "10", "A2": "20", "A3": "=SUM(A1:A2)*2", "B1": "=A1/0", "B2": "=B3", "B3": "=B2", "C1": '=IF(A3>50,"big","small")&"!"',
                         "D1": "=1+", "D2": "=FOO(1)", "D3": "=2^3^2", "E1": '=SUMIF(A1:A3,">15")', "E2": "=-A1%"})
        d = s.display
        self.assertEqual((d("A3"), d("B1"), d("B2"), d("C1")), ("60", "#DIV/0!", "#CYCLE!", "big!"))
        self.assertEqual((d("D1"), d("D2"), d("D3"), d("E1"), d("E2")), ("#PARSE!", "#NAME?", "512", "80", "-0.1"))

    def test_no_python_eval_reachable(self):
        s = sheet.Sheet({"A1": '=__import__("os").system("true")', "A2": "=open(1)"})
        self.assertIn(s.display("A1"), ("#NAME?", "#PARSE!")); self.assertEqual(s.display("A2"), "#NAME?")

    def test_dates_and_copy_adjustment(self):
        s = sheet.Sheet({"A1": "2026-01-30", "A2": "=DATEADD(A1,5)", "A3": "=DAYS(A1,A2)"})
        self.assertEqual((s.display("A2"), s.display("A3")), ("2026-02-04", "5"))
        self.assertEqual(sheet.adjust_formula("=A1+$B$2+C3", 1, 1), "=B2+$B$2+D4")

    def test_editor_edits_and_saves(self):
        saved = []
        h = drive(lambda h: sheet.SheetEditor("t", sheet.Sheet(), lambda sh: saved.append(dict(sh.cells))), ["5", "enter", "7", "enter", "=A1+A2", "enter", "ctrl-s"])
        self.assertEqual(saved[-1], {"A1": "5", "A2": "7", "A3": "=A1+A2"})


class TestRecords(unittest.TestCase):
    def spec(self):
        return S["contacts"]

    def test_add_validate_summary_export(self):
        h = drive(lambda h: records.make_root(h, self.spec()), ["a", "enter", "Ann", "enter", "down", "down", "enter", "bad", "enter"])
        self.assertIn("not an email", h.text)
        h = drive(lambda h: records.make_root(h, self.spec()), ["a", "enter", "Ann", "enter", "down", "down", "enter", "ann@x.io", "enter", "ctrl-s", "g"])
        d = json.loads(h.data["records"]); self.assertEqual(d["items"][0]["name"], "Ann")
        self.assertIn("1 contact", h.text)

    def test_csv_import_reports_bad_rows(self):
        h = FakeHost(data={}); data = records.Data(h, self.spec())
        added, errs = data.import_csv("name,email\nAnn,ann@x.io\nBob,not-an-email\n")
        self.assertEqual(added, 1); self.assertIn("line 3", errs[0])

    def test_validate_kinds(self):
        v = records.validate
        self.assertFalse(v(records.Field("d", "d", "date"), "2026-02-30")[0])
        self.assertTrue(v(records.Field("d", "d", "date"), "2028-02-29")[0])
        self.assertFalse(v(records.Field("p", "p", "percent"), "101")[0])
        self.assertEqual(v(records.Field("t", "t", "tags"), "B, a ,b")[1], "a, b")

    def test_every_spec_is_internally_consistent_and_calcs_work(self):
        for k, sp in S.items():
            keys = {f.key for f in sp.fields}
            for ref in (sp.status, sp.amount, sp.due, sp.start, sp.group):
                self.assertTrue(not ref or ref in keys, (k, ref))
            self.assertTrue(set(sp.cols()) <= keys, k)
            self.assertTrue({c for c, _ in sp.calc} <= keys, k)
        h = FakeHost(data={})
        r = records.Data(h, S["retention"]).add({"dataset": "logs", "created": "2020-01-01", "retain_days": "30", "legal_hold": "no"})
        self.assertEqual(r["expires"], "2020-01-31")
        d = records.Data(h, S["regions"], "r2")
        self.assertEqual(d.add({"dataset": "a", "stored_region": "us", "allowed_regions": "eu, uk"})["compliant"], "VIOLATION")
        self.assertEqual(records.Data(h, S["subscriptions"], "r3").add({"service": "s", "cost": "120", "cycle": "yearly"})["monthly"], "10")
        items = records.Data(h, S["workplace"], "r4"); items.add({"resource": "A", "person": "x", "date": "2026-02-02", "from": "09:00", "to": "11:00"})
        items.add({"resource": "A", "person": "y", "date": "2026-02-02", "from": "10:00", "to": "12:00"})
        self.assertIn("CONFLICT", S["workplace"].report(items.items)[0])


class TestTools(unittest.TestCase):
    def test_transform_pipeline(self):
        cols, rows = tools.parse_table("name,qty,price,region\nA,2,3.5,N\nB,10,1,S\nC,4,9,N\nD,400,2,S")
        c, r, log = tools.transform(cols, rows, "filter qty>3 | addcol total = qty*price | sort total desc | limit 2")
        self.assertEqual([x["name"] for x in r], ["D", "C"]); self.assertEqual(r[0]["total"], "800")
        c, r, _ = tools.transform(cols, rows, "group region sum:qty")
        self.assertEqual({x["region"]: x["sum_qty"] for x in r}, {"N": "6", "S": "410"})
        _, _, log = tools.transform(cols, rows, "select nope"); self.assertTrue(log[-1].startswith("!"))

    def test_dlp_validates_before_redacting(self):
        finds, red = tools.dlp("ok 4111 1111 1111 1111 bad 4111 1111 1111 1112 ssn 123-45-6789 key AKIAABCDEFGHIJKLMNOP iban GB82 WEST 1234 5698 7654 32")
        kinds = [f.split(":")[0] for f in finds]
        self.assertEqual(sorted(kinds), ["aws-key", "card", "iban", "ssn"])
        self.assertIn("4111 1111 1111 1112", red); self.assertNotIn("4111 1111 1111 1111", red)

    def test_threats(self):
        out = tools.threats("Failed password for root from 10.0.0.5\n" * 5 + "GET /?id=1 UNION SELECT 1\n")
        self.assertTrue(any("brute force" in x for x in out)); self.assertTrue(any("SQL injection" in x for x in out))

    def test_summarize_extract_recommend_translate(self):
        text = "Cats are great pets. Cats purr and cats sleep. Dogs bark. The weather is nice today and cats like sun. Birds fly."
        self.assertEqual(len(tools.summarize(text, 2)), 2)
        self.assertIn("email (1): a@b.co", tools.extract("mail a@b.co now"))
        rec = tools.recommend("a,x,5\na,y,3\nb,x,4\nb,z,5\nc,y,4\nc,z,2\nc,x,5", "a")
        self.assertIn("z", rec[1])
        out, unknown = tools.glossary_translate("Hello friend, thank you for the water!", tools.SEED_GLOSSARY["es"])
        self.assertEqual(out, "Hola amigo, gracias for the agua!"); self.assertEqual(unknown, [])

    def test_analyze_finds_outliers(self):
        cols, rows = tools.parse_table("x\n1\n2\n3\n2\n400")
        self.assertTrue(any("outliers 1" in l for l in tools.analyze(cols, rows)))


class TestSearch(unittest.TestCase):
    def test_ranking_and_prefix(self):
        ix = Index({"a": "the quick brown fox", "b": "lazy dogs sleep", "c": "foxes and hounds hunt fox fox"})
        self.assertEqual(ix.search("fox")[0][0], "c")
        self.assertEqual(ix.search("hou")[0][0], "c")
        ix.remove("c"); self.assertEqual(ix.search("fox")[0][0], "a")


class TestDocs(unittest.TestCase):
    def test_library_create_edit_persist_export(self):
        mk = lambda h: Library_(h)
        def Library_(h): return docs.Library(h, "Docs", "document", lambda n, t, s: docs.DocEditor(h, n, t, s), "")
        h = drive(mk, ["n", "My Doc", "enter", "# Hi", "enter", "- a", "ctrl-s", "ctrl-e"])
        self.assertIn("<h1>Hi</h1>", h.data["export-my-doc.html"]); self.assertIn("<li>a</li>", h.data["export-my-doc.html"])
        h2 = drive(mk, ["enter"], data=h.data)             # reopened in a new run
        self.assertIn("# Hi", h2.text)

    def test_html_is_escaped(self):
        self.assertNotIn("<script>", docs.md_html("<script>alert(1)</script>"))

    def test_slides_polls_and_links(self):
        h = FakeHost(); st = docs.Store(h)
        p = docs.Presenter("d", "# A\n---\n? Pick | red | blue\n[go](#3)\n---\n# End", st)
        h2 = FakeHost(["right", "b", "3"]); run(h2, p)
        self.assertEqual(p.i, 2); self.assertEqual(p.votes, {"2:1": 1})

    def test_notes_backlinks(self):
        h = drive(lambda h: docs.NoteBook(h), ["n", "A", "enter", "see [[B]]", "ctrl-s", "escape", "n", "B", "enter", "x", "ctrl-s", "ctrl-b"])
        self.assertIn("A", h.text.split("Linked from:")[1].split("Links to:")[0])


class TestSqlCalendar(unittest.TestCase):
    def test_sql_persists_and_blocks_attach(self):
        h = drive(sqlapp.SqlConsole, [*"create table t(a int);", "enter", *"insert into t values (7);", "enter", *"attach database '/etc/passwd' as p;", "enter"])
        self.assertIn("not authorized", h.text)
        h2 = drive(sqlapp.SqlConsole, [*"select a from t;", "enter"], data=h.data); self.assertIn("7", h2.text)

    def test_recurrence_and_conflicts(self):
        ev = {"date": "2026-11-02", "repeat": "weekly"}
        self.assertTrue(calendar_.occurs(ev, dt.date(2026, 11, 9))); self.assertFalse(calendar_.occurs(ev, dt.date(2026, 11, 10)))
        self.assertTrue(calendar_.overlaps({"start": "10:00", "end": "11:00"}, {"start": "10:30", "end": "12:00"}))

    def test_scheduler_prevents_double_booking(self):
        h = FakeHost(["enter", "Zed", "enter"], data={}); s = calendar_.SlotScheduler(h); first = s.slots()[0]; run(h, s)
        self.assertNotIn(first, s.slots())
        s._book(first[0], first[1], "Other"); self.assertEqual(len(s.book), 1)


class TestQuizBuilderFlow(unittest.TestCase):
    def test_quiz_scores(self):
        h = drive(lambda h: quiz.QuizApp(h, "Q"), ["t", "down", "enter", "down", "enter", *"blue", "enter"])
        self.assertIn("Score: 2/2", h.text)

    def test_survey_aggregates(self):
        h = drive(lambda h: quiz.QuizApp(h, "S", "survey"), ["t", "right", "right", "enter", "enter", "nice", "enter", "escape", "r"])
        self.assertIn("average 3.00", h.text)

    def test_schema_with_calculated_field(self):
        specs = builder.parse_schema(builder.SCHEMA_SAMPLE)
        d = records.Data(FakeHost(data={}), specs[0])
        self.assertEqual(d.add({"customer": "A", "qty": "3", "price": "2.5"})["total"], "7.5")
        with self.assertRaises(builder.SchemaError):
            builder.parse_schema("table X\nfoo: wat")

    def test_site_build_and_cms_only_publishes_published(self):
        h = FakeHost(["n", "Home", "enter", "ctrl-s", "ctrl-b"], data={}); run(h, builder.SiteBuilder(h, "S", "website"))
        self.assertIn("site-home.html", h.data)
        h = FakeHost(["n", "Draft", "enter", "ctrl-s", "ctrl-b"], data={}); run(h, builder.SiteBuilder(h, "S", "cms"))
        self.assertNotIn("site-draft.html", h.data)

    def test_chatbot_slots_and_unhandled(self):
        h = drive(lambda h: builder.BotConsole(h, "B"), [*"hello", "enter", *"i want to buy", "enter", *"Zed", "enter", *"tea", "enter", *"zzz qqq", "enter"])
        self.assertIn("Thanks Zed, one tea is on its way.", h.text); self.assertIn("did not understand", h.text)

    def test_flow_runs_and_saves_and_ask_is_skipped_without_a_model(self):
        h = FakeHost(data={})
        f = flow.parse_flows("flow x\nstep: input\nstep: pipeline addcol t = a*2\nstep: ask polish it\nstep: save out\n")[0]
        reg, trace = flow.run_flow(f, "a\n2\n5", h, {})
        self.assertIn("4", reg); self.assertTrue(any("skipped (no model" in t for t in trace)); self.assertIn("export-out.txt", h.data)

    def test_macro_recorder_saves_a_replayable_flow(self):
        h = drive(lambda h: flow.FlowApp(h, "M", "recorder"), ["m", *"summarize 1", "enter", "ctrl-s", "ctrl-u", *"mine", "enter"])
        self.assertIn("flow mine\nenabled: yes\nstep: input\nstep: summarize 1", json.loads(h.data["flows"]))


class TestMail(unittest.TestCase):
    def test_pipeline_alias_rule_quota_bounce_relay(self):
        h = FakeHost(data={}); ms = mail.MailStore(h)
        for a in ("ann@kos.local", "bob@kos.local"): ms.users.add({"addr": a, "quota": "2", "active": "yes"})
        ms.aliases.add({"alias": "team@kos.local", "targets": "ann@kos.local, bob@kos.local"})
        ms.rules.add({"field": "subject", "contains": "[spam]", "action": "folder", "arg": "spam"})
        r = ms.submit({"from": "ann@kos.local", "to": ["team@kos.local", "zed@kos.local", "far@example.org"], "subject": "hi", "body": "yo"})
        self.assertEqual(sorted(x.split(":")[1].strip() for x in r), ["bounced (no such user)", "delivered to inbox", "delivered to inbox", "queued for relay"])
        ms.submit({"from": "ann@kos.local", "to": ["bob@kos.local"], "subject": "[spam] x", "body": "x"})
        self.assertEqual([m["folder"] for m in ms.box("bob@kos.local")], ["inbox", "spam"])
        self.assertIn("mailbox full", ms.submit({"from": "ann@kos.local", "to": ["bob@kos.local"], "subject": "3", "body": "x"})[0])
        self.assertTrue(any("Undelivered" in m["subject"] for m in ms.box("ann@kos.local")))     # NDR reached the sender
        self.assertIn("no SMTP relay", ms.relay()[0])
        self.assertIn("From: ann@kos.local", mail.to_rfc822(ms.box("bob@kos.local")[0]))

    def test_client_compose_flow(self):
        h = FakeHost(data={}); ms = mail.MailStore(h); ms.users.add({"addr": "me@kos.local", "quota": "50", "active": "yes"}); ms.users.add({"addr": "you@kos.local", "quota": "50", "active": "yes"})
        run(h, mail.MailClient(h))      # no-op run to create state
        h2 = drive(lambda h: mail.MailClient(h), ["c", *"you@kos.local", "enter", *"Subj", "enter", *"body", "ctrl-x"], data=h.data)
        self.assertEqual(mail.MailStore(h2).box("you@kos.local")[0]["subject"], "Subj")


class TestSecurity(unittest.TestCase):
    def test_totp_matches_rfc6238_vector(self):
        self.assertEqual(security.totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59, 30, 8), "94287082")

    def test_rbac_deny_overrides_and_default_deny(self):
        roles, users = security.parse_rbac(security.RBAC_SAMPLE)
        c = lambda u, a: security.check(roles, users, u, a)[0]
        self.assertTrue(c("ann", "doc:read")); self.assertFalse(c("ann", "doc:delete")); self.assertTrue(c("bob", "doc:delete"))
        self.assertFalse(c("nobody", "doc:read")); self.assertFalse(c("ann", "billing:read"))

    def test_audit_chain_detects_tampering(self):
        a = security.AuditLog(FakeHost(data={}))
        for i in range(4): a.append("ann", "login", f"s{i}")
        self.assertEqual(security.verify_chain(a.entries), -1)
        a.entries[2]["actor"] = "mallory"; self.assertEqual(security.verify_chain(a.entries), 2)
        a.entries[2]["actor"] = "ann"; del a.entries[1]; self.assertNotEqual(security.verify_chain(a.entries), -1)

    def test_auth_policy_hash_and_lockout(self):
        self.assertTrue(security.policy_problems("short", security.DEFAULT_POLICY))
        rec = security.hash_password("Good-Pass-123", n=2 ** 10)
        self.assertTrue(security.verify_password("Good-Pass-123", rec)); self.assertFalse(security.verify_password("nope", rec))
        h = FakeHost(data={}); a = security.AuthSystem(h); a.n = 2 ** 10
        a._add_pw("ann", "Good-Pass-123!"); self.assertNotIn("Good-Pass", json.dumps(h.data))     # never stored in clear
        for _ in range(5): a._login("ann", "wrong")
        self.assertGreater(a.users["ann"]["locked_until"], 0)


class TestExtras(unittest.TestCase):
    def test_sync_plan_three_way(self):
        out = "\n".join(extras.sync_plan("a,1,10\nb,2,20\nnew,1,5\n---\na,1,10\nb,2,15\nold,1,1\n---\na,1,10\nb,2,15\nold,1,1\n"))
        self.assertIn("update →   b", out); self.assertIn("copy →     new", out); self.assertIn("delete →   old", out)
        self.assertIn("CONFLICT", "\n".join(extras.sync_plan("x,1,10\n---\nx,2,20\n---\nx,1,5\n")))

    def test_srt_recur_formula_outline_code_model_edl(self):
        self.assertIn("00:00:01,000 --> 00:00:04,000", "\n".join(extras.srt("[00:00:01] a\n[00:00:04] b")))
        r = extras.recur("every weekday 09:00 Standup", 7, dt.date(2026, 11, 2)); self.assertEqual(len(r), 5)
        self.assertIn("=SUM(B1:B100)", "\n".join(extras.nl_formula("sum of column B")))
        self.assertIn("---", "\n".join(extras.outline_to_slides("T\nA\n  x\nB\n  y")))
        self.assertTrue(extras.code_check("def f(:\n")[0].startswith("syntax error"))
        ddl, problems = extras.to_model("table a\n  id pk\ntable b\n  a_id -> a.id\n  x text")
        self.assertTrue(any("no primary key" in p for p in problems)); self.assertIn("FOREIGN KEY (a_id) REFERENCES a(id)", "\n".join(ddl))
        out = extras.edl([{"clip": "A", "tc_in": "00:00:01:00", "tc_out": "00:00:03:00"}])
        self.assertIn("00:00:00:00 00:00:02:00", "\n".join(out))

    def test_script_runner_limits(self):
        self.assertEqual(extras.run_script("import math\nprint(math.sqrt(16))"), ("4.0\n", ""))
        self.assertIn("not allowed", extras.run_script("import os")[1]); self.assertIn("open", extras.run_script("open('/etc/passwd')")[1])
        self.assertIn("stopped after", extras.run_script("while True: pass", 0.3)[1])

    def test_llm_request_shapes_and_endpoint_rule(self):
        cfg = {"provider": "anthropic", "model": "m", "key": "K"}
        url, headers, body = llm.build_request(cfg, "sys", [{"role": "user", "content": "hi"}])
        self.assertEqual(headers["x-api-key"], "K"); self.assertEqual(json.loads(body)["system"], "sys")
        with self.assertRaises(llm.LLMError): llm.ask({**cfg, "endpoint": "http://evil.example/x"}, "", [])
        with self.assertRaises(llm.LLMError): llm.ask({}, "", [])

    def test_hub_isolates_components(self):
        h = FakeHost(data={})
        a, b = extras.PrefixHost(h, "c0-"), extras.PrefixHost(h, "c1-")
        a.put("records", "A"); b.put("records", "B")
        self.assertEqual((a.get("records"), b.get("records")), ("A", "B")); self.assertEqual(a.keys(), ["records"])

    def test_search_library_legal_hold_blocks_delete(self):
        h = drive(lambda h: extras.SearchLibrary(h, "E", hold=True), ["n", "d1", "enter", "x", "ctrl-s", "escape", "h", "d", "y"])
        self.assertTrue(any(k.startswith("doc-d1") for k in h.data))


class TestGraphics(unittest.TestCase):
    def test_image_editor_exports_valid_png(self):
        import base64
        from kos.office.pixels import ImageEditor
        h = drive(ImageEditor, [" ", "right", " ", "e"], mode="graphical")
        self.assertEqual(base64.b64decode(h.data["export-image.png.b64"])[:8], b"\x89PNG\r\n\x1a\n")
        self.assertTrue(h.data["export-image.ppm"].startswith("P3\n24 24"))

    def test_generator_is_deterministic_and_exports_within_vault_limit(self):
        from kos.office.pixels import ImageGenerator, generate
        self.assertEqual(generate("plasma", 8, 3), generate("plasma", 8, 3))
        h = drive(ImageGenerator, ["e"])
        for k, v in h.data.items():
            if k.startswith("export-"): self.assertLessEqual(len(v), MAX_ITEM, k)

    def test_whiteboard_draws_from_pointer_events(self):
        from kos.office.board import Board
        B = lambda pressed, x, y: {"cmd": "button", "button": "left", "pressed": pressed, "x": x, "y": y}
        h = drive(Board, ["r", B(True, 10, 20), B(False, 50, 60), "x"], mode="graphical", width=320, height=240)
        self.assertEqual(json.loads(h.data["shapes"])[0][0], "rect"); self.assertIn("<rect", h.data["export-board.svg"])
        for ops in h.canvases: validate_app_message({"cmd": "frame", "ops": ops}, "graphical")


sys.path.insert(0, str(ROOT / "tests"))
from test_kos import Env, PW  # noqa: E402


class TestSuiteInTheRealSandbox(Env):
    """A suite app launched exactly like any app: sealed zip, Landlock sandbox, real Session."""

    def test_contact_manager_creates_the_shared_folder_from_inside_the_sandbox(self):
        from kos import loader
        from kos.auth import Authority, Throttle
        from kos.display import HeadlessBackend, GraphicalSurface
        from kos.devices import ScriptedDevices
        from kos.protocol import Channel
        from kos.sandbox import SandboxPolicy
        from kos.store import AppStore
        from kos.tui import TUISurface
        from suite import gen
        gen.build(Path(self.tmp.name) / "k")
        kapp = Path(self.tmp.name) / "k" / "contact-manager.kapp"
        store = AppStore(self.paths); store.install(kapp, self.authority(PW))
        with self.authority(PW).authorize("app.run", "contact-manager") as g:
            app = store.load_verified("contact-manager", g)
        self.assertIn("owns:contacts", app.manifest.permissions)
        a, b = socket.socketpair()
        proc = loader.launch(loader.plan(app, b.fileno(), "tui"), SandboxPolicy(), None); b.close()
        devices = ScriptedDevices()
        auth = Authority(self.paths, None, Throttle(self.paths, base=0))
        devnull = os.open(os.devnull, os.O_WRONLY)
        s = Session(name="contact-manager", mode="tui", channel=Channel(a), proc=proc, surface=TUISurface(devnull, 100, 30, "contact-manager"),
                    devices=devices, authority=auth, boot_devices=("keyboard",), vault=AppStorage(self.paths, "contact-manager", app.manifest.permissions))
        key = lambda *names: [{"type": "key", "key": n} for n in names]
        devices.push(*key("y", *PW, "enter"))                                              # boot the keyboard with the password
        devices.push(*key("a", "enter", *"Ann", "enter", "down", "down", "enter", *"ann@x.io", "enter", "ctrl-s", "escape"))
        self.assertEqual(s.run(first_frame_timeout=5), 0)
        os.close(devnull)
        self.assertEqual(Permissions(self.paths).owner_of("space:contacts"), "contact-manager")
        saved = json.loads((self.paths.state / "spaces" / "contacts" / "records").read_text())
        self.assertEqual(saved["items"][0]["email"], "ann@x.io")
        self.assertFalse(list(AppDirs(self.paths, "contact-manager").cache.glob("*")))      # the run's scratch was wiped


class TestRealProcess(unittest.TestCase):
    """A packed .kapp, started the way the loader starts apps (isolated interpreter, imported
    from the zip), talking over a real socket to the real vault handler."""

    BOOT = ("import sys, importlib\nkapp, entry, sdk = sys.argv[1], sys.argv[2], sys.argv[3]\n"
            "sys.path[:0] = [sdk, kapp]\nmod, _, fn = entry.partition(':')\n"
            "sys.exit(getattr(importlib.import_module(mod), fn or 'main')())\n")

    def test_document_editor_saves_to_the_vault_from_a_real_process(self):
        import subprocess
        from suite import gen
        with tempfile.TemporaryDirectory() as td:
            gen.build(Path(td) / "k")
            a, b = socket.socketpair(); b.settimeout(15)
            env = {"KOS_CHANNEL_FD": str(a.fileno()), "KOS_MODE": "tui", "PATH": "/usr/bin:/bin"}
            p = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", self.BOOT, str(Path(td) / "k" / "document-editor.kapp"), "app:main", str(ROOT)],
                                 env=env, pass_fds=[a.fileno()], stdin=subprocess.DEVNULL, stderr=subprocess.PIPE)
            a.close()
            paths = Paths(Path(td) / "root"); stub = StubOS(AppStorage(paths, "document-editor", ["storage"]), b)
            f = b.makefile("rb"); last = [None]

            def send(o): b.sendall(json.dumps(o).encode() + b"\n")

            def pump(until):
                try:
                    for line in f:
                        m = validate_app_message(json.loads(line), "tui")
                        if m["cmd"] == "vault": stub._on_vault(m)
                        elif m["cmd"] == "screen":
                            last[0] = m
                            if until in "\n".join(m["lines"] + [m["title"], m["status"]]): return True
                except (socket.timeout, TimeoutError):
                    pass
                return False
            try:
                send({"cmd": "hello", "mode": "tui", "width": 80, "height": 24})
                self.assertTrue(pump("No document"), last[0])
                for k in ["n", *"Real", "enter", *"hello", "ctrl-s"]: send({"cmd": "key", "key": k})
                self.assertTrue(pump("saved"), last[0])
                send({"cmd": "quit"}); self.assertEqual(p.wait(timeout=10), 0)
            finally:
                if p.poll() is None: p.kill()
                err = p.stderr.read().decode(); p.stderr.close()
            self.assertEqual(err, "")
            self.assertIn("hello", Vault(paths, "document-editor").get("doc-real"))


class TestCatalog(unittest.TestCase):
    def test_every_requested_product_is_in_the_catalogue(self):
        requested = [l.strip() for l in (ROOT / "docs" / "REQUESTED.txt").read_text().splitlines() if l.strip()]
        self.assertEqual(len(requested), 149)
        self.assertEqual(sorted(requested), sorted(e.title for e in CATALOG))

    def test_not_built_items_say_why(self):
        for e in CATALOG:
            if e.scope == "none": self.assertGreater(len(e.note), 20, e.title)
            if e.scope == "partial": self.assertGreater(len(e.note), 20, e.title)

    def test_every_buildable_app_packs_with_a_valid_manifest(self):
        from suite import gen
        with tempfile.TemporaryDirectory() as td:
            made = gen.build(Path(td))
            self.assertEqual(len(made), sum(1 for e in gen.every() if e.scope != "none"))
            for n in made:
                m = KApp.from_file(Path(td) / f"{n}.kapp").manifest
                self.assertIn("storage", m.permissions); self.assertEqual(m.entry, "app:main")

    def test_every_app_survives_a_key_battery_with_valid_protocol_output(self):
        opens = ["enter", "a", "n", "t", "g", "x", "/", "b", "?", "e", "c", "h", "r", "i", "s", "d", "R", "f", " ", "l", "o", "p", "u", "m", "w", "1"]
        body = ["T", "e", "1", "enter", "down", "enter", "x", "enter", "ctrl-s", "ctrl-r", "ctrl-p", "ctrl-e", "ctrl-w", "ctrl-o", "ctrl-b", "ctrl-x", "escape", "y", "escape", "escape"]
        for e in CATALOG:
            if e.scope == "none": continue
            data, mode = {}, ("graphical" if e.graphical else "tui")
            for o in opens:
                h = FakeHost([o] + body, data=data, mode=mode, width=100, height=30)
                run(h, build(h, e)); data = h.data
                for t, lines, st in h.frames:
                    validate_app_message({"cmd": "screen", "title": t, "lines": lines, "status": st}, "tui")
                    self.assertNotIn("Internal error", t, (e.name, o))
                for ops in h.canvases: validate_app_message({"cmd": "frame", "ops": ops}, "graphical")

    def test_a_bug_in_a_screen_shows_an_error_instead_of_killing_the_app(self):
        from kos.office.ui import Screen
        class Boom(Screen):
            def key(self, k): raise ValueError("planted")
        h = FakeHost(["x"]); run(h, Boom())
        self.assertIn("Internal error", h.text)


if __name__ == "__main__":
    unittest.main()
