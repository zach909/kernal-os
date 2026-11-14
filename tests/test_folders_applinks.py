"""The standard data folders and apps backed up as pinned https addresses.

Run with: python3 -m unittest discover -s tests -v
"""

import argparse
import hashlib
import io
import os
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_kos import Env, PW  # noqa: E402
from kos import applinks, cli, folders  # noqa: E402
from kos.auth import ACTIONS, AuditLog, AuthorizationDenied  # noqa: E402
from kos.backup import VaultTamperedError  # noqa: E402
from kos.kapp import ID_RE, KApp  # noqa: E402
from kos.permissions import Permissions  # noqa: E402
from kos.spaces import AppStorage, StorageError  # noqa: E402
from kos.store import AppStore  # noqa: E402

URL = "https://apps.example.org/hello.kapp"


class TestFolders(Env):
    def test_catalogue_is_the_whole_list_and_every_name_is_usable(self):
        self.assertEqual(len(folders.FOLDERS), 27)
        self.assertEqual([sum(f.group == g for f in folders.FOLDERS) for g in folders.GROUPS], [8, 8, 6, 5])
        self.assertEqual(len({f.name for f in folders.FOLDERS}), 27)

    def test_the_owner_is_not_a_possible_app_name(self):
        self.assertIsNone(ID_RE.match(folders.OWNER))

    def test_create_needs_the_password_and_a_wrong_one_makes_nothing(self):
        with self.assertRaises(AuthorizationDenied):
            folders.create(self.paths, self.authority("no", "no", "no"))
        self.assertFalse((self.paths.state / "spaces" / "documents").exists())
        self.assertEqual(Permissions(self.paths).list("space:"), [])

    def test_create_makes_every_folder_owned_by_the_os_and_is_repeatable(self):
        created, kept = folders.create(self.paths, self.authority(PW))
        self.assertEqual((len(created), len(kept)), (27, 0))
        for f in folders.FOLDERS:
            d = self.paths.state / "spaces" / f.name
            self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)
            self.assertEqual(Permissions(self.paths).owner_of(f"space:{f.name}"), folders.OWNER)
        created, kept = folders.create(self.paths, self.authority(PW))
        self.assertEqual((len(created), len(kept)), (0, 27))
        self.assertEqual(len(Permissions(self.paths).list("space:")), 27)

    def test_a_folder_an_app_already_owns_is_left_alone(self):
        Permissions(self.paths).grant("notes-app", "space:notes", "own")
        created, kept = folders.create(self.paths, self.authority(PW))
        self.assertIn("notes", kept)
        self.assertNotIn("notes", created)
        self.assertEqual(Permissions(self.paths).owner_of("space:notes"), "notes-app")

    def test_no_app_can_take_a_folder_and_none_gets_in_without_a_grant(self):
        folders.create(self.paths, self.authority(PW))
        with self.assertRaisesRegex(StorageError, "owned by @os"):
            AppStorage(self.paths, "thief", ["owns:documents"]).vault("documents", "put")
        reader = AppStorage(self.paths, "viewer", ["uses:documents"])
        with self.assertRaisesRegex(StorageError, "no read access"):
            reader.vault("documents", "get")
        Permissions(self.paths).grant("viewer", "space:documents", "read")
        reader.vault("documents", "get")
        with self.assertRaisesRegex(StorageError, "no write access"):
            reader.vault("documents", "put")
        with self.assertRaisesRegex(StorageError, "no read access"):      # another folder stays shut
            AppStorage(self.paths, "viewer", ["uses:keychain"]).vault("keychain", "get")

    def test_status_reads_without_a_password_and_marks_the_secret_ones(self):
        self.assertFalse(any(s.exists for s in folders.status(self.paths)))
        folders.create(self.paths, self.authority(PW))
        Permissions(self.paths).grant("viewer", "space:media", "read")
        st = {s.folder.name: s for s in folders.status(self.paths)}
        self.assertTrue(all(s.exists for s in st.values()))
        self.assertEqual(st["media"].access, (("viewer", "read"),))
        self.assertTrue(st["keychain"].folder.sensitive and not st["media"].folder.sensitive)

    def test_actions_are_known(self):
        self.assertIn("folders.create", ACTIONS)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class FakeOpener:
    def __init__(self, body=None, error=None):
        self.body, self.error, self.requests = body, error, []

    def open(self, req, timeout=None):
        self.requests.append((req.full_url, req.get_method(), timeout))
        if self.error:
            raise self.error
        return FakeResponse(self.body)


class TestAppLinks(Env):
    def setUp(self):
        super().setUp()
        AppStore(self.paths).install(self.kapp, self.authority(PW))
        self.data = self.kapp.read_bytes()

    def audit(self):
        return [e for e in AuditLog(self.paths).entries() if e["action"] == "net.applink"]

    def test_only_https_addresses_with_nothing_hidden_are_accepted(self):
        self.assertEqual(applinks.check_url(URL), URL)
        for bad in ("http://apps.example.org/a.kapp", "http://127.0.0.1/a.kapp", "ftp://x.org/a", "file:///etc/passwd",
                    "https://user:pw@apps.example.org/a", "https://apps.example.org/a#frag", "https://",
                    "https://apps.example.org/a b", "https://apps.example.org/a\n", "https://x.org:99999/a",
                    "https://x.org/" + "a" * 400, "", None, 5, "//x.org/a", "javascript:alert(1)"):
            with self.assertRaises(applinks.AppLinkError, msg=repr(bad)):
                applinks.check_url(bad)

    def test_a_link_needs_the_password_an_installed_app_and_stores_no_bytes(self):
        with self.assertRaises(AuthorizationDenied):
            applinks.add(self.paths, self.authority("no", "no", "no"), "hello", URL)
        self.assertFalse((self.paths.backup / "applinks.json").exists())
        with self.assertRaises(applinks.AppLinkError):
            applinks.add(self.paths, self.authority(PW), "ghost", URL)
        with self.assertRaises(applinks.AppLinkError):
            applinks.add(self.paths, self.authority(PW), "hello", "http://apps.example.org/hello.kapp")
        link = applinks.add(self.paths, self.authority(PW), "hello", URL)
        self.assertEqual((link.name, link.sha256, link.size),
                         ("hello", hashlib.sha256(self.data).hexdigest(), len(self.data)))
        self.assertFalse((self.paths.backup / "blobs").exists())
        self.assertLess((self.paths.backup / "applinks.json").stat().st_size, len(self.data))
        links = applinks.snapshot(self.paths, self.authority(PW))
        self.assertEqual([l.name for l in links], ["hello"])

    def test_listing_and_removing_need_the_password(self):
        applinks.add(self.paths, self.authority(PW), "hello", URL)
        with self.assertRaises(AuthorizationDenied):
            applinks.snapshot(self.paths, self.authority("no", "no", "no"))
        with self.assertRaises(AuthorizationDenied):
            applinks.remove(self.paths, self.authority("no", "no", "no"), "hello")
        self.assertEqual(len(applinks.snapshot(self.paths, self.authority(PW))), 1)
        applinks.remove(self.paths, self.authority(PW), "hello")
        self.assertEqual(applinks.snapshot(self.paths, self.authority(PW)), [])
        with self.assertRaises(applinks.AppLinkError):
            applinks.remove(self.paths, self.authority(PW), "hello")

    def test_a_tampered_index_is_refused(self):
        applinks.add(self.paths, self.authority(PW), "hello", URL)
        f = self.paths.backup / "applinks.json"
        f.write_text(f.read_text().replace("apps.example.org", "evil.example.org"))
        with self.assertRaises(VaultTamperedError):
            applinks.snapshot(self.paths, self.authority(PW))
        with self.assertRaises(VaultTamperedError):
            applinks.fetch(self.paths, self.authority(PW), "hello", opener=FakeOpener(self.data))

    def test_fetch_checks_the_hash_and_is_logged(self):
        applinks.add(self.paths, self.authority(PW), "hello", URL)
        op = FakeOpener(self.data)
        link, data = applinks.fetch(self.paths, self.authority(PW), "hello", opener=op)
        self.assertEqual((data, op.requests[0][:2]), (self.data, (URL, "GET")))
        self.assertEqual(self.audit()[-1]["outcome"], "allowed")
        self.assertIn("apps.example.org:443", self.audit()[-1]["target"])
        evil = FakeOpener(self.data + b"x")                 # same address, different bytes
        with self.assertRaisesRegex(applinks.AppLinkError, "SHA-256 differs"):
            applinks.fetch(self.paths, self.authority(PW), "hello", opener=evil)
        self.assertEqual(self.audit()[-1]["outcome"], "failed")
        with self.assertRaises(AuthorizationDenied):
            applinks.fetch(self.paths, self.authority("no", "no", "no"), "hello", opener=FakeOpener(self.data))

    def test_fetch_refuses_redirects_and_unreachable_servers_and_never_leaks_details(self):
        applinks.add(self.paths, self.authority(PW), "hello", URL)
        redirect = urllib.error.HTTPError(URL, 302, "Found", {}, None)
        with self.assertRaisesRegex(applinks.AppLinkError, "redirects are not followed"):
            applinks.fetch(self.paths, self.authority(PW), "hello", opener=FakeOpener(error=redirect))
        down = urllib.error.URLError(OSError("secret detail"))
        with self.assertRaisesRegex(applinks.AppLinkError, "could not reach the server") as cm:
            applinks.fetch(self.paths, self.authority(PW), "hello", opener=FakeOpener(error=down))
        self.assertNotIn("secret detail", str(cm.exception))
        self.assertEqual([e["outcome"] for e in self.audit()], ["failed", "failed"])

    def test_the_real_opener_follows_no_redirect_and_verifies_certificates(self):
        op = applinks._opener()
        handlers = {type(h).__name__ for h in op.handlers}
        self.assertIn("_NoRedirect", handlers)
        https = next(h for h in op.handlers if type(h).__name__ == "HTTPSHandler")
        self.assertTrue(https._context.check_hostname)
        self.assertEqual(https._context.verify_mode.name, "CERT_REQUIRED")

    def test_a_link_that_somehow_is_not_https_is_blocked_and_logged(self):
        applinks.add(self.paths, self.authority(PW), "hello", URL)
        with self.authority(PW).authorize("applink.add", "hello") as g:    # a sealed index holding a bad address
            applinks._save_links(self.paths, g, [applinks.Link("hello", "1.0.0", "http://x.org/a", "0" * 64, 1, 0)])
        op = FakeOpener(self.data)
        with self.assertRaises(applinks.AppLinkError):
            applinks.fetch(self.paths, self.authority(PW), "hello", opener=op)
        self.assertEqual(op.requests, [])
        self.assertEqual(self.audit()[-1]["outcome"], "blocked")

    def test_the_download_must_be_the_linked_app(self):
        applinks.add(self.paths, self.authority(PW), "hello", URL)
        with self.authority(PW).authorize("applink.add", "hello") as g:    # hash right for these bytes, not an app
            junk = b"not a zip"
            applinks._save_links(self.paths, g, [applinks.Link(
                "hello", "1.0.0", URL, hashlib.sha256(junk).hexdigest(), 9, 0)])
        with self.assertRaisesRegex(applinks.AppLinkError, "not a valid app"):
            applinks.fetch(self.paths, self.authority(PW), "hello", opener=FakeOpener(junk))

    def test_restore_end_to_end_reinstalls_through_the_normal_install(self):
        applinks.add(self.paths, self.authority(PW), "hello", URL)
        AppStore(self.paths).remove("hello", self.authority(PW))
        self.assertEqual(AppStore(self.paths).installed(), [])
        orig = applinks._opener
        applinks._opener = lambda: FakeOpener(self.data)
        try:
            args = argparse.Namespace(app="hello", url=None)
            self.assertEqual(cli._cmd_applinks(args, self.paths, self.authority(PW, PW), "fetch"), 0)
        finally:
            applinks._opener = orig
        self.assertEqual([a.name for a in AppStore(self.paths).installed()], ["hello"])
        self.assertEqual(AppStore(self.paths).installed()[0].sha256, hashlib.sha256(self.data).hexdigest())

    def test_restore_without_the_install_password_installs_nothing(self):
        applinks.add(self.paths, self.authority(PW), "hello", URL)
        AppStore(self.paths).remove("hello", self.authority(PW))
        orig = applinks._opener
        applinks._opener = lambda: FakeOpener(self.data)
        try:
            with self.assertRaises(AuthorizationDenied):
                cli._cmd_applinks(argparse.Namespace(app="hello", url=None), self.paths,
                                  self.authority(PW, "no", "no", "no"), "fetch")
        finally:
            applinks._opener = orig
        self.assertEqual(AppStore(self.paths).installed(), [])

    def test_actions_are_known(self):
        for a in ("applink.add", "applink.list", "applink.remove", "applink.fetch"):
            self.assertIn(a, ACTIONS)


if __name__ == "__main__":
    import unittest
    unittest.main()
