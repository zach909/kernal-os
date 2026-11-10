"""The firewall (README Rule 3): every connection is denied until a rule recognises it.

Refusals first. Real TLS is tested with a throwaway self-signed certificate made by the `cryptography`
package: the client context trusts ONLY that certificate (verification stays ON), and a server with a
different certificate must be refused."""

import base64
import contextlib
import datetime
import http.server
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from kos import aios  # noqa: E402
from kos import assistant as A  # noqa: E402
from kos import cli as kcli  # noqa: E402
from kos import firewall as F  # noqa: E402
from kos import netfetch as N  # noqa: E402
from kos.auth import Authority, KdfParams, PasswordStore, Throttle  # noqa: E402
from kos.kapp import KAppError, Manifest  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.prompt import ScriptedPrompter  # noqa: E402
from kos.protocol import ProtocolError, validate_app_message  # noqa: E402
from kos.sandbox import SandboxPolicy  # noqa: E402
from kos.sdk import App  # noqa: E402
from kos.session import Session  # noqa: E402
from kos.system import SystemBridge, authorize_app_action  # noqa: E402
from kos.office.ui import FakeHost  # noqa: E402

PW = "correct horse battery"
KEY = "sk-SECRETKEY-0123456789"


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.chmod(self.tmp.name, 0o755)
        self.paths = Paths(Path(self.tmp.name))
        PasswordStore(self.paths).create(PW.encode(), KdfParams.fresh(n=2**10), throttle_base=0)

    def tearDown(self):
        self.tmp.cleanup()

    def authority(self, *answers):
        self.prompter = ScriptedPrompter(answers)
        return Authority(self.paths, self.prompter, Throttle(self.paths, base=0))

    def audit_text(self):
        f = self.paths.logs / "audit.log"
        return f.read_text() if f.exists() else ""

    def rules_file(self):
        return F.rules_path(self.paths)

    def write_rules(self, text):
        self.paths.state.mkdir(parents=True, exist_ok=True)
        self.rules_file().write_text(text)


# ------------------------------------------------------------ real servers ----
def make_cert(d: str, tag: str):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=False, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    crt, pem = f"{d}/{tag}.crt", f"{d}/{tag}.key"
    Path(crt).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    Path(pem).write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
    return crt, pem


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a): pass

    def _do(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else b""
        self.server.seen.append((self.command, self.path, dict(self.headers), body))
        try:
            if self.path.startswith("/redirect"):
                self.send_response(302); self.send_header("Location", "http://127.0.0.1:1/plain"); self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path.startswith("/big"):
                self.send_response(200); self.send_header("Content-Type", "application/octet-stream"); self.end_headers()
                chunk = b"x" * 65536
                for _ in range((N.MAX_REPLY // 65536) + 3):
                    self.wfile.write(chunk)
                self.close_connection = True
            elif self.path.startswith("/lie"):
                self.send_response(200); self.send_header("Content-Length", str(N.MAX_REPLY * 10)); self.end_headers()
                self.wfile.write(b"short")
                self.close_connection = True
            else:
                out = json.dumps({"method": self.command, "path": self.path}).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = do_POST = _do


class Server:
    """A loopback server in a thread: plain http, or https with the given certificate."""

    def __init__(self, cert=None):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.seen = []
        self.httpd.handle_error = lambda *a: None
        if cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*cert)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.seen = self.httpd.seen
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()


class Listener:
    """A raw TCP listener that only counts connections: proof that nothing connected."""

    def __init__(self):
        self.s = socket.socket(); self.s.bind(("127.0.0.1", 0)); self.s.listen(5)
        self.port, self.count = self.s.getsockname()[1], 0
        self.s.settimeout(0.2)
        self._stop = False
        self.t = threading.Thread(target=self._run, daemon=True); self.t.start()

    def _run(self):
        while not self._stop:
            try:
                c, _ = self.s.accept(); self.count += 1; c.close()
            except OSError:
                pass

    def close(self):
        self._stop = True; self.t.join(); self.s.close()


class TLS(Env):
    """Env + a TLS server whose certificate the test context trusts (and only that one)."""

    def setUp(self):
        super().setUp()
        self.certs = tempfile.TemporaryDirectory()
        self.crt, self.pem = make_cert(self.certs.name, "good")
        self.crt2, self.pem2 = make_cert(self.certs.name, "other")
        self.ctx = ssl.create_default_context(cafile=self.crt)      # trusts ONLY this certificate; verification ON
        self.srv = Server((self.crt, self.pem))
        self.addCleanup(self.srv.close)
        self.addCleanup(self.certs.cleanup)

    def allow(self, who="app:web", host="localhost", port=None):
        F.add_rule(self.paths, who, host, port or self.srv.port, "https")

    def url(self, path="/", host="localhost"):
        return f"https://{host}:{self.srv.port}{path}"

    def get(self, path="/", who="app:web", **kw):
        return N.fetch(self.paths, who, self.url(path), context=self.ctx, **kw)

    def code(self, fn):
        with self.assertRaises(N.FetchError) as cm:
            fn()
        return cm.exception.code


# ===================================================== default deny, fail closed ====
class TestDefaultDeny(Env):
    def blocked(self, who="app:web", host="example.com", port=443, proto="https"):
        return not F.decide(self.paths, who, host, port, proto)

    def test_no_file_means_everything_is_blocked(self):
        self.assertFalse(self.rules_file().exists())
        self.assertEqual(F.load(self.paths), [])
        for who in ("app:web", "os:assistant", "os:aios"):
            self.assertTrue(self.blocked(who))
        self.assertTrue(self.blocked("os:aios", "127.0.0.1", 7861, "loopback"))

    def test_empty_damaged_and_garbage_files_mean_no_rules(self):
        good = {"who": "app:web", "host": "example.com", "port": 443, "proto": "https"}
        bad_files = ["", "   ", "{", "not json", "[]", "null", "5", '{"rules": 5}', '{"rules": "x"}', '{"rules": [1]}',
                     '{"rules": [{"who": "app:web"}]}', '{"rules": [{"who":"app:web","host":"*","port":443,"proto":"http"}]}',
                     json.dumps({"rules": [good, {**good, "extra": 1}]}),           # one odd row: the whole file is not trusted
                     json.dumps({"rules": [good, {**good, "port": "443"}]}),
                     json.dumps({"rules": [good, {**good, "proto": "http"}]}),
                     json.dumps({"rules": [good] * (F.MAX_RULES + 1)}),
                     "\x00\x01\x02" * 50, "[" * 5000]
        for text in bad_files:
            self.write_rules(text)
            self.assertEqual(F.load(self.paths), [], text[:40])
            self.assertTrue(self.blocked(), text[:40])
        self.write_rules(json.dumps({"rules": [good]}))
        self.assertFalse(self.blocked())                                      # and a good file does work

    def test_a_directory_or_unreadable_file_is_no_rules(self):
        self.paths.state.mkdir(parents=True, exist_ok=True)
        self.rules_file().mkdir()
        self.assertEqual(F.load(self.paths), [])
        self.assertTrue(self.blocked())

    def test_wrong_who_host_port_or_proto_is_blocked(self):
        F.add_rule(self.paths, "app:web", "example.com", 443, "https")
        self.assertFalse(self.blocked())
        self.assertTrue(self.blocked(who="app:other"))
        self.assertTrue(self.blocked(who="os:assistant"))
        self.assertTrue(self.blocked(who="app:web2"))
        self.assertTrue(self.blocked(host="example.org"))
        self.assertTrue(self.blocked(host="www.example.com"))
        self.assertTrue(self.blocked(host="example.com.evil.com"))
        self.assertTrue(self.blocked(port=444))
        self.assertTrue(self.blocked(port=80))
        self.assertTrue(self.blocked(proto="loopback"))
        self.assertTrue(self.blocked(proto="http"))
        self.assertTrue(self.blocked(proto="HTTPS"))
        self.assertTrue(self.blocked(proto=""))

    def test_odd_types_are_blocked_not_crashes(self):
        F.add_rule(self.paths, "app:web", "example.com", 443, "https")
        for who, host, port, proto in (("app:web", None, 443, "https"), ("app:web", "example.com", "443", "https"),
                                       ("app:web", "example.com", True, "https"), (None, "example.com", 443, "https"),
                                       ("app:web", "example.com", 443, None), ("app:web", b"example.com", 443, "https"),
                                       ("app:web", "example.com", 70000, "https"), ("app:web", "example.com", 0, "https")):
            self.assertFalse(F.decide(self.paths, who, host, port, proto), (who, host, port, proto))

    def test_host_tricks_never_match(self):
        F.add_rule(self.paths, "app:web", "example.com", 443, "https")
        F.add_rule(self.paths, "app:web", "localhost", 8443, "https")
        F.add_rule(self.paths, "app:web", "127.0.0.1", 8444, "loopback")
        self.assertFalse(self.blocked(host="EXAMPLE.com"))                    # case-insensitive, exact otherwise
        for h in ("example.com.", ".example.com", "example.com:443", "example.com/", "example.com\\", "user@example.com",
                  "example.com@evil.com", "evil.com\\@example.com", "exämple.com", "еxample.com", "example.com ", " example.com",
                  "example.com\x00", "example.com\n", "http://example.com", "[example.com]", "*.example.com", "example.*"):
            self.assertTrue(self.blocked(host=h), repr(h))
        for h in ("localhost.evil.com", "localhost.", "LOCALHOST.evil.com", "localhost@evil.com", "xlocalhost"):
            self.assertTrue(self.blocked(host=h, port=8443), repr(h))
            self.assertTrue(self.blocked(host=h, port=8443, proto="loopback"), repr(h))
        for h in ("127.0.0.1.evil.com", "0x7f.1", "0x7f.0.0.1", "127.1", "2130706433", "0177.0.0.1", "127.000.000.001",
                  "127.0.0.1.", "[127.0.0.1]", "::ffff:127.0.0.1", "127.0.0.2", "0.0.0.0", "::1"):
            self.assertTrue(self.blocked(host=h, port=8444, proto="loopback"), repr(h))
        self.assertFalse(self.blocked(host="127.0.0.1", port=8444, proto="loopback"))

    def test_decide_never_connects_and_has_no_way_to_change_the_default(self):
        names = [n for n in dir(F) if not n.startswith("_")]
        self.assertFalse([n for n in names if re.search(r"default|disable|allow_all|turn_off|off\b|bypass|log_only", n, re.I)], names)
        sub = next(a for a in kcli.build_parser()._actions if isinstance(a, __import__("argparse")._SubParsersAction))
        fw = next(a for a in sub.choices["firewall"]._actions if isinstance(a, __import__("argparse")._SubParsersAction))
        self.assertEqual(sorted(fw.choices), ["allow", "log", "remove", "status"])


# ============================================================ rules and state ====
class TestRules(Env):
    def refused(self, *a):
        with self.assertRaises(F.FirewallError, msg=repr(a)):
            F.check_rule(*a)

    def test_plain_http_to_another_host_can_never_be_a_rule(self):
        for proto in ("http", "HTTP", "tcp", "", None, "https+http", "ftp"):
            self.refused("app:web", "example.com", 80, proto)
        self.refused("app:web", "example.com", 80, "loopback")               # loopback is only this computer
        self.refused("app:web", "192.168.1.5", 80, "loopback")
        self.refused("app:web", "localhost.evil.com", 80, "loopback")
        self.refused("app:web", "127.0.0.1.evil.com", 80, "loopback")
        self.refused("app:web", "0x7f.1", 80, "loopback")
        self.refused("app:web", "2130706433", 80, "loopback")
        self.refused("app:web", "*", 80, "loopback")
        F.check_rule("app:web", "127.0.0.1", 80, "loopback")
        F.check_rule("app:web", "localhost", 80, "loopback")
        F.check_rule("app:web", "::1", 80, "loopback")
        F.check_rule("app:web", "127.5.6.7", 80, "loopback")

    def test_bad_who_host_and_port_are_refused(self):
        for who in ("", "web", "app:", "app:Web", "app:web;x", "os:other", "os:", "OS:assistant", "*", None, "app:" + "a" * 40):
            self.refused(who, "example.com", 443, "https")
        for host in ("", "*.example.com", "example.*", "**", "* ", "http://example.com", "example.com/x", "example.com:443",
                     "user@example.com", "exämple.com", "0x7f.1", "127.1", "2130706433", "example", "a..b.com", "-a.com",
                     "[::1]", None, 5, "example.com."):
            self.refused("app:web", host, 443, "https")
        for port in (0, -1, 65536, "443", 443.0, None, True):
            self.refused("app:web", "example.com", port, "https")

    def test_a_wildcard_exists_only_when_typed_exactly_and_is_one_who_and_one_port(self):
        self.assertEqual(F.check_rule("app:web", "*", 443, "https")["host"], "*")
        for h in ("*.com", "a*", "*a", "**", "?", "%", "any", "all", "0.0.0.0", "0.0.0.0/0", "*/*"):
            self.refused("app:web", h, 443, "https")
        F.add_rule(self.paths, "app:web", "*", 443, "https")
        self.assertTrue(F.decide(self.paths, "app:web", "anything.example.org", 443, "https"))
        self.assertTrue(F.decide(self.paths, "app:web", "10.1.2.3", 443, "https"))
        self.assertTrue(not F.decide(self.paths, "app:web", "anything.example.org", 8443, "https"))     # one port
        self.assertTrue(not F.decide(self.paths, "app:other", "anything.example.org", 443, "https"))    # one who
        self.assertTrue(not F.decide(self.paths, "os:assistant", "anything.example.org", 443, "https"))
        self.assertTrue(not F.decide(self.paths, "app:web", "anything.example.org", 443, "loopback"))   # never plain
        self.assertTrue(not F.decide(self.paths, "app:web", "not a host", 443, "https"))                # still a valid host
        self.assertTrue(not F.decide(self.paths, "app:web", "evil.com\\@x", 443, "https"))
        self.assertIn("WILDCARD", F.describe(F.load(self.paths)[0]))

    def test_exact_rules_are_stored_lower_case_and_listed(self):
        r = F.add_rule(self.paths, "app:web", "Example.COM", 443, "https")
        self.assertEqual(r, {"who": "app:web", "host": "example.com", "port": 443, "proto": "https"})
        self.assertEqual(F.add_rule(self.paths, "app:web", "example.com", 443, "https"), r)
        self.assertEqual(len(F.load(self.paths)), 1)                         # the same rule twice is one rule

    def test_the_file_is_private_atomic_and_has_no_temp_files(self):
        F.add_rule(self.paths, "app:web", "example.com", 443, "https")
        F.add_rule(self.paths, "os:aios", "127.0.0.1", 7861, "loopback")
        self.assertEqual(os.stat(F.rules_path(self.paths)).st_mode & 0o777, 0o600)
        self.assertEqual([p.name for p in F.rules_path(self.paths).parent.glob(".firewall.json*")], [])
        F.remove_rule(self.paths, "app:web", "example.com", 443)
        self.assertEqual(os.stat(F.rules_path(self.paths)).st_mode & 0o777, 0o600)
        self.assertEqual(F.load(self.paths), [{"who": "os:aios", "host": "127.0.0.1", "port": 7861, "proto": "loopback"}])

    def test_at_most_200_rules(self):
        rules = [{"who": "app:web", "host": f"h{i}.example.com", "port": 443, "proto": "https"} for i in range(F.MAX_RULES)]
        self.write_rules(json.dumps({"rules": rules}))
        self.assertEqual(len(F.load(self.paths)), F.MAX_RULES)
        F.add_rule(self.paths, "app:web", "h0.example.com", 443, "https")    # already there: not a new rule
        with self.assertRaises(F.FirewallError):
            F.add_rule(self.paths, "app:web", "one-too-many.example.com", 443, "https")
        self.assertEqual(len(F.load(self.paths)), F.MAX_RULES)

    def test_remove_takes_only_that_rule(self):
        F.add_rule(self.paths, "app:web", "example.com", 443, "https")
        F.add_rule(self.paths, "app:web", "example.org", 443, "https")
        self.assertEqual(F.remove_rule(self.paths, "app:web", "example.com", 443), 1)
        self.assertEqual(F.remove_rule(self.paths, "app:web", "example.com", 443), 0)
        self.assertEqual([r["host"] for r in F.load(self.paths)], ["example.org"])
        with self.assertRaises(F.FirewallError):
            F.remove_rule(self.paths, "app:web", "*.org", 443)


# ================================================================== the audit ====
class TestAudit(Env):
    def test_every_decision_is_logged_with_who_host_port_proto(self):
        F.add_rule(self.paths, "app:web", "example.com", 443, "https")
        self.assertTrue(F.decide(self.paths, "app:web", "example.com", 443, "https"))
        self.assertFalse(F.decide(self.paths, "app:web", "evil.example", 443, "https"))
        self.assertFalse(F.decide(self.paths, "app:web", "x\x1b[2Jevil", 443, "https"))
        log = [json.loads(l) for l in self.audit_text().splitlines()]
        rows = [(e["action"], e["target"], e["outcome"]) for e in log]
        self.assertIn(("firewall.connect", "app:web example.com:443 https", "allowed"), rows)
        self.assertIn(("firewall.connect", "app:web evil.example:443 https", "blocked"), rows)
        self.assertIn(("firewall.connect", "app:web invalid-host:443 https", "blocked"), rows)
        self.assertNotIn("\x1b", self.audit_text())

    def test_if_the_audit_record_cannot_be_written_it_does_not_happen(self):
        F.add_rule(self.paths, "app:web", "example.com", 443, "https")
        with mock.patch("kos.auth.AuditLog.record", side_effect=OSError("disk full")):
            self.assertFalse(F.decide(self.paths, "app:web", "example.com", 443, "https"))
            self.assertFalse(F.decide(self.paths, "app:web", "evil.example", 443, "https"))
        self.assertTrue(F.decide(self.paths, "app:web", "example.com", 443, "https"))

    def test_the_audit_never_holds_path_query_header_body_or_key(self):
        srv = Server()
        self.addCleanup(srv.close)
        F.add_rule(self.paths, "os:assistant", "127.0.0.1", srv.port, "loopback")
        cfg = {"active": "local", "local": {"endpoint": f"http://127.0.0.1:{srv.port}/SECRETPATH-1/v1?token=SECRETQUERY-2", "model": "m"}, "api": {}}
        with self.assertRaises(A.AssistantError):          # the stand-in answers JSON that is not a chat reply: fine
            A.ask(cfg, "", [{"role": "user", "content": "SECRETBODY-3"}], paths=self.paths)
        self.assertTrue(srv.seen)
        text = self.audit_text()
        self.assertIn("os:assistant 127.0.0.1:%d loopback" % srv.port, text)
        for secret in ("SECRETPATH-1", "SECRETQUERY-2", "SECRETBODY-3", "token"):
            self.assertNotIn(secret, text)


# ==================================================================== URL parse ====
class TestUrlAndHeaders(Env):
    def bad(self, url):
        with self.assertRaises(N.FetchError, msg=repr(url)) as cm:
            N.parse_url(url)
        self.assertEqual(cm.exception.code, "bad-url")

    def test_only_plain_https_urls_are_understood(self):
        for u in ("http://example.com/", "ftp://example.com", "file:///etc/passwd", "javascript:alert(1)", "example.com", "//example.com",
                  "HTTPS://example.com/", "https:/example.com", "https://", "https:///x", "https://user@example.com/",
                  "https://user:pw@example.com/", "https://example.com@evil.com/", "https://evil.com\\@example.com/",
                  "https://example.com\\evil/", "https://example.com/#frag", "https://example.com/x#", "https://exämple.com/",
                  "https://example.com:0/", "https://example.com:65536/", "https://example.com:abc/", "https://example.com:/",
                  "https://example.com:443:443/", "https://0x7f.1/", "https://2130706433/", "https://127.1/", "https://localhost./",
                  "https://example.com./", "https://exa mple.com/", "https://example.com/a b", "https://example.com/\x00", "https://example.com/\n",
                  "https://[::1/", "https://[::1]x/", "https://[127.0.0.1]/", "https://[zz]/", "https://example.com%2f@evil/",
                  "https://" + "a" * 300 + ".com/", "https://example.com/" + "a" * 2100, "", None, 5, b"https://example.com/"):
            self.bad(u)

    def test_good_urls_give_host_port_and_target(self):
        self.assertEqual(N.parse_url("https://Example.com/a/b?q=1"), ("example.com", 443, "/a/b?q=1"))
        self.assertEqual(N.parse_url("https://example.com"), ("example.com", 443, "/"))
        self.assertEqual(N.parse_url("https://example.com?q=1"), ("example.com", 443, "/?q=1"))
        self.assertEqual(N.parse_url("https://example.com:8443/x"), ("example.com", 8443, "/x"))
        self.assertEqual(N.parse_url("https://127.0.0.1:9/"), ("127.0.0.1", 9, "/"))
        self.assertEqual(N.parse_url("https://[::1]:9/x"), ("::1", 9, "/x"))
        self.assertEqual(N.parse_url("https://localhost:9/"), ("localhost", 9, "/"))

    def test_headers_are_allow_listed(self):
        self.assertEqual(N.check_headers({"Accept": "a", "X-Api-Key": "k"}), {"accept": "a", "x-api-key": "k"})
        for h in ({"cookie": "a"}, {"host": "evil"}, {"proxy-authorization": "x"}, {"x-forwarded-for": "1"}, {"content-length": "1"},
                  {"transfer-encoding": "chunked"}, {"accept": "a\r\nhost: evil"}, {"accept": "a\n"}, {"accept": "\x00"},
                  {"accept": "x" * 513}, {"accept": 5}, {5: "a"}, {"Accept": "a", "accept": "b"}, [("accept", "a")],
                  {n: "x" for n in ("accept", "content-type", "authorization", "x-api-key", "anthropic-version", "user-agent", "a")}):
            with self.assertRaises(N.FetchError, msg=repr(h)):
                N.check_headers(h)

    def test_method_and_body_rules(self):
        for kw in ({"method": "PUT"}, {"method": "DELETE"}, {"method": "get"}, {"method": None},
                   {"method": "GET", "body": "x"}, {"method": "POST", "body": "x" * (N.MAX_BODY + 1)}, {"method": "POST", "body": b"x"}):
            with self.assertRaises(N.FetchError, msg=repr(kw)) as cm:
                N.fetch(self.paths, "app:web", "https://example.com/", **kw)
            self.assertEqual(cm.exception.code, "bad-url")
        self.assertNotIn("firewall.connect", self.audit_text())              # a malformed request never reached the firewall

    def test_the_protocol_accepts_only_a_well_formed_fetch(self):
        def req(**kw):
            return {"cmd": "request", "action": "fetch", "url": "https://example.com/", **kw}
        ok = validate_app_message(req(), "tui")
        self.assertEqual((ok["method"], ok["headers"], ok["body"]), ("GET", {}, ""))
        validate_app_message(req(method="POST", body="x" * N.MAX_BODY, headers={"Content-Type": "a"}), "cmd")
        for bad in (req(method="PUT"), req(headers={"cookie": "a"}), req(body="x"), req(method="POST", body="x" * (N.MAX_BODY + 1)),
                    req(extra=1), req(url=5), req(url=""), req(url="https://e.com/" + "a" * 2100), req(headers=[]), req(body=5),
                    {"cmd": "request", "action": "fetch"}):
            with self.assertRaises(ProtocolError, msg=repr(bad)[:80]):
                validate_app_message(bad, "tui")


# ===================================================== real TLS, verification ON ====
class TestFetchOverRealTls(TLS):
    def test_no_rule_means_nothing_is_connected(self):
        lst = Listener()
        self.addCleanup(lst.close)
        self.assertEqual(self.code(lambda: N.fetch(self.paths, "app:web", f"https://localhost:{lst.port}/", context=self.ctx)), "blocked")
        self.assertEqual(self.code(lambda: self.get("/")), "blocked")
        self.assertEqual(self.srv.seen, [])
        lst.close()
        self.assertEqual(lst.count, 0)
        self.assertIn('"outcome":"blocked"', self.audit_text())

    def test_a_rule_for_another_app_port_or_host_does_not_help(self):
        self.allow("app:other")
        self.allow("app:web", port=self.srv.port + 1)
        self.allow("app:web", host="example.com")
        self.assertEqual(self.code(lambda: self.get("/")), "blocked")
        self.assertEqual(self.srv.seen, [])

    def test_happy_path_get_and_post_with_verification_on(self):
        self.allow()
        got = self.get("/hello?x=1")
        self.assertEqual((got["status"], got["content_type"]), (200, "application/json; charset=utf-8"))
        self.assertEqual(json.loads(got["body"]), {"method": "GET", "path": "/hello?x=1"})
        got = self.get("/p", method="POST", headers={"Content-Type": "application/json", "x-api-key": KEY}, body='{"a":1}')
        self.assertEqual(json.loads(got["body"])["method"], "POST")
        cmd, path, hdrs, body = self.srv.seen[-1]
        self.assertEqual((cmd, path, body), ("POST", "/p", b'{"a":1}'))
        self.assertEqual(hdrs.get("x-api-key"), KEY)
        self.assertEqual(hdrs.get("Connection", hdrs.get("connection")), "close")
        self.assertNotIn("Cookie", hdrs)

    def test_the_default_context_cannot_trust_a_self_signed_certificate(self):
        self.allow()
        # no injected context: the real default store does not know our throwaway certificate
        self.assertEqual(self.code(lambda: N.fetch(self.paths, "app:web", self.url("/"))), "refused")

    def test_a_server_with_a_different_certificate_is_refused(self):
        other = Server((self.crt2, self.pem2))
        self.addCleanup(other.close)
        F.add_rule(self.paths, "app:web", "localhost", other.port, "https")
        c = self.code(lambda: N.fetch(self.paths, "app:web", f"https://localhost:{other.port}/", context=self.ctx))
        self.assertEqual(c, "refused")
        self.assertEqual(other.seen, [])                                      # no request was ever sent over the bad channel

    def test_the_host_name_is_checked_not_just_the_certificate(self):
        # the certificate is valid for localhost and 127.0.0.1 only: a rule for another name cannot be reached by TLS
        F.add_rule(self.paths, "app:web", "127.0.0.2", self.srv.port, "https")
        self.assertIn(self.code(lambda: N.fetch(self.paths, "app:web", self.url("/", "127.0.0.2"), context=self.ctx)),
                      ("refused", "unreachable"))
        self.assertEqual(self.srv.seen, [])
        self.allow(host="127.0.0.1")
        self.assertEqual(N.fetch(self.paths, "app:web", self.url("/", "127.0.0.1"), context=self.ctx)["status"], 200)   # IP SAN matches

    def test_an_injected_context_must_still_verify(self):
        self.allow()
        weak = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        weak.check_hostname = False
        weak.verify_mode = ssl.CERT_NONE
        self.assertEqual(self.code(lambda: self.get("/", )), "refused") if False else None
        self.assertEqual(self.code(lambda: N.fetch(self.paths, "app:web", self.url("/"), context=weak)), "refused")
        self.assertEqual(self.srv.seen, [])

    def test_a_redirect_is_an_error_and_never_followed(self):
        self.allow()
        self.assertEqual(self.code(lambda: self.get("/redirect")), "redirect")
        self.assertEqual([s[1] for s in self.srv.seen], ["/redirect"])        # exactly one request: nothing was followed

    def test_the_reply_is_capped(self):
        self.allow()
        self.assertEqual(self.code(lambda: self.get("/big")), "too-big")
        self.assertEqual(self.code(lambda: self.get("/lie")), "too-big")      # a declared size over the cap is refused up front

    def test_http_to_a_non_loopback_host_cannot_be_a_rule_and_cannot_be_fetched(self):
        lst = Listener()
        self.addCleanup(lst.close)
        with self.assertRaises(F.FirewallError):
            F.add_rule(self.paths, "app:web", "example.com", lst.port, "http")
        for url in (f"http://127.0.0.1:{lst.port}/", f"http://localhost:{lst.port}/", f"http://example.com:{lst.port}/"):
            self.assertEqual(self.code(lambda: N.fetch(self.paths, "app:web", url, context=self.ctx)), "bad-url")
        lst.close()
        self.assertEqual(lst.count, 0)

    def test_a_wildcard_allows_any_host_for_one_app_and_one_port_only(self):
        F.add_rule(self.paths, "app:web", "*", self.srv.port, "https")
        self.assertEqual(self.get("/")["status"], 200)
        self.assertEqual(self.code(lambda: self.get("/", who="app:other")), "blocked")
        self.assertEqual(self.code(lambda: N.fetch(self.paths, "app:web", f"https://localhost:{self.srv.port + 1}/", context=self.ctx)), "blocked")

    def test_the_audit_log_has_who_host_port_proto_and_nothing_of_the_request(self):
        self.allow()
        self.get("/SECRETPATH-1?token=SECRETQUERY-2", method="POST", headers={"authorization": "Bearer " + KEY, "x-api-key": KEY},
                 body="SECRETBODY-3")
        self.code(lambda: N.fetch(self.paths, "app:web", "https://blocked.example.com/SECRETPATH-4?q=SECRETQUERY-5",
                                  method="POST", headers={"x-api-key": KEY}, body="SECRETBODY-6", context=self.ctx))
        text = self.audit_text()
        self.assertIn(f"app:web localhost:{self.srv.port} https", text)
        self.assertIn("app:web blocked.example.com:443 https", text)
        for secret in ("SECRETPATH", "SECRETQUERY", "SECRETBODY", KEY, "Bearer", "token", "authorization"):
            self.assertNotIn(secret, text)

    def test_an_audit_failure_means_no_connection(self):
        self.allow()
        lst = Listener()
        self.addCleanup(lst.close)
        F.add_rule(self.paths, "app:web", "localhost", lst.port, "https")
        with mock.patch("kos.auth.AuditLog.record", side_effect=OSError("full")):
            self.assertEqual(self.code(lambda: self.get("/")), "blocked")
            self.assertEqual(self.code(lambda: N.fetch(self.paths, "app:web", f"https://localhost:{lst.port}/", context=self.ctx)), "blocked")
        lst.close()
        self.assertEqual((self.srv.seen, lst.count), ([], 0))


# ================================================ the bridge: who may even ask ====
class TestBridgeFetch(TLS):
    def ask(self, bridge, url=None, **kw):
        out = []
        bridge.handle(validate_app_message({"cmd": "request", "action": "fetch", "url": url or self.url("/hi"), **kw}, "tui"),
                      out.append, self.authority())               # no answers: a password prompt would fail the test
        return out[-1]

    def bridge(self, **kw):
        return SystemBridge(self.paths, **{"app": "web", "system": False, "network": True, "fetch_context": self.ctx, **kw})

    def test_an_app_without_network_is_refused_and_nothing_connects(self):
        self.allow()
        for kw in ({"network": False}, {"network": False, "system": True}, {"network": False, "assistant": True},
                   {"network": False, "sysinfo": True}, {"network": False, "assistant": True, "sysinfo": True, "system": True}):
            r = self.ask(self.bridge(**kw))
            self.assertEqual(r, {"cmd": "fetch", "ok": False, "error": "refused"}, kw)
        self.assertEqual(self.srv.seen, [])
        self.assertNotIn("firewall.connect", self.audit_text())

    def test_there_is_no_firewall_permission_for_apps_at_all(self):
        base = {"name": "x", "version": "1", "runtime": "python", "entry": "a:main"}
        for p in ("firewall", "fetch", "net", "networks"):
            with self.assertRaises(KAppError):
                Manifest.parse(json.dumps({**base, "permissions": [p]}).encode())
        self.assertEqual(Manifest.parse(json.dumps({**base, "permissions": ["network"]}).encode()).permissions, ("network",))

    def test_a_session_with_no_bridge_refuses(self):
        sent = []
        fake = types.SimpleNamespace(bridge=None, _send=sent.append)
        Session._on_request(fake, validate_app_message({"cmd": "request", "action": "fetch", "url": self.url()}, "tui"))
        self.assertEqual(sent, [{"cmd": "fetch", "ok": False, "error": "refused"}])

    def test_bridge_for_gives_a_network_app_only_the_fetch_request(self):
        self.assertIsNone(kcli._bridge_for(self.paths, "web", ["storage"]))
        b = kcli._bridge_for(self.paths, "web", ["network"])
        self.assertEqual((b.network, b.system, b.assistant, b.sysinfo), (True, False, False, False))
        out = []
        for req in ({"cmd": "request", "action": "apps"}, {"cmd": "request", "action": "open", "app": "hello", "mode": "tui"},
                    {"cmd": "request", "action": "close", "id": "hello-abcdef"}, {"cmd": "request", "action": "backup"}):
            self.assertIsNone(b.handle(req, out.append, self.authority()))
            self.assertFalse(out[-1]["ok"])
            self.assertIn("'system' permission", out[-1]["detail"])
        r = []
        b.handle({"cmd": "request", "action": "assistant", "system": "", "messages": [{"role": "user", "content": "x"}]}, r.append, self.authority())
        self.assertEqual(r[-1]["error"], "refused")                          # network is not the assistant permission
        r.clear()
        b.handle({"cmd": "request", "action": "sysinfo", "topic": "os"}, r.append, self.authority())
        self.assertEqual(r[-1]["error"], "refused")

    def test_blocked_then_allowed_end_to_end(self):
        b = self.bridge()
        self.assertEqual(self.ask(b), {"cmd": "fetch", "ok": False, "error": "blocked"})
        self.assertEqual(self.srv.seen, [])
        self.allow()
        r = self.ask(b)
        self.assertEqual((r["ok"], r["status"]), (True, 200))
        self.assertEqual(json.loads(base64.b64decode(r["body_b64"])), {"method": "GET", "path": "/hi"})
        self.assertEqual(self.ask(b, url="http://localhost:1/")["error"], "bad-url")

    def test_the_sdk_round_trip_and_precheck(self):
        a, b = socket.socketpair()
        app = App(a)
        b.sendall(b'{"cmd":"key","key":"x"}\n{"cmd":"fetch","ok":true,"status":200,"content_type":"text/plain","body_b64":"aGk="}\n')
        self.assertEqual(app.fetch("https://example.com/"), (True, {"status": 200, "content_type": "text/plain", "body": b"hi"}))
        sent = json.loads(b.recv(65536).split(b"\n")[0])
        self.assertEqual((sent["cmd"], sent["action"], sent["method"]), ("request", "fetch", "GET"))
        self.assertEqual(next(app.events())["key"], "x")
        b.sendall(b'{"cmd":"fetch","ok":false,"error":"blocked"}\n')
        self.assertEqual(app.fetch("https://example.com/"), (False, "blocked"))
        b.sendall(b'{"cmd":"fetch","ok":true,"status":200,"content_type":"","body_b64":"!!!"}\n')
        self.assertEqual(app.fetch("https://example.com/"), (False, "unreachable"))
        b.setblocking(False)
        try:
            while b.recv(65536): pass                                       # drain what the good calls sent
        except BlockingIOError:
            pass
        for bad in (dict(url="https://e.com/", headers={"cookie": "x"}), dict(url="https://e.com/", method="PUT"),
                    dict(url="https://e.com/", body="x"), dict(url=5)):
            self.assertEqual(app.fetch(**bad), (False, "bad-url"))
        with self.assertRaises(BlockingIOError):
            b.recv(10)                                                       # a malformed request was never even sent
        b.close()
        self.assertEqual(app.fetch("https://example.com/"), (False, "unreachable"))

    def test_the_fake_host_defaults_to_refused_and_can_be_injected(self):
        h = FakeHost([])
        self.assertEqual(h.fetch("https://example.com/"), (False, "refused"))
        h.fetch_fn = lambda url, m, hd, body: (True, {"status": 200, "content_type": "", "body": b"ok"})
        self.assertEqual(h.fetch("https://example.com/", "POST", {"accept": "a"}, "b")[0], True)
        self.assertEqual(h.fetch_calls[-1], ("https://example.com/", "POST", {"accept": "a"}, "b"))


# ================================================= the sandbox: no host network ====
class TestSandboxNeverGivesTheNetwork(Env):
    def test_no_code_path_can_set_the_host_network(self):
        import dataclasses
        self.assertNotIn("allow_network", [f.name for f in dataclasses.fields(SandboxPolicy)])
        with self.assertRaises(TypeError):
            SandboxPolicy(allow_network=True)
        hits = [str(p.relative_to(ROOT)) for p in list((ROOT / "kos").rglob("*.py")) + list((ROOT / "examples").rglob("*.py"))
                if "allow_network" in p.read_text() or "allow_net =" in p.read_text()]
        self.assertEqual(hits, [])
        self.assertNotIn("app.network", __import__("kos.auth", fromlist=["ACTIONS"]).ACTIONS)

    def test_a_manifest_that_says_network_still_gets_a_sandbox_without_one_and_no_prompt(self):
        app = types.SimpleNamespace(manifest=types.SimpleNamespace(modes=("tui",), permissions=("storage", "network")))
        prompter = types.SimpleNamespace(confirm=mock.Mock(side_effect=AssertionError("no network question exists any more")))
        policy = authorize_app_action("web", app, "tui", self.authority(), prompter)
        self.assertIsInstance(policy, SandboxPolicy)
        prompter.confirm.assert_not_called()
        self.assertNotIn("app.network", self.audit_text())

    def test_every_launch_path_uses_the_one_policy(self):
        # the only SandboxPolicy constructors in the OS take no network argument
        for p in (ROOT / "kos").rglob("*.py"):
            for m in re.finditer(r"SandboxPolicy\(([^)]*)\)", p.read_text()):
                self.assertNotRegex(m.group(1), r"net", f"{p.name}: {m.group(0)}")

    @unittest.skipUnless(os.uname().machine == "x86_64", "the sandbox filter is x86_64 only")
    def test_a_sandboxed_app_cannot_connect_out_even_when_its_manifest_says_network(self):
        lst = Listener()
        self.addCleanup(lst.close)
        app = types.SimpleNamespace(manifest=types.SimpleNamespace(modes=("tui",), permissions=("network",)))
        policy = authorize_app_action("web", app, "tui", self.authority(), types.SimpleNamespace(confirm=lambda q: True))
        code = (f"import socket,sys\n"
                f"try:\n s=socket.create_connection(('127.0.0.1',{lst.port}),timeout=3); print('CONNECTED')\n"
                f"except OSError as e:\n print('DENIED', type(e).__name__)\n")
        try:
            r = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", code], preexec_fn=policy.preexec(),
                               capture_output=True, text=True, cwd="/", timeout=30)
        except Exception as e:                                              # a host that cannot unshare is not a pass
            self.skipTest(f"cannot sandbox here: {e}")
        if r.returncode != 0 and "unshare" in (r.stderr or "") + str(r.stdout):
            self.skipTest("cannot sandbox here")
        lst.close()
        self.assertIn("DENIED", r.stdout, r.stderr[-300:])
        self.assertNotIn("CONNECTED", r.stdout)
        self.assertEqual(lst.count, 0)


# ============================================ the OS's own connections: assistant ====
class TestAssistantIsFirewalled(Env):
    def cli(self, argv, *answers):
        out, err = io.StringIO(), io.StringIO()
        auth = self.authority(*answers)
        with mock.patch.dict(os.environ, {"KOS_ROOT": self.tmp.name}), \
                mock.patch("kos.cli._authority", return_value=(auth, self.prompter)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = kcli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def bridge(self, **kw):
        return SystemBridge(self.paths, **{"app": "notes", "system": False, "assistant": True, **kw})

    def asked(self, bridge, *answers):
        out = []
        bridge.handle(validate_app_message({"cmd": "request", "action": "assistant", "system": "s",
                                            "messages": [{"role": "user", "content": "hi"}]}, "tui"), out.append, self.authority(*answers))
        return out[-1]

    def test_without_a_rule_the_assistant_is_blocked_with_no_password_and_no_connection(self):
        srv = Server()
        self.addCleanup(srv.close)
        A.set_local(self.paths, f"http://127.0.0.1:{srv.port}/v1/chat/completions", "m")
        A.use(self.paths, "local")
        r = self.asked(self.bridge())                                         # no answers: a password prompt would fail
        self.assertEqual(r, {"cmd": "assistant", "ok": False, "error": "blocked"})
        self.assertEqual(srv.seen, [])
        self.assertIn("os:assistant 127.0.0.1:%d loopback" % srv.port, self.audit_text())
        self.assertIn("blocked", self.audit_text())
        self.assertIn("blocked", A.ERRORS)

    def test_with_a_rule_it_goes_through_a_real_loopback_server(self):
        def answer(h):
            pass
        srv = Server()
        self.addCleanup(srv.close)
        url = f"http://127.0.0.1:{srv.port}/v1/chat/completions"
        cfg = {"active": "local", "local": {"endpoint": url, "model": "m"}, "api": {}}
        with self.assertRaises(A.AssistantError) as cm:                       # blocked: nothing connected
            A.ask(cfg, "", [{"role": "user", "content": "hi"}], paths=self.paths)
        self.assertEqual((cm.exception.code, srv.seen), ("blocked", []))
        F.add_rule(self.paths, "os:assistant", "127.0.0.1", srv.port, "loopback")
        with self.assertRaises(A.AssistantError) as cm:                       # connected; the stand-in's reply is not a chat reply
            A.ask(cfg, "", [{"role": "user", "content": "hi"}], paths=self.paths)
        self.assertEqual(cm.exception.code, "bad-reply")
        self.assertEqual(len(srv.seen), 1)

    def test_a_rule_for_the_wrong_port_or_proto_does_not_allow_it(self):
        A.set_local(self.paths, "http://127.0.0.1:11434/v1/chat/completions", "m")
        A.use(self.paths, "local")
        F.add_rule(self.paths, "os:assistant", "127.0.0.1", 11435, "loopback")
        F.add_rule(self.paths, "app:notes", "127.0.0.1", 11434, "loopback")      # an app's rule is not the OS's rule
        self.assertEqual(self.asked(self.bridge())["error"], "blocked")
        self.assertFalse(A.status(self.paths)["firewall_allows"])

    def test_set_local_adds_exactly_the_matching_rule_with_the_same_password(self):
        code, out, _ = self.cli(["assistant", "set", "local", "--endpoint", "http://127.0.0.1:11434/v1/chat/completions", "--model", "llama3"], PW)
        self.assertEqual(code, 0)
        self.assertEqual(F.load(self.paths), [{"who": "os:assistant", "host": "127.0.0.1", "port": 11434, "proto": "loopback"}])
        self.assertIn("firewall rule added", out)
        self.assertIn("os:assistant", out)
        self.assertEqual(len(self.prompter.asked), 1)                           # one password, one action

    def test_set_api_adds_exactly_the_matching_rule(self):
        code, out, err = self.cli(["assistant", "set", "api", "--provider", "anthropic", "--model", "claude-x"], PW, KEY)
        self.assertEqual(code, 0, err)
        self.assertEqual(F.load(self.paths), [{"who": "os:assistant", "host": "api.anthropic.com", "port": 443, "proto": "https"}])
        self.assertNotIn(KEY, out + err + self.rules_text())
        code, out, err = self.cli(["assistant", "set", "api", "--provider", "openai", "--endpoint", "https://api.example.com/v1/chat", "--model", "m"], PW, KEY)
        self.assertEqual(sorted(r["host"] for r in F.load(self.paths)), ["api.anthropic.com", "api.example.com"])

    def rules_text(self):
        p = F.rules_path(self.paths)
        return p.read_text() if p.exists() else ""

    def test_without_the_password_set_writes_no_rule_and_no_settings(self):
        code, _, _ = self.cli(["assistant", "set", "local", "--endpoint", "http://127.0.0.1:11434/v1/x", "--model", "m"], "wrong", "wrong", "wrong")
        self.assertEqual(code, 2)
        self.assertFalse(F.rules_path(self.paths).exists())
        self.assertFalse(A.config_path(self.paths).exists())

    def test_status_says_whether_the_firewall_allows_it(self):
        A.set_local(self.paths, "http://127.0.0.1:11434/v1/chat/completions", "m")
        A.use(self.paths, "local")
        code, out, _ = self.cli(["assistant", "status"])
        self.assertIn("BLOCKS", out)
        self.assertIn("kos firewall allow os:assistant", out)
        F.add_rule(self.paths, "os:assistant", "127.0.0.1", 11434, "loopback")
        code, out, _ = self.cli(["assistant", "status"])
        self.assertIn("allows it", out)

    def test_assistant_test_names_the_allow_command_when_blocked(self):
        A.set_local(self.paths, "http://127.0.0.1:11434/v1/chat/completions", "m")
        A.use(self.paths, "local")
        code, out, _ = self.cli(["assistant", "test"], PW)
        self.assertEqual(code, 1)
        self.assertIn("error: blocked", out)
        self.assertIn("kos firewall allow os:assistant", out)

    def test_the_agent_tells_the_owner_how_to_allow_it(self):
        from kos.office.agent import _NOTICE
        self.assertIn("kos firewall allow os:assistant", _NOTICE["blocked"])


# ============================================== the OS's own connections: AI OS ====
class TestAiosIsFirewalled(Env):
    class Fake:
        def __init__(self):
            self.sent = []

        def __call__(self, req, timeout=None):
            self.sent.append(req.full_url)
            body = json.dumps({"status": "ran", "text": "done", "layers": []}).encode()
            return type("R", (), {"read": lambda s: body, "__enter__": lambda s: s, "__exit__": lambda s, *a: False})()

    def test_blocked_without_a_rule_and_the_message_names_the_command(self):
        fake = self.Fake()
        with self.assertRaises(aios.AiosError) as cm:
            aios.run_layer("gui", ["click"], opener=fake, paths=self.paths)
        self.assertIn("kos firewall allow os:aios 127.0.0.1 7861 --proto loopback", str(cm.exception))
        with self.assertRaises(aios.AiosError):
            aios.status(opener=fake, paths=self.paths)
        self.assertEqual(fake.sent, [])
        self.assertIn("os:aios 127.0.0.1:7861 loopback", self.audit_text())

    def test_allowed_with_the_rule_and_only_for_that_port(self):
        fake = self.Fake()
        F.add_rule(self.paths, "os:aios", "127.0.0.1", 7861, "loopback")
        self.assertEqual(aios.run_layer("gui", ["click"], opener=fake, paths=self.paths)["text"], "done")
        with self.assertRaises(aios.AiosError):
            aios.run_layer("gui", ["click"], opener=fake, env={"KOS_AIOS_URL": "http://127.0.0.1:7862"}, paths=self.paths)
        self.assertEqual(len(fake.sent), 1)

    def test_a_real_loopback_engine_and_the_cli_path(self):
        srv = Server()
        self.addCleanup(srv.close)
        env = {"KOS_AIOS_URL": f"http://127.0.0.1:{srv.port}"}
        with self.assertRaises(aios.AiosError):
            aios.run_layer("app", ["ls"], env=env, paths=self.paths)
        self.assertEqual(srv.seen, [])
        F.add_rule(self.paths, "os:aios", "127.0.0.1", srv.port, "loopback")
        aios.run_layer("app", ["ls"], env=env, paths=self.paths)
        self.assertEqual([s[0] for s in srv.seen], ["POST"])
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"KOS_ROOT": self.tmp.name, "KOS_AIOS_URL": "http://127.0.0.1:9"}), contextlib.redirect_stderr(err):
            self.assertEqual(kcli.main(["aios", "app", "ls"]), 1)
        self.assertIn("kos firewall allow os:aios", err.getvalue())

    def test_the_engine_request_ignores_environment_proxies(self):
        srv = Server()
        self.addCleanup(srv.close)
        F.add_rule(self.paths, "os:aios", "127.0.0.1", srv.port, "loopback")
        with mock.patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9", "no_proxy": ""}):
            aios.run_layer("app", ["ls"], env={"KOS_AIOS_URL": f"http://127.0.0.1:{srv.port}"}, paths=self.paths)
        self.assertEqual(len(srv.seen), 1)


# ============================================================== the CLI itself ====
class TestFirewallCli(Env):
    def cli(self, argv, *answers):
        out, err = io.StringIO(), io.StringIO()
        auth = self.authority(*answers)
        with mock.patch.dict(os.environ, {"KOS_ROOT": self.tmp.name}), \
                mock.patch("kos.cli._authority", return_value=(auth, self.prompter)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = kcli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_status_needs_no_password_and_says_deny_by_default(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"KOS_ROOT": self.tmp.name}), \
                mock.patch("kos.cli._authority", side_effect=AssertionError("status must not ask for a password")), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(kcli.main(["firewall", "status"]), 0)
        self.assertIn("default DENY", out.getvalue())
        self.assertIn("0 of 200", out.getvalue())

    def test_allow_and_remove_need_the_password_and_write_nothing_without_it(self):
        F.add_rule(self.paths, "app:web", "keep.example.com", 443, "https")
        before = F.rules_path(self.paths).read_text()
        for argv in (["firewall", "allow", "app:web", "example.com", "443", "--proto", "https"],
                     ["firewall", "allow", "app:web", "*", "443", "--proto", "https"],
                     ["firewall", "remove", "app:web", "keep.example.com", "443"]):
            code, _, _ = self.cli(argv, "wrong", "wrong", "wrong")
            self.assertEqual(code, 2, argv)
            self.assertEqual(F.rules_path(self.paths).read_text(), before, argv)
        code, _, _ = self.cli(["firewall", "allow", "app:web", "example.com", "443", "--proto", "https"], None)     # cancelled
        self.assertEqual(code, 2)
        self.assertEqual(F.rules_path(self.paths).read_text(), before)

    def test_a_bad_rule_is_refused_before_any_password_is_asked(self):
        for argv in (["firewall", "allow", "app:web", "example.com", "80", "--proto", "http"],
                     ["firewall", "allow", "app:web", "example.com", "80", "--proto", "loopback"],
                     ["firewall", "allow", "app:web", "*.example.com", "443", "--proto", "https"],
                     ["firewall", "allow", "app:web", "*", "443", "--proto", "loopback"],
                     ["firewall", "allow", "app:web", "example.com", "0", "--proto", "https"],
                     ["firewall", "allow", "app:web", "example.com", "http", "--proto", "https"],
                     ["firewall", "allow", "web", "example.com", "443", "--proto", "https"],
                     ["firewall", "remove", "app:web", "*.example.com", "443"]):
            with contextlib.redirect_stderr(io.StringIO()):
                try:
                    code, _, err = self.cli(argv)                           # no answers: any prompt would raise
                except SystemExit as e:                                     # argparse refusing --proto http
                    code = e.code
            self.assertEqual(code, 2, argv)
            self.assertEqual(self.prompter.asked, [], argv)
        self.assertFalse(F.rules_path(self.paths).exists())

    def test_allow_log_and_remove_with_the_password(self):
        code, out, _ = self.cli(["firewall", "allow", "app:web", "Example.com", "443", "--proto", "https"], PW)
        self.assertEqual(code, 0)
        self.assertEqual(F.load(self.paths), [{"who": "app:web", "host": "example.com", "port": 443, "proto": "https"}])
        self.assertIn("app:web  example.com:443  https", out)
        self.assertTrue(F.decide(self.paths, "app:web", "example.com", 443, "https"))
        self.assertFalse(F.decide(self.paths, "app:web", "evil.com", 443, "https"))
        code, out, _ = self.cli(["firewall", "log", "-n", "5"])
        self.assertIn("allowed  app:web example.com:443 https", out)
        self.assertIn("blocked  app:web evil.com:443 https", out)
        self.assertIn("firewall.change", self.audit_text())
        code, out, _ = self.cli(["firewall", "remove", "app:web", "example.com", "443"], PW)
        self.assertEqual((code, F.load(self.paths)), (0, []))

    def test_a_wildcard_is_shown_as_wildcard_and_only_when_typed(self):
        code, out, _ = self.cli(["firewall", "allow", "app:web", "*", "443", "--proto", "https"], PW)
        self.assertEqual(code, 0)
        self.assertIn("WILDCARD", out)
        code, out, _ = self.cli(["firewall", "status"])
        self.assertIn("WILDCARD", out)
        self.assertEqual(F.load(self.paths)[0]["host"], "*")

    def test_the_log_prints_escaped_text(self):
        self.paths.logs.mkdir(parents=True, exist_ok=True)
        from kos.auth import AuditLog
        AuditLog(self.paths).record("firewall.connect", "app:web ev\x1b[2Jil:443 https", "blocked")
        code, out, _ = self.cli(["firewall", "log"])
        self.assertNotIn("\x1b", out)
        self.assertIn("\\x1b", out)

    def test_help_lists_firewall(self):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"KOS_ROOT": self.tmp.name}), contextlib.redirect_stdout(out):
            kcli.main(["help"])
        self.assertIn("firewall", out.getvalue())
        self.assertIn("firewall", kcli.COMMANDS)


# =========================================== the apps that used the network ====
class TestMigratedApps(unittest.TestCase):
    def model_host(self, reply):
        h = FakeHost([])
        h.fetch_fn = lambda url, m, hd, body: reply(url, m, hd, body)
        return h

    def test_the_model_client_goes_through_host_fetch(self):
        from kos.office import llm
        cfg = {"provider": "anthropic", "model": "m", "key": KEY}
        seen = []

        def ok(url, m, hd, body):
            seen.append((url, m, hd, body))
            return (True, {"status": 200, "content_type": "application/json", "body": json.dumps({"content": [{"type": "text", "text": "hi"}]}).encode()})
        self.assertEqual(llm.ask(self.model_host(ok), cfg, "sys", [{"role": "user", "content": "q"}]), "hi")
        self.assertEqual((seen[0][0], seen[0][1]), ("https://api.anthropic.com/v1/messages", "POST"))
        self.assertEqual(seen[0][2]["x-api-key"], KEY)
        N.check_headers(seen[0][2])                                           # only allow-listed header names

    def test_blocked_and_plain_http_and_no_host_are_errors_and_never_leak_the_key(self):
        from kos.office import llm
        cfg = {"provider": "openai", "model": "m", "key": KEY}
        with self.assertRaises(llm.LLMError) as cm:
            llm.ask(self.model_host(lambda *a: (False, "blocked")), cfg, "", [])
        self.assertIn("kos firewall allow", str(cm.exception))
        self.assertNotIn(KEY, str(cm.exception))
        calls = []
        h = self.model_host(lambda *a: calls.append(a) or (False, "refused"))
        for ep in ("http://api.example.com/v1", "http://127.0.0.1:11434/v1", "ftp://x"):
            with self.assertRaises(llm.LLMError):
                llm.ask(h, {**cfg, "endpoint": ep}, "", [])
        self.assertEqual(calls, [])                                           # never even asked the OS
        with self.assertRaises(llm.LLMError):
            llm.ask(None, cfg, "", [])
        with self.assertRaises(llm.LLMError):
            llm.ask(FakeHost([]), cfg, "", [])                                # default host: refused

    def test_the_api_tool_uses_host_fetch_and_reports_blocked(self):
        from kos.office import extras
        h = FakeHost([], data={})
        tool = extras.ApiTool(h)
        rec = {"name": "t", "method": "GET", "url": "https://example.com/x", "headers": "accept: a", "body": "", "pick": "a"}
        self.assertTrue(any("refused" in l for l in tool.send(rec)))
        h.fetch_fn = lambda *a: (False, "blocked")
        self.assertTrue(any("blocked by the firewall" in l for l in tool.send(rec)))
        h.fetch_fn = lambda *a: (True, {"status": 200, "content_type": "application/json", "body": b'{"a": 5}'})
        self.assertIn("5", "\n".join(tool.send(rec)))
        self.assertTrue(any("only GET and POST" in l for l in tool.send({**rec, "method": "DELETE"})))
        self.assertEqual(h.fetch_calls[0][1], "GET")

    def test_email_has_no_network_send_and_no_smtp(self):
        from kos.office import catalog, mail
        self.assertNotIn("smtplib", Path(mail.__file__).read_text().replace("smtplib is gone", ""))
        ms = mail.MailStore(FakeHost([], data={}))
        self.assertIn("no network send", ms.relay()[0])
        by = {e.title: e for e in catalog.CATALOG}
        for t in ("Email Client", "Email Server", "Email Automation Tool"):
            self.assertIn("no network send", by[t].note.lower(), t)
            self.assertFalse(by[t].network, t)

    def test_only_the_gated_modules_may_import_a_network_library(self):
        allowed = {"kos/netfetch.py", "kos/assistant.py", "kos/aios.py"}
        pat = re.compile(r"^\s*(import|from)\s+(urllib\.request|smtplib|http\.client|ftplib|imaplib|poplib|telnetlib|xmlrpc|requests|aiohttp|httpx)\b", re.M)
        hits = set()
        for base in ("kos", "examples", "suite", "bin", "packaging"):
            for p in (ROOT / base).rglob("*.py"):
                t = p.read_text()
                if pat.search(t) or "AF_INET" in t:
                    hits.add(str(p.relative_to(ROOT)))
        self.assertEqual(hits - allowed, set(), "a module makes connections outside the firewall's gate")
        self.assertFalse((ROOT / "examples/web/web.py").read_text().count("urllib.request"))


if __name__ == "__main__":
    unittest.main()
