"""The swappable assistant: the OS makes the model connection, apps get no network.

Refusals first (rule: a refusal test, not just a happy path). What cannot be tested here: a real
https/API server. The certificate path is checked by its policy decisions and by asserting the SSL
context in use is CERT_REQUIRED with check_hostname on; no real TLS handshake is performed."""

import contextlib
import io
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import traceback
import types
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kos import assistant as A  # noqa: E402
from kos import firewall as F  # noqa: E402
from kos import cli as kcli  # noqa: E402
from kos.auth import ACTIONS, Authority, AuthorizationDenied, KdfParams, PasswordStore, Throttle  # noqa: E402
from kos.kapp import KAppError, Manifest  # noqa: E402
from kos.paths import Paths  # noqa: E402
from kos.prompt import ScriptedPrompter  # noqa: E402
from kos.protocol import ProtocolError, validate_app_message  # noqa: E402
from kos.sdk import App  # noqa: E402
from kos.session import Session  # noqa: E402
from kos.system import SystemBridge  # noqa: E402

PW = "correct horse battery"
KEY = "sk-SECRET-KEY-0123456789"
MSG = [{"role": "user", "content": "SECRET-MESSAGE-TEXT hello"}]


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


def fw_ask(cfg, system, messages, opener=None):
    """A.ask now needs the firewall's yes (os:assistant): these transport tests are about the wire, so
    they allow exactly this config's endpoint first (the firewall itself is tested in test_firewall.py)."""
    with tempfile.TemporaryDirectory() as d:
        paths = Paths(Path(d))
        tgt = A.firewall_target(cfg)
        if tgt:
            F.add_rule(paths, "os:assistant", *tgt)
        return A.ask(cfg, system, messages, opener=opener, paths=paths)


class Resp:
    def __init__(self, body: bytes): self.b = body
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, n=-1):
        out, self.b = self.b[:n], self.b[n:]
        return out


class FakeOpener:
    """Stands in for the network: counts every attempt, never connects."""
    def __init__(self, body=None, exc=None):
        self.calls, self.reqs = 0, []
        self.body = body if body is not None else json.dumps({"choices": [{"message": {"content": "hi there"}}]}).encode()
        self.exc = exc

    def open(self, req, timeout=None):
        self.calls += 1
        self.reqs.append(req)
        if self.exc: raise self.exc
        return Resp(self.body)


class Server:
    """A loopback http.server in a thread, answering whatever ``handler(self)`` does."""
    def __init__(self, respond):
        self.seen = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("content-length", 0))
                outer.seen.append((self.path, dict(self.headers), self.rfile.read(n)))
                respond(self)
            def log_message(self, *a): pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/v1/chat/completions"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()


def reply_json(obj, status=200):
    def f(h):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        h.send_response(status); h.send_header("content-length", str(len(body))); h.end_headers(); h.wfile.write(body)
    return f


def local_cfg(url, model="m"):
    return {"active": "local", "local": {"endpoint": url, "model": model}, "api": {}}


def api_cfg(provider="anthropic", endpoint="https://api.example.com/v1/messages"):
    return {"active": "api", "local": {}, "api": {"provider": provider, "endpoint": endpoint, "model": "m", "key": KEY}}


# ===================================================================== policy ====
class TestEndpointPolicy(unittest.TestCase):
    def refused(self, kind, url):
        with self.assertRaises(A.PolicyError, msg=f"{kind} {url}"):
            A.check_endpoint(kind, url)

    def allowed(self, kind, url):
        self.assertEqual(A.check_endpoint(kind, url), url)

    def test_local_refuses_anything_not_loopback(self):
        for u in ["http://example.com:8080/v1", "http://192.168.1.5:11434/v1", "http://10.0.0.1:1234/",
                  "http://0.0.0.0:11434/", "http://localhost.evil.com:11434/", "http://127.0.0.1.evil.com:11434/",
                  "http://evil.com:11434/@127.0.0.1", "http://0x7f.1:11434/", "http://0x7f000001:11434/",
                  "http://2130706433:11434/", "http://017700000001:11434/", "http://127.1:11434/",
                  "http://localhost.:11434/", "http://[::ffff:127.0.0.1]:11434/", "http://[::2]:11434/",
                  "http://[2001:db8::1]:11434/", "http://127.0.0.1@evil.com:11434/", "http://:11434/",
                  "ftp://127.0.0.1:21/", "file:///etc/passwd", "ws://127.0.0.1:1/", "127.0.0.1:11434/v1",
                  "http://notlocalhost:11434/", "http://localhost%2eevil.com:11434/", "http://localhost\\@evil.com:1/"]:
            self.refused("local", u)

    def test_local_needs_an_explicit_valid_port(self):
        for u in ["http://127.0.0.1/v1", "http://127.0.0.1:0/", "http://127.0.0.1:65536/", "http://127.0.0.1:abc/",
                  "http://127.0.0.1:-1/", "https://localhost/v1"]:
            self.refused("local", u)

    def test_local_refuses_credentials_fragments_and_odd_text(self):
        for u in ["http://user:pass@127.0.0.1:1234/", "http://user@127.0.0.1:1234/", "http://127.0.0.1:1234/#x",
                  "http://127.0.0.1:1234/ x", "http://127.0.0.1:1234/\x00", "http://127.0.0.1:1234/\n", "http://１２７.0.0.1:1234/",
                  "", "http://127.0.0.1:1234/" + "a" * 3000]:
            self.refused("local", u)

    def test_local_allows_loopback_forms(self):
        for u in ["http://127.0.0.1:11434/v1/chat/completions", "http://localhost:1234/v1/chat/completions",
                  "http://LOCALHOST:1234/v1", "http://127.5.6.7:8080/v1", "http://[::1]:8080/v1",
                  "https://127.0.0.1:8443/v1", "https://localhost:8443/v1"]:
            self.allowed("local", u)

    def test_api_refuses_plain_http_loopback_ips_and_odd_hosts(self):
        for u in ["http://api.anthropic.com/v1/messages", "http://127.0.0.1:8080/v1", "https://127.0.0.1/v1",
                  "https://127.0.0.1:8443/v1", "https://localhost/v1", "https://localhost:8443/v1", "https://[::1]/v1",
                  "https://8.8.8.8/v1", "https://0x7f.1/v1", "https://2130706433/v1", "https://printer.local/v1",
                  "https://x.localhost/v1", "https://intranet.internal/v1", "https://api.example.com:8443/v1",
                  "https://api.example.com:80/v1", "https://user:pw@api.example.com/v1", "https://api.example.com@evil.com/v1",
                  "https://api.example.com/v1#frag", "https://api.example.com\\@evil.com/", "https://nodots/v1",
                  "ftp://api.example.com/", "api.example.com/v1", "https:///v1", "https://exa mple.com/v1", "https://api.example.com:/v1x\n"]:
            self.refused("api", u)

    def test_api_allows_https_dns_names_on_443(self):
        for u in ["https://api.anthropic.com/v1/messages", "https://api.openai.com/v1/chat/completions",
                  "https://gateway.example.org:443/v1/chat", "HTTPS://API.EXAMPLE.COM/v1"]:
            self.allowed("api", u)

    def test_unknown_kind_refused(self):
        self.refused("off", "http://127.0.0.1:1/")
        self.refused("both", "https://api.example.com/")

    def test_ask_enforces_the_policy_even_if_the_config_file_was_edited(self):
        op = FakeOpener()
        for cfg in (local_cfg("http://evil.com:80/v1"), local_cfg("http://127.0.0.1/v1"),
                    api_cfg(endpoint="http://api.example.com/v1"), api_cfg(endpoint="https://127.0.0.1/v1")):
            with self.assertRaises(A.AssistantError) as c:
                fw_ask(cfg, "", MSG, opener=op)
            self.assertEqual(c.exception.code, "refused")
        self.assertEqual(op.calls, 0)

    def test_off_and_incomplete_configs_are_not_configured_and_never_connect(self):
        op = FakeOpener()
        for cfg in (A.default_config(), {"active": "local", "local": {}, "api": {}},
                    {"active": "api", "local": {}, "api": {"provider": "anthropic", "model": "m"}},   # no key
                    {"active": "api", "local": {}, "api": {"provider": "evil", "model": "m", "key": "k"}}):
            with self.assertRaises(A.AssistantError) as c:
                fw_ask(cfg, "", MSG, opener=op)
            self.assertEqual(c.exception.code, "not-configured")
        self.assertEqual(op.calls, 0)


class TestTransportSafety(unittest.TestCase):
    def test_ssl_context_verifies_certificate_and_host_name(self):
        ctx = A.make_ssl_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        https = [h for h in A.make_opener().handlers if isinstance(h, urllib.request.HTTPSHandler)]
        self.assertEqual(len(https), 1)
        used = https[0]._context
        self.assertEqual((used.verify_mode, used.check_hostname), (ssl.CERT_REQUIRED, True))

    def test_the_opener_has_no_proxy_handler_and_refuses_redirects(self):
        op = A.make_opener()
        self.assertFalse([h for h in op.handlers if isinstance(h, urllib.request.ProxyHandler)])
        with mock.patch.dict(os.environ, {"http_proxy": "http://evil:1", "HTTP_PROXY": "http://evil:1"}):
            self.assertFalse([h for h in A.make_opener().handlers if isinstance(h, urllib.request.ProxyHandler)])

    def test_a_redirect_is_an_error_and_is_never_followed(self):
        target = Server(reply_json({"choices": [{"message": {"content": "followed!"}}]}))
        for status in (301, 302, 307, 308):
            def redirect(h, status=status):
                h.send_response(status); h.send_header("location", target.url); h.send_header("content-length", "0"); h.end_headers()
            s = Server(redirect)
            try:
                with self.assertRaises(A.AssistantError) as c:
                    fw_ask(local_cfg(s.url), "", MSG)
                self.assertIn(c.exception.code, A.ERRORS)
            finally:
                s.close()
        self.assertEqual(target.seen, [])          # the redirect target was never contacted
        target.close()

    def test_an_oversized_reply_is_refused(self):
        s = Server(reply_json(b"x" * (A.MAX_REPLY + 5000)))
        try:
            with self.assertRaises(A.AssistantError) as c:
                fw_ask(local_cfg(s.url), "", MSG)
            self.assertEqual(c.exception.code, "bad-reply")
        finally:
            s.close()

    def test_reply_control_characters_are_stripped(self):
        evil = "ok\x1b[2J\x1b]0;pwn\x07 line1\nline2\x00\x7f‮\u0085end\ttab"
        s = Server(reply_json({"choices": [{"message": {"content": evil}}]}))
        try:
            out = fw_ask(local_cfg(s.url), "", MSG)
        finally:
            s.close()
        self.assertNotRegex(out, r"[\x00-\x09\x0b-\x1f\x7f-\x9f‮]")
        self.assertIn("line1\nline2", out)
        self.assertTrue(out.startswith("ok"))

    def test_garbage_and_wrong_shapes_are_bad_reply(self):
        for body in (b"not json", b"{}", b'{"choices": []}', b'{"choices":[{"message":{"content":5}}]}', b"[1]"):
            s = Server(reply_json(body))
            try:
                with self.assertRaises(A.AssistantError) as c:
                    fw_ask(local_cfg(s.url), "", MSG)
                self.assertEqual(c.exception.code, "bad-reply")
            finally:
                s.close()

    def test_unreachable_and_http_errors_use_fixed_phrases(self):
        sock = socket.socket(); sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]; sock.close()
        with self.assertRaises(A.AssistantError) as c:
            fw_ask(local_cfg(f"http://127.0.0.1:{port}/v1"), "", MSG)
        self.assertEqual(c.exception.code, "unreachable")
        s = Server(reply_json({"error": "SECRET-SERVER-BODY"}, 500))
        try:
            with self.assertRaises(A.AssistantError) as c:
                fw_ask(local_cfg(s.url), "", MSG)
        finally:
            s.close()
        self.assertEqual((c.exception.code, str(c.exception)), ("refused", "refused"))
        self.assertNotIn("SECRET-SERVER-BODY", "".join(traceback.format_exception(c.exception)))

    def test_localhost_that_resolves_elsewhere_is_refused(self):
        op = FakeOpener()
        with mock.patch("kos.assistant._localhost_is_loopback", return_value=False):
            with self.assertRaises(A.AssistantError) as c:
                fw_ask(local_cfg("http://localhost:1234/v1"), "", MSG, opener=op)
        self.assertEqual((c.exception.code, op.calls), ("refused", 0))


class TestWireFormats(unittest.TestCase):
    def test_local_server_openai_format_end_to_end(self):
        s = Server(reply_json({"choices": [{"message": {"content": "Hello from the local model"}}]}))
        try:
            out = fw_ask(local_cfg(s.url, "llama3"), "be brief", [{"role": "user", "content": "hi"}])
        finally:
            s.close()
        self.assertEqual(out, "Hello from the local model")
        path, headers, body = s.seen[0]
        sent = json.loads(body)
        self.assertEqual(sent["model"], "llama3")
        self.assertEqual(sent["messages"][0], {"role": "system", "content": "be brief"})
        self.assertNotIn("authorization", {k.lower() for k in headers})    # no key goes to a local server

    def test_anthropic_format_end_to_end_through_a_loopback_stand_in(self):
        s = Server(reply_json({"content": [{"type": "text", "text": "Hel"}, {"type": "tool_use"}, {"type": "text", "text": "lo"}]}))

        class Redirecting:                # the https URL is policy-checked; the bytes go to the loopback test server
            def open(self, req, timeout=None):
                r = urllib.request.Request(s.url, data=req.data, headers=dict(req.header_items()), method="POST")
                return A.make_opener().open(r, timeout=timeout)
        try:
            out = fw_ask(api_cfg("anthropic"), "sys", [{"role": "user", "content": "hi"}], opener=Redirecting())
        finally:
            s.close()
        self.assertEqual(out, "Hello")
        _, headers, body = s.seen[0]
        h = {k.lower(): v for k, v in headers.items()}
        self.assertEqual(h["x-api-key"], KEY)
        sent = json.loads(body)
        self.assertEqual((sent["system"], sent["max_tokens"], sent["messages"]), ("sys", A.MAX_TOKENS, [{"role": "user", "content": "hi"}]))

    def test_openai_api_format_sends_a_bearer_key(self):
        op = FakeOpener()
        self.assertEqual(fw_ask(api_cfg("openai", "https://api.example.com/v1/chat/completions"), "s", MSG, opener=op), "hi there")
        req = op.reqs[0]
        self.assertEqual(req.get_header("Authorization"), "Bearer " + KEY)
        self.assertEqual(json.loads(req.data)["messages"][0]["role"], "system")


# ================================================================= protocol ====
def request(**kw):
    return {"cmd": "request", "action": "assistant", **kw}


class TestAssistantProtocol(unittest.TestCase):
    def bad(self, msg):
        for mode in ("tui", "cmd"):
            with self.assertRaises(ProtocolError, msg=str(msg)[:80]):
                validate_app_message(msg, mode)

    def test_the_accepted_shape(self):
        out = validate_app_message(request(system="be kind\x1b[2J", messages=[
            {"role": "user", "content": "hi\x00 there\nline2"}, {"role": "assistant", "content": "yo"}]), "tui")
        self.assertEqual(out["system"], "be kind[2J")
        self.assertEqual(out["messages"][0], {"role": "user", "content": "hi there\nline2"})
        self.assertEqual(validate_app_message(request(messages=[{"role": "user", "content": "x"}]), "cmd")["system"], "")

    def test_hostile_payloads_are_rejected(self):
        ok = {"role": "user", "content": "x"}
        for msg in [request(), request(messages=[]), request(messages="hi"), request(messages={"role": "user"}),
                    request(messages=[ok] * 21), request(messages=[ok], system=5), request(messages=[ok], system="a" * 2001),
                    request(messages=[{"role": "user", "content": "a" * 4001}]),
                    request(messages=[{"role": "user", "content": "a" * 4000}] * 7),         # 28000 > 24000
                    request(messages=[{"role": "system", "content": "x"}]), request(messages=[{"role": "tool", "content": "x"}]),
                    request(messages=[{"role": "User", "content": "x"}]), request(messages=[{"role": 1, "content": "x"}]),
                    request(messages=[{"role": "user", "content": 5}]), request(messages=[{"role": "user", "content": None}]),
                    request(messages=[{"role": "user"}]), request(messages=[{"content": "x"}]),
                    request(messages=[{"role": "user", "content": "x", "extra": 1}]),
                    request(messages=[ok], model="gpt"), request(messages=[ok], endpoint="http://evil"), request(messages=[ok], key="k"),
                    request(messages=["hi"]), request(messages=[None]), request(messages=[ok], id=1)]:
            self.bad(msg)

    def test_the_limits_themselves_are_accepted(self):
        validate_app_message(request(system="s" * 2000, messages=[{"role": "user", "content": "a" * 4000}] * 6), "tui")
        validate_app_message(request(messages=[{"role": "user", "content": "x"}] * 20), "tui")

    def test_other_request_shapes_still_work(self):
        self.assertEqual(validate_app_message({"cmd": "request", "action": "apps"}, "tui")["action"], "apps")

    def test_the_permission_is_a_manifest_permission_and_a_typo_is_not(self):
        base = {"name": "x", "version": "1", "runtime": "python", "entry": "a:main"}
        self.assertEqual(Manifest.parse(json.dumps({**base, "permissions": ["storage", "assistant"]}).encode()).permissions, ("storage", "assistant"))
        for bad in ("assistants", "Assistant", "assist"):
            with self.assertRaises(KAppError):
                Manifest.parse(json.dumps({**base, "permissions": [bad]}).encode())

    def test_actions_exist(self):
        self.assertIn("assistant.config", ACTIONS)
        self.assertIn("assistant.ask", ACTIONS)


# ================================================================= the bridge ====
class TestAssistantBridge(Env):
    def setUp(self):
        super().setUp()
        A.set_local(self.paths, "http://127.0.0.1:11434/v1/chat/completions", "llama3")
        A.use(self.paths, "local")
        self.out, self.op = [], FakeOpener()

    def bridge(self, **kw):
        kw = {"app": "notes", "system": False, "assistant": True, "opener": self.op, **kw}
        return SystemBridge(self.paths, **kw)

    def ask(self, bridge, *answers, messages=MSG):
        tgt = A.firewall_target(A.load(self.paths))      # these tests are about the password/grant; the rule is allowed
        if tgt:                                          # (a missing rule is tested in test_firewall.py)
            F.add_rule(self.paths, "os:assistant", *tgt)
        bridge.handle(validate_app_message(request(system="s", messages=messages), "tui"), self.out.append, self.authority(*answers))
        return self.out[-1]

    def test_an_app_without_the_permission_is_refused_and_nothing_connects(self):
        r = self.ask(self.bridge(assistant=False, system=True))
        self.assertEqual(r, {"cmd": "assistant", "ok": False, "error": "refused"})
        self.assertEqual(self.op.calls, 0)
        self.assertIn("notes -", self.audit_text())        # logged as a refusal

    def test_a_session_with_no_bridge_refuses(self):
        sent = []
        fake = types.SimpleNamespace(bridge=None, _send=sent.append)
        Session._on_request(fake, validate_app_message(request(messages=MSG), "tui"))
        self.assertEqual(sent, [{"cmd": "assistant", "ok": False, "error": "refused"}])

    def test_an_app_with_only_assistant_cannot_use_any_other_request(self):
        b = self.bridge()
        for req in ({"cmd": "request", "action": "apps"}, {"cmd": "request", "action": "open", "app": "hello", "mode": "tui"},
                    {"cmd": "request", "action": "close", "id": "hello-abcdef"}, {"cmd": "request", "action": "focus", "id": "hello-abcdef"},
                    {"cmd": "request", "action": "backup"}, {"cmd": "request", "action": "backup_add", "path": "/etc"},
                    {"cmd": "request", "action": "backup_remove", "id": "0" * 12}):
            sw = b.handle(req, self.out.append, self.authority())      # no answers: any password prompt would fail the test
            self.assertIsNone(sw)
            self.assertFalse(self.out[-1]["ok"], req)
            self.assertIn("'system' permission", self.out[-1]["detail"])
        self.assertEqual(self.op.calls, 0)

    def test_a_system_only_app_cannot_use_the_assistant(self):
        self.assertEqual(self.ask(self.bridge(system=True, assistant=False))["error"], "refused")
        self.assertEqual(self.op.calls, 0)

    def test_no_password_means_no_network_call_at_all(self):
        for answers in ([None], ["no", "no", "no"], [b""] * 3):
            self.out.clear()
            r = self.ask(self.bridge(), *answers)
            self.assertEqual(r, {"cmd": "assistant", "ok": False, "error": "refused"})
        self.assertEqual(self.op.calls, 0)

    def test_a_refusal_is_remembered_so_an_app_cannot_nag(self):
        b = self.bridge()
        self.assertEqual(self.ask(b, None)["error"], "refused")
        self.assertEqual(self.ask(b)["error"], "refused")       # no prompt (no answers were given)
        self.assertEqual(self.op.calls, 0)

    def test_not_configured_asks_nothing_and_connects_nowhere(self):
        A.use(self.paths, "off")
        r = self.ask(self.bridge())
        self.assertEqual(r, {"cmd": "assistant", "ok": False, "error": "not-configured"})
        self.assertEqual((self.op.calls, self.prompter.asked), (0, []))

    def test_with_the_password_the_app_gets_text_and_the_grant_lasts_for_the_instance(self):
        b = self.bridge()
        r = self.ask(b, PW)
        self.assertEqual(r, {"cmd": "assistant", "ok": True, "text": "hi there"})
        self.assertEqual(self.prompter.asked, [f"Password to let an app use the assistant 'notes (local)': "])
        self.assertEqual(self.ask(b)["ok"], True)               # second ask in the same instance: no prompt
        self.assertEqual(self.op.calls, 2)
        # a new instance of the app (a new bridge) is asked again
        b2 = self.bridge()
        self.assertEqual(self.ask(b2, None)["error"], "refused")  # asked again (cancelled here)
        self.assertEqual(self.ask(self.bridge(), PW)["ok"], True)

    def test_switching_the_backend_mid_instance_asks_again(self):
        b = self.bridge()
        self.assertTrue(self.ask(b, PW)["ok"])
        A.set_local(self.paths, "http://127.0.0.1:9999/v1/chat/completions", "other")
        r = self.ask(b, PW)                                     # new endpoint -> new password
        self.assertTrue(r["ok"])
        self.assertEqual(len(self.prompter.asked), 1)

    def test_failures_are_short_fixed_phrases_and_audited(self):
        b = self.bridge(opener=FakeOpener(exc=OSError("boom SECRET-MESSAGE-TEXT")))
        r = self.ask(b, PW)
        self.assertEqual(r, {"cmd": "assistant", "ok": False, "error": "unreachable"})
        b = self.bridge(opener=FakeOpener(body=b"junk"))
        self.assertEqual(self.ask(b, PW)["error"], "bad-reply")

    def test_audit_has_app_and_kind_but_never_message_text_or_key(self):
        A.set_api(self.paths, "openai", "https://api.example.com/v1/chat/completions", "m", KEY)
        A.use(self.paths, "api")
        b = self.bridge()
        self.assertTrue(self.ask(b, PW)["ok"])
        b2 = self.bridge(opener=FakeOpener(exc=OSError(KEY)))
        self.assertEqual(self.ask(b2, PW)["error"], "unreachable")
        log = self.audit_text()
        self.assertIn('"action":"assistant.ask"', log)
        self.assertIn('"target":"notes api"', log)
        for outcome in ("granted", "allowed", "failed:unreachable"):
            self.assertIn(outcome, log)
        # the host:port IS now logged (firewall.connect, by design); the URL path, message and key never are
        for secret in (KEY, "SECRET-MESSAGE-TEXT", "/v1/chat/completions"):
            self.assertNotIn(secret, log)
        self.assertIn("os:assistant api.example.com:443 https", log)

    def test_the_key_never_leaves_in_an_error_a_reply_or_a_traceback(self):
        s = Server(reply_json({"error": "bad key " + KEY}, 401))
        cfg = api_cfg("openai", "https://api.example.com/v1/chat/completions")
        seen = []

        class Redirecting:
            def open(self, req, timeout=None):
                r = urllib.request.Request(s.url, data=req.data, headers=dict(req.header_items()), method="POST")
                return A.make_opener().open(r, timeout=timeout)
        try:
            with self.assertRaises(A.AssistantError) as c:
                fw_ask(cfg, "", MSG, opener=Redirecting())
        finally:
            s.close()
        seen += [str(c.exception), repr(c.exception), "".join(traceback.format_exception(c.exception))]
        for op in (FakeOpener(exc=OSError(KEY)), FakeOpener(exc=ValueError(KEY)), FakeOpener(body=KEY.encode())):
            with self.assertRaises(A.AssistantError) as c:
                fw_ask(cfg, "", MSG, opener=op)
            seen += [str(c.exception), repr(c.exception), "".join(traceback.format_exception(c.exception))]
        for e in ("", "http://u:" + KEY + "@127.0.0.1:1/", "http://" + KEY + ".evil.com:80/"):
            with self.assertRaises(A.PolicyError) as c:
                A.check_endpoint("api", e) if e == "" else A.check_endpoint("local", e)
            seen += [str(c.exception)]
        self.assertFalse([t for t in seen if KEY in t])


# ======================================================================= config ====
class TestConfigFile(Env):
    def test_default_is_off_and_status_hides_nothing_it_should_not(self):
        self.assertEqual(A.load(self.paths)["active"], "off")
        self.assertEqual(A.status(self.paths)["active"], "off")

    def test_file_is_mode_0600_even_if_an_old_one_was_looser(self):
        A.set_api(self.paths, "anthropic", "", "claude-x", KEY)
        f = A.config_path(self.paths)
        self.assertEqual(f.stat().st_mode & 0o777, 0o600)
        os.chmod(f, 0o644)
        A.use(self.paths, "api")
        self.assertEqual(f.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(f.read_text())["active"], "api")

    def test_bad_endpoints_are_refused_at_set_time_and_nothing_is_saved(self):
        with self.assertRaises(A.PolicyError): A.set_local(self.paths, "http://example.com:80/v1", "m")
        with self.assertRaises(A.PolicyError): A.set_api(self.paths, "openai", "http://api.example.com/v1", "m", KEY)
        with self.assertRaises(A.ConfigError): A.set_api(self.paths, "mystery", "", "m", KEY)
        with self.assertRaises(A.ConfigError): A.set_api(self.paths, "openai", "", "m", "")
        with self.assertRaises(A.ConfigError): A.set_api(self.paths, "openai", "", "m", "k\x1b[2J")
        with self.assertRaises(A.ConfigError): A.set_local(self.paths, "http://127.0.0.1:1/v1", "bad model!")
        self.assertFalse(A.config_path(self.paths).exists())

    def test_use_refuses_an_unset_backend(self):
        for kind in ("local", "api", "nope"):
            with self.assertRaises(A.ConfigError): A.use(self.paths, kind)

    def test_a_damaged_or_hostile_file_fails_closed_to_off(self):
        self.paths.state.mkdir(parents=True, exist_ok=True)
        for text in ("{not json", "[]", json.dumps({"active": "evil"}), json.dumps({"active": 5})):
            A.config_path(self.paths).write_text(text)
            self.assertEqual(A.load(self.paths)["active"], "off")

    def test_status_never_shows_the_key(self):
        A.set_api(self.paths, "anthropic", "", "claude-x", KEY)
        A.use(self.paths, "api")
        s = A.status(self.paths)
        self.assertTrue(s["key_set"])
        self.assertEqual(s["endpoint_host"], "api.anthropic.com")
        self.assertNotIn(KEY, json.dumps(s))


# ========================================================================= CLI ====
class TestAssistantCLI(Env):
    def run_cli(self, argv, *answers, opener=None):
        out, err = io.StringIO(), io.StringIO()
        auth = self.authority(*answers)
        with mock.patch.dict(os.environ, {"KOS_ROOT": self.tmp.name}), \
                mock.patch("kos.cli._authority", return_value=(auth, self.prompter)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            if opener:
                with mock.patch("kos.assistant.make_opener", return_value=opener):
                    code = kcli.main(argv)
            else:
                code = kcli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_status_needs_no_password_and_never_prints_the_key(self):
        A.set_api(self.paths, "anthropic", "", "claude-x", KEY)
        A.use(self.paths, "api")
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"KOS_ROOT": self.tmp.name}), \
                mock.patch("kos.cli._authority", side_effect=AssertionError("status must not ask for a password")), \
                mock.patch("kos.cli.Authority", side_effect=AssertionError("no password")), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = kcli.main(["assistant", "status"])
        self.assertEqual(code, 0)
        self.assertIn("api.anthropic.com", out.getvalue())
        self.assertIn("api key   : set", out.getvalue())
        self.assertNotIn(KEY, out.getvalue() + err.getvalue())

    def test_status_when_off(self):
        code, out, _ = self.run_cli(["assistant", "status"])
        self.assertEqual(code, 0)
        self.assertIn("off", out)
        self.assertEqual(self.prompter.asked, [])

    def test_use_set_and_test_need_the_password(self):
        A.set_local(self.paths, "http://127.0.0.1:11434/v1/chat/completions", "m")
        for argv in (["assistant", "use", "local"],
                     ["assistant", "set", "local", "--endpoint", "http://127.0.0.1:1234/v1", "--model", "x"],
                     ["assistant", "set", "api", "--provider", "openai", "--model", "x"],
                     ["assistant", "test"]):
            before = A.config_path(self.paths).read_text()
            op = FakeOpener()
            code, out, _ = self.run_cli(argv, "wrong", "wrong", "wrong", opener=op)
            self.assertEqual(code, 2, argv)
            self.assertEqual(A.config_path(self.paths).read_text(), before, argv)
            self.assertEqual(op.calls, 0, argv)
            self.assertNotIn("api key (typed", "".join(self.prompter.asked).lower())

    def test_use_and_set_local_with_the_password(self):
        code, out, _ = self.run_cli(["assistant", "set", "local", "--endpoint", "http://127.0.0.1:11434/v1/chat/completions", "--model", "llama3"], PW)
        self.assertEqual(code, 0)
        code, out, _ = self.run_cli(["assistant", "use", "local"], PW)
        self.assertEqual(A.load(self.paths)["active"], "local")
        code, out, _ = self.run_cli(["assistant", "use", "off"], PW)
        self.assertEqual(A.load(self.paths)["active"], "off")

    def test_set_refuses_a_bad_endpoint_before_asking_for_anything(self):
        for argv in (["assistant", "set", "local", "--endpoint", "http://example.com:80/v1", "--model", "m"],
                     ["assistant", "set", "api", "--provider", "openai", "--endpoint", "http://api.example.com/v1", "--model", "m"],
                     ["assistant", "set", "api", "--provider", "openai", "--endpoint", "https://127.0.0.1/v1", "--model", "m"]):
            code, out, err = self.run_cli(argv)               # no answers: any prompt would raise
            self.assertEqual(code, 2, argv)
            self.assertIn("refused:", err)
            self.assertEqual(self.prompter.asked, [])
        self.assertFalse(A.config_path(self.paths).exists())

    def test_the_api_key_comes_from_a_hidden_prompt_not_argv_or_the_environment(self):
        with mock.patch.dict(os.environ, {"KOS_ASSISTANT_KEY": "from-env", "ANTHROPIC_API_KEY": "from-env2"}):
            code, out, err = self.run_cli(["assistant", "set", "api", "--provider", "anthropic", "--model", "claude-x"], PW, KEY)
        self.assertEqual(code, 0)
        self.assertEqual(A.load(self.paths)["api"]["key"], KEY)
        self.assertEqual(len(self.prompter.asked), 2)
        self.assertNotIn(KEY, out + err)
        self.assertEqual(A.config_path(self.paths).stat().st_mode & 0o777, 0o600)
        self.assertFalse([a for a in kcli.build_parser()._actions if "key" in str(getattr(a, "option_strings", ""))])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.run_cli(["assistant", "set", "api", "--provider", "anthropic", "--model", "m", "--key", "x"])   # no --key option

    def test_test_sends_one_fixed_message_and_reports_ok_or_the_phrase(self):
        A.set_local(self.paths, "http://127.0.0.1:11434/v1/chat/completions", "m"); A.use(self.paths, "local")
        op = FakeOpener()
        code, out, _ = self.run_cli(["assistant", "test"], PW, opener=op)
        self.assertEqual((code, op.calls), (1, 0))      # no firewall rule yet: blocked, nothing connected
        self.assertIn("firewall", out)
        F.add_rule(self.paths, "os:assistant", "127.0.0.1", 11434, "loopback")
        code, out, _ = self.run_cli(["assistant", "test"], PW, opener=op)
        self.assertEqual((code, op.calls), (0, 1))
        self.assertIn("ok", out)
        code, out, _ = self.run_cli(["assistant", "test"], PW, opener=FakeOpener(body=b"junk"))
        self.assertEqual(code, 1)
        self.assertIn("error: bad-reply", out)

    def test_every_assistant_command_is_listed_by_help(self):
        self.assertIn("assistant", kcli.COMMANDS)


# =============================================================== SDK / the app ====
class TestSdkAndAgent(unittest.TestCase):
    def test_sdk_round_trip_and_keeps_unrelated_events(self):
        a, b = socket.socketpair()
        app = App(a)
        b.sendall(b'{"cmd":"key","key":"x"}\n{"cmd":"assistant","ok":true,"text":"yes"}\n')
        self.assertEqual(app.assistant("s", [{"role": "user", "content": "q"}]), (True, "yes"))
        sent = json.loads(b.recv(65536).split(b"\n")[0])
        self.assertEqual((sent["cmd"], sent["action"]), ("request", "assistant"))
        self.assertEqual(next(app.events())["key"], "x")          # the key event was not lost
        b.sendall(b'{"cmd":"assistant","ok":false,"error":"not-configured"}\n')
        self.assertEqual(app.assistant("", [{"role": "user", "content": "q"}]), (False, "not-configured"))
        b.sendall(b'{"cmd":"assistant","ok":true,"text":5}\n')
        self.assertEqual(app.assistant("", [{"role": "user", "content": "q"}])[0], False)
        b.close()
        self.assertEqual(app.assistant("", [{"role": "user", "content": "q"}]), (False, "unreachable"))

    def agent(self, fn=None, data=None):
        from kos.office.agent import Agent
        from kos.office.ui import FakeHost
        h = FakeHost([], data=data)
        h.assistant_fn = fn
        return Agent(h, "Notes", "A notes app."), h

    def say(self, ag, text):
        for ch in text: ag.key(ch)
        ag.key("enter")

    def test_default_host_says_not_configured(self):
        from kos.office.ui import FakeHost
        self.assertEqual(FakeHost([]).assistant("", []), (False, "not-configured"))

    def test_when_the_os_answers_the_agent_uses_it(self):
        ag, h = self.agent(lambda s, m: (True, "model says hi"))
        self.say(ag, "hello")
        self.assertEqual(ag.hist[-1], ["ai", "model says hi"])
        self.assertEqual(len(h.assistant_calls), 1)

    def test_the_model_never_sees_the_apps_data(self):
        ag, h = self.agent(lambda s, m: (True, "ok"), data={"contact-1": "TOPSECRET-DATA Ann 555-0100", "note": "TOPSECRET-DATA more"})
        self.say(ag, "/remember buy milk")
        self.say(ag, "what is TOPSECRET-DATA?")
        self.say(ag, "and what about Ann?")
        self.assertTrue(h.assistant_calls)
        blob = json.dumps(h.assistant_calls)
        self.assertNotIn("555-0100", blob)
        self.assertNotIn("contact-1", blob)
        self.assertIn("buy milk", blob)                           # the /remember notes are sent
        for system, msgs in h.assistant_calls:
            self.assertLessEqual(len(system), 2000)
            self.assertLessEqual(len(msgs), 20)
            validate_app_message(request(system=system, messages=msgs), "tui")   # always a valid request

    def test_when_the_os_refuses_one_line_then_local_tools(self):
        ag, h = self.agent(lambda s, m: (False, "not-configured"), data={"note": "Ann lives in Paris"})
        self.say(ag, "Ann Paris")
        reply = ag.hist[-1][1]
        self.assertTrue(reply.startswith("No assistant is set up"))
        self.assertIn("kos assistant", reply.splitlines()[0])
        self.assertIn("From this app's data", reply)              # local tools still answered
        self.say(ag, "Ann Paris")                                 # told once, not on every message
        self.assertFalse(ag.hist[-1][1].startswith("No assistant"))
        ag2, _ = self.agent(lambda s, m: (False, "refused"))
        self.say(ag2, "hello")
        self.assertIn("did not allow", ag2.hist[-1][1].splitlines()[0])

    def test_a_host_that_raises_is_not_fatal_and_slash_commands_never_ask_the_model(self):
        def boom(s, m): raise RuntimeError("x")
        ag, h = self.agent(boom)
        self.say(ag, "hello")
        self.assertIn("local tools", ag.hist[-1][1])
        self.say(ag, "/calc 1+2")
        self.assertEqual(len(h.assistant_calls), 1)               # only the first one asked

    def test_ctrl_l_explains_kos_assistant_and_shows_nothing_secret(self):
        ag, _ = self.agent()
        act = ag.key("ctrl-l")
        self.assertEqual(act[0], "push")
        text = "\n".join(act[1].render(80, 24))
        self.assertIn("kos assistant", text)
        self.assertNotRegex(text, r"sk-|key\s*:")

    def test_every_suite_app_manifest_declares_the_assistant_permission(self):
        from suite.gen import every, manifest
        n = 0
        for e in every():
            if e.scope == "none": continue
            n += 1
            self.assertIn("assistant", manifest(e)["permissions"], e.name)
            self.assertNotIn("system", manifest(e)["permissions"], e.name)
        self.assertGreater(n, 100)


if __name__ == "__main__":
    unittest.main()
