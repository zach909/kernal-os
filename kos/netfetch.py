"""The one place an app's network request is made - by the OS, never by the app.

An app never gets a network. It sends ``request fetch {url, method, headers, body}`` (protocol.py);
if its manifest declares ``network`` the OS calls :func:`fetch`, which

1. parses the URL strictly: ``https://`` only, no user name or password, no fragment, no backslash,
   a host that is a DNS name or an IP literal, port 443 unless the URL names one;
2. asks :func:`kos.firewall.decide` (``app:NAME``, host, port, ``https``). If that says no, NOTHING is
   connected: the app gets ``blocked``. The decision (either way) is in the audit log, without the
   path, query, headers, body or any key;
3. connects itself with the default SSL context - certificate AND host name verified, no off switch,
   no proxy from the environment, **no redirects** (a 3xx is the error ``redirect``, so an encrypted
   request can never be bounced to plain http), 60 s in total, the reply capped at 4 MiB.

Errors are short fixed phrases (:data:`ERRORS`); never the server's text, the URL or a header.
No password is asked per request: the password was typed when the owner created the rule.

Not covered: the machine's trust store (``SSL_CERT_FILE`` and the system CA bundle decide which
certificates verify) and name resolution (a DNS name is resolved by the OS resolver; the rule names the
host, not an address).
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import ssl
import time
from typing import Optional

from . import firewall
from .paths import Paths

ERRORS = ("blocked", "refused", "unreachable", "redirect", "too-big", "bad-url")
METHODS = ("GET", "POST")
HEADER_NAMES = ("accept", "content-type", "authorization", "x-api-key", "anthropic-version", "user-agent")
MAX_URL = 2048
MAX_HEADERS = len(HEADER_NAMES)
MAX_HEADER_VALUE = 512
MAX_BODY = 262144
MAX_REPLY = 4 << 20
TIMEOUT = 60.0

_URL_OK = re.compile(r"[\x21-\x7e]+")            # printable ASCII, no space: no unicode hosts, no control chars
_HDR_VALUE_OK = re.compile(r"[\x20-\x7e]*")
_PORT_RE = re.compile(r"[0-9]{1,5}")


class FetchError(Exception):
    def __init__(self, code: str):
        assert code in ERRORS
        super().__init__(code)
        self.code = code


def parse_url(url: object) -> tuple[str, int, str]:
    """(host, port, request target) or FetchError('bad-url'). The host is canonical lower case."""
    bad = FetchError("bad-url")
    if not isinstance(url, str) or not 1 <= len(url) <= MAX_URL or not _URL_OK.fullmatch(url):
        raise bad
    if not url.startswith("https://") or "#" in url or "\\" in url:
        raise bad
    rest = url[len("https://"):]
    cut = min((i for i in (rest.find("/"), rest.find("?")) if i >= 0), default=len(rest))
    authority, target = rest[:cut], rest[cut:]
    if not authority or "@" in authority or "%" in authority:
        raise bad
    if authority.startswith("["):                  # [IPv6]:port
        end = authority.find("]")
        if end < 0:
            raise bad
        host, tail = authority[1:end], authority[end + 1:]
        if tail and not tail.startswith(":"):
            raise bad
        port_s = tail[1:] if tail else ""
        try:
            if ipaddress.ip_address(host).version != 6:
                raise bad
        except ValueError:
            raise bad from None
    else:
        host, sep, port_s = authority.partition(":")
        if sep and not port_s:
            raise bad
        if ":" in port_s:
            raise bad
    if port_s and not _PORT_RE.fullmatch(port_s):
        raise bad
    port = int(port_s) if port_s else 443
    if not 1 <= port <= 65535:
        raise bad
    h = firewall.parse_host(host)
    if h is None or h != host.lower():             # not a name, or not the canonical spelling of an address
        raise bad
    if not target:
        target = "/"
    elif target.startswith("?"):
        target = "/" + target
    return h, port, target


def check_headers(headers: object) -> dict:
    """The headers as {lower-case name: value}, or FetchError('bad-url'). Names are allow-listed."""
    if headers is None:
        return {}
    if not isinstance(headers, dict) or len(headers) > MAX_HEADERS:
        raise FetchError("bad-url")
    out = {}
    for k, v in headers.items():
        name = k.lower() if isinstance(k, str) else ""
        if name not in HEADER_NAMES or name in out:
            raise FetchError("bad-url")
        if not isinstance(v, str) or len(v) > MAX_HEADER_VALUE or not _HDR_VALUE_OK.fullmatch(v):
            raise FetchError("bad-url")
        out[name] = v
    return out


def make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()             # CERT_REQUIRED + check_hostname
    if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:
        raise RuntimeError("TLS verification is off")
    return ctx


def fetch(paths: Paths, who: str, url: object, method: object = "GET", headers: object = None,
          body: object = "", *, context: Optional[ssl.SSLContext] = None) -> dict:
    """One brokered request. Returns {"status": int, "content_type": str, "body": bytes} or raises
    FetchError. ``context`` is a TEST hook (so a test can trust only its own certificate); it must still
    verify certificates and host names, and production callers never pass it."""
    if method not in METHODS:
        raise FetchError("bad-url")
    hdrs = check_headers(headers)
    if not isinstance(body, str) or len(body) > MAX_BODY or (body and method != "POST"):
        raise FetchError("bad-url")
    host, port, target = parse_url(url)
    if not firewall.decide(paths, who, host, port, "https"):
        raise FetchError("blocked")                # nothing has been connected
    ctx = context if context is not None else make_ssl_context()
    if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:
        raise FetchError("refused")
    deadline = time.monotonic() + TIMEOUT
    hdrs.setdefault("user-agent", "kos-fetch/1")
    hdrs["accept-encoding"] = "identity"
    hdrs["connection"] = "close"
    data = body.encode("utf-8") if body else None
    conn = None
    code = ""
    result: dict = {}
    try:
        conn = http.client.HTTPSConnection(host, port, timeout=10.0, context=ctx)   # no proxy: http.client never reads one
        conn.request(method, target, body=data, headers=hdrs)
        resp = conn.getresponse()
        if 300 <= resp.status < 400:
            code = "redirect"
        else:
            declared = resp.getheader("content-length")
            if declared is not None and declared.isdigit() and int(declared) > MAX_REPLY:
                code = "too-big"
            else:
                buf = bytearray()
                while len(buf) <= MAX_REPLY:
                    left = deadline - time.monotonic()
                    if left <= 0:
                        code = "unreachable"
                        break
                    conn.sock.settimeout(min(10.0, left))
                    chunk = resp.read(min(65536, MAX_REPLY + 1 - len(buf)))
                    if not chunk:
                        break
                    buf += chunk
                if not code and len(buf) > MAX_REPLY:
                    code = "too-big"
                if not code:
                    ct = resp.getheader("content-type") or ""
                    result = {"status": int(resp.status), "content_type": re.sub(r"[^\x20-\x7e]", "", ct)[:100],
                              "body": bytes(buf)}
    except ssl.SSLError:
        code = "refused"
    except (OSError, http.client.HTTPException, ValueError, AttributeError):
        code = "unreachable"
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    if code:
        raise FetchError(code)                     # raised outside the except block: no chained cause
    return result
