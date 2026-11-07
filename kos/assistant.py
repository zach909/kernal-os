"""The swappable assistant: the OS makes the model connection, never the app.

Every suite app has a built-in assistant (Ctrl-N). Its backend is chosen by the owner:

* ``off``   (the default) the app's built-in offline tools only
* ``local`` a model on this computer (Ollama, llama.cpp, LM Studio: OpenAI-compatible chat)
* ``api``   someone else's model over https (Anthropic Messages or OpenAI-compatible chat)

Apps get NO network for this. An app with the ``assistant`` permission sends a ``request``
(see protocol.py); the OS password-gates it once per app instance, audits it, and makes the
one connection itself, through the policy below. The policy is code, not configuration:

* ``local``: http or https, to a loopback address only (127.0.0.0/8, ::1 or the literal host
  ``localhost``), on an explicit port. Anything else (a name that merely *starts* with
  localhost, a numeric trick such as ``0x7f.1``) is refused.
* ``api``: https only, to a DNS name (never an IP address, never ``localhost``) on port 443,
  with the default SSL context: certificate AND host name verified, no off switch.
* no redirects at all (a redirect is an error, so encrypted -> plain cannot happen);
  no proxy from the environment; replies capped at 1 MiB; 60 s in total.
* errors are short fixed phrases. Never the API key, the request or the server's reply.

Gap (README): the key is stored unencrypted in ``<state>/assistant.json`` (mode 0600)
because KOS has no encryption at rest yet. Use a key you can revoke.

Standard library only. This module deliberately does not import kos.office.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from .paths import Paths, atomic_write

KINDS = ("off", "local", "api")
PROVIDERS = ("anthropic", "openai")
DEFAULT_ENDPOINTS = {"anthropic": "https://api.anthropic.com/v1/messages",
                     "openai": "https://api.openai.com/v1/chat/completions"}
MAX_REPLY = 1 << 20
TIMEOUT = 60.0
MAX_TOKENS = 1024
ERRORS = ("not-configured", "refused", "unreachable", "bad-reply")

# Control characters, C1 and bidi overrides are dropped; newline stays (a reply has paragraphs),
# tab becomes a space.
_CONTROL_RE = re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")
_URL_OK = re.compile(r"^[\x21-\x7e]+$")      # printable ASCII, no spaces: no unicode hosts
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class AssistantError(Exception):
    """What the OS tells an app: ``code`` is one of ERRORS, and the text is that fixed phrase."""

    def __init__(self, code: str):
        assert code in ERRORS
        super().__init__(code)
        self.code = code


class PolicyError(Exception):
    """An endpoint the policy refuses. The message is for the owner at ``set`` time and never
    echoes the URL (it may carry credentials)."""


class ConfigError(Exception):
    pass


# ------------------------------------------------------------- endpoint policy ----
def check_endpoint(kind: str, url: str) -> str:
    """Return ``url`` if the policy allows it for ``kind`` ('local' or 'api'), else PolicyError."""
    if kind not in ("local", "api"):
        raise PolicyError("kind must be local or api")
    if not isinstance(url, str) or not url or len(url) > 2048 or not _URL_OK.match(url):
        raise PolicyError("the endpoint must be a plain ASCII URL")
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        raise PolicyError("the endpoint is not a valid URL") from None
    if "@" in p.netloc or p.username is not None or p.password is not None:
        raise PolicyError("the endpoint must not contain a user name or password")
    if "#" in url or "\\" in url:
        raise PolicyError("the endpoint must not contain a fragment or a backslash")
    scheme, host = p.scheme.lower(), p.hostname or ""
    if not host:
        raise PolicyError("the endpoint has no host")
    if kind == "api":
        if scheme != "https":
            raise PolicyError("an API endpoint must be https (never plain http)")
        if port not in (None, 443):
            raise PolicyError("an API endpoint must use port 443")
        h = host.lower()
        if not _HOST_RE.match(h) or h.endswith((".localhost", ".local", ".internal", ".lan")):
            raise PolicyError("an API endpoint must be a public DNS name (not an IP address or a local name)")
        return url
    if scheme not in ("http", "https"):
        raise PolicyError("a local endpoint must be http or https")
    if port is None or port < 1:
        raise PolicyError("a local endpoint needs an explicit port, e.g. http://127.0.0.1:11434/v1/chat/completions")
    if host.lower() != "localhost":
        try:
            ip = ipaddress.ip_address(host)       # strict: 0x7f.1 and 2130706433 are not addresses here
        except ValueError:
            raise PolicyError("a local endpoint must be 127.0.0.1, ::1 or localhost on this computer") from None
        if not ((ip.version == 4 and ip.is_loopback) or ip == ipaddress.IPv6Address("::1")):
            raise PolicyError("a local endpoint must be 127.0.0.1, ::1 or localhost on this computer")
    return url


def _localhost_is_loopback(host: str, port: int) -> bool:
    """The literal name ``localhost`` is only trusted while it resolves to loopback addresses."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return bool(infos) and all(ipaddress.ip_address(i[4][0]).is_loopback for i in infos)
    except (OSError, ValueError):
        return False


# --------------------------------------------------------------------- opener ----
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        raise urllib.error.URLError("redirect refused")


def make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()           # CERT_REQUIRED + check_hostname
    if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:
        raise RuntimeError("TLS verification is off")
    return ctx


def make_opener() -> urllib.request.OpenerDirector:
    """No ProxyHandler (so no proxy from the environment), no redirects, default SSL context."""
    op = urllib.request.OpenerDirector()
    for h in (urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor(),
              _NoRedirect(), urllib.request.HTTPHandler(),
              urllib.request.HTTPSHandler(context=make_ssl_context())):
        op.add_handler(h)
    return op


# ----------------------------------------------------------------- wire formats ----
def clean_reply(s: str) -> str:
    return _CONTROL_RE.sub("", s.replace("\t", " ")).strip()


def build_request(cfg: dict, system: str, messages: list) -> tuple[str, str, dict, bytes]:
    """(url, wire format, headers, body) - after the endpoint policy has said yes."""
    kind = cfg.get("active")
    if kind == "local":
        c = cfg.get("local") or {}
        url, fmt, headers = c.get("endpoint", ""), "openai", {"content-type": "application/json"}
    elif kind == "api":
        c = cfg.get("api") or {}
        fmt, key = c.get("provider"), c.get("key", "")
        url = c.get("endpoint") or DEFAULT_ENDPOINTS.get(fmt, "")
        if fmt not in PROVIDERS or not key:
            raise AssistantError("not-configured")
        headers = ({"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
                   if fmt == "anthropic" else
                   {"authorization": "Bearer " + key, "content-type": "application/json"})
    else:
        raise AssistantError("not-configured")
    model = c.get("model", "")
    if not model or not url:
        raise AssistantError("not-configured")
    try:
        check_endpoint(kind, url)
    except PolicyError:
        raise AssistantError("refused") from None
    if fmt == "anthropic":
        body = {"model": model, "max_tokens": MAX_TOKENS, "messages": messages}
        if system:
            body["system"] = system
    else:
        body = {"model": model,
                "messages": ([{"role": "system", "content": system}] if system else []) + messages}
    return url, fmt, headers, json.dumps(body).encode()


def parse_response(fmt: str, raw: bytes) -> str:
    try:
        d = json.loads(raw)
        if fmt == "anthropic":
            text = "".join(b.get("text", "") for b in d["content"] if b.get("type") == "text")
        else:
            text = d["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise AssistantError("bad-reply") from None
    if not isinstance(text, str):
        raise AssistantError("bad-reply")
    return clean_reply(text)


def ask(cfg: dict, system: str, messages: list, opener=None) -> str:
    """One question to the configured model. Raises AssistantError(code) and nothing else."""
    if not isinstance(messages, list) or not messages:
        raise AssistantError("refused")
    url, fmt, headers, data = build_request(cfg, system, messages)
    p = urlsplit(url)
    if cfg["active"] == "local" and (p.hostname or "").lower() == "localhost" \
            and not _localhost_is_loopback("localhost", p.port):
        raise AssistantError("refused")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    code, raw = "", b""
    deadline = time.monotonic() + TIMEOUT
    try:
        with (opener or make_opener()).open(req, timeout=TIMEOUT) as r:
            buf = bytearray()
            while len(buf) <= MAX_REPLY:
                if time.monotonic() > deadline:
                    code = "unreachable"
                    break
                chunk = r.read(min(65536, MAX_REPLY + 1 - len(buf)))
                if not chunk:
                    break
                buf += chunk
            if not code:
                if len(buf) > MAX_REPLY:
                    code = "bad-reply"
                else:
                    raw = bytes(buf)
    except urllib.error.HTTPError:
        code = "refused"
    except (urllib.error.URLError, OSError, ValueError, ssl.SSLError):
        code = "unreachable"
    if code:
        raise AssistantError(code)       # raised outside the except block: no chained cause
    return parse_response(fmt, raw)


# ------------------------------------------------------------------- config file ----
def config_path(paths: Paths) -> Path:
    return paths.state / "assistant.json"


def default_config() -> dict:
    return {"active": "off", "local": {}, "api": {}}


def load(paths: Paths) -> dict:
    """The config, or the default (off) if there is none or it is damaged: fail closed."""
    cfg = default_config()
    try:
        d = json.loads(config_path(paths).read_text())
    except (OSError, ValueError):
        return cfg
    if not isinstance(d, dict):
        return cfg
    if d.get("active") in KINDS:
        cfg["active"] = d["active"]
    for k, fields in (("local", ("endpoint", "model")), ("api", ("provider", "endpoint", "model", "key"))):
        if isinstance(d.get(k), dict):
            cfg[k] = {f: d[k][f] for f in fields if isinstance(d[k].get(f), str)}
    return cfg


def save(paths: Paths, cfg: dict) -> None:
    paths.state.mkdir(parents=True, exist_ok=True)
    atomic_write(config_path(paths), json.dumps(cfg, indent=2).encode(), mode=0o600)


def _model(model: str) -> str:
    if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}", model):
        raise ConfigError("the model name is empty or has odd characters")
    return model


def set_local(paths: Paths, endpoint: str, model: str) -> None:
    check_endpoint("local", endpoint)
    model = _model(model)
    cfg = load(paths)
    cfg["local"] = {"endpoint": endpoint, "model": model}
    save(paths, cfg)


def set_api(paths: Paths, provider: str, endpoint: str, model: str, key: str) -> None:
    if provider not in PROVIDERS:
        raise ConfigError(f"provider must be one of {', '.join(PROVIDERS)}")
    endpoint = endpoint or DEFAULT_ENDPOINTS[provider]
    check_endpoint("api", endpoint)
    model = _model(model)
    if not key or len(key) > 512 or _CONTROL_RE.search(key) or not key.isprintable():
        raise ConfigError("the API key is empty, too long or has odd characters")
    cfg = load(paths)
    cfg["api"] = {"provider": provider, "endpoint": endpoint, "model": model, "key": key}
    save(paths, cfg)


def use(paths: Paths, kind: str) -> None:
    if kind not in KINDS:
        raise ConfigError("use off, local or api")
    cfg = load(paths)
    if kind == "local":
        c = cfg["local"]
        if not (c.get("endpoint") and c.get("model")):
            raise ConfigError("local is not set up yet: kos assistant set local --endpoint URL --model NAME")
        check_endpoint("local", c["endpoint"])
    if kind == "api":
        c = cfg["api"]
        if not (c.get("provider") in PROVIDERS and c.get("model") and c.get("key")):
            raise ConfigError("api is not set up yet: kos assistant set api --provider P --endpoint URL --model NAME")
        check_endpoint("api", c.get("endpoint") or DEFAULT_ENDPOINTS[c["provider"]])
    cfg["active"] = kind
    save(paths, cfg)


def status(paths: Paths) -> dict:
    """What the owner may see: never the key itself."""
    cfg = load(paths)
    kind = cfg["active"]
    c = cfg.get(kind) or {}
    url = c.get("endpoint") or (DEFAULT_ENDPOINTS.get(c.get("provider", ""), "") if kind == "api" else "")
    try:
        u = urlsplit(url) if url else None
        host = (u.hostname or "") + (f":{u.port}" if u and u.port else "") if u else ""
    except ValueError:
        host = ""
    return {"active": kind, "endpoint_host": host, "model": c.get("model", ""),
            "provider": c.get("provider", "") if kind == "api" else "",
            "key_set": bool(cfg["api"].get("key"))}


def fingerprint(cfg: dict) -> tuple:
    """What a per-instance grant covers: the kind, endpoint and model (not the key)."""
    kind = cfg.get("active")
    c = cfg.get(kind) or {}
    return (kind, c.get("endpoint", ""), c.get("model", ""))
