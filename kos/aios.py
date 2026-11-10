"""AI OS: KOS is the engine, NeuroClaw does the work.

AI OS has exactly four layers and nothing else of NeuroClaw is reachable through KOS:

* ``gui``    the graphical button clicker
* ``app``    terminal commands: app commands
* ``kernel`` kernel commands (NeuroClaw's Linux permission tools)
* ``skill``  the auto skill maker

KOS carries a request to the NeuroClaw engine on this computer (``POST /api/ai-os/layer``). It asks for
no password of its own. NeuroClaw's own tool gate, Computer Access switches and approval queue decide
what happens next, exactly as they do for chat.

The connection is ``os:aios`` -> the engine's host:port, ``loopback``, and the firewall decides first
(firewall.py): without a rule nothing is connected and the error names the command that allows it.

Nothing here starts at boot or runs in the background, in keeping with the rest of KOS: the engine is
asked, once, when you ask. The engine address must be this computer (loopback); anything else is refused.
Standard library only.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from . import assistant, firewall
from .paths import Paths

LAYERS: dict[str, str] = {
    "gui": "graphical button clicker",
    "app": "terminal app commands",
    "kernel": "kernel commands",
    "skill": "auto skill maker",
}
DEFAULT_URL = "http://127.0.0.1:7861"
MAX_REQUEST = 600
TIMEOUT = 60

# A request is one line of words for the engine; control characters (terminal escapes) never go through.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class AiosError(Exception):
    pass


def engine_url(env: dict | None = None) -> str:
    """The NeuroClaw engine to talk to. Must be this computer: KOS never sends a request off the machine."""
    url = (env if env is not None else os.environ).get("KOS_AIOS_URL", DEFAULT_URL).rstrip("/")
    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        local = ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = host == "localhost"
    if parts.scheme != "http" or not local:
        raise AiosError(f"the AI OS engine must be on this computer (http://127.0.0.1:PORT), not {url!r}")
    return url


def clean_request(words: list[str] | str) -> str:
    text = words if isinstance(words, str) else " ".join(words)
    text = _CONTROL.sub(" ", text).strip()
    if not text:
        raise AiosError("say what you want, e.g.: kos aios app list the files here")
    if len(text) > MAX_REQUEST:
        raise AiosError(f"too long: {len(text)} characters (the limit is {MAX_REQUEST})")
    return text


def _gate(url: str, paths: Paths) -> None:
    """Ask the firewall about this engine connection; refuse (nothing connected) if no rule allows it."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port or 80
    except ValueError:
        raise AiosError("the AI OS engine address has a bad port") from None
    if not firewall.decide(paths, "os:aios", host, port, "loopback"):
        raise AiosError("the firewall blocks the AI OS engine. Allow it with: "
                        f"kos firewall allow os:aios {host} {port} --proto loopback")


def _call(url: str, method: str, body: dict | None = None, opener=None, *, paths: Paths) -> dict:
    _gate(url, paths)
    if opener is None:
        opener = assistant.make_opener().open     # no proxy from the environment, no redirects
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with opener(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read().decode("utf-8", "replace")).get("error") or e.reason
        except Exception:
            msg = e.reason
        raise AiosError(f"the engine said {e.code}: {msg}")
    except (urllib.error.URLError, OSError) as e:
        raise AiosError(f"cannot reach the NeuroClaw engine at {url} ({getattr(e, 'reason', e)}). "
                        "Start NeuroClaw first.")


def status(opener=None, env: dict | None = None, *, paths: Paths) -> dict:
    """What the engine offers. No password: it only lists the four layers."""
    return _call(engine_url(env) + "/api/ai-os/layer", "GET", opener=opener, paths=paths)


def run_layer(layer: str, words: list[str] | str,
              opener=None, env: dict | None = None, *, paths: Paths) -> dict:
    """Hand one request to the engine. Returns the engine's outcome."""
    if layer not in LAYERS:
        raise AiosError(f"AI OS has four layers: {', '.join(LAYERS)}")
    request = clean_request(words)
    return _call(engine_url(env) + "/api/ai-os/layer", "POST", {"layer": layer, "request": request},
                 opener=opener, paths=paths)
