"""Optional language-model client for the AI apps.

KOS apps have no network unless the manifest asks for it and the owner types
the password at launch, so every AI app here works WITHOUT a model (local,
deterministic tools) and gets better when you point it at one. Two wire
formats are supported: Anthropic Messages and OpenAI-compatible chat.

The API key is kept in the app's vault in clear text (see vault.py's gap
note). Use a key you can revoke. Errors never echo the key.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

DEFAULTS = {
    "anthropic": {"endpoint": "https://api.anthropic.com/v1/messages", "model": "claude-sonnet-5-5"},
    "openai": {"endpoint": "https://api.openai.com/v1/chat/completions", "model": ""},
}


class LLMError(Exception):
    pass


def configured(cfg: dict | None) -> bool:
    return bool(cfg and cfg.get("provider") in DEFAULTS and cfg.get("key") and cfg.get("model"))


def build_request(cfg: dict, system: str, messages: list) -> tuple[str, dict, bytes]:
    prov = cfg["provider"]
    url = cfg.get("endpoint") or DEFAULTS[prov]["endpoint"]
    if prov == "anthropic":
        headers = {"x-api-key": cfg["key"], "anthropic-version": "2023-06-01", "content-type": "application/json"}
        body = {"model": cfg["model"], "max_tokens": int(cfg.get("max_tokens", 1024)), "messages": messages}
        if system: body["system"] = system
    else:
        headers = {"authorization": "Bearer " + cfg["key"], "content-type": "application/json"}
        body = {"model": cfg["model"], "messages": ([{"role": "system", "content": system}] if system else []) + messages}
    return url, headers, json.dumps(body).encode()


def parse_response(prov: str, raw: bytes) -> str:
    try:
        d = json.loads(raw)
        if prov == "anthropic":
            return "".join(b.get("text", "") for b in d["content"] if b.get("type") == "text")
        return d["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise LLMError("unexpected response from the model endpoint") from None


def ask(cfg: dict, system: str, messages: list, timeout: float = 60.0) -> str:
    if not configured(cfg):
        raise LLMError("no model configured")
    url, headers, data = build_request(cfg, system, messages)
    if not url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
        raise LLMError("endpoint must be https (or localhost)")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return parse_response(cfg["provider"], r.read(4 << 20))
    except urllib.error.HTTPError as e:
        raise LLMError(f"endpoint returned HTTP {e.code}") from None
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise LLMError(f"could not reach the endpoint ({type(e).__name__}) - does this app have network access?") from None
