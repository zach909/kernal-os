"""Optional language-model client for the AI apps.

An app has NO network. A model request goes through ``host.fetch`` (the OS makes the https request, and
only if the owner's firewall has a rule ``app:NAME HOST 443 https``); without one the answer is
``blocked`` and every AI app falls back to its local, deterministic tools. The endpoint must be https
(plain http and loopback http cannot be fetched; a model on this computer is reached through the OS
assistant instead: ``kos assistant set local``). Two wire formats are supported: Anthropic Messages and
OpenAI-compatible chat.

The API key is kept in the app's vault in clear text (see vault.py's gap note). Use a key you can
revoke. Errors never echo the key.
"""

from __future__ import annotations

import json

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


_WHY = {"blocked": "the firewall blocks this app: the owner allows it with `kos firewall allow app:NAME HOST PORT --proto https`",
        "refused": "this app may not use the network (or the certificate was not verified)",
        "unreachable": "could not reach the endpoint", "redirect": "the endpoint redirected (refused)",
        "too-big": "the reply was too big", "bad-url": "the endpoint is not a plain https URL"}


def ask(host, cfg: dict, system: str, messages: list) -> str:
    if not configured(cfg):
        raise LLMError("no model configured")
    if host is None:
        raise LLMError("no network: this app cannot reach a model here")
    url, headers, data = build_request(cfg, system, messages)
    if not url.startswith("https://"):
        raise LLMError("endpoint must be https")
    ok, got = host.fetch(url, "POST", headers, data.decode())
    if not ok:
        raise LLMError(_WHY.get(got, "could not reach the endpoint")) from None
    if not 200 <= got["status"] < 300:
        raise LLMError(f"endpoint returned HTTP {got['status']}")
    return parse_response(cfg["provider"], got["body"])
