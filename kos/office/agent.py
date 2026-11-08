"""The agent that every suite app carries: press Ctrl-N on any screen.

Light by design: nothing here is imported until the key is pressed, it adds no
permission, no process and no files of its own beyond three vault keys under
the prefix ``agent-``. It is the suite's ``Chat`` with three additions:

  /about          what this app is, and what it is not (its catalogue note)
  /data           how much this app has stored
  /find WORDS     ranked search over this app's own stored text
  anything else   searched against this app's data first

It never reads another app's data (the vault is per app) and never sends this
app's data anywhere. With a model configured (needs the app's own ``network``
permission, so only apps that declared it) the model sees only what you type
and what you ``/remember`` - the same as every AI app in the suite. Without a
model it answers from local tools, and says so.
"""

from __future__ import annotations

from .search import Index
from .workbench import Chat

KEY = "ctrl-n"
_SKIP = ("agent-", "export-")          # its own keys, and exported files (not the user's records)
_MAX_KEYS, _MAX_CHARS = 200, 20000     # bounded: a big vault must not make the agent slow


class _Prefixed:
    """Gives the agent its own slice of the vault (keys start with ``agent-``)."""

    def __init__(self, host): self.h = host
    def __getattr__(self, n): return getattr(self.h, n)
    def get(self, key, space=None): return self.h.get("agent-" + key, space)
    def put(self, key, value, space=None): return self.h.put("agent-" + key, value, space)
    def delete(self, key, space=None): return self.h.delete("agent-" + key, space)
    def keys(self, space=None): return [k[6:] for k in self.h.keys(space) if k.startswith("agent-")]


class Agent(Chat):
    is_agent = True

    def __init__(self, host, title: str, note: str = ""):
        self.app_host, self.app_title, self.app_note = host, title, note
        system = (f"You are the built-in assistant of the KOS app '{title}'. {note} "
                  "Be brief and accurate; if you are unsure, say so.")
        super().__init__(_Prefixed(host), f"Agent: {title}", system, extra_local=self._answer)
        self.help = "Enter send   ^L model settings   /help /about /data /find   Esc back"

    # -- the app's own data, bounded ----------------------------------------
    def _docs(self) -> dict:
        out = {}
        for k in sorted(self.app_host.keys())[:_MAX_KEYS]:
            if k.startswith(_SKIP): continue
            v = self.app_host.get(k)
            if isinstance(v, str) and v: out[k] = v[:_MAX_CHARS]
        return out

    def _find(self, q: str) -> str:
        hits = Index(self._docs()).search(q, 3)
        return "\n".join(f"[{n}] {s}" for n, _x, s in hits)

    def _answer(self, text: str, _hits) -> str | None:
        cmd, _, rest = text.partition(" ")
        if cmd == "/about":
            return f"{self.app_title}: {self.app_note or 'a KOS suite app'}. Single-user and local; it cannot reach other apps, files or the network on its own."
        if cmd == "/data":
            d = self._docs()
            return f"{len(d)} stored item(s), {sum(map(len, d.values()))} characters." if d else "nothing stored yet."
        if cmd == "/find": return self._find(rest) or "nothing in this app's data matches."
        if text.startswith("/"): return None
        found = self._find(text)
        return ("From this app's data:\n" + found) if found else None

    def local(self, text: str) -> str:
        if text.startswith("/help"):
            return super().local(text) + "  /about  /data  /find WORDS"
        return super().local(text)

    def key(self, k):
        if k == "escape": return ("pop", None)
        return super().key(k)
