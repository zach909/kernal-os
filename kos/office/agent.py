"""The agent that every suite app carries: press Ctrl-N on any screen.

Light by design: nothing here is imported until the key is pressed, it adds no
permission, no process and no files of its own beyond three vault keys under
the prefix ``agent-``. It is the suite's ``Chat`` with three additions:

  /about          what this app is, and what it is not (its catalogue note)
  /data           how much this app has stored
  /find WORDS     ranked search over this app's own stored text
  anything else   searched against this app's data first

It never reads another app's data (the vault is per app) and never sends this
app's data anywhere. The model is the OS's, not the app's: the app has no network. It asks the OS
(``host.assistant``, the manifest permission ``assistant``); the owner chose the
backend with ``kos assistant`` (off / a model on this computer / an API) and the
OS asks the password once per app instance. The model sees only the chat history
and what you ``/remember`` - never this app's data (``_docs`` is for the local
tools only). When the OS says no, or nothing is configured, the agent says so in
one line and answers from its local tools. Apps that declared ``network`` keep the
older direct model path (``Chat``), untouched.
"""

from __future__ import annotations

from .search import Index
from .ui import Screen
from .workbench import Chat

KEY = "ctrl-n"
_SKIP = ("agent-", "export-")          # its own keys, and exported files (not the user's records)
_MAX_SYSTEM, _MAX_CONTENT, _MAX_MSGS, _MAX_TOTAL = 2000, 4000, 20, 24000   # = protocol.py's limits
_NOTICE = {"not-configured": "No assistant is set up (the owner chooses one with `kos assistant`), so I'm using my local tools.",
           "refused": "The OS did not allow the assistant just now, so I'm using my local tools.",
           "unreachable": "The assistant could not be reached, so I'm using my local tools.",
           "bad-reply": "The assistant sent an unusable reply, so I'm using my local tools."}
_MAX_KEYS, _MAX_CHARS = 200, 20000     # bounded: a big vault must not make the agent slow


class _Prefixed:
    """Gives the agent its own slice of the vault (keys start with ``agent-``)."""

    def __init__(self, host): self.h = host
    def __getattr__(self, n): return getattr(self.h, n)
    def get(self, key, space=None): return self.h.get("agent-" + key, space)
    def put(self, key, value, space=None): return self.h.put("agent-" + key, value, space)
    def delete(self, key, space=None): return self.h.delete("agent-" + key, space)
    def keys(self, space=None): return [k[6:] for k in self.h.keys(space) if k.startswith("agent-")]


class AssistantInfo(Screen):
    """Ctrl-L. Explains where the assistant comes from. Shows nothing secret: the app never sees
    the key or the settings, only answers."""
    title = "Assistant"
    help = "Esc back"

    def __init__(self, host): self.host = host

    def render(self, w, h):
        return ["  The assistant is chosen by the owner of this computer, not by this app.", "",
                "  Out of the box it is OFF and this agent uses its built-in offline tools.",
                "  To switch it on, in a terminal (each needs your password):", "",
                "    kos assistant status", "    kos assistant set local --endpoint URL --model NAME   (a model on this computer)",
                "    kos assistant set api --provider anthropic|openai --model NAME   (someone else's model)",
                "    kos assistant use off|local|api", "",
                "  This app has no network: the OS makes the connection, asks your password",
                "  once per time this app is opened, and logs it. The model sees only this",
                "  chat and what you /remember - never this app's data."]

    def key(self, k):
        if k in ("escape", "enter"): return ("pop", None)


class Agent(Chat):
    is_agent = True

    def __init__(self, host, title: str, note: str = ""):
        self.app_host, self.app_title, self.app_note = host, title, note
        system = (f"You are the built-in assistant of the KOS app '{title}'. {note} "
                  "Be brief and accurate; if you are unsure, say so.")
        super().__init__(_Prefixed(host), f"Agent: {title}", system, extra_local=self._answer)
        self.help = "Enter send   ^L assistant   /help /about /data /find   Esc back"
        self._told: set = set()
        self._via_os = False

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

    # -- the OS's assistant ---------------------------------------------------
    def _context(self):
        """(system, messages): the chat history and /remember notes. Never the app's data."""
        notes = "\n".join(self.mem.values())
        system = (self.system + ("\nNotes the user asked you to remember:\n" + notes if notes else ""))[:_MAX_SYSTEM]
        return system

    def _messages(self, text: str) -> list:
        msgs = [{"role": "user" if w == "you" else "assistant", "content": str(t)[:_MAX_CONTENT]}
                for w, t in self.hist[-(_MAX_MSGS - 1):] if w in ("you", "ai") and str(t)]
        msgs.append({"role": "user", "content": text[:_MAX_CONTENT]})
        while sum(len(m["content"]) for m in msgs) > _MAX_TOTAL and len(msgs) > 1:
            msgs.pop(0)
        while msgs[0]["role"] != "user":
            msgs.pop(0)
        return msgs

    def _ask_os(self, text: str):
        """(ok, reply or reason). A host that raises is treated as 'unreachable'."""
        try:
            ok, out = self.app_host.assistant(self._context(), self._messages(text))
        except Exception:
            return False, "unreachable"
        return (True, out) if ok and isinstance(out, str) and out.strip() else (False, out if out in _NOTICE else "bad-reply")

    def render(self, w, h):
        lines = super().render(w, h)
        if self._via_os and len(lines) >= 2:
            lines[-2] = "[assistant: chosen by the owner, via the OS]"
        return lines

    def key(self, k):
        if k == "escape": return ("pop", None)
        if k == "ctrl-l": return ("push", AssistantInfo(self.app_host))
        text = self.inp.value.strip()
        if k == "enter" and text and not text.startswith("/"):
            ok, out = self._ask_os(text)
            self._via_os = ok
            if ok:
                self.inp = type(self.inp)(); self.top = -1
                self.say("you", text); self.say("ai", out)
                return None
            super().key(k)                    # offline tools (or the app's own network path, if it has one)
            if out not in self._told or out != "not-configured":
                self._told.add(out)
                if self.hist and self.hist[-1][0] == "ai":
                    self.hist[-1][1] = _NOTICE[out] + "\n" + self.hist[-1][1]
                    self.st.save("chat", self.hist)
            return None
        return super().key(k)
