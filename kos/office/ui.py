"""Host abstraction, widgets and the screen-stack runner shared by every
suite app. Everything here is pure Python on top of the KOS command protocol;
``Host`` is the only thing that touches an ``App``, so apps can be driven by
scripted keys in tests (``FakeHost``)."""

from __future__ import annotations

import json
from typing import Any, Callable, Iterator, Optional

CURSOR = "▌"      # shown at the insertion point


# ---------------------------------------------------------------- hosts ----
class Host:
    """What suite code needs from the OS. ``AppHost`` is the real one."""

    width = 80
    height = 22

    def events(self) -> Iterator[dict]: raise NotImplementedError
    def screen(self, title: str, lines: list, status: str = "") -> None: raise NotImplementedError
    error = ""      # why the last storage call was refused (shown by apps instead of failing silently)

    def get(self, key: str, space: Optional[str] = None) -> Optional[str]: raise NotImplementedError
    def put(self, key: str, value: str, space: Optional[str] = None) -> bool: raise NotImplementedError
    def keys(self, space: Optional[str] = None) -> list: raise NotImplementedError
    def delete(self, key: str, space: Optional[str] = None) -> bool: raise NotImplementedError
    def exit(self, code: int = 0) -> None: raise NotImplementedError
    def assistant(self, system: str, messages: list) -> tuple:
        """Ask the OS's assistant (no network for the app). -> (ok, text or short reason)."""
        return (False, "not-configured")
    def present(self, canvas) -> None: raise NotImplementedError


class AppHost(Host):
    def __init__(self, app):
        self.app = app

    @property
    def width(self): return self.app.width
    @property
    def height(self): return self.app.height
    @property
    def mode(self): return self.app.mode

    def events(self): return self.app.events()
    def screen(self, title, lines, status=""): self.app.screen(title, lines, status)
    def present(self, canvas): self.app.present(canvas)
    @property
    def error(self): return self.app.vault_error

    def get(self, key, space=None): return self.app.vault_get(key, space)
    def put(self, key, value, space=None): return self.app.vault_put(key, value, space)
    def keys(self, space=None): return self.app.vault_keys(space)
    def delete(self, key, space=None): return self.app.vault_delete(key, space)
    def exit(self, code=0): self.app.exit(code)
    def assistant(self, system, messages): return self.app.assistant(system, messages)


class FakeHost(Host):
    """Scripted host for tests: feed keys, read back the last screen."""

    def __init__(self, keys: list | str = (), width: int = 80, height: int = 22, data=None, mode: str = "tui", storage=None):
        self.width, self.height, self.mode = width, height, mode
        self.assistant_fn = None            # tests inject (system, messages) -> (ok, text); default: not configured
        self.assistant_calls: list = []
        self.storage = storage              # a real kos.spaces.AppStorage: shared spaces are then truly enforced
        self.spaces: dict = {}              # without storage, spaces are plain in-memory dicts
        self.data: dict = dict(data or {})
        raw = list(keys) if not isinstance(keys, str) else self.tokens(keys)
        self.script = [c for k in raw for c in self.expand(k)]
        self.frames: list = []
        self.exited = None
        self.canvases: list = []

    NAMED = {"enter", "escape", "backspace", "delete", "tab", "up", "down", "left", "right", "home", "end", "pageup", "pagedown", "insert"}

    @classmethod
    def expand(cls, k):
        """'Ann' -> ['A','n','n']; named keys ('enter', 'ctrl-s') and event dicts pass through."""
        if isinstance(k, dict) or len(k) == 1 or k in cls.NAMED or k.startswith("ctrl-"):
            return [k]
        return list(k)

    @staticmethod
    def tokens(s: str) -> list:
        """'abc<enter><up>' -> ['a','b','c','enter','up']"""
        out, i = [], 0
        while i < len(s):
            if s[i] == "<" and ">" in s[i:]:
                j = s.index(">", i)
                out.append(s[i + 1:j]); i = j + 1
            else:
                out.append(s[i]); i += 1
        return out

    def events(self):
        yield {"cmd": "hello"}
        for k in self.script:
            yield k if isinstance(k, dict) else {"cmd": "key", "key": k}

    def screen(self, title, lines, status=""):
        self.frames.append((title, list(lines), status))

    def present(self, canvas): self.canvases.append(canvas.ops)
    def _vault(self, space, op):
        from kos.spaces import StorageError
        try:
            self.error = ""
            return self.storage.vault(space, op)
        except StorageError as e:
            self.error = str(e)
            return None

    def get(self, key, space=None):
        if space and self.storage:
            v = self._vault(space, "get"); return v.get(key) if v else None
        return (self.spaces.setdefault(space, {}) if space else self.data).get(key)

    def put(self, key, value, space=None):
        if space and self.storage:
            v = self._vault(space, "put")
            if not v: return False
            v.put(key, value); return True
        (self.spaces.setdefault(space, {}) if space else self.data)[key] = value
        return True

    def keys(self, space=None):
        if space and self.storage:
            v = self._vault(space, "list"); return v.keys() if v else []
        return sorted(self.spaces.setdefault(space, {}) if space else self.data)

    def delete(self, key, space=None):
        if space and self.storage:
            v = self._vault(space, "delete"); return bool(v and v.delete(key))
        return (self.spaces.setdefault(space, {}) if space else self.data).pop(key, None) is not None
    def exit(self, code=0): self.exited = code
    def assistant(self, system, messages):
        self.assistant_calls.append((system, [dict(m) for m in messages]))
        return self.assistant_fn(system, messages) if self.assistant_fn else (False, "not-configured")

    @property
    def text(self) -> str:
        t, lines, st = self.frames[-1]
        return "\n".join([t, *lines, st])


class SpaceHost:
    """The same host API, pointed at a shared space instead of the app's private data."""

    def __init__(self, host, space: str):
        self._h, self.space = host, space

    def __getattr__(self, n): return getattr(self._h, n)
    @property
    def error(self): return self._h.error
    def get(self, key): return self._h.get(key, space=self.space)
    def put(self, key, value): return self._h.put(key, value, space=self.space)
    def keys(self): return self._h.keys(space=self.space)
    def delete(self, key): return self._h.delete(key, space=self.space)


# --------------------------------------------------------- persistence ----
class Store:
    """JSON documents in the vault."""

    def __init__(self, host: Host):
        self.host = host

    def load(self, key: str, default: Any = None) -> Any:
        raw = self.host.get(key)
        if raw is None:
            return default
        try:
            return json.loads(raw)
        except ValueError:
            return default

    def save(self, key: str, value: Any) -> bool:
        return self.host.put(key, json.dumps(value, separators=(",", ":"), ensure_ascii=False))


def slug(s: str, fallback: str = "item") -> str:
    out = "".join(c if c.isalnum() and c.isascii() else "-" for c in s.lower()).strip("-")
    while "--" in out:
        out = out.replace("--", "-")
    return (out or fallback)[:48]


# -------------------------------------------------------------- widgets ----
class TextInput:
    def __init__(self, value: str = ""):
        self.value, self.pos = value, len(value)

    def key(self, k: str) -> bool:
        """True if the key was an edit/move this widget consumed."""
        if len(k) == 1 and k.isprintable():
            self.value = self.value[:self.pos] + k + self.value[self.pos:]
            self.pos += 1
        elif k == "backspace" and self.pos:
            self.value = self.value[:self.pos - 1] + self.value[self.pos:]
            self.pos -= 1
        elif k == "delete":
            self.value = self.value[:self.pos] + self.value[self.pos + 1:]
        elif k == "left": self.pos = max(0, self.pos - 1)
        elif k == "right": self.pos = min(len(self.value), self.pos + 1)
        elif k == "home": self.pos = 0
        elif k == "end": self.pos = len(self.value)
        elif k == "ctrl-u": self.value, self.pos = "", 0
        else:
            return False
        return True

    def render(self) -> str:
        return self.value[:self.pos] + CURSOR + self.value[self.pos:]


class ListNav:
    def __init__(self, n: int = 0):
        self.n, self.sel, self.top = n, 0, 0

    def resize(self, n: int) -> None:
        self.n = n
        self.sel = max(0, min(self.sel, n - 1))

    def key(self, k: str, page: int = 10) -> bool:
        before = self.sel
        if k == "up": self.sel -= 1
        elif k == "down": self.sel += 1
        elif k == "pageup": self.sel -= page
        elif k == "pagedown": self.sel += page
        elif k == "home": self.sel = 0
        elif k == "end": self.sel = self.n - 1
        else:
            return False
        self.sel = max(0, min(self.sel, self.n - 1))
        return self.sel != before or True

    def window(self, height: int) -> tuple[int, int]:
        height = max(1, height)
        if self.sel < self.top: self.top = self.sel
        if self.sel >= self.top + height: self.top = self.sel - height + 1
        return self.top, min(self.n, self.top + height)


class TextArea:
    """A small multiline editor with undo."""

    def __init__(self, text: str = ""):
        self.lines = text.split("\n") if text else [""]
        self.r = self.c = self.top = 0
        self._undo: list = []
        self.dirty = False

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    def set_text(self, text: str) -> None:
        self._snap()
        self.lines = text.split("\n") if text else [""]
        self.r = min(self.r, len(self.lines) - 1)
        self.c = min(self.c, len(self.lines[self.r]))
        self.dirty = True

    def _snap(self) -> None:
        self._undo.append((list(self.lines), self.r, self.c))
        del self._undo[:-100]

    def undo(self) -> None:
        if self._undo:
            self.lines, self.r, self.c = self._undo.pop()
            self.dirty = True

    def key(self, k: str) -> bool:
        L = self.lines
        if len(k) == 1 and k.isprintable():
            self._snap(); L[self.r] = L[self.r][:self.c] + k + L[self.r][self.c:]; self.c += 1
        elif k == "tab":
            self._snap(); L[self.r] = L[self.r][:self.c] + "    " + L[self.r][self.c:]; self.c += 4
        elif k == "enter":
            self._snap()
            rest = L[self.r][self.c:]
            L[self.r] = L[self.r][:self.c]
            L.insert(self.r + 1, rest); self.r += 1; self.c = 0
        elif k == "backspace":
            if self.c:
                self._snap(); L[self.r] = L[self.r][:self.c - 1] + L[self.r][self.c:]; self.c -= 1
            elif self.r:
                self._snap(); self.c = len(L[self.r - 1]); L[self.r - 1] += L.pop(self.r); self.r -= 1
        elif k == "delete":
            if self.c < len(L[self.r]):
                self._snap(); L[self.r] = L[self.r][:self.c] + L[self.r][self.c + 1:]
            elif self.r + 1 < len(L):
                self._snap(); L[self.r] += L.pop(self.r + 1)
        elif k == "left":
            if self.c: self.c -= 1
            elif self.r: self.r -= 1; self.c = len(L[self.r])
        elif k == "right":
            if self.c < len(L[self.r]): self.c += 1
            elif self.r + 1 < len(L): self.r += 1; self.c = 0
        elif k == "up" and self.r: self.r -= 1; self.c = min(self.c, len(L[self.r]))
        elif k == "down" and self.r + 1 < len(L): self.r += 1; self.c = min(self.c, len(L[self.r]))
        elif k == "home": self.c = 0
        elif k == "end": self.c = len(L[self.r])
        elif k == "pageup": self.r = max(0, self.r - 15); self.c = min(self.c, len(L[self.r]))
        elif k == "pagedown": self.r = min(len(L) - 1, self.r + 15); self.c = min(self.c, len(L[self.r]))
        elif k == "ctrl-z": self.undo(); return True
        elif k == "ctrl-k":      # cut the rest of the line
            self._snap(); L[self.r] = L[self.r][:self.c]
        else:
            return False
        self.dirty = True if k not in ("left", "right", "up", "down", "home", "end",
                                       "pageup", "pagedown") else self.dirty
        return True

    def render(self, height: int, width: int = 78, numbers: bool = False) -> list:
        if self.r < self.top: self.top = self.r
        if self.r >= self.top + height: self.top = self.r - height + 1
        out = []
        for i in range(self.top, min(len(self.lines), self.top + height)):
            line = self.lines[i]
            if i == self.r:
                line = line[:self.c] + CURSOR + line[self.c:]
            out.append((f"{i + 1:>4} " if numbers else "") + line[:width])
        return out


def wrap(text: str, width: int) -> list:
    out = []
    for para in text.split("\n"):
        line = ""
        for word in para.split(" "):
            while len(word) > width:
                if line: out.append(line); line = ""
                out.append(word[:width]); word = word[width:]
            if not line: line = word
            elif len(line) + 1 + len(word) <= width: line += " " + word
            else: out.append(line); line = word
        out.append(line)
    return out


def table(rows: list, headers: list, widths: Optional[list] = None, maxw: int = 78) -> list:
    """Plain-text table. rows are lists of values."""
    cols = len(headers)
    cells = [[str(c) for c in r] for r in rows]
    if widths is None:
        widths = [max([len(headers[i])] + [len(r[i]) for r in cells if i < len(r)]) for i in range(cols)]
        over = sum(widths) + 2 * (cols - 1) - maxw
        while over > 0 and max(widths) > 6:
            i = widths.index(max(widths)); widths[i] -= 1; over -= 1
    def fmt(r): return "  ".join((str(r[i]) if i < len(r) else "")[:widths[i]].ljust(widths[i]) for i in range(cols))
    return [fmt(headers), "  ".join("-" * w for w in widths), *(fmt(r) for r in cells)]


def bar(value: float, maximum: float, width: int = 30, ch: str = "█") -> str:
    if maximum <= 0:
        return ""
    n = max(0, min(width, round(width * value / maximum)))
    return ch * (n or (1 if value > 0 else 0))


# ------------------------------------------------------ screens + runner ----
class Screen:
    title = ""
    help = ""

    def canvas(self, w: int, h: int):         # graphical screens return a Canvas here
        return None

    def event(self, ev: dict):                # pointer / button events (graphical)
        return None

    def render(self, w: int, h: int) -> list: return []
    def status(self) -> str: return self.help
    def key(self, k: str): return None          # -> Action | None
    def on_enter(self): return None             # called when it (re)becomes the top


class Prompt(Screen):
    """One-line input. ``on_done(text)`` runs after this screen has popped."""

    def __init__(self, title: str, label: str, initial: str = "", on_done: Callable = None,
                 secret: bool = False, suggest: Callable = None):
        self.title, self.label, self.on_done, self.secret, self.suggest = title, label, on_done, secret, suggest
        self.inp = TextInput(initial)
        self.help = "Enter accept   Esc cancel" + ("   Tab complete" if suggest else "")

    def _suggestions(self):
        if not self.suggest: return []
        last = self.inp.value.rsplit(",", 1)[-1].strip()
        return self.suggest(last)[:5] if last else []

    def render(self, w, h):
        v = self.inp.render()
        if self.secret:
            v = "*" * len(self.inp.value) + CURSOR
        sug = self._suggestions()
        return ["", f"  {self.label}", "", f"  > {v}"] + (["", "  suggestions:"] + [f"    {x}" for x in sug] if sug else [])

    def key(self, k):
        if k == "escape": return ("pop", None)
        if k == "tab" and self.suggest:
            sug = self._suggestions()
            if sug:
                head = self.inp.value.rsplit(",", 1)[0] + ", " if "," in self.inp.value else ""
                self.inp = TextInput(head + sug[0]); return None
        if k == "enter":
            val = self.inp.value
            return ("pop", (lambda: self.on_done(val)) if self.on_done else None)
        self.inp.key(k)


class Confirm(Screen):
    def __init__(self, question: str, on_yes: Callable, title: str = "Confirm"):
        self.title, self.question, self.on_yes = title, question, on_yes
        self.help = "y yes   n no"

    def render(self, w, h): return ["", "  " + self.question, "", "  [y]es   [n]o"]

    def key(self, k):
        if k in ("y", "Y", "enter"): return ("pop", self.on_yes)
        if k in ("n", "N", "escape"): return ("pop", None)


class Message(Screen):
    def __init__(self, title: str, lines: list):
        self.title, self.lines = title, lines
        self.help = "any key to continue"
        self.nav = ListNav(len(lines))

    def render(self, w, h):
        out = []
        for l in self.lines:
            out += wrap(l, w - 4)
        return ["  " + l for l in out[:h]]

    def key(self, k):
        if k in ("enter", "escape", "q", " "): return ("pop", None)


class TextView(Screen):
    """Scrollable read-only text."""

    def __init__(self, title: str, lines: list):
        self.title, self.lines, self.top = title, lines, 0
        self.help = "up/down scroll   Esc back"

    def render(self, w, h):
        self.top = max(0, min(self.top, max(0, len(self.lines) - h)))
        return self.lines[self.top:self.top + h]

    def key(self, k):
        if k in ("escape", "q", "enter"): return ("pop", None)
        if k == "up": self.top -= 1
        elif k == "down": self.top += 1
        elif k == "pageup": self.top -= 15
        elif k == "pagedown": self.top += 15
        elif k == "home": self.top = 0
        elif k == "end": self.top = 10 ** 6


class Menu(Screen):
    """A list of (label, callable-returning-Action) entries."""

    def __init__(self, title: str, entries: list, intro: list = ()):
        self.title, self.entries, self.intro = title, entries, list(intro)
        self.nav = ListNav(len(entries))
        self.help = "up/down   Enter select   Esc back"

    def render(self, w, h):
        top, end = self.nav.window(h - len(self.intro) - 1)
        out = list(self.intro) + ([""] if self.intro else [])
        for i in range(top, end):
            out.append(("  > " if i == self.nav.sel else "    ") + self.entries[i][0])
        return out

    def key(self, k):
        if self.nav.key(k): return None
        if k == "enter" and self.entries: return self.entries[self.nav.sel][1]()
        if k == "escape": return ("pop", None)
        if len(k) == 1 and k.isdigit():
            i = int(k) - 1
            if 0 <= i < len(self.entries): return self.entries[i][1]()


def run(host: Host, root: Screen, quit_keys=("ctrl-q",), agent=None) -> None:
    """The screen-stack loop. Esc at the root exits the app.

    `agent`, if given, is a function that makes the app's built-in assistant; Ctrl-N opens it from any
    screen (kos/office/agent.py - imported only when used)."""
    stack = [root]

    def draw():
        s = stack[-1]
        if getattr(host, "mode", "tui") == "graphical":
            cv = s.canvas(host.width, host.height)
            if cv is not None:
                host.present(cv); return
        h = max(5, host.height - 1)
        body = s.render(host.width, h)
        crumbs = " > ".join(x.title for x in stack if x.title) or "KOS"
        host.screen(crumbs[:80], body[:h], s.status())

    def apply(action):
        # Actions may chain: ("pop", fn) runs fn after the pop and applies its result.
        while action is not None:
            kind = action[0]
            if kind == "push":
                stack.append(action[1]); action = stack[-1].on_enter()
            elif kind == "replace":
                stack[-1] = action[1]; action = stack[-1].on_enter()
            elif kind == "pop":
                if len(stack) > 1: stack.pop()
                fn = action[1] if len(action) > 1 else None
                action = fn() if fn else stack[-1].on_enter()
            elif kind == "quit":
                host.exit(0); return True
            else:
                return False
        return False

    if apply(root.on_enter()): return
    for ev in host.events():
        cmd = ev.get("cmd")
        if cmd == "key":
            k = ev["key"]
            if k in quit_keys:
                host.exit(0); return
            if k == "ctrl-n" and agent and not getattr(stack[-1], "is_agent", False):
                apply(("push", agent())); draw(); continue
            try:
                act = stack[-1].key(k)
            except Exception as e:          # a bug in one screen must not lose the user's session
                act = ("push", Message("Internal error", [f"{type(e).__name__}: {e}", "", "Your saved data is untouched. Press Esc to go back."]))
            if act is None and k == "escape" and len(stack) == 1:
                act = ("quit",)
            if apply(act): return
        elif cmd == "scroll":
            act = stack[-1].key("down" if ev.get("dy", 1) > 0 else "up")
            if apply(act): return
        elif cmd in ("pointer", "button"):
            try:
                if apply(stack[-1].event(ev)): return
            except Exception as e:
                apply(("push", Message("Internal error", [f"{type(e).__name__}: {e}"])))
        elif cmd not in ("hello", "device"):
            continue
        draw()


class Editor(Screen):
    """Full-screen multiline editor. Ctrl-S calls ``on_save(text)`` (and stays);
    Esc leaves (asks first if there are unsaved edits)."""

    def __init__(self, title: str, text: str = "", on_save: Callable = None, numbers: bool = False,
                 extra_keys: Optional[dict] = None, hint: str = ""):
        self.title, self.on_save, self.numbers = title, on_save, numbers
        self.area = TextArea(text)
        self.area.dirty = False
        self.extra = extra_keys or {}
        self.flash = ""
        self.hint = hint

    def status(self):
        return (self.flash or ("Ctrl-S save   Esc leave   Ctrl-Z undo   " + self.hint)).strip()

    def render(self, w, h):
        return self.area.render(h, w - 2, self.numbers)

    def save(self):
        if self.on_save:
            self.on_save(self.area.text)
        self.area.dirty = False
        self.flash = "saved"

    def key(self, k):
        self.flash = ""
        if k == "ctrl-s":
            self.save(); return None
        if k in self.extra:
            return self.extra[k](self)
        if k == "escape":
            if self.area.dirty and self.on_save:
                return ("push", Confirm("Unsaved changes. Save before leaving?",
                                        lambda: (self.save(), ("pop", None))[1], "Unsaved"))
            return ("pop", None)
        self.area.key(k)


def today() -> str:
    import time
    return time.strftime("%Y-%m-%d")


def now_stamp() -> str:
    import time
    return time.strftime("%Y-%m-%d %H:%M")
