"""One box for four things: talk to the assistant, search commands, search apps, search files.

You type; the box decides. No modes to pick, no prefixes to learn:

  * what you typed is matched against the **commands** (``kos help``), the **apps** the screen
    knows about (only the App Library does) and the **files** this app can already read;
  * the last row is always "Ask the assistant" - or the *first* row when the text reads like a
    question ("how do I back up?", anything ending in "?", anything starting with "/");
  * empty box: a plain "Talk to the assistant" row, so you can just talk.

This module is pure logic (no screen, no OS call) so the same code serves the Ctrl-N box in every
suite app and the App Library.

Rules it holds to (kos-rules):

* **Search shows, it never does.** A command hit is text to read; KOS has no way to type a password
  or run a command on your behalf. An app hit is a *request* the OS still asks your password for.
* **Files means what this app can already read.** Its own vault plus the shared folders the owner
  granted it. No path is opened, no new permission exists. Keys that look like credentials (the
  model settings hold an API key), the agent's own chat history and exported files are never indexed.
* **Everything searched is untrusted text.** App descriptions, stored notes and shared-folder
  contents are written by someone else: every label that reaches the screen goes through ``plain``
  (control characters and escape sequences removed, one line, bounded).
* **Bounded.** At most ``MAX_FILES`` files per place and ``MAX_CHARS`` characters of each are read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .cmdindex import COMMANDS
from .search import Index, tokens

MAX_FILES, MAX_CHARS, MAX_SPACES = 200, 20000, 8
PER_GROUP = 4            # rows per kind; the box is a shortcut, not a results page
MAX_QUERY = 120

ACTION, APP, FILE, ASK = "action", "app", "file", "ask"
HEADINGS = {ACTION: "Commands", APP: "Apps", FILE: "Files", ASK: "Assistant"}

# Keys never indexed: credentials, the agent's own history, exported files.
_HIDDEN = re.compile(r"^(agent-|export-)|llm|secret|token|passw|api[-_]?key|credential|private", re.I)
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
_QUESTION = frozenset("""what why how who whom whose when where which can could should would will is are am do does
did explain tell show help write summarize summarise translate give list compare""".split())


def plain(text, limit: int = 80) -> str:
    """One line of inert text. Anything someone else wrote must pass through here before it is shown."""
    s = _CTRL.sub(" ", str(text))
    return " ".join(s.split())[:limit]


@dataclass(frozen=True)
class Hit:
    kind: str            # ACTION | APP | FILE | ASK
    label: str           # what the row says (already plain)
    detail: str = ""     # a second, dimmer line (already plain)
    ref: str = ""        # ACTION: command name  APP: app name  FILE: "space\0key"  ASK: the question


def looks_like_question(q: str) -> bool:
    q = q.strip()
    first = q.split(None, 1)[0].lower() if q else ""
    return q.endswith("?") or q.startswith("/") or first in _QUESTION


def hidden_key(key: str) -> bool:
    return bool(_HIDDEN.search(key))


def gather_files(host) -> list:
    """[(space, key, text)] this app can read right now, bounded. ``space`` is "" for its own data.
    Uses only what the host already gives the app (its vault and the shared folders it was granted)."""
    out: list = []
    places = [""] + [s for s in list(host.space_names())[:MAX_SPACES] if isinstance(s, str)]
    for space in places:
        try:
            keys = sorted(host.keys(space or None))
        except Exception:
            continue
        for k in keys[:MAX_FILES]:
            if hidden_key(k):
                continue
            v = host.get(k, space or None)
            if isinstance(v, str) and v:
                out.append((space, k, v[:MAX_CHARS]))
    return out


_FILLER = _QUESTION | frozenset("i me my we you your please just so".split())


def _commands(words: list, commands, limit: int) -> list:
    """Commands whose *name* starts with one of the words first ("bac" or "back" -> backup), then a text match."""
    by_name = {c[0]: c for c in commands}
    stems = [w for w in words if len(w) >= 3]
    first = [by_name[n] for n in sorted(by_name) if any(n.startswith(w) or w.startswith(n) and len(n) >= 4 for w in stems)]
    idx = Index({c[0]: f"{c[0]} {c[1]}" for c in commands})
    rest = [by_name[k] for k, _s, _x in idx.search(" ".join(words), limit * 2) if by_name[k] not in first]
    return (first + rest)[:limit]


def search(query: str, *, apps=(), files=(), commands=COMMANDS) -> list:
    """The rows for ``query``, in the order the box shows them (headings are added by the screen)."""
    query = query.strip()[:MAX_QUERY]
    if not query:
        return [Hit(ASK, "Talk to the assistant", "type to search commands and files, or just talk", "")]
    question = looks_like_question(query)
    words = [w for w in tokens(query) if w not in _FILLER]        # "how do I back up?" -> back up
    hits: list = []
    for name, helptext, _usage in _commands(words, commands, 2 if question else PER_GROUP):
        hits.append(Hit(ACTION, "kos " + plain(name, 24), plain(helptext, 70), name))
    if words:
        app_list = [a for a in apps if isinstance(a, dict) and isinstance(a.get("name"), str)]
        aidx = Index({a["name"]: f'{a["name"]} {a.get("description", "")}' for a in app_list})
        by = {a["name"]: a for a in app_list}
        for k, _s, _x in aidx.search(query, PER_GROUP):
            hits.append(Hit(APP, plain(k, 30), plain(by[k].get("description", ""), 60), k))
        fl = {f"{sp}\0{k}": (sp, k, t) for sp, k, t in files}
        fidx = Index({key: v[2] for key, v in fl.items()})
        for key, _s, snip in fidx.search(query, PER_GROUP):
            sp, k, _t = fl[key]
            hits.append(Hit(FILE, plain((sp + "/" if sp else "") + k, 50), plain(snip, 70), key))
    ask = Hit(ASK, "Ask the assistant: " + plain(query, 60), "", query)
    return [ask] + hits if question or not hits else hits + [ask]


def file_text(files, ref: str) -> str:
    """The full (bounded) text of the file a FILE hit points at, from what ``gather_files`` returned."""
    for sp, k, t in files:
        if f"{sp}\0{k}" == ref:
            return t
    return ""


def describe_command(commands, name: str) -> list:
    """Lines to show for one command: what it does and the exact thing to type."""
    for n, helptext, usage in commands:
        if n == name:
            return [plain(helptext, 200), "", "Type this in the KOS shell:", "  " + plain(usage, 200), "",
                    "Searching never runs a command. If it needs your password,",
                    "KOS asks for it itself, in its own prompt."]
    return ["no such command"]
