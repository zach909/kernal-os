"""Healing: a self-healing counter.

One whole number is kept in three copies (a, b, c) in this app's own private storage. Each copy carries
a generation and a SHA-256 checksum. On start, and after every key or click, the app *checks* all three
and *repairs* what is wrong, with no one asking:

  * a copy that is missing, unreadable, or whose checksum does not match is rewritten from the best copy
  * a copy that is older than the best one (a write that was cut short) is brought forward
  * the best copy is the valid one with the highest generation; if two disagree at the same generation,
    the value more copies hold wins, and the lowest letter breaks a tie

If no copy is valid, nothing can be repaired and the app says so: it starts again from 0 and logs that
the old value was lost. It never makes up a value. A checksum is not a signature: someone who can
write the storage and compute SHA-256 can forge a copy, so this heals accidents, not attackers.

If handling a key raises an error, the app drops its in-memory state, reloads from storage, logs it and
carries on, instead of dying. Whole numbers only (no decimals); it needs only the 'storage' permission.

Keys: up/+ add 1   down/- subtract 1   c check now   d damage a copy (test the healing)   Ctrl-C back
"""

import hashlib
import json

from kos.sdk import App, Canvas

COPIES = ("a", "b", "c")
LOG_KEY, LOG_MAX, LOG_LINE = "heal-log", 12, 70
LIMIT = 10 ** 9                  # the counter stays inside +-LIMIT so the stored text stays small


def checksum(gen, val):
    return hashlib.sha256(f"{gen}:{val}".encode()).hexdigest()


def encode(gen, val):
    return json.dumps({"gen": gen, "val": val, "sum": checksum(gen, val)}, sort_keys=True)


def _whole(x):
    return type(x) is int and abs(x) <= 2 ** 62


def decode(text):
    """(gen, val) if ``text`` is a well-formed copy whose checksum matches, else None. Never raises."""
    try:
        d = json.loads(text)
    except (TypeError, ValueError, RecursionError):
        return None
    if not isinstance(d, dict) or set(d) != {"gen", "val", "sum"}:
        return None
    gen, val, s = d["gen"], d["val"], d["sum"]
    if not (_whole(gen) and gen >= 0 and _whole(val) and abs(val) <= LIMIT and isinstance(s, str)):
        return None
    return (gen, val) if s == checksum(gen, val) else None


def pick(found):
    """The winning (gen, val) among ``found`` (a list of (gen, val) or None), or None if none is valid."""
    good = [f for f in found if f is not None]
    if not good:
        return None
    return max(set(good), key=lambda f: (f[0], good.count(f)))     # highest generation, then most copies


def plan(found):
    """What to do about each copy: (winner, {letter: 'ok' | 'repair-damaged' | 'repair-stale'})."""
    win = pick(found)
    out = {}
    for letter, f in zip(COPIES, found):
        out[letter] = ("ok" if f == win else "repair-damaged" if f is None else "repair-stale") if win else "lost"
    return win, out


class Store:
    """The three copies and the heal log, in this app's private vault. All reads and writes are checked."""

    def __init__(self, app):
        self.app = app

    def read(self):
        return [decode(self.app.vault_get(c)) for c in COPIES]

    def write(self, letter, gen, val):
        return self.app.vault_put(letter, encode(gen, val))

    def log(self):
        try:
            d = json.loads(self.app.vault_get(LOG_KEY) or "[]")
        except (TypeError, ValueError, RecursionError):
            return ["log was damaged and was reset"]
        if not isinstance(d, list):
            return ["log was damaged and was reset"]
        return [s[:LOG_LINE] for s in d if isinstance(s, str)][-LOG_MAX:]

    def add_log(self, lines):
        if lines:
            self.app.vault_put(LOG_KEY, json.dumps((self.log() + [s[:LOG_LINE] for s in lines])[-LOG_MAX:]))


def heal(store):
    """Check every copy and repair what is wrong. Returns (value, generation, status per copy, log lines).
    value is None only when nothing could be recovered and nothing could be written."""
    found = store.read()
    win, status = plan(found)
    lines = []
    if win is None:
        gen, val = 1, 0
        if all(store.write(c, gen, val) for c in COPIES):
            lines.append("all copies lost: restarted at 0 (the old value is gone)")
            return val, gen, {c: "restarted" for c in COPIES}, lines
        lines.append("all copies lost and the storage refused a restart")
        return None, 0, {c: "lost" for c in COPIES}, lines
    gen, val = win
    for letter in COPIES:
        if status[letter] == "ok":
            continue
        if store.write(letter, gen, val):
            lines.append(f"copy {letter}: {status[letter][7:]}, repaired from generation {gen}")
            status[letter] = "repaired"
        else:
            lines.append(f"copy {letter}: {status[letter][7:]}, could not be rewritten")
            status[letter] = "unwritten"
    return val, gen, status, lines


def change(store, state, delta):
    """Write a new value to all three copies (generation + 1), keeping inside +-LIMIT."""
    val = max(-LIMIT, min(LIMIT, state["val"] + delta))
    gen = state["gen"] + 1
    for c in COPIES:
        store.write(c, gen, val)


def damage(store, state):
    """Test hook: overwrite the next copy with junk, so you can watch it get healed."""
    letter = COPIES[state["hits"] % len(COPIES)]
    state["hits"] += 1
    store.app.vault_put(letter, "garbage " + str(state["hits"]))
    return letter


def refresh(store, state):
    val, gen, status, lines = heal(store)
    state.update(val=val if val is not None else state["val"], gen=gen, status=status, ok=val is not None)
    store.add_log(lines)
    state["log"] = store.log()
    return lines


def rows(state):
    head = [f"value {state['val']}   generation {state['gen']}"] if state["ok"] else ["NOTHING COULD BE RECOVERED"]
    return head + [f"copy {c}: {state['status'].get(c, '?')}" for c in COPIES]


def tui_lines(state):
    lines = [""] + ["  " + r for r in rows(state)] + ["", "  heals so far (newest last):"]
    lines += ["    " + s for s in state["log"][-6:]] or ["    none yet"]
    lines += ["", "  up/down change   c check   d damage a copy   Ctrl-C back"]
    if state["note"]:
        lines += ["", "  " + state["note"]]
    return lines


def draw_graphical(app, state):
    c = Canvas().clear("#101820").rect(0, 0, app.width, 18, "#1f3a5f").text(6, 5, "HEALING", "#ffffff")
    y = 28
    for n, r in enumerate(rows(state)):
        bad = "unwritten" in r or "lost" in r or "NOTHING" in r
        c.text(8, y, r.upper()[:60], "#ff6060" if bad else "#ffcc00" if "repaired" in r else "#a0ffa0", 2 if n == 0 else 1)
        y += 22 if n == 0 else 12
    y += 6
    for s in state["log"][-5:]:
        c.text(8, y, s.upper()[:60], "#a0a0ff")
        y += 12
    c.text(6, app.height - 12, "UP/DOWN CHANGE  C CHECK  D DAMAGE  CTRL-C BACK", "#6080a0")
    app.present(c)


def handle(store, state, ev):
    """React to one event. True if the screen should be redrawn; False for events this app ignores."""
    cmd, key = ev["cmd"], ev.get("key")
    if cmd == "key" and key in ("up", "+", "=", "down", "-"):
        refresh(store, state)                 # heal first, so the new value is built on a good one
        change(store, state, 1 if key in ("up", "+", "=") else -1)
        state["note"] = ""
    elif cmd == "key" and key == "d":
        state["note"] = f"damaged copy {damage(store, state)}"
    elif cmd == "key" and key == "c":
        state["note"] = ""
    elif cmd != "hello" and not (cmd == "button" and ev.get("pressed")):
        return False
    refresh(store, state)
    return True


def main():
    app = App()
    store = Store(app)
    state = {"val": 0, "gen": 0, "status": {}, "log": [], "note": "", "ok": True, "hits": 0}
    for ev in app.events():
        try:
            if not handle(store, state, ev):
                continue
        except Exception as e:           # self-heal the process too: reload everything from storage and go on
            state.update(val=0, gen=0, status={}, note="")
            refresh(store, state)
            store.add_log([f"recovered from {type(e).__name__}"])
            state["log"] = store.log()
        if app.mode == "graphical":
            draw_graphical(app, state)
        else:
            app.screen("Healing", tui_lines(state), status="c: check  d: damage")
