"""pack_learn: Reference Library, KOS Help, Book Reader, Flashcards (see docs/PACKS.md).

Plain stdlib code, nothing in the background. Every input is cut to a size and every stored document is
checked against the vault's value limit before it is written."""

from __future__ import annotations

import csv
import io
import json
import math
import random

from .packkit import app, none, shared_add  # noqa: F401
from .records import Data
from .search import Index
from .specs import R
from .ui import Confirm, Editor, ListNav, Menu, Message, Prompt, Screen, SpaceHost, TextView, slug, wrap

MAXV = 390_000          # the vault refuses values over 400_000 characters
MAXIN = 200_000         # most text accepted by an import editor


def clean(s, n: int, keep_nl: bool = False) -> str:
    """Printable text only, at most n characters; control characters become spaces."""
    s = str(s)[: n * 2 + 8]
    out = "".join(c if c.isprintable() or (keep_nl and c == "\n") else " " for c in s)
    return out.strip()[:n]


def save_doc(host, key: str, doc) -> bool:
    raw = json.dumps(doc, separators=(",", ":"), ensure_ascii=False)
    return len(raw) <= MAXV and bool(host.put(key, raw))


def load_doc(host, key: str, default):
    try:
        v = json.loads(host.get(key) or "")
        return v if isinstance(v, type(default)) else default
    except (ValueError, TypeError):
        return default


class Pick(Screen):
    """A list of (label, payload); Enter calls on_pick(payload); extra single keys call keys[k](payload)."""

    def __init__(self, title, rows, on_pick, keys=None, help="up/down   Enter open   Esc back"):
        self.title, self.rows, self.on_pick, self.keys, self.help = title, rows, on_pick, keys or {}, help
        self.nav = ListNav(len(rows))

    def render(self, w, h):
        if not self.rows:
            return ["", "  (nothing here)"]
        top, end = self.nav.window(h)
        return [("> " if i == self.nav.sel else "  ") + self.rows[i][0][: max(10, w - 4)] for i in range(top, end)]

    def key(self, k):
        if self.nav.key(k):
            return None
        if k == "escape":
            return ("pop", None)
        if not self.rows:
            return None
        pay = self.rows[self.nav.sel][1]
        if k == "enter":
            return self.on_pick(pay)
        if k in self.keys:
            return self.keys[k](pay)
        return None


class Importer(Editor):
    """Paste text, Ctrl-S imports it with do(text) -> message (shown in the status line), then clears."""

    def __init__(self, title, hint, do):
        super().__init__(title, "", None, hint=hint)
        self.do = do

    def key(self, k):
        r = super().key(k)
        if len(self.area.text) > MAXIN:
            self.area.set_text(self.area.text[:MAXIN]); self.flash = "text cut to the size limit"
        return r

    def save(self):
        self.flash = clean(self.do(self.area.text[:MAXIN]), 70)
        self.area.set_text(""); self.area.dirty = False


def show(title, text, w=76):
    return ("push", TextView(title, wrap(text, w)))


# ===================================================================== Reference Library ====
REF_KEY, REF_MAX = "ref", 600


def ref_parse(line: str):
    """'term | definition | tag, tag' -> dict or None."""
    p = [x.strip() for x in str(line)[:2000].split("|", 2)]
    if len(p) < 2:
        return None
    t, d = clean(p[0], 60), clean(p[1], 600)
    if not t or not d:
        return None
    tags = []
    for g in (p[2] if len(p) > 2 else "").split(","):
        g = clean(g, 20).lower()
        if g and g not in tags and len(tags) < 8:
            tags.append(g)
    return {"t": t, "d": d, "g": tags}


def ref_prefix(entries, q):
    q = q.strip().lower()
    return sorted((e for e in entries if q and e["t"].lower().startswith(q)), key=lambda e: e["t"].lower())


def lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def ref_fuzzy(entries, q, limit=20):
    """Entries whose term is within a few edits of q (or of its same-length start), closest first."""
    q = q.strip().lower()[:60]
    if not q:
        return []
    lim, out = max(1, len(q) // 3), []
    for e in entries:
        t = e["t"].lower()
        d = min(lev(q, t), lev(q, t[: len(q)]) + 1)     # a typed start of a longer word costs one extra
        if d <= lim:
            out.append((d, t, e))
    out.sort(key=lambda x: (x[0], x[1]))
    return [e for _, _, e in out[:limit]]


def ref_search(entries, q, limit=20):
    idx = Index({str(e["id"]): f"{e['t']} {e['t']} {e['d']} {' '.join(e['g'])}" for e in entries})
    by = {str(e["id"]): e for e in entries}
    return [by[k] for k, _, _ in idx.search(q, limit)]


def ref_export(entries) -> str:
    return "\n".join(f"{e['t']} | {e['d']} | {', '.join(e['g'])}" for e in entries)


def ref_view(e) -> list:
    return [e["t"], "tags: " + (", ".join(e["g"]) or "-"), "", *wrap(e["d"], 74)]


class RefLibrary(Menu):
    def __init__(self, host, rng=None):
        self.host, self.rng = host, rng or random.Random()
        super().__init__("Reference Library", [
            ("Look up by start of term", lambda: self.ask("Term starts with", ref_prefix)),
            ("Fuzzy lookup (typos)", lambda: self.ask("Term (typos allowed)", ref_fuzzy)),
            ("Search text (BM25)", lambda: self.ask("Search words", ref_search)),
            ("Browse all", lambda: self.results("All entries", sorted(self.load()["e"], key=lambda e: e["t"].lower()))),
            ("Random entry", self.random),
            ("Add an entry", lambda: ("push", Prompt("Add", "term | definition | tags (tags optional)", on_done=self.add))),
            ("Import entries (one per line)", self.importer),
            ("Export", self.export),
            ("About", lambda: ("push", Message("About", [
                "A personal reference library: you add or import the entries.",
                "It ships NO dictionary data. Format: term | definition | tags, one per line.",
                f"Up to {REF_MAX} entries; a definition is cut at 600 characters."])))])

    def load(self):
        d = load_doc(self.host, REF_KEY, {})
        d.setdefault("nid", 1); d.setdefault("e", [])
        return d

    def add_many(self, lines):
        d, n, bad = self.load(), 0, 0
        have = {(e["t"].lower(), e["d"]) for e in d["e"]}
        for line in lines[:REF_MAX]:
            if not line.strip():
                continue
            e = ref_parse(line)
            if not e or (e["t"].lower(), e["d"]) in have:
                bad += 1; continue
            if len(d["e"]) >= REF_MAX:
                bad += 1; break
            e["id"] = d["nid"]; d["nid"] += 1; d["e"].append(e); have.add((e["t"].lower(), e["d"])); n += 1
        if n and not save_doc(self.host, REF_KEY, d):
            return "not saved: the library is full", 0
        return f"added {n}, skipped {bad}", n

    def add(self, text):
        msg, n = self.add_many([text])
        return ("push", Message("Add", [msg if n else "Not added (needs 'term | definition', or it is a duplicate or the library is full)."]))

    def importer(self):
        return ("push", Importer("Import", "Ctrl-S import", lambda t: self.add_many(t.split("\n"))[0]))

    def ask(self, label, fn):
        def go(q):
            return self.results(f"{label}: {q[:30]}", fn(self.load()["e"], q))
        return ("push", Prompt(label, label, on_done=go))

    def results(self, title, es):
        rows = [(f"{e['t']} - {e['d']}", e["id"]) for e in es]
        return ("push", Pick(title, rows, self.open, help="up/down   Enter open   Esc back"))

    def open(self, eid):
        for e in self.load()["e"]:
            if e["id"] == eid:
                v = TextView(e["t"], ref_view(e))
                v.help = "up/down scroll   f make a flashcard   Esc back"
                kv = v.key
                v.key = lambda k, e=e, kv=kv: ("push", Message("Flashcard", make_card(self.host, e["t"], e["d"]))) if k == "f" else kv(k)
                return ("push", v)
        return None

    def random(self):
        es = self.load()["e"]
        if not es:
            return ("push", Message("Random", ["The library is empty. Add or import entries first."]))
        return self.open(self.rng.choice(es)["id"])

    def export(self):
        text = ref_export(self.load()["e"])
        self.host.put("ref-export.txt", text[:MAXV])
        return ("push", TextView("Export (also kept as ref-export.txt in this app's vault)", text.split("\n")))


# ========================================================================== KOS Help ====
GUIDE = [
    ("Getting help", "`kos help` lists the commands and `kos help COMMAND` explains one. This app has the user guide, tutorials "
     "and troubleshooting for the same commands."),
    ("What KOS is", "KOS is a password-first, security-focused Linux OS written in Python. Nothing runs in the background and "
     "nothing starts by itself. Every action asks for your password. Apps are sealed .kapp files run in a Landlock and "
     "namespace sandbox. Every line typed in the shell is a command: see `kos line`."),
    ("Passwords", "`kos setup` chooses your password and `kos passwd` changes it. Each action (running an app, viewing a "
     "file, writing a file) asks for the password again, typed for that action. `kos audit` lists every decision and "
     "`kos audit --verify` checks the log for tampering."),
    ("Installing and running apps", "`kos pack DIR -o APP.kapp` builds an app. `kos install APP.kapp` scans it, then seals "
     "and installs it. `kos permit NAME` allows it to run at all; the password is still asked on every launch. "
     "`kos run NAME` runs it as a text page, `kos run graphical NAME` draws pixels, `kos run cmd NAME` shows the raw "
     "command stream. `kos open NAME` opens one and returns your shell; `kos ps` lists them, `kos attach ID` connects, "
     "`kos close ID` stops. `kos list` shows installed apps, `kos remove NAME` removes one, `kos update APP.kapp` installs "
     "a newer version (downgrades are refused)."),
    ("Files", "`kos ls PATH` and `kos cat PATH` browse real folders and zip files without extracting. `kos explore` does the "
     "same interactively. `kos view FILE` views a file after the password. `kos write PATH --text T` writes a file; it "
     "needs the administrator keyboard and owes a security scan and a disk optimize afterwards (`kos owed`, `kos settle`)."),
    ("App data and shared folders", "Each app keeps private data in its own vault; `kos dirs NAME` shows its folders. Apps "
     "share only through owned folders: `kos spaces` lists them, `kos grant APP space:NAME --level read` lets an app in "
     "(password), `kos grant --list` shows who has access."),
    ("Safety checks", "`kos security` checks everything KOS can verify about itself, read-only, no password. `kos doctor` "
     "reports kernel protections; without Landlock apps do not start. `kos scan file PATH` scans a file or zip. "
     "`kos firmware` reports management processors (Intel ME, AMD PSP, BMC) and whether the OS would boot."),
    ("Suite apps and keys", "The productivity suite apps are .kapp files: `bin/suite list` lists them and "
     "`bin/suite build DIR` packs one .kapp per app. Inside an app: Ctrl-Q quits, Esc goes back, Ctrl-N opens the "
     "built-in assistant, arrows move, Enter selects, Ctrl-S saves in editors."),
    ("Backups", "`kos backup add PATH...` stores files once per content after scanning. `kos backup list` shows them, "
     "`kos backup restore ID DIR` puts one back (never overwrites), `kos backup remove ID` forgets one."),
    ("Human language and code", "`kos do WORDS...` runs one line of human language as one command; add `--explain` to see "
     "how it was understood. `kos exec --code LINE` runs one line of code in the sandbox. `kos line` is the shell."),
    ("Extensions, desktop, addresses", "`kos extend NAME` switches an extension or mod on (password); `--list` shows what is "
     "on and `--revoke` switches one off. `kos desktop install` installs the taskbar and App Library; `kos boot desktop` "
     "starts them (`--graphical` for pixels). `kos go kos://NAME/path` opens an app by address."),
    ("Cells, USB, conversion", "`kos cell start NAME --kernel K --initrd I --cpus 2,3` starts a parallel kernel cell; "
     "`kos cell list` and `kos cell stop NAME` manage them. `kos usb list` shows disks it would write and `kos usb check IMG` "
     "verifies an image. `kos convert PKG.deb -o OUT.kapp` converts a statically linked Debian package. "
     "`kos skills --out DIR` makes agent skills."),
]

TUTORIALS = [
    ("Run your first app", ["`kos setup`: choose your password.", "`kos pack examples/hello -o hello.kapp`",
                            "`kos install hello.kapp`: it is scanned, then sealed after your password.",
                            "`kos permit hello`: allow it to run.", "`kos run hello`: type the password. The app opens.",
                            "Answer y to Boot mouse? or Boot keyboard? (with the password) to use them. Ctrl-C always quits."]),
    ("Install a suite app", ["`bin/suite build DIR`: packs every app into DIR.", "`kos install DIR/document-editor.kapp`",
                             "`kos permit document-editor`", "`kos run document-editor`. Ctrl-Q quits, Ctrl-N opens the assistant."]),
    ("Share contacts with another app", ["Install and permit both apps (contact-manager owns the contacts folder).",
                                         "`kos grant email-client space:contacts --level read`: type the password.",
                                         "`kos spaces`: see who owns it and who has access.",
                                         "`kos grant email-client space:contacts --revoke` takes access away."]),
    ("Back up and restore", ["`kos backup add PATH`: files are scanned, then stored once per content.", "`kos backup list`",
                             "`kos backup restore ID DIR`: a guarded write that never overwrites.", "`kos backup remove ID`"]),
    ("Check the system's health", ["`kos doctor`: which kernel protections this machine has.",
                                   "`kos security`: read-only check, no password.", "`kos audit --verify`: is the log intact?",
                                   "`kos owed`: does an earlier write still owe a scan or optimize? `kos settle` does it."]),
    ("Write a file", ["`kos admin status`: is the administrator keyboard booted? (`kos admin boot` boots it)",
                      "`kos write notes.txt --text hello`", "`kos owed`: shows the scan and optimize it owes.",
                      "`kos settle`: does them now."]),
]

# Troubleshooting tree. NODES: id -> (question, [(answer, next id)]); LEAVES: id -> (symptom, checks, command)
NODES = {
    "start": ("What is wrong?", [("An app will not start", "app"), ("A password, update or scan was refused", "deny"),
                                 ("Writing a file is blocked", "write"), ("Mouse or keyboard does nothing in an app", "input"),
                                 ("An app cannot reach the network or a shared folder", "net"),
                                 ("The computer will not boot or unlock", "boot"), ("I am unsure something is safe", "safe")]),
    "app": ("What does it say?", [("SECURITY or tampered", "tamper"), ("Not permitted", "permit"),
                                  ("Nothing starts at all", "doctor"), ("The app is not listed", "install")]),
    "deny": ("Which refusal?", [("Wrong password or denied", "pw"), ("An update was refused", "update"),
                                ("A scan flagged my file", "scan")]),
    "write": ("Which message?", [("It says writes are owed", "owed"), ("The administrator keyboard is missing", "admin")]),
    "net": ("Which?", [("An app has no network", "network"), ("An app cannot see a shared folder", "grant")]),
}
LEAVES = {
    "tamper": ("The app's seal no longer matches: it was modified or damaged.", "Check it is listed. Remove it and install it again from the original file.", "kos list"),
    "permit": ("The app has not been given permission to run at all.", "Check the list of permitted apps, then permit it.", "kos permit NAME"),
    "doctor": ("KOS will not start apps if the kernel cannot enforce Landlock.", "Read which protections are missing.", "kos doctor"),
    "install": ("The app is not installed.", "Install it, then permit it.", "kos install APP.kapp"),
    "pw": ("The password was refused.", "Use the password chosen with setup. See what was decided and when. Change it with the current one.", "kos audit"),
    "update": ("Updates must be newer; downgrades are refused. An update that asks for more permissions needs approval again.", "Check the version, then permit again.", "kos permit NAME"),
    "scan": ("A flagged file is never installed.", "Scan it yourself to see the finding. Do not install a file you do not trust.", "kos scan file PATH"),
    "owed": ("An earlier write still owes a security scan and a disk optimize, which blocks the next write.", "See what is owed, then settle it.", "kos settle"),
    "admin": ("Writing needs the elevated administrator keyboard.", "Check its status, then boot it.", "kos admin status"),
    "input": ("Devices stay off until booted with the password.", "Answer y to Boot mouse? or Boot keyboard? at launch. Ctrl-C always quits.", "kos run NAME"),
    "network": ("An app has no network of its own. The OS fetches for it over verified https only if its manifest asks AND a firewall rule allows that host (kos firewall).", "Look at the app's permissions and folders.", "kos dirs NAME"),
    "grant": ("An app is let into a shared folder only after you grant it.", "See owners and access, then grant it.", "kos spaces"),
    "boot": ("The boot gate refuses when a management processor (ME, PSP, BMC) is running.", "Read the status and the advice. kos.firmware=warn on the kernel command line boots anyway.", "kos firmware plan"),
    "safe": ("You want to know whether the system is intact.", "Run the read-only check, then verify the audit log.", "kos security"),
}


def help_docs() -> dict:
    d = {f"g{i}": (t, b) for i, (t, b) in enumerate(GUIDE)}
    d.update({f"t{i}": (t, "\n".join(f"{n}. {s}" for n, s in enumerate(st, 1))) for i, (t, st) in enumerate(TUTORIALS)})
    d.update({f"x{k}": (s, f"{s}\nCheck: {c}\nCommand: {m}") for k, (s, c, m) in LEAVES.items()})
    return d


def help_search(q: str, limit: int = 15) -> list:
    docs = help_docs()
    idx = Index({k: t + " " + b for k, (t, b) in docs.items()})
    return [(k, docs[k][0]) for k, _, _ in idx.search(q[:80], limit)]


class Tree(Screen):
    title = "Troubleshooting"
    help = "up/down   Enter choose   Esc back"

    def __init__(self):
        self.path, self.nav = ["start"], ListNav(len(NODES["start"][1]))

    def render(self, w, h):
        n = self.path[-1]
        if n in LEAVES:
            s, c, m = LEAVES[n]
            return ["", *("  " + x for x in wrap(s, w - 4)), "", "  Check:", *("    " + x for x in wrap(c, w - 6)), "", f"  Command:  {m}"]
        q, ans = NODES[n]
        return ["", "  " + q, ""] + [("  > " if i == self.nav.sel else "    ") + f"{i + 1}. {a}" for i, (a, _) in enumerate(ans)]

    def key(self, k):
        n = self.path[-1]
        if k == "escape":
            if len(self.path) == 1:
                return ("pop", None)
            self.path.pop(); self.nav = ListNav(len(NODES[self.path[-1]][1])); return None
        if n in LEAVES:
            return None
        ans = NODES[n][1]
        if self.nav.key(k):
            return None
        i = int(k) - 1 if len(k) == 1 and k.isdigit() else (self.nav.sel if k == "enter" else -1)
        if 0 <= i < len(ans):
            self.path.append(ans[i][1])
            self.nav = ListNav(len(NODES[ans[i][1]][1]) if ans[i][1] in NODES else 0)
        return None


def kos_help(host, entry=None):
    def doc(k):
        t, b = help_docs()[k]
        return show(t, b)

    def listing(title, keys):
        docs = help_docs()
        return ("push", Pick(title, [(docs[k][0], k) for k in keys], doc))

    def search(q):
        return ("push", Pick(f"Search: {q[:30]}", [(t, k) for k, t in help_search(q)], doc))

    return Menu("KOS Help", [
        ("Search help", lambda: ("push", Prompt("Search", "Search words", on_done=search))),
        ("User guide", lambda: listing("User guide", [f"g{i}" for i in range(len(GUIDE))])),
        ("Tutorials", lambda: listing("Tutorials", [f"t{i}" for i in range(len(TUTORIALS))])),
        ("Troubleshooting (symptom -> checks -> command)", lambda: ("push", Tree())),
    ], ["  Help for KOS and the suite. Commands shown are the real `kos` commands."])


# ======================================================================== Book Reader ====
BOOK_MAX, BM_MAX, HL_MAX = 150_000, 50, 200


def book_text(raw: str) -> str:
    raw = raw.replace("\r\n", "\n").replace("\r", "\n").replace("\t", "    ")
    return "".join(c for c in raw[:BOOK_MAX] if c == "\n" or c.isprintable())


def book_layout(lines, width):
    rows = []
    for i, l in enumerate(lines):
        for seg in wrap(l, max(10, width)):
            rows.append((i, seg))
    return rows


def book_chapters(lines):
    out = []
    for i, l in enumerate(lines):
        s = l.lstrip("#")
        if l.startswith("#") and len(l) - len(s) <= 6 and s.startswith(" ") and s.strip():
            out.append((len(l) - len(s), s.strip()[:60], i))
    return out


def book_find(lines, q, start=0):
    """Index of the first line at or after start containing q (case-insensitive), wrapping round; -1 if none."""
    q = q.lower()
    if not q or not lines:
        return -1
    for k in range(len(lines)):
        i = (start + k) % len(lines)
        if q in lines[i].lower():
            return i
    return -1


class Reader(Screen):
    def __init__(self, host, bid):
        self.host, self.bid = host, bid
        self.lines = (host.get("b-" + bid) or "").split("\n")
        self.meta = load_doc(host, "m-" + bid, {})
        for k, v in (("t", bid), ("top", 0), ("bm", []), ("hl", [])):
            self.meta.setdefault(k, v)
        self.title, self.width, self.rows, self.top, self.ph, self.q = self.meta["t"], 0, [], 0, 18, ""
        self.help = "space/PgDn next  b/PgUp prev  c chapters  m mark  g marks  / find  n next  h highlight  H notes"

    def _layout(self, w):
        if w != self.width:
            self.width, self.rows = w, book_layout(self.lines, w - 4)
            self.goto(self.meta["top"], save=False)

    def goto(self, src, save=True):
        self.top = next((r for r, (i, _) in enumerate(self.rows) if i >= src), max(0, len(self.rows) - 1))
        self.moved(save)

    def moved(self, save=True):
        self.top = max(0, min(self.top, max(0, len(self.rows) - 1)))
        self.meta["top"] = self.rows[self.top][0] if self.rows else 0
        if save:
            save_doc(self.host, "m-" + self.bid, self.meta)

    def pct(self):
        return 100 * (self.top + min(self.ph, len(self.rows) - self.top)) // max(1, len(self.rows))

    def render(self, w, h):
        self._layout(w)
        self.ph = max(1, h - 2)
        hl = {x["l"] for x in self.meta["hl"]}
        bm = {x["l"] for x in self.meta["bm"]}
        out, last = [f" {self.title[:40]}  {self.pct()}%  page {self.top // self.ph + 1}/{max(1, -(-len(self.rows) // self.ph))}", ""], -1
        for i, seg in self.rows[self.top:self.top + self.ph]:
            mark = ("*" if i in hl else "#" if i in bm else " ") if i != last else " "
            out.append(f" {mark} {seg}"); last = i
        return out

    def key(self, k):
        if k in ("pagedown", " ", "right"): self.top += self.ph
        elif k in ("pageup", "b", "left"): self.top -= self.ph
        elif k == "down": self.top += 1
        elif k == "up": self.top -= 1
        elif k == "home": self.top = 0
        elif k == "end": self.top = len(self.rows)
        elif k == "escape": return ("pop", None)
        elif k == "c":
            ch = book_chapters(self.lines)
            return ("push", Pick("Chapters", [("  " * (lv - 1) + t, i) for lv, t, i in ch], lambda i: self.jump(i)))
        elif k == "m": return ("push", Prompt("Bookmark", "Label (optional)", on_done=self.mark))
        elif k == "g":
            rows = [(f"line {x['l'] + 1}: {x['n'] or self.lines[x['l']][:50]}", x["l"]) for x in self.meta["bm"]]
            return ("push", Pick("Bookmarks", rows, lambda i: self.jump(i), {"d": self.unmark}, "Enter go   d delete   Esc back"))
        elif k == "/": return ("push", Prompt("Find", "Find in this book", on_done=self.find))
        elif k == "n":
            if self.q:
                self.jump_find(self.q, self.meta["top"] + 1)
            return None
        elif k == "h": return ("push", Prompt("Highlight", "Note for this page's first line (optional)", on_done=self.highlight))
        elif k == "H":
            rows = [(f"line {x['l'] + 1}: {self.lines[x['l']][:40]} -- {x['n']}", x["l"]) for x in self.meta["hl"]]
            return ("push", Pick("Highlights and notes", rows, lambda i: self.jump(i), {"d": self.unhl, "f": self.card}, "Enter go   d delete   f make a flashcard   Esc back"))
        else: return None
        self.moved()
        return None

    def jump(self, i):
        self.goto(i)
        return ("pop", None)

    def mark(self, label):
        i = self.meta["top"]
        if len(self.meta["bm"]) < BM_MAX and not any(x["l"] == i for x in self.meta["bm"]):
            self.meta["bm"].append({"l": i, "n": clean(label, 60)}); save_doc(self.host, "m-" + self.bid, self.meta)

    def unmark(self, i):
        self.meta["bm"] = [x for x in self.meta["bm"] if x["l"] != i]; save_doc(self.host, "m-" + self.bid, self.meta)
        return ("pop", None)

    def highlight(self, note):
        i = self.meta["top"]
        if len(self.meta["hl"]) < HL_MAX:
            self.meta["hl"] = [x for x in self.meta["hl"] if x["l"] != i] + [{"l": i, "n": clean(note, 200)}]
            save_doc(self.host, "m-" + self.bid, self.meta)

    def card(self, i):
        n = next((x["n"] for x in self.meta["hl"] if x["l"] == i), "")
        return ("push", Message("Flashcard", make_card(self.host, n or f"{self.title}, line {i + 1}", self.lines[i], "Reading")))

    def unhl(self, i):
        self.meta["hl"] = [x for x in self.meta["hl"] if x["l"] != i]; save_doc(self.host, "m-" + self.bid, self.meta)
        return ("pop", None)

    def jump_find(self, q, start):
        i = book_find(self.lines, q, start)
        if i >= 0:
            self.goto(i)
        return i

    def find(self, q):
        self.q = clean(q, 60)
        if self.jump_find(self.q, 0) < 0:
            return ("push", Message("Find", ["Not found."]))


class Library(Screen):
    title = "Book Reader"
    help = "Enter read   n new book   d delete   Esc quit"

    def __init__(self, host):
        self.host, self.nav, self.ids = host, ListNav(0), []

    def on_enter(self):
        self.ids = sorted(k[2:] for k in self.host.keys() if k.startswith("m-"))[:BM_MAX]
        self.nav.resize(len(self.ids))

    def meta(self, bid):
        return load_doc(self.host, "m-" + bid, {})

    def render(self, w, h):
        if not self.ids:
            return ["", "  No books yet. Press n to add one: type or paste plain text or Markdown.",
                    f"  Headings (# Title) become chapters. A book is cut at {BOOK_MAX} characters."]
        top, end = self.nav.window(h)
        out = []
        for i in range(top, end):
            m = self.meta(self.ids[i])
            out.append(("> " if i == self.nav.sel else "  ") + f"{m.get('t', self.ids[i])[:50]}  line {m.get('top', 0) + 1}")
        return out

    def key(self, k):
        if self.nav.key(k):
            return None
        if k == "n":
            return ("push", Prompt("New book", "Title", on_done=self.new))
        if k == "enter" and self.ids:
            return ("push", Reader(self.host, self.ids[self.nav.sel]))
        if k == "d" and self.ids:
            bid = self.ids[self.nav.sel]
            return ("push", Confirm(f"Delete this book and its notes?", lambda: self.delete(bid)))

    def delete(self, bid):
        self.host.delete("b-" + bid); self.host.delete("m-" + bid)
        self.on_enter()

    def new(self, title):
        title = clean(title, 60)
        if not title:
            return None
        if len(self.ids) >= BM_MAX:
            return ("push", Message("Book Reader", ["The library is full."]))
        bid, n = slug(title)[:40], 2
        while bid in self.ids:
            bid = slug(title)[:36] + f"-{n}"; n += 1

        def put(text):
            self.host.put("b-" + bid, book_text(text))
            old = load_doc(self.host, "m-" + bid, {})
            save_doc(self.host, "m-" + bid, {"t": title, "top": 0, "bm": old.get("bm", []), "hl": old.get("hl", [])})
            self.on_enter()
        return ("push", Editor(f"Add: {title}", "", put, hint="Ctrl-S store the book"))


# ========================================================================== Flashcards ====
# Cards live in the shared space "decks" (records: deck, front, back; the scheduling fields ef, n, i, due, s, r are
# extra keys this app adds). Cards other apps add have only deck/front/back and count as new.
DECK_MAX, CARD_MAX, SIDE_MAX, SESSION = 30, 700, 200, 50
SPEC = R("decks", "Flashcards", "card", "deck*; front*; back*")


def num(v, default, cast=float):
    try:
        return cast(v)
    except (TypeError, ValueError, OverflowError):
        return default


def sm2(card: dict, q: int, today: int) -> dict:
    """One review of the published SuperMemo SM-2 algorithm. q is the 0-5 grade.
    q >= 3: interval 1 day, then 6, then previous interval * EF (rounded half up), repetitions + 1.
    q < 3: start again (repetitions 0, interval 1) with EF unchanged.
    EF' = EF + 0.1 - (5-q)(0.08 + (5-q)0.02) when q >= 3 (applied after the interval is chosen), never below 1.3."""
    q = max(0, min(5, int(q)))
    ef, n, i = card["ef"], card["n"], card["i"]
    if q >= 3:
        i = 1 if n == 0 else 6 if n == 1 else math.floor(i * ef + 0.5)
        n += 1
        ef = max(1.3, ef + 0.1 - (5 - q) * (0.08 + (5 - q) * 0.02))
    else:
        n, i = 0, 1
    return {**card, "ef": ef, "n": n, "i": i, "due": today + i, "s": 1}


def card_of(rec: dict, today: int) -> dict:
    """A record from the shared space as a card; missing or odd fields mean a new card due today."""
    ef = num(rec.get("ef"), 2.5)
    return {"id": rec.get("_id"), "d": str(rec.get("deck", ""))[:40], "f": str(rec.get("front", ""))[:SIDE_MAX],
            "b": str(rec.get("back", ""))[:SIDE_MAX], "r": 1 if num(rec.get("r"), 0, int) else 0,
            "ef": max(1.3, min(5.0, ef)) if ef == ef else 2.5, "n": max(0, num(rec.get("n"), 0, int)),
            "i": max(0, num(rec.get("i"), 0, int)), "due": num(rec.get("due"), today, int),
            "s": 1 if num(rec.get("s"), 0, int) else 0}


class Cards:
    def __init__(self, host):
        self.host, self.data = host, Data(SpaceHost(host, "decks"), SPEC)

    def cards(self, deck, today) -> list:
        return [card_of(r, today) for r in self.data.items if isinstance(r, dict) and str(r.get("deck", "")) == deck]

    def names(self) -> list:
        extra = load_doc(self.host, "names", [])
        return sorted({str(x)[:40] for x in extra if x} | {str(r.get("deck", ""))[:40] for r in self.data.items if r.get("deck")})[:DECK_MAX]

    def add_deck(self, name):
        names = [x for x in load_doc(self.host, "names", []) if x != name][:DECK_MAX]
        self.host.put("names", json.dumps(names + [name]))

    def add_many(self, deck, pairs, both, today) -> int:
        """Add (front, back) pairs, plus reverse cards when both. Skips duplicates; stops at the caps. One save."""
        have = {(str(r.get("front")), str(r.get("back")), num(r.get("r"), 0, int)) for r in self.data.items if str(r.get("deck")) == deck}
        n, d = 0, self.data.d
        for f, b in pairs:
            f, b = clean(f, SIDE_MAX), clean(b, SIDE_MAX)
            for rv in ((0, 1) if both else (0,)):
                if not f or not b or (f, b, rv) in have or len(d["items"]) >= CARD_MAX:
                    continue
                d["items"].append({"deck": deck, "front": f, "back": b, "r": rv, "ef": 2.5, "n": 0, "i": 0, "due": today, "s": 0,
                                   "_id": d["next"], "_at": ""})
                d["next"] += 1; n += 1; have.add((f, b, rv))
        if n:
            if len(json.dumps(d, separators=(",", ":"))) > MAXV:
                del d["items"][-n:]
                return 0
            self.data.save()
            if self.data.error:
                return 0
        return n

    def import_csv(self, deck, text, both, today) -> int:
        pairs = []
        try:
            for row in csv.reader(io.StringIO(text[:MAXIN])):
                if len(row) >= 2:
                    pairs.append((row[0], row[1]))
        except csv.Error:
            pass
        return self.add_many(deck, pairs[:CARD_MAX], both, today)

    def save_card(self, c: dict) -> None:
        for r in self.data.items:
            if r.get("_id") == c["id"]:
                r.update(ef=c["ef"], n=c["n"], i=c["i"], due=c["due"], s=c["s"], r=c["r"])
        self.data.save()

    def delete_deck(self, name):
        self.data.d["items"] = [r for r in self.data.items if str(r.get("deck", "")) != name]
        self.data.save()
        self.host.put("names", json.dumps([x for x in load_doc(self.host, "names", []) if x != name]))
        rv = load_doc(self.host, "rv", {}); rv.pop(name, None); self.host.put("rv", json.dumps(rv))

    def review(self, deck, ok: bool):
        rv = load_doc(self.host, "rv", {})
        t = rv.get(deck) if isinstance(rv.get(deck), list) and len(rv.get(deck)) == 2 else [0, 0]
        rv[deck] = [t[0] + 1, t[1] + (1 if ok else 0)]
        self.host.put("rv", json.dumps(rv))

    def rv(self, deck) -> list:
        v = load_doc(self.host, "rv", {}).get(deck)
        return v if isinstance(v, list) and len(v) == 2 else [0, 0]


def deck_due(cards, today):
    return sorted((c for c in cards if c["due"] <= today), key=lambda c: (c["due"], c["id"] or 0))


def deck_stats(cards, rv, today) -> dict:
    seen = [c for c in cards if c["s"]]
    tot, ok = rv
    return {"cards": len(cards), "new": sum(1 for c in cards if not c["s"]),
            "due": sum(1 for c in cards if c["due"] <= today), "overdue": sum(1 for c in seen if c["due"] < today),
            "mature": sum(1 for c in seen if c["i"] >= 21),
            "avg_ef": round(sum(c["ef"] for c in seen) / len(seen), 2) if seen else 0.0,
            "reviews": tot, "retention": round(100 * ok / tot) if tot else 0,
            "next7": [sum(1 for c in seen if c["due"] == today + d) for d in range(1, 8)]}


class Study(Screen):
    def __init__(self, host, deck, clock):
        self.store, self.deck, self.clock, self.shown, self.again, self.done = Cards(host), deck, clock, False, set(), 0
        cs = self.store.cards(deck, clock())
        self.by = {c["id"]: c for c in cs}
        self.queue = [c["id"] for c in deck_due(cs, clock())[:SESSION]]
        self.title = "Study: " + deck
        self.help = "Space show answer   0-5 grade (0 blackout ... 5 perfect)   Esc stop"

    def render(self, w, h):
        if not self.queue:
            return ["", f"  Session finished: {self.done} reviews.", "  Esc to go back."]
        c = self.by[self.queue[0]]
        q, a = (c["b"], c["f"]) if c["r"] else (c["f"], c["b"])
        out = ["", f"  {len(self.queue)} left", "", *("  " + x for x in wrap(q, w - 4))]
        if self.shown:
            out += ["", "  ----", *("  " + x for x in wrap(a, w - 4)), "", "  Grade: 0 1 2 3 4 5"]
        return out

    def key(self, k):
        if k == "escape":
            return ("pop", None)
        if not self.queue:
            return None
        if not self.shown:
            if k in (" ", "enter"):
                self.shown = True
            return None
        if len(k) == 1 and k in "012345":
            q, cid = int(k), self.queue.pop(0)
            if cid not in self.again:                       # the scheduling review
                self.by[cid] = sm2(self.by[cid], q, self.clock())
                self.store.save_card(self.by[cid]); self.store.review(self.deck, q >= 3); self.done += 1
            if q < 4:                                       # SM-2 step 7: ask again this session until >= 4
                self.queue.append(cid); self.again.add(cid)
            self.shown = False
        return None


class DeckScreen(Screen):
    help = "s study  a add  A add+reverse  i import CSV  I import CSV+reverse  t stats  Esc back"

    def __init__(self, host, deck, clock):
        self.host, self.deck, self.clock, self.title = host, deck, clock, deck

    def stats(self):
        st = Cards(self.host)
        return deck_stats(st.cards(self.deck, self.clock()), st.rv(self.deck), self.clock())

    def render(self, w, h):
        s = self.stats()
        return ["", f"  {s['cards']} cards: {s['due']} due, {s['new']} new, {s['overdue']} overdue", "",
                "  s  study the due cards (up to %d per session)" % SESSION, "  a  add a card (front | back)",
                "  A  add a card and its reverse", "  i  import CSV (front,back)", "  I  import CSV with reverse cards",
                "  t  statistics"]

    def add(self, text, both):
        f, _, b = text.partition("|")
        n = Cards(self.host).add_many(self.deck, [(f, b)], both, self.clock())
        return ("push", Message("Add", [f"Added {n} card(s)." if n else "Not added (needs 'front | back', not a duplicate, deck not full)."]))

    def imp(self, both):
        def do(text):
            n = Cards(self.host).import_csv(self.deck, text, both, self.clock())
            return f"imported {n} cards" if n else "nothing imported"
        return ("push", Importer("Import CSV", "Ctrl-S import  front,back per line", do))

    def key(self, k):
        if k == "escape": return ("pop", None)
        if k == "s": return ("push", Study(self.host, self.deck, self.clock))
        if k in ("a", "A"): return ("push", Prompt("Add", "front | back", on_done=lambda t: self.add(t, k == "A")))
        if k in ("i", "I"): return self.imp(k == "I")
        if k == "t":
            s = self.stats()
            return ("push", Message("Statistics", [f"cards {s['cards']}   new {s['new']}   due {s['due']}   overdue {s['overdue']}",
                                                   f"mature (interval >= 21 days) {s['mature']}   average ease {s['avg_ef']}",
                                                   f"reviews {s['reviews']}   retention (grade >= 3) {s['retention']}%",
                                                   "due in the next 7 days: " + " ".join(map(str, s["next7"]))]))


class Decks(Screen):
    title = "Flashcards"
    help = "Enter open   n new deck   d delete deck   Esc quit"

    def __init__(self, host, clock=None):
        from datetime import date
        self.host, self.nav, self.names = host, ListNav(0), []
        self.clock = clock or (lambda: date.today().toordinal())

    def on_enter(self):
        self.names = Cards(self.host).names()
        self.nav.resize(len(self.names))

    def render(self, w, h):
        if not self.names:
            return ["", "  No decks yet. Press n to make one.", "  Scheduling is SM-2; grade 0-5 after seeing the answer."]
        st, today = Cards(self.host), self.clock()
        top, end = self.nav.window(h)
        out = []
        for i in range(top, end):
            s = deck_stats(st.cards(self.names[i], today), [0, 0], today)
            out.append(("> " if i == self.nav.sel else "  ") + f"{self.names[i][:40]}  due {s['due']}  new {s['new']}  total {s['cards']}")
        return out

    def key(self, k):
        if self.nav.key(k):
            return None
        if k == "n":
            return ("push", Prompt("New deck", "Deck name", on_done=self.new))
        if k == "enter" and self.names:
            return ("push", DeckScreen(self.host, self.names[self.nav.sel], self.clock))
        if k == "d" and self.names:
            name = self.names[self.nav.sel]
            return ("push", Confirm("Delete this deck and its cards?", lambda: (Cards(self.host).delete_deck(name), self.on_enter())[1]))

    def new(self, name):
        name = clean(name, 40)
        if name and len(self.names) < DECK_MAX:
            Cards(self.host).add_deck(name); self.on_enter()


def make_card(host, front, back, deck="Reference") -> list:
    """For apps that only use the shared space: add one card, or say plainly why not."""
    ok = shared_add(host, "decks", {"deck": deck, "front": clean(front, SIDE_MAX), "back": clean(back, SIDE_MAX)})
    return ["Card added to deck '%s'. Open Flashcards to study it." % deck] if ok else [
        "Could not add the card: this app has no write access to the shared 'decks' folder (or it is full).",
        "Grant it with your password: kos grant APP space:decks --level write (APP is this app's name)."]


# ================================================================================ entries ====
ENTRIES = [
    app("Reference Library", lambda host, e: RefLibrary(host), "partial",
        "A personal reference library: you add or import entries (term | definition | tags). Ships NO dictionary data; "
        "no pronunciation, synonyms or online lookup. Prefix, fuzzy and BM25 search, random entry, export. Can add an entry "
        "to the shared decks folder as a flashcard (needs a write grant).", uses=["decks"]),
    app("KOS Help", lambda host, e: kos_help(host, e), "full",
        "Searchable user guide, step-by-step tutorials and a troubleshooting tree for KOS and the suite, "
        "written from this repository's real commands."),
    app("Book Reader", lambda host, e: Library(host), "partial",
        "Reads plain text and Markdown books you type or paste into the vault (no EPUB, PDF or file import): paged reading, "
        "chapters from # headings, bookmarks, progress, find, highlights with notes. Books are cut at 150000 characters. Highlights can become flashcards in the shared decks folder (needs a write grant).", uses=["decks"]),
    app("Flashcards", lambda host, e: Decks(host), "full",
        "Decks, SM-2 spaced repetition, due counts, CSV paste import (front,back), reverse cards and statistics. "
        "No images or audio on cards, no sync. Cards live in the shared decks folder.", owns=["decks"]),
]
