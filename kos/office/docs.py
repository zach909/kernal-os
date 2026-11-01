"""Documents: the library (many named documents per app), the text editor with
find/replace/outline/preview/export, a Markdown->HTML converter, readability
statistics, slides (with polls and branching) and notes with backlinks."""

from __future__ import annotations

import html
import re

from .search import Index
from .ui import (Confirm, Editor, ListNav, Message, Prompt, Screen, Store, TextView, bar, now_stamp,
                 slug, table, wrap)


# ----------------------------------------------------------- text helpers --
def md_html(md: str, title: str = "") -> str:
    out, para, in_list = [], [], False

    def inline(s):
        s = html.escape(s)
        s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
        s = re.sub(r"(?<!\*)\*(?!\s)(.+?)(?<!\s)\*(?!\*)", r"<i>\1</i>", s)
        s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
        return re.sub(r"\[(.+?)\]\((https?://[^\s)]+)\)", r'<a href="\2">\1</a>', s)

    def flush():
        nonlocal para
        if para: out.append("<p>" + inline(" ".join(para)) + "</p>"); para = []

    def close_list():
        nonlocal in_list
        if in_list: out.append("</ul>"); in_list = False

    for line in md.split("\n"):
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        b = re.match(r"^\s*[-*]\s+(.*)$", line)
        if m:
            flush(); close_list(); n = len(m.group(1)); out.append(f"<h{n}>{inline(m.group(2))}</h{n}>")
        elif b:
            flush()
            if not in_list: out.append("<ul>"); in_list = True
            out.append(f"<li>{inline(b.group(1))}</li>")
        elif not line.strip():
            flush(); close_list()
        else:
            close_list(); para.append(line.strip())
    flush(); close_list()
    return ("<!doctype html><meta charset=utf-8><title>" + html.escape(title) + "</title><body>\n"
            + "\n".join(out) + "\n</body>\n")


def preview(md: str, width: int) -> list:
    out = []
    for line in md.split("\n"):
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        b = re.match(r"^\s*[-*]\s+(.*)$", line)
        if m:
            t = m.group(2).upper() if len(m.group(1)) == 1 else m.group(2)
            out += ["", t, ("=" if len(m.group(1)) == 1 else "-") * min(len(t), width)]
        elif b:
            w = wrap(b.group(1), width - 4)
            out += ["  • " + w[0]] + ["    " + x for x in w[1:]]
        else:
            out += wrap(re.sub(r"\*\*?|`", "", line), width)
    return out


def words(text: str) -> list: return re.findall(r"[A-Za-z0-9'’-]+", text)


def syllables(w: str) -> int:
    w = w.lower().strip("'’-")
    n = len(re.findall(r"[aeiouy]+", w))
    if w.endswith("e") and not w.endswith(("le", "ee")) and n > 1: n -= 1
    return max(1, n)


def stats(text: str) -> dict:
    ws = words(text)
    sents = [s for s in re.split(r"[.!?]+(?:\s|$)", text) if s.strip()]
    syl = sum(syllables(w) for w in ws)
    flesch = (206.835 - 1.015 * (len(ws) / max(1, len(sents))) - 84.6 * (syl / max(1, len(ws)))) if ws else 0.0
    return {"words": len(ws), "chars": len(text), "lines": text.count("\n") + 1, "sentences": len(sents),
            "paragraphs": len([p for p in re.split(r"\n\s*\n", text) if p.strip()]),
            "reading_min": round(len(ws) / 230, 1), "flesch": round(flesch, 1),
            "grade": round(0.39 * (len(ws) / max(1, len(sents))) + 11.8 * (syl / max(1, len(ws))) - 15.59, 1) if ws else 0.0}


# --------------------------------------------------------------- library ----
class Library(Screen):
    """Named documents for an app. ``opener(name, text, save)`` -> Screen."""

    def __init__(self, host, title: str, noun: str, opener, template: str = "", prefix: str = "doc-"):
        self.host, self.title, self.noun, self.opener = host, title, noun, opener
        self.template, self.prefix = template, prefix
        self.st = Store(host)
        self.idx: dict = self.st.load("index", {})
        self.nav = ListNav(len(self.idx))
        self.msg = ""
        self.help = f"n new  Enter open  r rename  d delete  c copy  / find in all"

    def names(self): return sorted(self.idx, key=lambda n: self.idx[n]["at"], reverse=True)

    def render(self, w, h):
        ns = self.names(); self.nav.resize(len(ns))
        out = [f" {len(ns)} {self.noun}(s)", ""]
        if not ns: out += [f"  No {self.noun}s yet. Press n to create one."]
        top, end = self.nav.window(h - 4)
        for i in range(top, end):
            n = ns[i]
            out.append(f"{'>' if i == self.nav.sel else ' '} {n[:40]:<40} {self.idx[n]['at']}")
        if self.msg: out += ["", " " + self.msg]
        return out

    def _save_index(self): self.st.save("index", self.idx)

    def load(self, name): return self.host.get(self.idx[name]["key"]) or ""

    def store(self, name, text):
        if name not in self.idx:
            base, k, i = self.prefix + slug(name), None, 1
            k = base
            used = {v["key"] for v in self.idx.values()}
            while k in used: i += 1; k = f"{base}-{i}"
            self.idx[name] = {"key": k, "at": now_stamp()}
        self.idx[name]["at"] = now_stamp()
        self.host.put(self.idx[name]["key"], text)
        self._save_index()

    def create(self, name, text=None):
        name = name.strip()
        if not name: return
        if name in self.idx: self.msg = "that name exists"; return
        self.store(name, self.template if text is None else text)
        return ("push", self.opener(name, self.load(name), lambda t, n=name: self.store(n, t)))

    def key(self, k):
        self.msg = ""
        ns = self.names()
        if self.nav.key(k): return
        cur = ns[self.nav.sel] if ns else None
        if k == "n": return ("push", Prompt("New", f"Name of the new {self.noun}:", "", self.create))
        if k == "enter" and cur:
            return ("push", self.opener(cur, self.load(cur), lambda t, n=cur: self.store(n, t)))
        if k == "d" and cur: return ("push", Confirm(f"Delete '{cur}'?", lambda: self._delete(cur)))
        if k == "r" and cur: return ("push", Prompt("Rename", "New name:", cur, lambda v: self._rename(cur, v)))
        if k == "c" and cur: return ("push", Prompt("Copy", "Name of the copy:", cur + " copy",
                                                    lambda v: self.create(v, self.load(cur)) if v.strip() and v not in self.idx else None))
        if k == "/":
            return ("push", Prompt("Find", "Find in all " + self.noun + "s:", "", self._find))
        if k == "escape": return ("quit",)

    def _delete(self, n):
        self.host.delete(self.idx[n]["key"]); del self.idx[n]; self._save_index(); self.msg = "deleted"

    def _rename(self, old, new):
        new = new.strip()
        if new and new not in self.idx:
            self.idx[new] = self.idx.pop(old); self._save_index()

    def _find(self, q):
        ix = Index({n: self.load(n) for n in self.idx})
        res = ix.search(q)
        lines = [f"{n}  ({s:.1f})\n   {sn}" for n, s, sn in res] or ["no matches"]
        return ("push", TextView(f"Find: {q}", [l for x in lines for l in x.split("\n")]))


# ---------------------------------------------------------- doc editor ----
class DocEditor(Editor):
    def __init__(self, host, name, text, save, ext="md", assist=None):
        self.host, self.name, self.ext = host, name, ext
        extra = {
            "ctrl-f": lambda s: ("push", Prompt("Find", "Find:", "", s.find)),
            "ctrl-r": lambda s: ("push", Prompt("Replace all", "old=>new :", "", s.replace)),
            "ctrl-w": lambda s: ("push", Message("Statistics", [f"{k}: {v}" for k, v in stats(s.area.text).items()])),
            "ctrl-o": lambda s: ("push", TextView("Outline", s.outline())),
            "ctrl-p": lambda s: ("push", TextView("Preview", preview(s.area.text, 76))),
            "ctrl-e": lambda s: s.export(),
        }
        if assist:
            extra["ctrl-g"] = lambda s: ("push", TextView("Assist", assist(s.area.text)))
        super().__init__(name, text, save, extra_keys=extra,
                         hint="^F find ^R replace ^W stats ^O outline ^P preview ^E export" + (" ^G assist" if assist else ""))

    def find(self, q):
        if not q: return
        low = [l.lower() for l in self.area.lines]
        n = len(low)
        for off in range(1, n + 1):
            r = (self.area.r + off) % n if self.area.c >= len(low[self.area.r]) or off > 1 else self.area.r
            i = low[r].find(q.lower(), self.area.c + 1 if r == self.area.r else 0)
            if i >= 0:
                self.area.r, self.area.c = r, i; self.flash = f"found at line {r + 1}"; return
        self.flash = "not found"

    def replace(self, spec):
        if "=>" not in spec: self.flash = "use old=>new"; return
        old, new = spec.split("=>", 1)
        if not old: return
        c = self.area.text.count(old)
        self.area.set_text(self.area.text.replace(old, new)); self.flash = f"replaced {c}"

    def outline(self):
        out = [f"{'  ' * (len(m.group(1)) - 1)}{m.group(2)}  (line {i + 1})"
               for i, l in enumerate(self.area.lines) if (m := re.match(r"^(#{1,6})\s+(.*)$", l))]
        return out or ["no headings (lines starting with #)"]

    def export(self):
        """Plain text/markdown and HTML copies go to the vault (exports/ keys)."""
        base = slug(self.name)
        self.save()
        self.host.put(f"export-{base}.{self.ext}", self.area.text)
        self.host.put(f"export-{base}.html", md_html(self.area.text, self.name))
        self.flash = f"exported: export-{base}.{self.ext}, export-{base}.html"


# --------------------------------------------------------------- slides ----
def parse_slides(text: str) -> list:
    out = []
    for chunk in re.split(r"(?m)^---\s*$", text):
        if chunk.strip():
            out.append(chunk.strip("\n"))
    return out or [""]


def render_slide(src: str, w: int, h: int, votes: dict | None = None, n: int = 0, total: int = 0) -> list:
    inner = w - 6
    lines, notes = [], []
    for raw in src.split("\n"):
        if raw.startswith(">"): notes.append(raw[1:].strip()); continue
        m = re.match(r"^#\s+(.*)$", raw)
        if m:
            t = m.group(1).upper(); lines += ["", t.center(inner), ("=" * min(len(t), inner)).center(inner), ""]; continue
        m = re.match(r"^##\s+(.*)$", raw)
        if m: lines += ["", m.group(1), "-" * min(len(m.group(1)), inner)]; continue
        m = re.match(r"^\s*[-*]\s+(.*)$", raw)
        if m:
            w2 = wrap(m.group(1), inner - 4); lines += ["  • " + w2[0]] + ["    " + x for x in w2[1:]]; continue
        m = re.match(r"^\?\s*(.+?)\s*\|\s*(.+)$", raw)
        if m:
            opts = [o.strip() for o in m.group(2).split("|")]
            tot = sum((votes or {}).get(f"{n}:{i}", 0) for i in range(len(opts))) or 1
            lines += ["", "POLL: " + m.group(1)]
            for i, o in enumerate(opts):
                v = (votes or {}).get(f"{n}:{i}", 0)
                lines.append(f"  [{chr(97 + i)}] {o:<20} {v:>3} {bar(v, tot, 16)}")
            continue
        m = re.match(r"^\[(.+?)\]\(#(\d+)\)\s*$", raw)
        if m: lines.append(f"  → [{m.group(2)}] {m.group(1)}"); continue
        lines += wrap(raw, inner) if raw.strip() else [""]
    pad = max(0, h - 4 - len(lines))
    box = ["+" + "-" * (w - 4) + "+"] + ["| " + l[:inner + 1].ljust(inner + 1) + "|" for l in lines[:h - 4]] \
          + ["| " + " " * (inner + 1) + "|" for _ in range(pad)] + ["+" + "-" * (w - 4) + "+"]
    return box + [f" slide {n}/{total}" + (f"   notes: {' '.join(notes)}" if notes else "")]


class Presenter(Screen):
    def __init__(self, name, text, st: Store | None = None):
        self.title, self.slides, self.i, self.st = "Present " + name, parse_slides(text), 0, st
        self.votes = (st.load("votes", {}) if st else {})
        self.help = "left/right slide   digit jump to [n] link   a-z vote on poll   Esc end"

    def render(self, w, h): return render_slide(self.slides[self.i], w, h, self.votes, self.i + 1, len(self.slides))

    def key(self, k):
        if k == "escape": return ("pop", None)
        if k in ("right", "enter", " ", "pagedown"): self.i = min(len(self.slides) - 1, self.i + 1)
        elif k in ("left", "backspace", "pageup"): self.i = max(0, self.i - 1)
        elif k == "home": self.i = 0
        elif k == "end": self.i = len(self.slides) - 1
        elif len(k) == 1 and k.isdigit() and f"](#{k})" in self.slides[self.i]:
            self.i = min(len(self.slides), int(k)) - 1
        elif len(k) == 1 and k.isalpha():
            n = sum(1 for l in self.slides[self.i].split("\n") if l.startswith("?"))
            for l in self.slides[self.i].split("\n"):
                m = re.match(r"^\?\s*(.+?)\s*\|\s*(.+)$", l)
                if m and ord(k) - 97 < len(m.group(2).split("|")):
                    key = f"{self.i + 1}:{ord(k) - 97}"; self.votes[key] = self.votes.get(key, 0) + 1
                    if self.st: self.st.save("votes", self.votes)
                    break


SLIDE_TEMPLATE = "# Title\n\n- first point\n- second point\n> speaker notes start with >\n---\n## Next slide\n\n- more\n"


def slide_editor(host, name, text, save):
    def present(s): return ("push", Presenter(name, s.area.text, Store(host)))
    def outline(s):
        return ("push", TextView("Slides", [f"{i + 1}. " + (re.search(r"(?m)^#+\s+(.*)$", c) or re.search(r"(?m)^(.+)$", c) or [0, "(empty)"])[1]
                                           for i, c in enumerate(parse_slides(s.area.text))]))
    def export(s):
        host.put(f"export-{slug(name)}.html", "<!doctype html><meta charset=utf-8><body>" + "<hr>".join(
            md_html(c) for c in parse_slides(s.area.text)) + "</body>")
        s.flash = "exported html to vault"
    return Editor(name, text, save, extra_keys={"ctrl-p": present, "ctrl-o": outline, "ctrl-e": export},
                  hint="--- splits slides  ^P present  ^O outline  ^E export")


# ---------------------------------------------------------------- notes ----
class NoteBook(Screen):
    """Notes with #tags, [[links]], backlinks and ranked search."""

    def __init__(self, host, title="Notes", noun="note"):
        self.lib = Library(host, title, noun, self.open_note, template="# \n\n")
        self.host, self.title = host, title
        self.nav = self.lib.nav

    def open_note(self, name, text, save):
        lib = self.lib

        def backlinks(s):
            hits = [n for n in lib.idx if n != name and f"[[{name}]]".lower() in lib.load(n).lower()]
            links = re.findall(r"\[\[(.+?)\]\]", s.area.text)
            return ("push", TextView("Links", ["Linked from:", *([f"  {h}" for h in hits] or ["  (none)"]), "",
                                              "Links to:", *([f"  {l}{'' if l in lib.idx else '  (missing)'}" for l in links] or ["  (none)"])]))
        def tags(s):
            return ("push", TextView("Tags", sorted({t for t in re.findall(r"(?<!\w)#([A-Za-z][\w-]*)", s.area.text)}) or ["(no tags)"]))
        return Editor(name, text, save, extra_keys={"ctrl-b": backlinks, "ctrl-t": tags}, hint="^B links  ^T tags")

    def render(self, w, h): return self.lib.render(w, h)
    def status(self): return self.lib.help + "  t tags"
    def on_enter(self): self.lib.idx = Store(self.host).load("index", {}); self.lib.nav.resize(len(self.lib.idx))
    def key(self, k):
        if k == "t":
            tags: dict = {}
            for n in self.lib.idx:
                for t in set(re.findall(r"(?<!\w)#([A-Za-z][\w-]*)", self.lib.load(n))):
                    tags.setdefault(t, []).append(n)
            return ("push", TextView("All tags", [f"#{t}: {', '.join(sorted(v))}" for t, v in sorted(tags.items())] or ["no tags yet"]))
        return self.lib.key(k)
