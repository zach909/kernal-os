"""Builders: a schema language that compiles to a working record app (no-code,
low-code, forms), a static-site/CMS builder, and a chatbot builder."""

from __future__ import annotations

import html
import re

from . import tools
from .docs import Library, md_html
from .records import Data, Field, KINDS, RecordList, Spec
from .search import tokens
from .ui import (Editor, ListNav, Menu, Message, Prompt, Screen, Store, TextInput, TextView, slug, wrap)

SCHEMA_HELP = """table Orders "order"            <- table NAME "singular noun"
customer: text*                  <- field: kind  (* = required)
qty: number
price: money
status: choice(new|paid|shipped) = new
due: date
total = qty * price              <- calculated field (spreadsheet formulas,
                                    other fields are variables)
kinds: """ + ", ".join(KINDS)

SCHEMA_SAMPLE = """table Orders "order"
customer: text*
qty: number
price: money
status: choice(new|paid|shipped) = new
due: date
total = qty * price
"""


class SchemaError(Exception):
    pass


def parse_schema(text: str) -> list:
    specs, cur = [], None
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.split("#")[0].strip() if not raw.strip().startswith('table') else raw.strip()
        if not line: continue
        m = re.match(r'^table\s+([A-Za-z][\w ]*?)(?:\s+"([^"]+)")?$', line)
        if m:
            name = m.group(1).strip()
            cur = {"id": slug(name), "title": name, "item": m.group(2) or "record", "fields": [], "calc": []}
            specs.append(cur); continue
        if cur is None: raise SchemaError(f"line {n}: start with: table NAME \"noun\"")
        m = re.match(r"^([a-z][a-z0-9_]*)\s*=\s*(.+)$", line)
        if m:
            cur["calc"].append((m.group(1), m.group(2).strip()))
            if not any(f.key == m.group(1) for f in cur["fields"]):
                cur["fields"].append(Field(m.group(1), m.group(1).replace("_", " ").title(), "text"))
            continue
        m = re.match(r"^([a-z][a-z0-9_]*)\s*:\s*([a-z]+)(?:\(([^)]*)\))?(\*)?(?:\s*=\s*(.*))?$", line)
        if not m: raise SchemaError(f"line {n}: cannot read '{line}'")
        key, kind, ch, req, default = m.groups()
        if kind not in KINDS: raise SchemaError(f"line {n}: unknown kind '{kind}'")
        if kind == "choice" and not ch: raise SchemaError(f"line {n}: choice needs options, e.g. choice(a|b)")
        cur["fields"].append(Field(key, key.replace("_", " ").title(), kind, tuple(c.strip() for c in (ch or "").split("|") if c.strip()),
                                   (default or "").strip(), bool(req)))
    out = []
    for c in specs:
        if not c["fields"]: raise SchemaError(f"table {c['title']} has no fields")
        status = next((f.key for f in c["fields"] if f.kind == "choice"), "")
        out.append(Spec(c["id"], c["title"], c["item"], c["fields"], status=status,
                        amount=next((f.key for f in c["fields"] if f.kind == "money"), ""),
                        due=next((f.key for f in c["fields"] if f.kind == "date"), ""), calc=tuple(c["calc"])))
    if not out: raise SchemaError("no tables defined")
    return out


class AppBuilder(Screen):
    """Define tables in the schema language, then use them as real apps."""

    def __init__(self, host, title: str, noun: str = "record", guided: bool = False):
        self.host, self.title, self.st, self.guided = host, title, Store(host), guided
        self.schema = self.st.load("schema", SCHEMA_SAMPLE)
        self.msg = ""
        self.nav = ListNav(0)
        self.help = "up/down   Enter open   d design (edit schema)   Esc quit"

    def specs(self):
        try: return parse_schema(self.schema), ""
        except SchemaError as e: return [], str(e)

    def render(self, w, h):
        specs, err = self.specs(); self.nav.resize(len(specs))
        out = [" Your tables (press d to design, Enter to use):", ""]
        for i, s in enumerate(specs):
            n = len((self.st.load("data-" + s.id) or {}).get("items", []))
            out.append(f"{'>' if i == self.nav.sel else ' '} {s.title}  ({len(s.fields)} fields, {n} {s.item}s)")
        if err: out += ["", "  ! schema problem: " + err]
        if self.msg: out += ["", " " + self.msg]
        return out

    def key(self, k):
        self.msg = ""
        if self.nav.key(k): return
        specs, _ = self.specs()
        if k == "enter" and specs:
            s = specs[self.nav.sel]
            return ("push", RecordList(Data(self.host, s, "data-" + s.id)))
        if k == "d":
            if self.guided:
                return ("push", Prompt("Add field", "Add a field as  name: kind  (e.g. email: email*)  or  table Name \"noun\":", "", self.add_line))
            return ("push", Editor("Design - schema", self.schema, on_save=self.save_schema, hint="? see Ctrl-H",
                                   extra_keys={"ctrl-h": lambda s: ("push", TextView("Schema language", SCHEMA_HELP.split("\n")))}))
        if k == "escape": return ("quit",)

    def save_schema(self, text):
        self.schema = text; self.st.save("schema", text)

    def add_line(self, v):
        if not v.strip(): return
        trial = self.schema.rstrip("\n") + "\n" + v.strip() + "\n"
        try: parse_schema(trial)
        except SchemaError as e: self.msg = str(e); return
        self.save_schema(trial); self.msg = "added"


# ---------------------------------------------------------------- sites ----
SITE_CSS = "body{font:16px/1.5 system-ui,sans-serif;max-width:46em;margin:2em auto;padding:0 1em;color:#222}nav a{margin-right:1em}nav{border-bottom:1px solid #ccc;padding-bottom:.5em;margin-bottom:1.5em}.card{border:1px solid #ccc;border-radius:8px;padding:.8em;margin:.6em 0}"


def parse_page(text: str) -> tuple[dict, str]:
    meta, lines = {}, text.split("\n")
    i = 0
    while i < len(lines) and re.match(r"^(title|nav|status|link|summary|date):", lines[i]):
        k, v = lines[i].split(":", 1); meta[k] = v.strip(); i += 1
    return meta, "\n".join(lines[i:]).lstrip("\n")


class SiteBuilder(Library):
    """Pages are Markdown with optional header lines (title:, nav:, status:,
    link:). Build writes a linked static site into the vault (site-*.html).
    kind: website | portal | intranet | cms"""

    def __init__(self, host, title: str, kind: str = "website"):
        self.kind = kind
        tpl = {"website": "title: New page\nnav: 10\n\n# New page\n\nWrite here.\n",
               "portal": "title: New page\nnav: 10\nlink: https://example.org\nsummary: What this is\n\n# New page\n",
               "intranet": "title: Announcement\nnav: 10\ndate: \n\n# Announcement\n\n",
               "cms": "title: Untitled\nstatus: draft\nnav: 10\ndate: \n\n# Untitled\n\n"}[kind]
        super().__init__(host, title, "page" if kind != "cms" else "entry", self._open, tpl, "page-")
        self.help += "  b build site"

    def _open(self, name, text, save):
        return Editor(name, text, save, hint="^B build site   ^P preview", extra_keys={
            "ctrl-b": lambda s: (save(s.area.text), self.build())[1], "ctrl-p": lambda s: ("push", TextView("Preview", __import__("kos.office.docs", fromlist=["preview"]).preview(parse_page(s.area.text)[1], 76)))})

    def build(self):
        pages = []
        for n in self.idx:
            meta, body = parse_page(self.load(n))
            if self.kind == "cms" and meta.get("status", "draft") != "published": continue
            pages.append((int(meta.get("nav", "50") or 50) if (meta.get("nav", "50") or "50").lstrip("-").isdigit() else 50, meta.get("title") or n, n, meta, body))
        pages.sort()
        nav = "<nav>" + "".join(f'<a href="site-{slug(n)}.html">{html.escape(t)}</a>' for _o, t, n, _m, _b in pages) + "</nav>"
        count = 0
        for _o, t, n, meta, body in pages:
            extra = ""
            if meta.get("link"): extra = f'<p><a href="{html.escape(meta["link"])}">{html.escape(meta["link"])}</a></p>'
            doc = md_html(body, t).replace("<body>", f"<style>{SITE_CSS}</style><body>{nav}", 1).replace("</body>", extra + "</body>")
            self.host.put(f"site-{slug(n)}.html", doc); count += 1
        if pages:
            cards = "".join(f'<div class="card"><a href="site-{slug(n)}.html"><b>{html.escape(t)}</b></a><br>{html.escape(m.get("summary", ""))}</div>' for _o, t, n, m, _b in pages)
            home = f"<!doctype html><meta charset=utf-8><title>{html.escape(self.title)}</title><style>{SITE_CSS}</style><body>{nav}<h1>{html.escape(self.title)}</h1>{cards}</body>"
            self.host.put("site-index.html", home)
        self.msg = f"built {count} page(s) -> site-index.html" if count else "nothing to build (cms: only status: published is built)"
        return ("push", Message("Build", [self.msg]))


# -------------------------------------------------------------- chatbot ----
BOT_SAMPLE = """intent greet
patterns: hello | hi | good morning
reply: Hello! How can I help?

intent hours
patterns: opening hours | when are you open | what time do you close
reply: We are open 9:00-17:00, Monday to Friday.

intent order
patterns: i want to order | place an order | buy
slots: name | item
reply: Thanks {name}, one {item} is on its way.

fallback: Sorry, I did not understand. Try asking about hours or placing an order.
"""


def parse_bot(text: str) -> dict:
    intents, fallback, cur = [], "Sorry, I did not understand.", None
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"): continue
        k, _, v = line.partition(" ") if line.startswith("intent ") else line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if k == "intent": cur = {"name": v, "patterns": [], "reply": "", "slots": []}; intents.append(cur)
        elif k == "fallback": fallback = v
        elif cur is not None and k == "patterns": cur["patterns"] = [p.strip() for p in v.split("|") if p.strip()]
        elif cur is not None and k == "reply": cur["reply"] = v
        elif cur is not None and k == "slots": cur["slots"] = [p.strip() for p in v.split("|") if p.strip()]
    return {"intents": intents, "fallback": fallback}


def match_intent(bot: dict, utterance: str) -> tuple[dict | None, float]:
    ut = set(tokens(utterance)); low = utterance.lower(); best, score = None, 0.0
    for it in bot["intents"]:
        for p in it["patterns"]:
            pt = set(tokens(p))
            if not pt: continue
            s = 1.0 if p.lower() in low else len(pt & ut) / len(pt | ut) * (1.0 if len(pt & ut) >= min(2, len(pt)) else 0.4)
            if s > score: best, score = it, s
    return (best, score) if score >= 0.5 else (None, score)


class BotConsole(Screen):
    """Edit the bot (Ctrl-E), talk to it, see what it could not answer."""

    def __init__(self, host, title: str, slots: bool = True):
        self.host, self.title, self.st = host, title, Store(host)
        self.src = self.st.load("bot", BOT_SAMPLE)
        self.log = [("bot", "Say something. Ctrl-E edits the bot, Ctrl-A shows analytics.")]
        self.inp = TextInput()
        self.state: dict | None = None            # slot filling in progress
        self.stats = self.st.load("stats", {"hits": {}, "unhandled": []})
        self.slots_on = slots
        self.help = "Enter send   ^E edit bot   ^A analytics   ^X reset chat"

    def render(self, w, h):
        out = []
        for who, t in self.log[-40:]:
            ls = wrap(t, w - 8); out += [f"{who:>4}: {ls[0]}"] + ["      " + x for x in ls[1:]]
        return out[-(h - 3):] + ["", "you> " + self.inp.render()]

    def reply(self, text: str) -> str:
        bot = parse_bot(self.src)
        if self.state:
            st = self.state; st["vals"][st["slots"][st["i"]]] = text; st["i"] += 1
            if st["i"] < len(st["slots"]): return f"What is the {st['slots'][st['i']]}?"
            self.state = None
            return re.sub(r"\{(\w+)\}", lambda m: st["vals"].get(m.group(1), m.group(0)), st["it"]["reply"])
        it, score = match_intent(bot, text)
        if not it:
            self.stats["unhandled"] = (self.stats["unhandled"] + [text])[-100:]; self.st.save("stats", self.stats); return bot["fallback"]
        self.stats["hits"][it["name"]] = self.stats["hits"].get(it["name"], 0) + 1; self.st.save("stats", self.stats)
        if self.slots_on and it["slots"]:
            self.state = {"it": it, "slots": it["slots"], "i": 0, "vals": {}}
            return f"What is the {it['slots'][0]}?"
        return re.sub(r"\{(\w+)\}", r"\1", it["reply"])

    def key(self, k):
        if k == "enter" and self.inp.value.strip():
            t = self.inp.value.strip(); self.inp = TextInput(); self.log += [("you", t), ("bot", self.reply(t))]
        elif k == "ctrl-e": return ("push", Editor("Bot definition", self.src, on_save=self.save, hint="intent/patterns/reply/slots/fallback"))
        elif k == "ctrl-a":
            hits = self.stats["hits"]
            return ("push", TextView("Analytics", ["Intent hits:"] + [f"  {n}: {c}" for n, c in sorted(hits.items(), key=lambda x: -x[1])]
                                     + ["", "Not understood (add patterns for these):"] + [f"  - {u}" for u in self.stats["unhandled"][-20:]]))
        elif k == "ctrl-x": self.log, self.state = [("bot", "reset")], None
        elif k == "escape": return ("quit",)
        else: self.inp.key(k)

    def save(self, t): self.src = t; self.st.save("bot", t)
