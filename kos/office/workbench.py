"""The workbench: pick a tool, paste text or data, run it. Plus the chat
assistant (local tools + optional model) and the model-settings screen."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import llm, tools
from .search import Index
from .ui import (Editor, ListNav, Menu, Message, Prompt, Screen, Store, TextInput, TextView, wrap)


@dataclass
class Tool:
    key: str
    label: str
    fn: Callable                 # fn(text, param) -> list[str]
    param: str = ""              # prompt for an extra argument ("" = none)
    sample: str = ""
    help: str = ""


def table_tool(key, label, fn, param="", sample="", help=""):
    def run(text, p):
        cols, rows = tools.parse_table(text)
        if not cols: return ["paste a table first (CSV, TSV or JSON)"]
        return fn(cols, rows, p)
    return Tool(key, label, run, param, sample, help)


CSV_SAMPLE = "region,product,qty,price\nNorth,Widget,10,2.5\nSouth,Widget,4,2.5\nNorth,Gadget,3,10\nSouth,Gadget,8,10\nEast,Widget,15,2.5\n"

TOOLS = {
    "summarize": Tool("summarize", "Summarize (extractive)", lambda t, p: tools.summarize(t, int(p or 3)) + ["", "keywords: " + ", ".join(tools.keywords(t, 8))],
                      "How many sentences? (default 3)", help="Picks the most representative sentences. It does not paraphrase."),
    "extract": Tool("extract", "Extract emails, dates, money, URLs…", lambda t, p: tools.extract(t)),
    "writing": Tool("writing", "Writing check + readability", lambda t, p: [f"{k}: {v}" for k, v in __import__("kos.office.docs", fromlist=["stats"]).stats(t).items()] + [""] + tools.writing_check(t)),
    "dlp": Tool("dlp", "Sensitive-data scan + redact", lambda t, p: (lambda f, r: (f or ["nothing sensitive found"]) + ["", "--- redacted ---", *r.split("\n")])(*tools.dlp(t))),
    "threats": Tool("threats", "Log threat rules", lambda t, p: tools.threats(t),
                    sample="Failed password for root from 10.1.1.9 port 22\n" * 5 + "GET /index.php?id=1 UNION SELECT user FROM users\n"),
    "meeting": Tool("meeting", "Action items & decisions", lambda t, p: tools.meeting(t),
                    sample="Decided to ship on Friday.\nAction: Sam to update the docs\nTODO write release notes\nWho owns QA?\n"),
    "recommend": Tool("recommend", "Recommend items (ratings)", lambda t, p: tools.recommend(t, p), "For which user? (blank = first)",
                      sample="ann,matrix,5\nann,alien,4\nbob,matrix,5\nbob,heat,4\ncat,alien,5\ncat,heat,2\ncat,matrix,4\n"),
    "translate": Tool("translate", "Glossary translate (en→es/fr/de)", lambda t, p: (lambda o, u: [o, "", "not in glossary: " + ", ".join(u)] if u else [o])(
        *tools.glossary_translate(t, tools.SEED_GLOSSARY.get((p or "es").strip().lower(), {}))), "Target language: es, fr or de",
        help="Phrase glossary lookup, not machine translation."),
    "analyze": table_tool("analyze", "Analyze a table (stats, outliers, correlations)", lambda c, r, p: tools.analyze(c, r), sample=CSV_SAMPLE),
    "chart": table_tool("chart", "Chart a column", lambda c, r, p: tools.chart(c, r, p), "Column, 'LABEL VALUE', or 'line VALUE'", CSV_SAMPLE),
    "transform": table_tool("transform", "Transform a table (pipeline)", lambda c, r, p: (lambda cc, rr, lg: tools.to_csv(cc, rr).split("\n") + ["", *lg])(*tools.transform(c, r, p)),
                            "Pipeline, e.g. filter qty>3 | addcol total = qty*price | sort total desc", CSV_SAMPLE),
    "import": table_tool("import", "Import & profile a dataset", lambda c, r, p: [f"{len(r)} rows, {len(c)} columns", *(f"  {k}: {v}" for k, v in tools.infer_types(c, r).items()), "", *tools.to_csv(c, r[:8]).split("\n")], sample=CSV_SAMPLE),
}


class Workbench(Screen):
    def __init__(self, host, title: str, keys: list, intro: str = ""):
        self.host, self.title, self.st = host, title, Store(host)
        self.tools = [TOOLS[k] if isinstance(k, str) else k for k in keys]
        self.intro = intro
        self.nav = ListNav(len(self.tools))
        self.help = "up/down   Enter open tool   Esc quit"

    def render(self, w, h):
        out = (wrap(self.intro, w - 4) + [""]) if self.intro else []
        for i, t in enumerate(self.tools):
            out.append(f"{'>' if i == self.nav.sel else ' '} {i + 1}. {t.label}")
        return out

    def key(self, k):
        if self.nav.key(k): return
        if k == "escape": return ("quit",)
        if k == "enter" or (len(k) == 1 and k.isdigit() and 0 < int(k) <= len(self.tools)):
            t = self.tools[self.nav.sel if k == "enter" else int(k) - 1]
            return ("push", self.open_tool(t))

    def open_tool(self, t: Tool) -> Screen:
        draft = self.st.load("in-" + t.key, t.sample)
        def run(ed):
            ed.on_save(ed.area.text)
            if t.param:
                last = self.st.load("param-" + t.key, "")
                return ("push", Prompt(t.label, t.param, last, lambda v: self.finish(t, ed.area.text, v)))
            return self.finish(t, ed.area.text, "")
        return Editor(t.label, draft, lambda text: self.st.save("in-" + t.key, text), extra_keys={"ctrl-r": run},
                      hint="Ctrl-R run" + (f"   ({t.help})" if t.help else ""))

    def finish(self, t: Tool, text: str, param: str):
        self.st.save("param-" + t.key, param)
        try:
            out = t.fn(text, param)
        except Exception as e:                 # a tool must never take the app down
            out = [f"error: {type(e).__name__}: {e}"]
        self.host.put("export-" + t.key + ".txt", "\n".join(out))
        return ("push", TextView(t.label + " - result", out + ["", "(saved to vault key export-" + t.key + ".txt)"]))


# ------------------------------------------------------- model settings ----
class ModelSettings(Screen):
    title = "Model"

    def __init__(self, host):
        self.st = Store(host)
        self.cfg = self.st.load("llm", {})
        self.nav = ListNav(4)
        self.help = "up/down   Enter change   Esc back"

    def render(self, w, h):
        c = self.cfg
        key = ("*" * 6 + c["key"][-4:]) if c.get("key") else "(not set)"
        rows = [f"provider : {c.get('provider', '(none) - local tools only')}", f"model    : {c.get('model', '')}",
                f"endpoint : {c.get('endpoint') or '(default for provider)'}", f"api key  : {key}"]
        return ["  Without a model every assistant still works with its local tools.", "  A model request is made by the OS and only if the firewall has a rule for this app (kos firewall allow).", ""] + \
               [f"{'>' if i == self.nav.sel else ' '} {r}" for i, r in enumerate(rows)] + ["", "  Key is stored in this app's vault in clear text; use a revocable key."]

    def key(self, k):
        if self.nav.key(k): return
        if k == "escape": return ("pop", None)
        if k == "enter":
            f = ["provider", "model", "endpoint", "key"][self.nav.sel]
            hint = {"provider": "anthropic or openai (openai = any OpenAI-compatible endpoint)", "model": "Model id", "endpoint": "Endpoint URL (blank = default)", "key": "API key"}[f]
            return ("push", Prompt("Model", hint, "" if f == "key" else self.cfg.get(f, ""), lambda v: self.set(f, v), secret=(f == "key")))

    def set(self, f, v):
        v = v.strip()
        if f == "provider" and v not in llm.DEFAULTS and v: return
        if v: self.cfg[f] = v
        else: self.cfg.pop(f, None)
        if f == "provider" and v and not self.cfg.get("model"): self.cfg["model"] = llm.DEFAULTS[v]["model"]
        self.st.save("llm", self.cfg)


class Chat(Screen):
    """Chat assistant. A model if configured, otherwise honest local tools:
    /summarize /keywords /extract /check /calc /remember /recall /forget /clear"""

    def __init__(self, host, title: str, system: str, extra_local: Callable = None):
        self.host, self.title, self.system, self.extra = host, title, system, extra_local
        self.st = Store(host)
        self.hist = self.st.load("chat", [])
        self.mem: dict = self.st.load("memory", {})
        self.inp = TextInput()
        self.top = -1
        self.help = "Enter send   ^L model settings   PgUp/PgDn scroll   /help"

    def render(self, w, h):
        lines = []
        for who, text in self.hist[-60:]:
            ls = wrap(text, w - 6)
            lines += [f"{who:>4}: {ls[0]}"] + ["      " + x for x in ls[1:]] + [""]
        body = max(3, h - 3)
        mx = max(0, len(lines) - body)
        top = mx if self.top < 0 else min(self.top, mx)
        mode = "model" if llm.configured(self.st.load("llm", {})) else "local tools (no model)"
        return lines[top:top + body] + [f"[{mode}]", "you> " + self.inp.render()]

    def say(self, who, text):
        self.hist.append([who, text]); self.hist[:] = self.hist[-200:]; self.st.save("chat", self.hist)

    def local(self, text: str) -> str:
        cmd, _, rest = text.partition(" ")
        if cmd == "/help": return "/summarize TEXT  /keywords TEXT  /extract TEXT  /check TEXT  /calc EXPR  /remember TEXT  /recall QUERY  /forget  /clear"
        if cmd == "/summarize": return " ".join(tools.summarize(rest, 2)) or "give me some text"
        if cmd == "/keywords": return ", ".join(tools.keywords(rest)) or "give me some text"
        if cmd == "/extract": return "\n".join(tools.extract(rest))
        if cmd == "/check": return "\n".join(tools.writing_check(rest))
        if cmd == "/calc":
            from .sheet import Sheet, to_str
            s = Sheet({"A1": "=" + rest}); return to_str(s.value("A1")) if s.display("A1") else ""
        if cmd == "/remember":
            self.mem[f"m{len(self.mem) + 1}"] = rest; self.st.save("memory", self.mem); return f"remembered ({len(self.mem)} notes)"
        if cmd == "/forget": self.mem.clear(); self.st.save("memory", self.mem); return "forgot everything"
        if cmd == "/clear": self.hist.clear(); self.st.save("chat", self.hist); return ""
        hits = Index(self.mem).search(rest if cmd == "/recall" else text, 3)
        if self.extra:
            r = self.extra(text, hits)
            if r: return r
        if hits: return "From what you told me:\n" + "\n".join("- " + self.mem[k] for k, _s, _n in hits)
        return "No model is configured, so I can only use my local tools (try /help) or search what you /remember. Press Ctrl-L to connect a model."

    def key(self, k):
        if k == "enter" and self.inp.value.strip():
            text = self.inp.value.strip(); self.inp = TextInput(); self.top = -1
            self.say("you", text)
            cfg = self.st.load("llm", {})
            if llm.configured(cfg) and not text.startswith("/"):
                msgs = [{"role": "user" if w == "you" else "assistant", "content": t} for w, t in self.hist[-20:] if w in ("you", "ai")]
                ctx = self.system + ("\nNotes the user asked you to remember:\n" + "\n".join(self.mem.values()) if self.mem else "")
                try: reply = llm.ask(self.host, cfg, ctx, msgs)
                except llm.LLMError as e: reply = f"(model error: {e}) " + self.local(text)
            else:
                reply = self.local(text)
            if reply: self.say("ai", reply)
        elif k == "ctrl-l": return ("push", ModelSettings(self.host))
        elif k == "pageup": self.top = max(0, (len(self.hist) * 3 if self.top < 0 else self.top) - 8)
        elif k == "pagedown": self.top = -1
        elif k == "escape": return ("quit",)
        else: self.inp.key(k)
