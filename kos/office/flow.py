"""Flows: small step pipelines over a text register. One engine behind the
workflow-automation, agent, macro and document/email/form-automation apps.

    flow Weekly digest
    enabled: yes
    step: set Revenue grew 12%. Costs fell 3%. Churn is flat.
    step: summarize 2
    step: save digest

Steps: set TEXT | input | summarize N | keywords N | extract | dlp | check |
pipeline SCRIPT | template TEXT | recall QUERY | calc EXPR | ask PROMPT | save NAME
(`ask` uses a model if one is configured, otherwise it is skipped and says so.)
KOS has no background services, so nothing here runs on a timer: flows run
when you run them."""

from __future__ import annotations

import re

from . import llm, tools
from .sheet import Sheet, to_str
from .ui import (Confirm, Editor, ListNav, Prompt, Screen, Store, TextInput, TextView, now_stamp, wrap)

SAMPLE = """flow Weekly digest
enabled: yes
goal: shrink a long update into two sentences
step: input
step: summarize 2
step: save digest

flow Order report
enabled: yes
goal: top orders by value from a pasted table
step: input
step: pipeline addcol total = qty*price | sort total desc | limit 3
step: save top-orders

flow Mail merge
enabled: no
goal: one personalised line per row
step: input
step: template Dear {name}, your order {item} has shipped.
"""


def parse_flows(text: str) -> list:
    flows, cur = [], None
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"): continue
        if line.lower().startswith("flow "):
            cur = {"name": line[5:].strip(), "enabled": True, "goal": "", "steps": []}; flows.append(cur)
        elif cur is not None:
            k, _, v = line.partition(":")
            k = k.strip().lower()
            if k == "enabled": cur["enabled"] = v.strip().lower() in ("yes", "true", "1", "on")
            elif k == "goal": cur["goal"] = v.strip()
            elif k == "step": cur["steps"].append(v.strip())
    return flows


def run_flow(flow: dict, inp: str, host=None, cfg: dict | None = None, notes: dict | None = None) -> tuple[str, list]:
    """-> (final register, trace). Never raises: a failing step ends the run."""
    reg, trace = inp, [f"run '{flow['name']}' with {len(inp)} chars of input"]
    for n, step in enumerate(flow["steps"], 1):
        op, _, arg = step.partition(" "); op = op.lower(); arg = arg.strip()
        try:
            if op == "set": reg = arg
            elif op == "input": reg = inp
            elif op == "summarize": reg = " ".join(tools.summarize(reg, int(arg or 3)))
            elif op == "keywords": reg = ", ".join(tools.keywords(reg, int(arg or 8)))
            elif op == "extract": reg = "\n".join(tools.extract(reg))
            elif op == "dlp": f, reg = tools.dlp(reg); trace.append(f"   {len(f)} sensitive item(s) redacted")
            elif op == "check": reg = "\n".join(tools.writing_check(reg))
            elif op == "calc": reg = to_str(Sheet({"A1": "=" + arg}).value("A1"))
            elif op == "recall":
                from .search import Index
                hits = Index(notes or {}).search(arg or reg, 3); reg = "\n".join((notes or {})[k] for k, _s, _n in hits) or "(nothing remembered)"
            elif op == "pipeline":
                cols, rows = tools.parse_table(reg)
                if not cols: raise ValueError("register is not a table")
                c2, r2, log = tools.transform(cols, rows, arg); reg = tools.to_csv(c2, r2).rstrip("\n"); trace += ["   " + l for l in log]
            elif op == "template":
                cols, rows = tools.parse_table(reg)
                c2, r2, _ = tools.transform(cols, rows, 'template "' + arg + '"'); reg = "\n".join(r["text"] for r in r2)
            elif op == "ask":
                if not llm.configured(cfg): trace.append(f"{n}. ask: skipped (no model configured)"); continue
                reg = llm.ask(host, cfg, "Follow the instruction using the text provided.", [{"role": "user", "content": f"{arg}\n\n---\n{reg}"}])
            elif op == "save":
                if host: host.put("export-" + re.sub(r"[^a-z0-9._-]", "-", (arg or flow["name"]).lower())[:48] + ".txt", reg)
            else: raise ValueError(f"unknown step '{op}'")
            trace.append(f"{n}. {op} -> {len(reg)} chars")
        except Exception as e:
            trace.append(f"{n}. {op} FAILED: {e}"); break
    return reg, trace


class FlowApp(Screen):
    """role: builder (edit + run) | manager (registry, enable/disable, history) | recorder (build by doing)"""

    def __init__(self, host, title: str, role: str = "builder", sample: str = "", sample_input: str = ""):
        self.host, self.title, self.role, self.st = host, title, role, Store(host)
        self.src = self.st.load("flows", sample or SAMPLE)
        self.inp = self.st.load("input", sample_input or "Revenue grew 12% this quarter. Costs fell 3%. Churn is flat. Hiring resumes in March.\n")
        self.hist = self.st.load("history", [])
        self.nav = ListNav(0)
        self.msg = ""
        self.recording: list | None = None
        self.rec_line = TextInput()
        self.help = "Enter run  e edit flows  i input  h history" + ("  space enable/disable  R run all enabled" if role == "manager" else "") + ("  m record a macro" if role == "recorder" else "")

    def flows(self): return parse_flows(self.src)

    def render(self, w, h):
        if self.recording is not None: return self.render_rec(w, h)
        fl = self.flows(); self.nav.resize(len(fl))
        out = [f" {len(fl)} flow(s)   input: {len(self.inp)} chars", ""]
        last = {x["flow"]: x for x in self.hist}
        for i, f in enumerate(fl):
            l = last.get(f["name"])
            out.append(f"{'>' if i == self.nav.sel else ' '} {'[on] ' if f['enabled'] else '[off]'} {f['name']:<24} {len(f['steps'])} steps   "
                       + (f"last {l['at']} {l['status']}" if l else "never run"))
            if i == self.nav.sel and f["goal"]: out.append("       goal: " + f["goal"])
        if self.msg: out += ["", " " + self.msg]
        return out

    def render_rec(self, w, h):
        reg, _ = run_flow({"name": "recording", "steps": self.recording}, self.inp, None, self.st.load("llm", {}))
        out = [" Recording: type a step and press Enter; each step runs on the result of the previous ones.", "",
               *(f"  {i + 1}. {s}" for i, s in enumerate(self.recording)), "", " Register now:"]
        out += ["   " + l for l in reg.split("\n")[:max(3, h - len(self.recording) - 9)]]
        return out + ["", "step> " + self.rec_line.render()]

    def key(self, k):
        self.msg = ""
        if self.recording is not None: return self.key_rec(k)
        if self.nav.key(k): return
        fl = self.flows(); cur = fl[self.nav.sel] if fl else None
        if k == "enter" and cur: return self.run_one(cur)
        if k == "e": return ("push", Editor("Flows", self.src, on_save=self.save_src, hint="flow / enabled / goal / step"))
        if k == "i": return ("push", Editor("Input register", self.inp, on_save=self.save_inp))
        if k == "h": return ("push", TextView("History", [f"{x['at']}  {x['flow']}  {x['status']}" for x in reversed(self.hist[-50:])] or ["no runs yet"]))
        if k == " " and cur and self.role == "manager":
            self.src = re.sub(r"(?s)(flow\s+" + re.escape(cur["name"]) + r"\s*\n)(enabled:\s*\w+\n)?", lambda m: m.group(1) + f"enabled: {'no' if cur['enabled'] else 'yes'}\n", self.src, count=1)
            self.st.save("flows", self.src)
        if k == "R" and self.role == "manager":
            n = 0
            for f in fl:
                if f["enabled"]: self.run_one(f, show=False); n += 1
            self.msg = f"ran {n} enabled flow(s)"
        if k == "m" and self.role == "recorder": self.recording = []
        if k == "escape": return ("quit",)

    def key_rec(self, k):
        if k == "enter" and self.rec_line.value.strip():
            self.recording.append(self.rec_line.value.strip()); self.rec_line = TextInput()
        elif k == "ctrl-z" and self.recording: self.recording.pop()
        elif k == "ctrl-s" and self.recording:
            return ("push", Prompt("Save macro", "Name for this macro:", "macro", self.save_macro))
        elif k == "escape": self.recording = None
        else: self.rec_line.key(k)

    def save_macro(self, name):
        name = name.strip()
        if not name: return
        block = f"\nflow {name}\nenabled: yes\nstep: input\n" + "".join(f"step: {s}\n" for s in self.recording)
        self.src += block; self.st.save("flows", self.src); self.recording = None; self.msg = f"saved macro '{name}'"

    def save_src(self, t): self.src = t; self.st.save("flows", t)
    def save_inp(self, t): self.inp = t; self.st.save("input", t)

    def run_one(self, f, show=True):
        notes = self.st.load("notes", {})
        reg, trace = run_flow(f, self.inp, self.host, self.st.load("llm", {}), notes)
        ok = not any("FAILED" in t for t in trace)
        self.hist = (self.hist + [{"flow": f["name"], "at": now_stamp(), "status": "ok" if ok else "failed"}])[-200:]; self.st.save("history", self.hist)
        if show: return ("push", TextView(f"{f['name']} - result", trace + ["", "--- output ---", *reg.split("\n")]))
