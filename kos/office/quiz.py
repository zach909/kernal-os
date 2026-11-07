"""Quizzes and surveys from one small question language.

    Q: Capital of France?          Q: How was it? [scale 1-5]
    - Berlin                       Q: Anything else? [text]
    + Paris                        Q: Pick any [choice]
    - Rome                         - red
                                   - blue
`+` marks the correct option (quiz mode)."""

from __future__ import annotations

import re

from .ui import ListNav, Screen, Store, TextInput, TextView, Editor, bar, now_stamp, wrap

QUIZ_SAMPLE = "Q: What is 2 + 2?\n- 3\n+ 4\n- 5\nQ: Which are primes?\n- 4\n+ 7\n- 9\nQ: Name a colour of the sky [text]\n"
SURVEY_SAMPLE = "Q: How satisfied are you? [scale 1-5]\nQ: What did you like most? [choice]\n- Speed\n- Price\n- Support\nQ: Any comments? [text]\n"


def parse(text: str) -> list:
    qs = []
    for raw in text.split("\n"):
        line = raw.rstrip()
        if line.startswith("Q:"):
            body = line[2:].strip(); kind, lo, hi = "choice", 1, 5
            m = re.search(r"\[(text|scale\s+(\d+)-(\d+)|choice)\]\s*$", body)
            if m:
                body = body[:m.start()].strip()
                kind = "scale" if m.group(1).startswith("scale") else m.group(1)
                if kind == "scale": lo, hi = int(m.group(2)), int(m.group(3))
            qs.append({"q": body, "kind": kind, "opts": [], "ans": [], "lo": lo, "hi": hi})
        elif qs and line[:1] and line[0] in "+-" and line[1:2] in (" ", ""):
            qs[-1]["opts"].append(line[2:].strip())
            if line[0] == "+": qs[-1]["ans"].append(len(qs[-1]["opts"]) - 1)
    for q in qs:
        if q["kind"] == "choice" and not q["opts"]: q["kind"] = "text"
    return qs


class Take(Screen):
    def __init__(self, host, title, qs, quiz_mode, on_done):
        self.title, self.qs, self.quiz, self.on_done = title, qs, quiz_mode, on_done
        self.i, self.answers, self.sel, self.inp = 0, [], 0, TextInput()
        self.help = "up/down choose   Enter answer   Esc abandon"

    def render(self, w, h):
        q = self.qs[self.i]
        out = [f" Question {self.i + 1} of {len(self.qs)}", "", *(" " + x for x in wrap(q["q"], w - 4)), ""]
        if q["kind"] == "choice":
            multi = len(q["ans"]) > 1
            out += [f"{'>' if j == self.sel else ' '} {'[x]' if j in getattr(self, 'picked', set()) else '[ ]'} {o}" for j, o in enumerate(q["opts"])]
            if multi: out += ["", " (space toggles, Enter confirms - more than one is correct)"]
        elif q["kind"] == "scale":
            out += ["  " + "  ".join(f"[{v}]" if v == self.sel + q["lo"] else f" {v} " for v in range(q["lo"], q["hi"] + 1)), "", " left/right, Enter"]
        else:
            out += ["  > " + self.inp.render()]
        return out

    def key(self, k):
        q = self.qs[self.i]
        if k == "escape": return ("pop", None)
        picked = self.__dict__.setdefault("picked", set())
        if q["kind"] == "choice":
            if k == "up": self.sel = max(0, self.sel - 1)
            elif k == "down": self.sel = min(len(q["opts"]) - 1, self.sel + 1)
            elif k == " " and len(q["ans"]) > 1: picked ^= {self.sel}
            elif k == "enter": self.answer(sorted(picked) if len(q["ans"]) > 1 else [self.sel])
        elif q["kind"] == "scale":
            if k == "left": self.sel = max(0, self.sel - 1)
            elif k == "right": self.sel = min(q["hi"] - q["lo"], self.sel + 1)
            elif k == "enter": self.answer(self.sel + q["lo"])
        else:
            if k == "enter": self.answer(self.inp.value.strip())
            else: self.inp.key(k)
        if self.i >= len(self.qs):
            res = self.on_done(self.answers)
            return ("replace", res)

    def answer(self, a):
        self.answers.append(a); self.i += 1; self.sel = 0; self.inp = TextInput(); self.picked = set()


class QuizApp(Screen):
    """mode: quiz | survey"""

    def __init__(self, host, title: str, mode: str = "quiz"):
        self.host, self.title, self.mode, self.st = host, title, mode, Store(host)
        self.src = self.st.load("questions", QUIZ_SAMPLE if mode == "quiz" else SURVEY_SAMPLE)
        self.runs = self.st.load("runs", [])
        self.msg = ""
        self.help = ("t take it   e edit questions   r results   x export CSV" if mode == "survey" else "t take quiz   e edit questions   r results")

    def render(self, w, h):
        qs = parse(self.src)
        out = [f" {len(qs)} question(s), {len(self.runs)} {'attempt' if self.mode == 'quiz' else 'response'}(s)", ""]
        out += [f"  {i + 1}. {q['q']}  [{q['kind']}]" for i, q in enumerate(qs[:h - 6])]
        if self.msg: out += ["", " " + self.msg]
        return out

    def key(self, k):
        self.msg = ""
        qs = parse(self.src)
        if k == "t" and qs: return ("push", Take(self.host, self.title, qs, self.mode == "quiz", self.finish))
        if k == "e": return ("push", Editor("Questions", self.src, on_save=self.save, hint="Q: text [text|scale 1-5|choice] then - option / + correct"))
        if k == "r": return ("push", TextView("Results", self.results(qs)))
        if k == "x":
            self.host.put("export.csv", self.csv(qs)); self.msg = "wrote vault key export.csv"
        if k == "escape": return ("quit",)

    def save(self, t): self.src = t; self.st.save("questions", t)

    def score(self, qs, answers):
        right = 0
        for q, a in zip(qs, answers):
            if q["kind"] == "choice" and q["ans"] and sorted(a if isinstance(a, list) else [a]) == q["ans"]: right += 1
        return right, sum(1 for q in qs if q["kind"] == "choice" and q["ans"])

    def finish(self, answers):
        qs = parse(self.src)
        self.runs.append({"at": now_stamp(), "answers": answers}); self.st.save("runs", self.runs)
        if self.mode == "survey": return TextView("Thanks", ["Your response was recorded."])
        right, total = self.score(qs, answers)
        lines = [f"Score: {right}/{total}" + (f" ({100 * right // total}%)" if total else ""), ""]
        for q, a in zip(qs, answers):
            if q["kind"] == "choice" and q["ans"]:
                ok = sorted(a if isinstance(a, list) else [a]) == q["ans"]
                lines.append(f"{'✔' if ok else '✘'} {q['q']}" + ("" if ok else "   answer: " + ", ".join(q["opts"][i] for i in q["ans"])))
        return TextView("Result", lines)

    def results(self, qs):
        if not self.runs: return ["nothing yet"]
        out = []
        if self.mode == "quiz":
            sc = [self.score(qs, r["answers"]) for r in self.runs]
            out += [f"{len(sc)} attempt(s); best {max(s[0] for s in sc)}/{sc[0][1]}, average {sum(s[0] for s in sc) / len(sc):.1f}", ""]
            for i, q in enumerate(qs):
                if q["kind"] == "choice" and q["ans"]:
                    ok = sum(1 for r in self.runs if i < len(r["answers"]) and sorted(r["answers"][i] if isinstance(r["answers"][i], list) else [r["answers"][i]]) == q["ans"])
                    out.append(f"{q['q'][:40]:<40} {bar(ok, len(self.runs), 20)} {ok}/{len(self.runs)} right")
            return out
        out.append(f"{len(self.runs)} response(s)\n")
        for i, q in enumerate(qs):
            out.append(q["q"])
            col = [r["answers"][i] for r in self.runs if i < len(r["answers"])]
            if q["kind"] == "choice":
                for j, o in enumerate(q["opts"]):
                    n = sum(1 for a in col if j in (a if isinstance(a, list) else [a])); out.append(f"   {o[:18]:<18} {bar(n, len(col), 24)} {n}")
            elif q["kind"] == "scale":
                vals = [a for a in col if isinstance(a, int)]
                out.append(f"   average {sum(vals) / len(vals):.2f} of {q['hi']}" if vals else "   no answers")
                for v in range(q["lo"], q["hi"] + 1): out.append(f"   {v}  {bar(vals.count(v), max(1, len(vals)), 24)} {vals.count(v)}")
            else:
                out += [f"   - {a}" for a in col if a][:10]
            out.append("")
        return out

    def csv(self, qs):
        import csv, io
        b = io.StringIO(); w = csv.writer(b, lineterminator="\n"); w.writerow(["at"] + [q["q"] for q in qs])
        for r in self.runs:
            w.writerow([r["at"]] + [", ".join(qs[i]["opts"][j] for j in a) if qs[i]["kind"] == "choice" and isinstance(a, list) else a for i, a in enumerate(r["answers"]) if i < len(qs)])
        return b.getvalue()
