"""Whiteboard / design canvas: strokes, lines, rectangles, ellipses-as-boxes,
text, colours, undo, eraser, SVG export. Graphical mode draws it; tui mode
lists the shapes. One person at a time: KOS apps cannot share a canvas with
other apps or machines, so 'collaborative' here means 'saved and re-openable'."""

from __future__ import annotations

import html

from kos.sdk import Canvas

from .ui import Screen, Store, TextInput

COLORS = ["#111111", "#d0021b", "#f5a623", "#f8e71c", "#417505", "#0070d2", "#9013fe", "#ffffff"]
TOOLS = {"p": "pen", "l": "line", "r": "rect", "b": "box (filled)", "t": "text", "e": "eraser"}
MAX_OPS = 4800


class Board(Screen):
    def __init__(self, host, title="Whiteboard", snap: int = 1):
        self.host, self.title, self.st = host, title, Store(host)
        self.shapes: list = self.st.load("shapes", [])
        self.tool, self.color = "p", 0
        self.down = False
        self.cur: list | None = None
        self.start = (0, 0)
        self.px = (0, 0)
        self.typing: TextInput | None = None
        self.snap = snap
        self.undo: list = []
        self.msg = ""
        self.help = "p pen l line r rect b box t text e eraser  1-8 colour  u undo  c clear  s save  x export svg  g grid"

    def save(self): self.st.save("shapes", self.shapes)

    def s(self, v): return (v // self.snap) * self.snap if self.snap > 1 else v

    def event(self, ev):
        x, y = self.s(ev["x"]), self.s(ev["y"])
        self.px = (x, y)
        if ev["cmd"] == "button" and ev.get("button", "left") == "left":
            if ev["pressed"]:
                if self.tool == "t":
                    self.typing = TextInput(); self.start = (x, y); return
                if self.tool == "e": self.erase(x, y); return
                self.down, self.start = True, (x, y)
                self.cur = ["pen", self.color, [(x, y)]] if self.tool == "p" else None
            elif self.down:
                self.down = False
                if self.tool == "p" and self.cur and len(self.cur[2]) > 0:
                    self.shapes.append(self.cur)
                elif self.tool in ("l", "r", "b"):
                    kind = {"l": "line", "r": "rect", "b": "box"}[self.tool]
                    self.shapes.append([kind, self.color, [self.start, (x, y)]])
                self.cur = None; self.save()
        elif ev["cmd"] == "pointer" and self.down and self.tool == "p" and self.cur:
            lx, ly = self.cur[2][-1]
            if abs(x - lx) + abs(y - ly) >= 3: self.cur[2].append((x, y))

    def erase(self, x, y):
        for i in range(len(self.shapes) - 1, -1, -1):
            kind, _c, pts = self.shapes[i][:3]
            xs, ys = [p[0] for p in pts], [p[1] for p in pts]
            pad = 6
            if kind == "text":
                w = 6 * len(self.shapes[i][3]); hit = pts[0][0] - pad <= x <= pts[0][0] + w + pad and pts[0][1] - pad <= y <= pts[0][1] + 8 + pad
            else:
                hit = min(xs) - pad <= x <= max(xs) + pad and min(ys) - pad <= y <= max(ys) + pad
            if hit:
                self.undo.append(("erase", i, self.shapes.pop(i))); self.save(); return

    def ops_for(self, sh):
        kind, col, pts = sh[:3]
        if kind == "pen": return [["line", *a, *b, COLORS[col]] for a, b in zip(pts, pts[1:])] or [["rect", pts[0][0], pts[0][1], 2, 2, COLORS[col]]]
        (x1, y1), (x2, y2) = pts[0], pts[-1]; x, y, w, h = min(x1, x2), min(y1, y2), abs(x2 - x1), abs(y2 - y1)
        if kind == "line": return [["line", x1, y1, x2, y2, COLORS[col]]]
        if kind == "box": return [["rect", x, y, max(1, w), max(1, h), COLORS[col]]]
        if kind == "rect": return [["rect", x, y, w, 1, COLORS[col]], ["rect", x, y + h, w, 1, COLORS[col]], ["rect", x, y, 1, h, COLORS[col]], ["rect", x + w, y, 1, h, COLORS[col]]]
        if kind == "text": return [["text", x1, y1, sh[3], COLORS[col], 1]]
        return []

    def canvas(self, w, h):
        c = Canvas().clear("#f4f4f0"); ops = []
        for sh in self.shapes + ([self.cur] if self.cur else []): ops += self.ops_for(sh)
        if self.down and self.tool in ("l", "r", "b"): ops += self.ops_for([{"l": "line", "r": "rect", "b": "box"}[self.tool], self.color, [self.start, self.px]])
        if self.typing is not None: ops.append(["text", *self.start, self.typing.value + "_", COLORS[self.color], 1])
        hidden = max(0, len(ops) - MAX_OPS)
        c.ops += ops[hidden:]
        c.rect(0, 0, w, 12, "#222222").text(3, 2, f"{TOOLS[self.tool]}  {len(self.shapes)} shapes" + (f"  ({hidden} old ops hidden)" if hidden else "") + (f"  {self.msg}" if self.msg else ""), "#ffffff")
        for i, col in enumerate(COLORS):
            c.rect(w - 12 * (len(COLORS) - i), 14, 10, 10, col)
        return c

    def render(self, w, h):
        out = [f" {self.title}: {len(self.shapes)} shape(s), tool={TOOLS[self.tool]}, colour {self.color + 1}", " (draw with the mouse in graphical mode: run graphical <app>)", ""]
        for sh in self.shapes[-(h - 6):]: out.append(f"  {sh[0]:<5} {sh[2][0]} -> {sh[2][-1]}" + (f"  '{sh[3]}'" if sh[0] == "text" else ""))
        if self.msg: out.append(" " + self.msg)
        return out

    def key(self, k):
        self.msg = ""
        if self.typing is not None:
            if k == "enter":
                if self.typing.value: self.shapes.append(["text", self.color, [self.start], self.typing.value]); self.save()
                self.typing = None
            elif k == "escape": self.typing = None
            else: self.typing.key(k)
            return
        if k in TOOLS: self.tool = k
        elif len(k) == 1 and k.isdigit() and 1 <= int(k) <= len(COLORS): self.color = int(k) - 1
        elif k == "u" and self.shapes: self.shapes.pop(); self.save()
        elif k == "c": self.shapes.clear(); self.save()
        elif k == "g": self.snap = 1 if self.snap > 1 else 10; self.msg = f"grid snap {self.snap}"
        elif k == "s": self.save(); self.msg = "saved"
        elif k == "x":
            self.host.put("export-board.svg", self.svg()); self.msg = "exported board.svg to the vault"
        elif k == "escape": return ("quit",)

    def svg(self) -> str:
        W = max([p[0] for sh in self.shapes for p in sh[2]] + [200]) + 20; H = max([p[1] for sh in self.shapes for p in sh[2]] + [200]) + 20
        out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}"><rect width="100%" height="100%" fill="#f4f4f0"/>']
        for sh in self.shapes:
            kind, col, pts = sh[:3]; c = COLORS[col]
            (x1, y1), (x2, y2) = pts[0], pts[-1]; x, y, w, h = min(x1, x2), min(y1, y2), abs(x2 - x1), abs(y2 - y1)
            if kind == "pen": out.append(f'<polyline fill="none" stroke="{c}" stroke-width="2" points="{" ".join(f"{a},{b}" for a, b in pts)}"/>')
            elif kind == "line": out.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{c}" stroke-width="2"/>')
            elif kind == "rect": out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="none" stroke="{c}" stroke-width="2"/>')
            elif kind == "box": out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{c}"/>')
            elif kind == "text": out.append(f'<text x="{x1}" y="{y1 + 10}" fill="{c}" font-size="12">{html.escape(sh[3])}</text>')
        return "".join(out) + "</svg>"
