"""Diagram editor: a text DSL drawn as a layered box-and-arrow diagram.

    Start -> Check input : valid?
    Check input -> Save
    Check input -> Error : invalid
Lines `Name [text]` set a box label. `#` starts a comment."""

from __future__ import annotations

import re



from .ui import Editor, TextView


def parse(src: str):
    nodes, edges, labels = [], [], {}
    def add(n):
        if n not in nodes: nodes.append(n)
    for raw in src.split("\n"):
        line = raw.split("#")[0].strip()
        if not line: continue
        m = re.match(r"^(.+?)\s*->\s*(.+?)(?:\s*:\s*(.*))?$", line)
        if m:
            a, b, lab = m.group(1).strip(), m.group(2).strip(), (m.group(3) or "").strip()
            add(a); add(b); edges.append((a, b, lab)); continue
        m = re.match(r"^(.+?)\s*\[(.*)\]$", line)
        if m: add(m.group(1).strip()); labels[m.group(1).strip()] = m.group(2).strip(); continue
        add(line)
    return nodes, edges, labels


def layers(nodes, edges):
    depth = {n: 0 for n in nodes}
    for _ in range(len(nodes)):                # longest path, tolerant of cycles
        moved = False
        for a, b, _l in edges:
            if a != b and depth[b] < depth[a] + 1 and depth[a] + 1 < len(nodes):
                depth[b] = depth[a] + 1; moved = True
        if not moved: break
    out: dict = {}
    for n in nodes: out.setdefault(depth[n], []).append(n)
    return [out[k] for k in sorted(out)]


def draw(src: str, width: int = 78) -> list:
    nodes, edges, labels = parse(src)
    if not nodes: return ["(empty diagram - try:  A -> B)"]
    L = layers(nodes, edges)
    text = {n: labels.get(n, n) for n in nodes}
    bw = {n: min(18, max(6, len(text[n]) + 2)) for n in nodes}
    pos, y = {}, 0
    grid: dict = {}
    def put(x, yy, s):
        for i, ch in enumerate(s):
            grid[(x + i, yy)] = ch
    for li, layer in enumerate(L):
        total = sum(bw[n] for n in layer) + 3 * (len(layer) - 1)
        x = max(0, (width - total) // 2)
        for n in layer:
            w = bw[n]; pos[n] = (x, y, w)
            put(x, y, "+" + "-" * (w - 2) + "+"); put(x, y + 1, "|" + text[n][:w - 2].center(w - 2) + "|")
            put(x, y + 2, "+" + "-" * (w - 2) + "+")
            x += w + 3
        y += 3 + 3
    # second pass: connectors, now that every box has a position
    for li, layer in enumerate(L[:-1]):
        gy = pos[layer[0]][1] + 3
        nxt = set(L[li + 1])
        for k, (a, b, lab) in enumerate(e for e in edges if e[0] in layer and e[1] in nxt):
            ax, bx = pos[a][0] + pos[a][2] // 2, pos[b][0] + pos[b][2] // 2
            put(ax, gy, "|")
            lo, hi = sorted((ax, bx))
            for x in range(lo, hi + 1):
                if grid.get((x, gy + 1)) in (None, " "): grid[(x, gy + 1)] = "-"
            grid[(ax, gy + 1)] = "+" if ax != bx else "|"
            grid[(bx, gy + 1)] = "+" if ax != bx else "|"
            grid[(bx, gy + 2)] = "v"
            if lab: put(bx + 2, gy + 2, lab[:20])
    H = max(yy for _x, yy in grid) + 1
    W = max(xx for xx, _y in grid) + 1
    lines = ["".join(grid.get((x, yy), " ") for x in range(W)).rstrip() for yy in range(H)]
    skip = [(a, b, l) for a, b, l in edges if not any(a in L[i] and b in L[i + 1] for i in range(len(L) - 1))]
    if skip:
        lines += ["", "Other connections:"] + [f"  {a} -> {b}" + (f" : {l}" if l else "") for a, b, l in skip]
    return lines


def export_svg(src: str) -> str:
    nodes, edges, labels = parse(src)
    L = layers(nodes, edges)
    pos = {}
    for li, layer in enumerate(L):
        for ci, n in enumerate(layer): pos[n] = (40 + ci * 180, 30 + li * 100)
    W = max((p[0] for p in pos.values()), default=0) + 180
    H = max((p[1] for p in pos.values()), default=0) + 90
    esc = lambda s: s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}"><defs><marker id="a" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z"/></marker></defs>']
    for a, b, lab in edges:
        (x1, y1), (x2, y2) = pos[a], pos[b]
        parts.append(f'<line x1="{x1 + 70}" y1="{y1 + 40}" x2="{x2 + 70}" y2="{y2}" stroke="#333" marker-end="url(#a)"/>')
        if lab: parts.append(f'<text x="{(x1 + x2) // 2 + 74}" y="{(y1 + y2) // 2 + 30}" font-size="11">{esc(lab)}</text>')
    for n, (x, y) in pos.items():
        parts.append(f'<rect x="{x}" y="{y}" width="140" height="40" rx="6" fill="#eef" stroke="#336"/>'
                     f'<text x="{x + 70}" y="{y + 24}" text-anchor="middle" font-size="13">{esc(labels.get(n, n))}</text>')
    return "".join(parts) + "</svg>"


SAMPLE = "Start -> Check input\nCheck input -> Save : valid\nCheck input -> Error : invalid\nSave -> Done\nError -> Done\n"


def diagram_editor(host, name, text, save):
    return Editor(name, text, save, hint="^P draw  ^E export svg", extra_keys={
        "ctrl-p": lambda s: ("push", TextView("Diagram", draw(s.area.text))),
        "ctrl-e": lambda s: (host.put(f"export-{name.lower().replace(' ', '-')}.svg", export_svg(s.area.text)), setattr(s, "flash", "svg saved to vault"))[0]})
