"""pack_org: the organization-centric blueprint (docs/ORG_BLUEPRINT.md), as far as sandboxed apps can go.

Two real apps and a set of honest "not built" entries for the parts that would have to live in the kernel.

* Semantic Graph - one app's own knowledge graph. Every node carries the same metadata (context, project,
  temporal validity, dependencies, relations). Content is stored once under its SHA-256. Dependencies form a DAG
  (a cycle is refused). A query line filters on any of it. A project x state matrix, a critical-path planner and a
  hash-chained change history are views over the same data. It is NOT a file system: it holds notes, tasks and
  similar items in the app's private vault and never sees the OS's files.
* Rule Router - event, condition, action rules written in a small declarative text format that is versioned and
  never overwritten. Actions can only change the router's own state and log. It cannot mute alerts, commit code or
  switch a view: sandboxed apps cannot reach the system.

Pure standard library. All logic is in plain functions and classes that take `now` / `today` as arguments so tests
are exact. Nothing runs in the background. Every input and every stored thing is bounded."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import heapq
import json
import re

from .packkit import app, none
from .ui import ListNav, Confirm, Editor, Menu, Message, Prompt, Screen, Store, TextView, now_stamp, table, today

# ============================================================ shared helpers ====
KINDS = ("note", "file", "task", "person", "event")
STATES = ("open", "doing", "done")
OPS = ("add", "edit", "dep+", "dep-", "rel+", "rel-", "del")
ID_RE = re.compile(r"^n[1-9]\d{0,5}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
WORD_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,23}$")
REL_RE = re.compile(r"^[a-z][a-z-]{0,19}$")
STAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}( \d{2}:\d{2})?$")
PREFIX_RE = re.compile(r"^\d{4}(-\d{2}(-\d{2})?)?$")

MAX_NODES, MAX_TITLE, MAX_BODY, MAX_EDGES, MAX_TAGS = 150, 80, 4000, 20, 10
MAX_BLOBS, MAX_LOG, FOLD, MAX_STORE = 100_000, 200, 50, 390_000    # MAX_STORE < the vault's 400,000-character item cap
MAX_TERMS, MAX_QUERY = 12, 200


class GraphError(ValueError):
    """A request the graph refuses. The message is safe to show."""


def clean(s, n: int = 200, keep_nl: bool = False) -> str:
    """Printable text only (control characters dropped), bounded."""
    if not isinstance(s, str):
        return ""
    return "".join(c for c in s if c.isprintable() or (keep_nl and c == "\n"))[:n].strip()


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def to_date(s):
    if not isinstance(s, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return None
    try:
        return dt.date.fromisoformat(s)
    except ValueError:
        return None


def resolve_day(text: str, today_: str) -> str:
    """'', 'today', '+N' or YYYY-MM-DD -> ISO date ('' stays empty). Raises GraphError."""
    t = clean(text, 20).lower()
    if t == "":
        return ""
    base = to_date(today_)
    if t == "today" and base:
        return today_
    if re.fullmatch(r"\+\d{1,4}", t) and base:
        return (base + dt.timedelta(days=int(t[1:]))).isoformat()
    if to_date(t):
        return t
    raise GraphError("a date looks like 2026-11-07, today, +3, or empty")


def idnum(i: str) -> int:
    return int(i[1:])


def tagword(s) -> str:
    """Lenient (used when loading): lower-case letters, digits and '-' only."""
    if not isinstance(s, str):
        return ""
    w = "".join(c for c in s.lower() if c.isascii() and (c.isalnum() or c == "-")).strip("-")[:24]
    return w if WORD_RE.match(w) else ""


def strict_word(text: str, what: str) -> str:
    t = clean(text, 40).lower()
    if t and not WORD_RE.match(t):
        raise GraphError(f"{what}: use 1-24 lower-case letters, digits or '-', or leave empty")
    return t


# ============================================================ graph state ====
def empty_state() -> dict:
    return {"v": 1, "next": 1, "nodes": {}, "blobs": {}, "log": [], "base": {"h": "", "at": "", "nodes": {}}}


def clean_node(raw):
    """A node from untrusted data -> a valid node with empty edges, or None."""
    if not isinstance(raw, dict):
        return None
    i, h = raw.get("id"), raw.get("sha")
    title = clean(raw.get("title"), MAX_TITLE)
    if not (isinstance(i, str) and ID_RE.match(i) and isinstance(h, str) and SHA_RE.match(h) and title):
        return None
    tags = []
    if isinstance(raw.get("tags"), list):
        for t in raw["tags"]:
            w = tagword(t)
            if w and w not in tags and len(tags) < MAX_TAGS:
                tags.append(w)
    days = raw.get("days")
    days = days if isinstance(days, int) and not isinstance(days, bool) and 0 <= days <= 365 else 0
    stamp = lambda v: v if isinstance(v, str) and STAMP_RE.match(v) else ""
    day = lambda v: v if to_date(v) else ""
    return {"id": i, "kind": raw.get("kind") if raw.get("kind") in KINDS else "note", "title": title, "sha": h,
            "status": raw.get("status") if raw.get("status") in STATES else "open",
            "project": tagword(raw.get("project")), "context": tagword(raw.get("context")), "tags": tags,
            "valid_from": day(raw.get("valid_from")), "valid_to": day(raw.get("valid_to")), "due": day(raw.get("due")),
            "days": days, "created": stamp(raw.get("created")), "edited": stamp(raw.get("edited")),
            "deps": [d for d in (raw.get("deps") if isinstance(raw.get("deps"), list) else [])
                     if isinstance(d, str) and ID_RE.match(d)][:MAX_EDGES],
            "rels": [[r[0], r[1]] for r in (raw.get("rels") if isinstance(raw.get("rels"), list) else [])
                     if isinstance(r, list) and len(r) == 2 and isinstance(r[0], str) and REL_RE.match(r[0])
                     and isinstance(r[1], str) and ID_RE.match(r[1])][:MAX_EDGES]}


def reaches(adj: dict, src: str, dst: str) -> bool:
    """Is dst reachable from src (or the same node) following `adj` (node -> list of nodes)?"""
    seen, stack = set(), [src]
    while stack:
        x = stack.pop()
        if x == dst:
            return True
        if x in seen:
            continue
        seen.add(x)
        stack.extend(adj.get(x, ()))
    return False


def entry_hash(prev: str, e: dict) -> str:
    body = json.dumps({k: v for k, v in e.items() if k != "h"}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha(prev + "\n" + body)


def sanitize(raw) -> dict:
    """Whatever the vault held -> a state the rest of the code can trust. Never raises."""
    s = empty_state()
    if not isinstance(raw, dict):
        return s
    nodes = {}
    if isinstance(raw.get("nodes"), dict):
        for k, v in list(raw["nodes"].items())[:MAX_NODES]:
            n = clean_node(v)
            if n and n["id"] == k:
                nodes[k] = n
    acc = {i: [] for i in nodes}
    for i in sorted(nodes, key=idnum):                    # keep a dependency only if it cannot close a cycle
        for d in nodes[i]["deps"]:
            if d in nodes and d != i and d not in acc[i] and not reaches(acc, d, i):
                acc[i].append(d)
        nodes[i]["deps"] = acc[i]
        nodes[i]["rels"] = [r for r in nodes[i]["rels"] if r[1] in nodes and r[1] != i]
    s["nodes"] = nodes
    nxt = raw.get("next")
    top = max((idnum(i) for i in nodes), default=0)
    s["next"] = max(top + 1, nxt if isinstance(nxt, int) and not isinstance(nxt, bool) else 1)
    s["next"] = min(s["next"], 999_999)
    if isinstance(raw.get("blobs"), dict):                # content-addressed: a body must hash to its own key
        s["blobs"] = {k: v for k, v in raw["blobs"].items()
                      if isinstance(k, str) and isinstance(v, str) and len(v) <= MAX_BODY and SHA_RE.match(k) and sha(v) == k}
    if isinstance(raw.get("log"), list):
        for e in raw["log"][:MAX_LOG * 2]:
            if (isinstance(e, dict) and isinstance(e.get("seq"), int) and isinstance(e.get("at"), str)
                    and STAMP_RE.match(e["at"]) and e.get("op") in OPS and isinstance(e.get("id"), str)
                    and ID_RE.match(e["id"]) and isinstance(e.get("h"), str) and SHA_RE.match(e["h"])
                    and (e.get("node") is None or clean_node(e.get("node")))):
                s["log"].append({"seq": e["seq"], "at": e["at"], "op": e["op"], "id": e["id"],
                                 "node": clean_node(e["node"]) if e.get("node") else None, "h": e["h"]})
    b = raw.get("base")
    if isinstance(b, dict):
        s["base"]["h"] = b["h"] if isinstance(b.get("h"), str) and (SHA_RE.match(b["h"]) or b["h"] == "") else ""
        s["base"]["at"] = b["at"] if isinstance(b.get("at"), str) and STAMP_RE.match(b["at"]) else ""
        if isinstance(b.get("nodes"), dict):
            for k, v in list(b["nodes"].items())[:MAX_NODES]:
                n = clean_node(v)
                if n and n["id"] == k:
                    s["base"]["nodes"][k] = n
    return s


# ---- field parsing -----------------------------------------------------------------------------------------
EDIT_FIELDS = ("title", "kind", "status", "project", "context", "tags", "valid_from", "valid_to", "due", "days")
ALIASES = {"from": "valid_from", "to": "valid_to", "state": "status", "type": "kind", "tag": "tags", "duration": "days"}


def parse_field(name: str, text: str, today_: str = ""):
    """The value for one editable field, from what the person typed. Raises GraphError."""
    name = ALIASES.get(name, name)
    t = clean(text, 400)
    if name == "title":
        if not t:
            raise GraphError("a title cannot be empty")
        return clean(t, MAX_TITLE)
    if name in ("kind", "status"):
        allowed = KINDS if name == "kind" else STATES
        if t.lower() not in allowed:
            raise GraphError(f"{name} is one of: {', '.join(allowed)}")
        return t.lower()
    if name in ("project", "context"):
        return strict_word(t, name)
    if name == "tags":
        out = []
        for w in re.split(r"[,\s]+", t.lower()):
            if not w:
                continue
            strict_word(w, "tag")
            if w not in out:
                out.append(w)
        if len(out) > MAX_TAGS:
            raise GraphError(f"at most {MAX_TAGS} tags")
        return out
    if name in ("valid_from", "valid_to", "due"):
        return resolve_day(t, today_)
    if name == "days":
        if not re.fullmatch(r"\d{1,3}", t) or int(t) > 365:
            raise GraphError("days is a whole number from 0 to 365")
        return int(t)
    raise GraphError(f"unknown field '{name}'. Fields: {', '.join(EDIT_FIELDS)}, body")


# ============================================================ the graph ====
class Graph:
    """Nodes + dependency DAG + content store + hash-chained history, kept in one dict `self.s`.

    Every change is built on a copy, checked, saved through `persist(state) -> bool`, and only then becomes the
    current state: a refusal or a failed save leaves the graph exactly as it was."""

    def __init__(self, raw=None, persist=None):
        self.s = sanitize(raw)
        self.persist = persist or (lambda state: True)
        self._index()

    # ---- indexing: rebuilt as part of every change, so a query never sees a stale index ----
    def _index(self):
        idx = {k: {} for k in ("kind", "status", "project", "context", "tag", "sha")}
        for i, n in self.s["nodes"].items():
            for key, val in (("kind", n["kind"]), ("status", n["status"]), ("project", n["project"]),
                             ("context", n["context"]), ("sha", n["sha"])):
                idx[key].setdefault(val, set()).add(i)
            for t in n["tags"]:
                idx["tag"].setdefault(t, set()).add(i)
        self.idx = idx

    # ---- reading ----
    @property
    def nodes(self) -> dict:
        return self.s["nodes"]

    def body(self, n: dict) -> str:
        return self.s["blobs"].get(n["sha"], "")

    def body_ok(self, n: dict) -> bool:
        return n["sha"] in self.s["blobs"]

    def get(self, i: str) -> dict:
        if i not in self.nodes:
            raise GraphError(f"no node '{i}'")
        return self.nodes[i]

    def blockers_of(self, i: str) -> list:
        return sorted((j for j, n in self.nodes.items() if i in n["deps"]), key=idnum)

    def shared_with(self, n: dict) -> list:
        return sorted((j for j in self.idx["sha"].get(n["sha"], ()) if j != n["id"]), key=idnum)

    # ---- changing ----
    def _mutate(self, fn, now: str):
        new = copy.deepcopy(self.s)
        fn(new)
        keep = {n["sha"] for n in new["nodes"].values()} | {n["sha"] for n in new["base"]["nodes"].values()}
        keep |= {e["node"]["sha"] for e in new["log"] if e["node"]}
        new["blobs"] = {k: v for k, v in new["blobs"].items() if k in keep}
        if sum(len(v) for v in new["blobs"].values()) > MAX_BLOBS:
            raise GraphError(f"the content store is full ({MAX_BLOBS} characters kept, history included)")
        if len(json.dumps(new, separators=(",", ":"), ensure_ascii=False)) > MAX_STORE:
            raise GraphError("the saved graph would be too large; remove something first")
        if not self.persist(new):
            raise GraphError("could not save; nothing was changed")
        self.s = new
        self._index()

    @staticmethod
    def _log(s: dict, now: str, op: str, i: str):
        prev = s["log"][-1]["h"] if s["log"] else s["base"]["h"]
        seq = (s["log"][-1]["seq"] + 1) if s["log"] else 1
        e = {"seq": seq, "at": now, "op": op, "id": i, "node": copy.deepcopy(s["nodes"].get(i))}
        e["h"] = entry_hash(prev, e)
        s["log"].append(e)
        if len(s["log"]) > MAX_LOG:                       # fold the oldest entries into the base snapshot
            for old in s["log"][:FOLD]:
                if old["node"] is None:
                    s["base"]["nodes"].pop(old["id"], None)
                else:
                    s["base"]["nodes"][old["id"]] = old["node"]
                s["base"]["h"], s["base"]["at"] = old["h"], old["at"]
            del s["log"][:FOLD]

    def add(self, title: str, now: str, kind: str = "note", body: str = "") -> str:
        title = parse_field("title", title)
        kind = parse_field("kind", kind)
        body = self._body_text(body)
        made = []

        def fn(s):
            if len(s["nodes"]) >= MAX_NODES:
                raise GraphError(f"at most {MAX_NODES} nodes")
            i = f"n{s['next']}"
            s["next"] += 1
            s["blobs"][sha(body)] = body
            s["nodes"][i] = clean_node({"id": i, "kind": kind, "title": title, "sha": sha(body), "created": now,
                                        "edited": now})
            self._log(s, now, "add", i)
            made.append(i)
        self._mutate(fn, now)
        return made[0]

    @staticmethod
    def _body_text(body) -> str:
        if not isinstance(body, str):
            raise GraphError("content must be text")
        body = "".join(c for c in body if c.isprintable() or c in "\n\t")
        if len(body) > MAX_BODY:
            raise GraphError(f"content is at most {MAX_BODY} characters")
        return body

    def set_body(self, i: str, body: str, now: str):
        body = self._body_text(body)
        self.get(i)

        def fn(s):
            s["blobs"][sha(body)] = body
            s["nodes"][i]["sha"], s["nodes"][i]["edited"] = sha(body), now
            self._log(s, now, "edit", i)
        self._mutate(fn, now)

    def set_field(self, i: str, name: str, text: str, now: str, today_: str = ""):
        self.get(i)
        name = ALIASES.get(name, name)
        value = parse_field(name, text, today_)

        def fn(s):
            n = s["nodes"][i]
            n[name] = value
            if n["valid_from"] and n["valid_to"] and n["valid_from"] > n["valid_to"]:
                raise GraphError("valid_from is after valid_to")
            n["edited"] = now
            self._log(s, now, "edit", i)
        self._mutate(fn, now)

    def add_dep(self, a: str, b: str, now: str):
        """`a` depends on `b`. A cycle is refused, so the dependency graph is always a DAG."""
        self.get(a), self.get(b)
        if a == b:
            raise GraphError("a node cannot depend on itself")
        adj = {i: n["deps"] for i, n in self.nodes.items()}
        if b in adj[a]:
            raise GraphError(f"{a} already depends on {b}")
        if len(adj[a]) >= MAX_EDGES:
            raise GraphError(f"at most {MAX_EDGES} dependencies per node")
        if reaches(adj, b, a):
            raise GraphError(f"refused: {b} already depends on {a} (directly or not), so this would be a cycle")

        def fn(s):
            s["nodes"][a]["deps"].append(b)
            s["nodes"][a]["edited"] = now
            self._log(s, now, "dep+", a)
        self._mutate(fn, now)

    def drop_dep(self, a: str, b: str, now: str):
        if b not in self.get(a)["deps"]:
            raise GraphError(f"{a} does not depend on {b}")

        def fn(s):
            s["nodes"][a]["deps"].remove(b)
            s["nodes"][a]["edited"] = now
            self._log(s, now, "dep-", a)
        self._mutate(fn, now)

    def add_rel(self, a: str, label: str, b: str, now: str):
        label = clean(label, 30).lower()
        self.get(a), self.get(b)
        if not REL_RE.match(label):
            raise GraphError("a relation label is 1-20 lower-case letters or '-', for example: see-also")
        if a == b:
            raise GraphError("a node cannot relate to itself")
        if [label, b] in self.nodes[a]["rels"]:
            raise GraphError("that relation already exists")
        if len(self.nodes[a]["rels"]) >= MAX_EDGES:
            raise GraphError(f"at most {MAX_EDGES} relations per node")

        def fn(s):
            s["nodes"][a]["rels"].append([label, b])
            s["nodes"][a]["edited"] = now
            self._log(s, now, "rel+", a)
        self._mutate(fn, now)

    def drop_rel(self, a: str, label: str, b: str, now: str):
        label = clean(label, 30).lower()
        if [label, b] not in self.get(a)["rels"]:
            raise GraphError("no such relation")

        def fn(s):
            s["nodes"][a]["rels"].remove([label, b])
            s["nodes"][a]["edited"] = now
            self._log(s, now, "rel-", a)
        self._mutate(fn, now)

    def remove(self, i: str, now: str):
        self.get(i)
        blockers = self.blockers_of(i)
        if blockers:
            raise GraphError(f"{', '.join(blockers)} depend on {i}; remove those dependencies first")

        def fn(s):
            for j, n in s["nodes"].items():                # relations to a node that is going away go with it
                if j != i and any(r[1] == i for r in n["rels"]):
                    n["rels"] = [r for r in n["rels"] if r[1] != i]
                    n["edited"] = now
                    self._log(s, now, "rel-", j)
            del s["nodes"][i]
            self._log(s, now, "del", i)                    # no node left to snapshot: the entry records the deletion
        self._mutate(fn, now)

    # ---- queries ----
    def query(self, text: str, today_: str) -> list:
        terms = parse_query(text)
        ids = set(self.nodes)
        for neg, key, val in terms:
            hit = self._match(key, val, today_)
            ids = (ids - hit) if neg else (ids & hit)
        return sorted(ids, key=idnum)

    def _match(self, key: str, val: str, today_: str) -> set:
        nodes = self.nodes
        if key in ("kind", "status", "project", "context", "tag"):
            return set(self.idx[key].get(val, ()))
        if key == "sha":
            if len(val) < 4:
                raise GraphError("sha: needs at least 4 characters")
            return {i for h, ids in self.idx["sha"].items() if h.startswith(val) for i in ids}
        if key in ("edited", "created"):
            v = today_ if val == "today" else val
            if not PREFIX_RE.match(v):
                raise GraphError(f"{key}: use today, 2026, 2026-11 or 2026-11-07")
            return {i for i, n in nodes.items() if n[key].startswith(v)}
        if key == "valid":
            d = today_ if val == "today" else val
            if not to_date(d):
                raise GraphError("valid: use today or a date like 2026-11-07")
            return {i for i, n in nodes.items()
                    if (not n["valid_from"] or n["valid_from"] <= d) and (not n["valid_to"] or n["valid_to"] >= d)}
        if key in ("depends", "needs", "rel"):
            if not ID_RE.match(val):
                raise GraphError(f"{key}: needs a node id like n3")
            if key == "depends":
                return {i for i, n in nodes.items() if val in n["deps"]}
            if key == "needs":
                return set(nodes[val]["deps"]) if val in nodes else set()
            out = {i for i, n in nodes.items() if any(r[1] == val for r in n["rels"])}
            return out | ({r[1] for r in nodes[val]["rels"]} if val in nodes else set())
        return {i for i, n in nodes.items() if val in n["title"].lower() or val in self.body(n).lower()}

    # ---- the dependency view ----
    def toposort(self, ids=None) -> list:
        """Dependencies first; ties broken by id so the order is the same every time. Raises on a cycle."""
        ids = set(self.nodes if ids is None else ids)
        indeg = {i: sum(1 for d in self.nodes[i]["deps"] if d in ids) for i in ids}
        users: dict = {i: [] for i in ids}
        for i in ids:
            for d in self.nodes[i]["deps"]:
                if d in ids:
                    users[d].append(i)
        heap = [(idnum(i), i) for i in ids if indeg[i] == 0]
        heapq.heapify(heap)
        out = []
        while heap:
            _, i = heapq.heappop(heap)
            out.append(i)
            for u in users[i]:
                indeg[u] -= 1
                if indeg[u] == 0:
                    heapq.heappush(heap, (idnum(u), u))
        if len(out) != len(ids):
            raise GraphError("dependency cycle among: " + ", ".join(sorted(ids - set(out), key=idnum)))
        return out

    def plan(self, start: str) -> dict:
        """Critical path over the open tasks (kind 'task', status not 'done'). A task with no days counts as 1.
        A dependency on a finished task, or on a node that is not a task, is already satisfied.
        Times are whole days from `start` (day 0 is the start date); a task of N days occupies N days."""
        d0 = to_date(start)
        if d0 is None:
            raise GraphError("the start is a date like 2026-11-07")
        tasks = {i for i, n in self.nodes.items() if n["kind"] == "task" and n["status"] != "done"}
        order = self.toposort(tasks)
        dur = {i: max(1, self.nodes[i]["days"]) for i in order}
        es, ef = {}, {}
        for i in order:
            es[i] = max((ef[d] for d in self.nodes[i]["deps"] if d in tasks), default=0)
            ef[i] = es[i] + dur[i]
        end = max(ef.values(), default=0)
        users = {i: [j for j in order if i in self.nodes[j]["deps"]] for i in order}
        lf, ls = {}, {}
        for i in reversed(order):
            lf[i] = min((ls[u] for u in users[i]), default=end)
            ls[i] = lf[i] - dur[i]
        rows = {}
        for i in order:
            n = self.nodes[i]
            finish = d0 + dt.timedelta(days=ef[i] - 1)
            rows[i] = {"id": i, "title": n["title"], "days": dur[i], "es": es[i], "ef": ef[i], "ls": ls[i], "lf": lf[i],
                       "slack": ls[i] - es[i], "start": (d0 + dt.timedelta(days=es[i])).isoformat(),
                       "finish": finish.isoformat(), "due": n["due"],
                       "late": bool(n["due"]) and finish.isoformat() > n["due"]}
        return {"order": order, "rows": rows, "end": end,
                "finish": (d0 + dt.timedelta(days=end - 1)).isoformat() if end else "",
                "critical": [i for i in order if rows[i]["slack"] == 0],
                "late": [i for i in order if rows[i]["late"]]}

    def matrix(self) -> tuple:
        """Projects (x) by state (y): counts. Returns (projects, {project: {state: count}})."""
        grid: dict = {}
        for n in self.nodes.values():
            grid.setdefault(n["project"], {s: 0 for s in STATES})[n["status"]] += 1
        return sorted(grid, key=lambda p: (p == "", p)), grid

    # ---- history ----
    def verify(self) -> tuple:
        """(ok, index of the first bad entry). Detects edits and removals made without recomputing the chain.
        It is not a signature: whoever can rewrite this whole file can rewrite the chain too."""
        prev = self.s["base"]["h"]
        for k, e in enumerate(self.s["log"]):
            if e["h"] != entry_hash(prev, e):
                return False, k
            if k and e["seq"] != self.s["log"][k - 1]["seq"] + 1:
                return False, k
            prev = e["h"]
        return True, -1

    def history(self, i: str) -> list:
        out = []
        for e in self.s["log"]:
            if e["id"] == i:
                n = e["node"]
                out.append({"at": e["at"], "op": e["op"], "title": n["title"] if n else "(deleted)",
                            "sha": n["sha"] if n else "", "kept": bool(n and n["sha"] in self.s["blobs"])})
        return out

    def asof(self, date: str) -> dict:
        """The nodes as they stood at the end of `date` (ISO). Refuses a date older than the kept history."""
        if not to_date(date):
            raise GraphError("use a date like 2026-11-07")
        base = self.s["base"]
        if base["at"] and date < base["at"][:10]:
            raise GraphError(f"history before {base['at'][:10]} was folded away to save space")
        nodes = copy.deepcopy(base["nodes"])
        for e in self.s["log"]:
            if e["at"][:10] <= date:
                if e["node"] is None:
                    nodes.pop(e["id"], None)
                else:
                    nodes[e["id"]] = e["node"]
        return nodes

    def stats(self) -> dict:
        nodes = self.nodes
        shas = [n["sha"] for n in nodes.values()]
        distinct = len(set(shas))
        saved = sum(len(self.s["blobs"].get(h, "")) * (shas.count(h) - 1) for h in set(shas))
        return {"nodes": len(nodes), "distinct": distinct, "saved": saved, "log": len(self.s["log"]),
                "folded_to": self.s["base"]["at"], "bytes": len(json.dumps(self.s, separators=(",", ":"), ensure_ascii=False))}


FILTERS = ("kind", "status", "project", "context", "tag", "edited", "created", "valid", "depends", "needs", "rel", "sha")


def parse_query(text: str) -> list:
    """'project:alpha -status:done edited:today word' -> [(negated, key, value)]. Raises GraphError."""
    t = clean(text, MAX_QUERY).lower()
    toks = t.split()
    if len(toks) > MAX_TERMS:
        raise GraphError(f"at most {MAX_TERMS} terms")
    out = []
    for tok in toks:
        neg = tok.startswith("-") and len(tok) > 1
        tok = tok[1:] if neg else tok
        if ":" in tok:
            key, _, val = tok.partition(":")
            if key not in FILTERS:
                raise GraphError(f"unknown filter '{key}'. Filters: {', '.join(FILTERS)}")
            if not val:
                raise GraphError(f"'{key}:' needs a value")
            out.append((neg, key, val))
        else:
            out.append((neg, "word", tok))
    return out


# ============================================================ rule router ====
RULE_RE = re.compile(r"^rule\s+([a-z0-9_-]{1,24})\s*:\s*on\s+(\S+)(?:\s+if\s+(.+?))?\s+then\s+(.+)$")
COND_RE = re.compile(r"^(not\s+)?([a-z][a-z0-9_-]{0,23})\s*(?:(>=|<=|!=|=|>|<)\s*(.{1,40}))?$")
EVENT_RE = re.compile(r"^[a-z0-9][a-z0-9:_.-]{0,39}$")
KEY_RE = re.compile(r"^[a-z][a-z0-9_-]{0,23}$")
MAX_RULES, MAX_ACTIONS, MAX_CONFIG, MAX_LINES = 40, 8, 4000, 100
MAX_STATE, MAX_DEPTH, MAX_STEPS, MAX_RUNLOG, MAX_VERSIONS = 30, 4, 60, 100, 30


class ConfigError(ValueError):
    pass


def parse_rules(text: str) -> list:
    """The declarative config -> a list of rules. All or nothing: the first bad line raises ConfigError("line N: ...").
    One rule per line:   rule NAME: on EVENT [if COND [and COND ...]] then ACTION [; ACTION ...]
    COND:   key | not key | key=v | key!=v | key>n | key<n | key>=n | key<=n
    ACTION: set key=value | unset key | log text | fire EVENT          (nothing else exists)"""
    if not isinstance(text, str) or len(text) > MAX_CONFIG:
        raise ConfigError(f"the config is at most {MAX_CONFIG} characters")
    lines = text.split("\n")
    if len(lines) > MAX_LINES:
        raise ConfigError(f"at most {MAX_LINES} lines")
    rules, seen = [], set()
    for no, raw in enumerate(lines, 1):
        if any(ord(c) < 32 and c != "\t" for c in raw.rstrip("\r")):
            raise ConfigError(f"line {no}: control characters are not allowed")
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = RULE_RE.match(line)
        if not m:
            raise ConfigError(f"line {no}: expected  rule NAME: on EVENT [if COND] then ACTION")
        name, event, conds, acts = m.groups()
        if name in seen:
            raise ConfigError(f"line {no}: rule '{name}' is defined twice")
        if not EVENT_RE.match(event):
            raise ConfigError(f"line {no}: bad event name '{event[:40]}'")
        if len(rules) >= MAX_RULES:
            raise ConfigError(f"line {no}: at most {MAX_RULES} rules")
        parsed_conds = []
        for c in (re.split(r"\s+and\s+", conds.strip()) if conds else []):
            cm = COND_RE.match(c.strip())
            if not cm:
                raise ConfigError(f"line {no}: cannot read the condition '{c.strip()[:40]}'")
            neg, key, op, val = cm.groups()
            if neg and op:
                raise ConfigError(f"line {no}: 'not' goes with a bare key only")
            parsed_conds.append((bool(neg), key, op, val.strip() if val else None))
        actions = []
        for a in [x.strip() for x in acts.split(";") if x.strip()]:
            verb, _, rest = a.partition(" ")
            rest = rest.strip()
            if verb == "set":
                k, eq, v = rest.partition("=")
                if not (eq and KEY_RE.match(k.strip()) and 0 < len(v.strip()) <= 40):
                    raise ConfigError(f"line {no}: 'set' is  set key=value")
                actions.append(("set", k.strip(), v.strip()))
            elif verb == "unset" and KEY_RE.match(rest):
                actions.append(("unset", rest, ""))
            elif verb == "log" and 0 < len(rest) <= 100:
                actions.append(("log", rest, ""))
            elif verb == "fire" and EVENT_RE.match(rest):
                actions.append(("fire", rest, ""))
            else:
                raise ConfigError(f"line {no}: unknown action '{a[:30]}'. Actions: set, unset, log, fire")
        if not actions or len(actions) > MAX_ACTIONS:
            raise ConfigError(f"line {no}: 1 to {MAX_ACTIONS} actions")
        seen.add(name)
        rules.append({"name": name, "event": event, "conds": parsed_conds, "actions": actions})
    return rules


def _num(x):
    try:
        v = float(x)
    except (TypeError, ValueError):
        return None
    return v if v == v and abs(v) != float("inf") else None


def holds(cond, state: dict) -> bool:
    neg, key, op, val = cond
    have = state.get(key)
    if op is None:
        present = have not in (None, "")
        return (not present) if neg else present
    if have is None:
        return False
    a, b = _num(have), _num(val)
    if op in ("=", "!="):
        same = (a == b) if (a is not None and b is not None) else (have == val)
        return same if op == "=" else not same
    if a is None or b is None:
        return False
    return {">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b}[op]


def fire(rules: list, state: dict, event: str) -> tuple:
    """Run the rules for `event` against a copy of `state` -> (new_state, trace).
    trace is a list of (kind, text) with kind match | skip | set | log | stop. The chain of `fire` actions is cut at
    MAX_DEPTH and the number of actions at MAX_STEPS, so no rule set can loop."""
    st = {k: v for k, v in state.items() if isinstance(k, str) and isinstance(v, str)}
    trace, budget = [], [MAX_STEPS]
    if not EVENT_RE.match(event or ""):
        return st, [("stop", "that is not an event name")]

    def go(ev, depth):
        if depth > MAX_DEPTH:
            trace.append(("stop", f"chain of fire actions deeper than {MAX_DEPTH}: stopped at {ev}"))
            return
        for r in rules:
            if r["event"] != ev:
                continue
            bad = [c for c in r["conds"] if not holds(c, st)]
            if bad:
                trace.append(("skip", f"{r['name']}: condition not met ({bad[0][1]})"))
                continue
            trace.append(("match", f"{r['name']} on {ev}"))
            for verb, a, b in r["actions"]:
                if budget[0] <= 0:
                    trace.append(("stop", f"more than {MAX_STEPS} actions: stopped"))
                    return
                budget[0] -= 1
                if verb == "set":
                    if a not in st and len(st) >= MAX_STATE:
                        trace.append(("stop", f"state is full ({MAX_STATE} keys): {a} not set"))
                        continue
                    st[a] = b
                    trace.append(("set", f"{a} = {b}"))
                elif verb == "unset":
                    st.pop(a, None)
                    trace.append(("set", f"{a} removed"))
                elif verb == "log":
                    trace.append(("log", a))
                else:
                    trace.append(("log", f"fire {a}"))
                    go(a, depth + 1)
    go(event, 1)
    if not any(k in ("match", "skip") for k, _ in trace):
        trace.append(("skip", f"no rule listens for {event}"))
    return st, trace


def version_hash(parent: str, text: str) -> str:
    return sha(parent + "\n" + text)


class Versions:
    """An append-only list of config texts, each hashed with its parent. Nothing is overwritten: a rollback is a new
    version that copies an old one. The oldest versions are dropped past MAX_VERSIONS, keeping the chain checkable."""

    def __init__(self, raw=None):
        self.base, self.items, self.next = "", [], 1
        if isinstance(raw, dict):
            if isinstance(raw.get("base"), str) and (SHA_RE.match(raw["base"]) or raw["base"] == ""):
                self.base = raw["base"]
            for v in raw.get("items", [])[:MAX_VERSIONS] if isinstance(raw.get("items"), list) else []:
                if (isinstance(v, dict) and isinstance(v.get("n"), int) and isinstance(v.get("text"), str)
                        and len(v["text"]) <= MAX_CONFIG and isinstance(v.get("at"), str) and STAMP_RE.match(v["at"])
                        and isinstance(v.get("h"), str) and SHA_RE.match(v["h"])):
                    self.items.append({"n": v["n"], "at": v["at"], "text": v["text"], "h": v["h"]})
        self.next = (self.items[-1]["n"] + 1) if self.items else 1

    def latest(self) -> str:
        return self.items[-1]["text"] if self.items else ""

    def save(self, text: str, now: str) -> int:
        """Validate then append. Returns the version number, or 0 if it is the same as the latest. Raises ConfigError."""
        text = text.replace("\r\n", "\n").rstrip("\n") if isinstance(text, str) else ""
        parse_rules(text)
        if self.items and text == self.items[-1]["text"]:
            return 0
        parent = self.items[-1]["h"] if self.items else self.base
        self.items.append({"n": self.next, "at": now, "text": text, "h": version_hash(parent, text)})
        self.next += 1
        while len(self.items) > MAX_VERSIONS:
            self.base = self.items.pop(0)["h"]
        return self.items[-1]["n"]

    def rollback(self, n: int, now: str) -> int:
        for v in self.items:
            if v["n"] == n:
                return self.save(v["text"], now)
        raise ConfigError(f"no version {n}")

    def verify(self) -> bool:
        prev = self.base
        for v in self.items:
            if v["h"] != version_hash(prev, v["text"]):
                return False
            prev = v["h"]
        return True

    def dump(self) -> dict:
        return {"base": self.base, "items": self.items}


EXAMPLE_RULES = """# One rule per line:  rule NAME: on EVENT [if COND and COND] then ACTION ; ACTION
rule deep-work: on enter:deep-work then set alerts=muted ; set view=pivot ; log entered deep work
rule leave-deep: on leave:deep-work then set alerts=on ; unset view ; log back to normal
rule late-ping: on enter:review if alerts=muted and hour>=18 then log skipped ping, it is late
"""


# ============================================================ semantic graph screens ====
def _row(n: dict) -> str:
    return f"{n['id']:<5} {n['kind']:<6} {n['status']:<6} {(n['project'] or '-'):<12} {n['title']}"


QUERY_HELP = [
    "Query: words and filters separated by spaces. All of them must match. A leading - means not.",
    "",
    "  kind:task  status:doing  project:alpha  context:work  tag:urgent",
    "  edited:today  edited:2026-11  created:2026  (a date, a month or a year; today works)",
    "  valid:today        nodes whose validity window covers a date (no window = always valid)",
    "  depends:n3         nodes that depend on n3        needs:n3   nodes that n3 depends on",
    "  rel:n3             nodes related to n3 either way  sha:9f2c     nodes with that content",
    "  report -status:done        any word must appear in the title or the content",
    "",
    "Example: show everything edited today in project alpha:   project:alpha edited:today",
    "",
    "What this is: one app's own notes, tasks and people in its private vault. It is not a file system",
    "and cannot see the OS's files. Content is stored once under its SHA-256; dependencies cannot form a",
    "cycle; the change history is a hash chain that catches accidental edits, not a signature.",
]


class NodeScreen(Screen):
    def __init__(self, g: Graph, i: str):
        self.g, self.i, self.title, self.flash = g, i, i, ""
        self.help = "e body  f field=value  d/D need  l/L relate  h history  g goto  x delete  Esc back"

    def status(self):
        return self.flash or self.help

    def _node(self):
        return self.g.nodes.get(self.i)

    def render(self, w, h):
        n = self._node()
        if not n:
            return ["", "  this node no longer exists"]
        g = self.g
        shared = g.shared_with(n)
        lines = [f"{n['id']}  [{n['kind']}]  {n['title']}", f"status: {n['status']}   days: {n['days'] or '-'}   due: {n['due'] or '-'}",
                 f"project: {n['project'] or '-'}   context: {n['context'] or '-'}   tags: {', '.join(n['tags']) or '-'}",
                 f"valid: {n['valid_from'] or '...'} to {n['valid_to'] or '...'}   created {n['created'] or '?'}   edited {n['edited'] or '?'}",
                 f"content: {n['sha'][:12]}" + (f" (the same content as {', '.join(shared)})" if shared else "")
                 + ("" if g.body_ok(n) else "  [content missing or damaged]"),
                 "needs:   " + (", ".join(f"{d} {g.nodes[d]['title'][:24]}" for d in n["deps"] if d in g.nodes) or "-"),
                 "blocks:  " + (", ".join(g.blockers_of(n["id"])) or "-"),
                 "related: " + (", ".join(f"{r[0]} {r[1]}" for r in n["rels"]) or "-"), "-" * 20]
        return lines + g.body(n).split("\n")

    def _do(self, fn):
        try:
            fn()
            self.flash = "saved"
        except GraphError as e:
            return ("push", Message("Not changed", [str(e)]))
        return None

    def key(self, k):
        self.flash = ""
        g, i, now = self.g, self.i, now_stamp()
        n = self._node()
        if k == "escape" or n is None:
            return ("pop", None)
        if k == "e":
            return ("push", BodyEditor(f"{i} content", g.body(n), self._save_body))
        if k == "f":
            def done(text):
                name, eq, val = text.partition("=")
                if not eq:
                    return ("push", Message("Not changed", ["Type  field=value  for example  project=alpha  or  tags=a,b",
                                                              "Fields: " + ", ".join(EDIT_FIELDS)]))
                return self._do(lambda: g.set_field(i, name.strip().lower(), val, now_stamp(), today()))
            return ("push", Prompt(f"{i} field", "field=value  (title kind status project context tags from to due days)", "", done))
        if k in ("d", "D"):
            add = k == "d"
            return ("push", Prompt(f"{i} dependency", f"{'Depends on' if add else 'No longer depends on'} node id:", "",
                                   lambda t: self._do(lambda: (g.add_dep if add else g.drop_dep)(i, t.strip().lower(), now_stamp()))))
        if k in ("l", "L"):
            add = k == "l"

            def rel(t):
                parts = t.strip().lower().split()
                if len(parts) != 2:
                    return ("push", Message("Not changed", ["Type  label node-id  for example  see-also n4"]))
                return self._do(lambda: (g.add_rel if add else g.drop_rel)(i, parts[0], parts[1], now_stamp()))
            return ("push", Prompt(f"{i} relation", f"{'Add' if add else 'Remove'} relation:  label node-id", "", rel))
        if k == "h":
            hist = g.history(i)
            lines = [f"{e['at']}  {e['op']:<5} {e['title'][:34]:<34} {e['sha'][:8]} {'kept' if e['kept'] else 'content dropped'}" for e in hist]
            return ("push", TextView(f"{i} history", lines or ["(nothing recorded)"]))
        if k == "g":
            def goto(t):
                t = t.strip().lower()
                if t in g.nodes:
                    return ("push", NodeScreen(g, t))
                return ("push", Message("No such node", [t[:20]]))
            return ("push", Prompt("Go to", "Node id:", "", goto))
        if k == "x":
            return ("push", Confirm(f"Delete {i} '{n['title'][:30]}'? The history keeps it.",
                                    lambda: self._delete(), "Delete"))
        return None

    def _save_body(self, text):
        try:
            self.g.set_body(self.i, text, now_stamp())
        except GraphError as e:
            raise ValueError(str(e))

    def _delete(self):
        try:
            self.g.remove(self.i, now_stamp())
        except GraphError as e:
            return ("push", Message("Not deleted", [str(e)]))
        return ("pop", None)


class BodyEditor(Editor):
    """The content editor: a refusal is shown on the status line instead of saying 'saved'."""

    def save(self):
        try:
            self.on_save(self.area.text)
        except ValueError as e:
            self.flash = str(e)[:70]
            return
        self.area.dirty = False
        self.flash = "saved"


class ResultList(Screen):
    def __init__(self, g: Graph, query: str):
        self.g, self.query = g, query
        self.title = "Results: " + (query[:30] or "all")
        self.nav = ListNav(0)
        self.help = "Enter open   / new query   n new node   Esc back"
        self.msg = ""
        self.ids = self._run()

    def _run(self):
        try:
            self.msg = ""
            return self.g.query(self.query, today())
        except GraphError as e:
            self.msg = str(e)
            return []

    def on_enter(self):
        self.ids = self._run()
        self.nav.resize(len(self.ids))

    def render(self, w, h):
        self.nav.resize(len(self.ids))
        if self.msg:
            return ["", "  " + self.msg]
        if not self.ids:
            return ["", "  nothing matches"]
        top, end = self.nav.window(h - 1)
        return [f"  {len(self.ids)} found"] + [("> " if j == self.nav.sel else "  ") + _row(self.g.nodes[self.ids[j]])[:w - 4]
                                                for j in range(top, end)]

    def key(self, k):
        if self.nav.key(k):
            return None
        if k == "escape":
            return ("pop", None)
        if k == "enter" and self.ids:
            return ("push", NodeScreen(self.g, self.ids[self.nav.sel]))
        if k == "/":
            return ("push", Prompt("Query", "words and filters (? in the menu for help):", self.query,
                                   lambda t: ("replace", ResultList(self.g, t))))
        if k == "n":
            return new_node(self.g)


def new_node(g: Graph):
    def done(text):
        t = text.strip()
        kind = "note"
        head, colon, rest = t.partition(":")
        if colon and head.strip().lower() in KINDS:
            kind, t = head.strip().lower(), rest
        try:
            i = g.add(t, now_stamp(), kind)
        except GraphError as e:
            return ("push", Message("Not added", [str(e)]))
        return ("push", NodeScreen(g, i))
    return ("push", Prompt("New node", "Title, optionally with a kind first:  task: Write the plan", "", done))


def plan_screen(g: Graph):
    def done(text):
        try:
            start = resolve_day(text, today()) or today()
            p = g.plan(start)
        except GraphError as e:
            return ("push", Message("No plan", [str(e)]))
        if not p["order"]:
            return ("push", Message("Nothing to plan", ["No open tasks. Make a node with kind task, give it days and needs."]))
        rows = [[i, p["rows"][i]["title"][:28], p["rows"][i]["days"], p["rows"][i]["start"], p["rows"][i]["finish"],
                 p["rows"][i]["slack"], ("CRITICAL " if p["rows"][i]["slack"] == 0 else "") + ("LATE" if p["rows"][i]["late"] else "")]
                for i in p["order"]]
        lines = [f"Starts {start}. Finishes {p['finish']} ({p['end']} days).",
                 f"Critical path (no slack): {' > '.join(p['critical'])}",
                 f"Late against their due date: {', '.join(p['late']) or 'none'}", ""]
        return ("push", TextView("Plan", lines + table(rows, ["id", "task", "days", "start", "finish", "slack", ""])))
    return ("push", Prompt("Plan", "Start date (Enter = today):", "", done))


def matrix_screen(g: Graph):
    xs, grid = g.matrix()
    rows = [[x or "(no project)", *[grid[x][s] for s in STATES], sum(grid[x].values())] for x in xs]
    lines = table(rows, ["project", *STATES, "total"]) if rows else ["(no nodes yet)"]
    return ("push", TextView("Matrix: project by state", lines))


def storage_screen(g: Graph):
    st, (ok, bad) = g.stats(), g.verify()
    lines = [f"nodes: {st['nodes']}   distinct contents: {st['distinct']}   characters not stored twice: {st['saved']}",
             f"saved size: {st['bytes']} of {MAX_STORE} characters",
             f"history: {st['log']} entries" + (f", older ones folded up to {st['folded_to']}" if st["folded_to"] else ""),
             "chain: ok" if ok else f"chain: BROKEN at entry {bad + 1} (edited or damaged since it was written)",
             "This chain catches accidental damage. Anyone who can rewrite this whole app's data can rewrite it too.", ""]
    for e in g.s["log"][-12:][::-1]:
        lines.append(f"{e['at']}  {e['op']:<5} {e['id']:<5} {(e['node'] or {}).get('title', '(deleted)')[:40]}")
    return ("push", TextView("Storage and history", lines))


def asof_screen(g: Graph):
    def done(text):
        try:
            d = resolve_day(text, today()) or today()
            nodes = g.asof(d)
        except GraphError as e:
            return ("push", Message("Cannot show that", [str(e)]))
        lines = [f"{len(nodes)} nodes at the end of {d}", ""] + [_row(nodes[i])[:76] for i in sorted(nodes, key=idnum)]
        return ("push", TextView(f"As of {d}", lines))
    return ("push", Prompt("As of", "Date (today, +N, 2026-11-07):", "", done))


def make_graph(host, entry):
    store = Store(host)
    raw_text = host.get("graph")
    bad = False
    if raw_text is not None:
        try:
            raw = json.loads(raw_text)
            bad = not isinstance(raw, dict)
        except ValueError:
            raw, bad = None, True
    else:
        raw = None

    def persist(state):
        if bad:                                           # never overwrite data we could not read
            raise GraphError("the saved graph could not be read, so nothing is saved over it")
        return store.save("graph", state)
    g = Graph(raw, persist)

    return GraphMenu(g, bad)


class GraphMenu(Menu):
    def __init__(self, g: Graph, unreadable: bool):
        self.g, self.unreadable = g, unreadable
        super().__init__("Semantic Graph", [
            ("Browse and search", lambda: ("push", Prompt("Query", "words and filters (empty = everything):", "",
                                                            lambda t: ("push", ResultList(g, t))))),
            ("New node", lambda: new_node(g)),
            ("Plan: critical path of open tasks", lambda: plan_screen(g)),
            ("Matrix: project by state", lambda: matrix_screen(g)),
            ("As of a date", lambda: asof_screen(g)),
            ("Storage and history", lambda: storage_screen(g)),
            ("Query help", lambda: ("push", TextView("Query help", QUERY_HELP))),
        ])

    def render(self, w, h):
        n = len(self.g.nodes)
        self.intro = [f"  {n} node{'s' if n != 1 else ''}"] + (
            ["  The saved data could not be read. Nothing will be saved over it."] if self.unreadable else [])
        return super().render(w, h)


# ============================================================ rule router screens ====
RULES_HELP = [
    "A rule is one line:   rule NAME: on EVENT [if COND and COND] then ACTION ; ACTION",
    "  EVENT   a name you choose, such as enter:deep-work. You fire it from this app.",
    "  COND    key   not key   key=v   key!=v   key>n   key<n   key>=n   key<=n",
    "  ACTION  set key=value   unset key   log text   fire EVENT",
    "",
    "Rules run in the order written. 'fire' chains events (at most 4 deep, 60 actions in all).",
    "Every save is a new numbered version with a hash of its parent. Nothing is overwritten;",
    "a rollback is a new version that copies an old one.",
    "",
    "What this is not: the actions change this app's own state and log. A sandboxed app cannot mute",
    "alerts, commit code or switch a view, and nothing here watches the system for events.",
]


class RuleEditor(Editor):
    """Ctrl-S checks the whole config and saves a new version, or says which line is wrong and saves nothing."""

    def __init__(self, router):
        super().__init__("Rules", router.versions.latest() or EXAMPLE_RULES, None, numbers=True,
                         hint="one rule per line")
        self.router = router

    def save(self):
        try:
            n = self.router.versions.save(self.area.text, now_stamp())
            if n and not self.router.persist():
                self.flash = "could not save"
                return
        except ConfigError as e:
            self.flash = str(e)[:70]
            return
        self.area.dirty = False
        self.flash = f"saved as version {n}" if n else "same as the latest version"


class Router:
    def __init__(self, host):
        self.store = Store(host)
        raw = self.store.load("rules", {})
        raw = raw if isinstance(raw, dict) else {}
        self.versions = Versions(raw.get("versions"))
        st = raw.get("state")
        self.state = {k: v for k, v in (st if isinstance(st, dict) else {}).items()
                      if isinstance(k, str) and KEY_RE.match(k) and isinstance(v, str) and len(v) <= 40}
        self.runlog = [x for x in (raw.get("runlog") if isinstance(raw.get("runlog"), list) else [])
                       if isinstance(x, str)][-MAX_RUNLOG:]

    def persist(self) -> bool:
        return self.store.save("rules", {"versions": self.versions.dump(), "state": self.state, "runlog": self.runlog[-MAX_RUNLOG:]})

    def rules(self):
        try:
            return parse_rules(self.versions.latest())
        except ConfigError:
            return []

    def fire(self, event: str) -> list:
        self.state, trace = fire(self.rules(), self.state, event.strip().lower())
        self.runlog.append(f"{now_stamp()}  {event.strip().lower()[:40]}  ->  " + "; ".join(t for k, t in trace if k in ("match", "log"))[:120])
        self.runlog = self.runlog[-MAX_RUNLOG:]
        self.persist()
        return trace


def make_router(host, entry):
    r = Router(host)

    def fire_screen():
        def done(text):
            ev = text.strip().lower()
            if not EVENT_RE.match(ev):
                return ("push", Message("Not an event", ["Use letters, digits and : _ . - , for example enter:deep-work"]))
            trace = r.fire(ev)
            lines = [f"{k:<6} {t}" for k, t in trace] + ["", "State now:"] + [f"  {k} = {v}" for k, v in sorted(r.state.items())]
            return ("push", TextView(f"Fired {ev}", lines))
        return ("push", Prompt("Fire an event", "Event name:", "", done))

    def versions_screen():
        v = r.versions
        lines = [("chain ok" if v.verify() else "CHAIN BROKEN: a version was changed after it was saved"), ""]
        lines += [f"v{x['n']:<3} {x['at']}  {x['h'][:10]}  {len(x['text'])} chars" for x in reversed(v.items)] or ["(no versions yet)"]

        def pick(text):
            if not re.fullmatch(r"\d{1,6}", text.strip()):
                return ("push", Message("Not a version", ["Type a version number such as 2"]))
            try:
                n = v.rollback(int(text), now_stamp())
                r.persist()
            except ConfigError as e:
                return ("push", Message("Not rolled back", [str(e)]))
            return ("push", Message("Rolled back", [f"Saved as version {n}." if n else "That is already the latest version."]))
        return ("push", Menu("Versions", [("Roll back to a version (saves a new one)", lambda: ("push", Prompt("Roll back", "Version number:", "", pick))),
                                          ("Show the list", lambda: ("push", TextView("Versions", lines)))],
                             [f"  {len(v.items)} version{'s' if len(v.items) != 1 else ''}"]))

    def state_screen():
        lines = [f"{k} = {v}" for k, v in sorted(r.state.items())] or ["(empty)"]
        return ("push", TextView("State", lines))

    def reset():
        r.state = {}
        r.persist()
        return ("push", Message("State cleared", ["The rules and their versions are untouched."]))

    return Menu("Rule Router", [
        ("Edit the rules (Ctrl-S saves a version)", lambda: ("push", RuleEditor(r))),
        ("Fire an event", fire_screen),
        ("Show the state", state_screen),
        ("Run log", lambda: ("push", TextView("Run log", list(reversed(r.runlog)) or ["(nothing yet)"]))),
        ("Versions and rollback", versions_screen),
        ("Clear the state", lambda: ("push", Confirm("Clear all state keys?", reset, "Clear"))),
        ("Rule syntax", lambda: ("push", TextView("Rule syntax", RULES_HELP))),
    ], ["  Event, condition, action rules over this app's own state."])


# ============================================================ catalogue ====
ENTRIES: list = [
    app("Semantic Graph", make_graph, "partial",
        "A graph of this app's own notes, tasks and people: shared metadata, content stored once by SHA-256, a "
        "dependency DAG, queries, project/state matrix, critical path and a hash-chained history. Not a file "
        "system and sees no OS files; no encryption yet."),
    app("Rule Router", make_router, "partial",
        "Event-condition-action rules in a versioned declarative text. Actions only change the router's own "
        "state and log: it cannot mute alerts, commit code or switch views, and nothing fires events for you."),
    none("Semantic Object Kernel",
         "Not buildable as an app: KOS runs on Linux, whose I/O is byte streams, and kernel transactions are "
         "out of reach for sandboxed apps. Apps already talk to the OS in schema-checked JSON commands."),
    none("Workflow Engine Isolation",
         "Partly covered by design: every app is its own sandboxed process, and `kos cell` runs code in KVM "
         "micro-VMs. KOS has no organizational automation daemons to separate from drivers."),
    none("Workspace Resource Scheduler",
         "Not built: the OS does not schedule CPU or memory per workspace. Each app gets fixed limits from the "
         "sandbox (1 GiB memory, 64 MiB per file); apps cannot set priorities."),
    none("Native Graph File System",
         "Not a file system. Semantic Graph keeps nodes and content hashes for one app's own items; `kos ls` "
         "still shows ordinary folders, and nothing in the OS indexes or deduplicates files."),
    none("Matrix Workspaces and Layouts",
         "Not built: there is no window manager (`kos boot desktop` lists apps one at a time), so no workspace "
         "matrix or semantic layouts. Semantic Graph's matrix only counts its own nodes."),
    none("Deep State Snapshots",
         "Not built: running apps cannot be paused, forked or restored, and registers and memory are out of "
         "reach. Semantic Graph can show its own data as of a past date."),
    none("Universal Data Bus",
         "Not built: apps cannot pass rich objects to each other. They share records only through shared "
         "folders the owner grants (`kos grant`, `kos spaces`); there is no common clipboard or drag-and-drop."),
    none("Structured Terminal Pipelines",
         "Not built: `kos line` runs one command per line with no pipes, and command output is text. The "
         "app-to-OS channel is already JSON lines, but nothing chains commands as objects."),
    none("Atomic Component Applications",
         "Not built: an app is a whole sandboxed program with its own screen, and one app cannot embed "
         "another's view. Shared folders are the only way apps combine today."),
    none("Kernel Event Router",
         "Not an app: the OS has no event bus and sandboxed apps cannot observe or change the system. Rule "
         "Router reacts only to events you fire inside it."),
    none("Declarative System Configuration",
         "Not built: OS state lives in several files and the kernel command line, and nothing rebuilds it from "
         "one config. Rule Router versions its own rules only."),
]
