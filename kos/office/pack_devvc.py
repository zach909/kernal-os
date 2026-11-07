"""pack_devvc: Version Control, Code Review, Package Manager, Build Planner, Config Editor (see docs/PACKS.md).

All engines are pure functions or small classes over text; nothing here runs a program, reads a file outside
the vault or opens a connection."""

from __future__ import annotations

import ast
import builtins
import configparser
import difflib
import hashlib
import json
import re
import tomllib

from .packkit import app, shared_items
from .ui import Editor, ListNav, Menu, Message, Confirm, Prompt, Screen, Store, TextView, now_stamp, slug

SHARED_TEXT = 50_000          # per-record cap in the shared "repos" folder


def _tv(title, lines): return ("push", TextView(title, list(lines)[:5000]))
def _ask(title, label, done, initial=""): return ("push", Prompt(title, label, initial, done))
def _edit(title, text, save, numbers=True): return ("push", Editor(title, text, save, numbers=numbers))


class Lister(Screen):
    """A cursor list; `keys` maps a key to fn(selected_index) -> Action."""

    def __init__(self, title, rows, keys, help, empty="(nothing here)"):
        self.title, self.rows, self.keys_, self.help, self.empty = title, rows, keys, help, empty
        self.nav, self.msg = ListNav(0), ""

    def render(self, w, h):
        rows = self.rows()
        self.nav.resize(len(rows))
        top, end = self.nav.window(h - 1)
        return [("> " if i == self.nav.sel else "  ") + rows[i][:w - 4] for i in range(top, end)] or ["  " + self.empty]

    def status(self): return self.msg or self.help

    def key(self, k):
        if self.nav.key(k): return None
        if k == "escape": return ("pop", None)
        fn = self.keys_.get(k)
        if fn:
            self.msg = ""
            return fn(self.nav.sel)


def _shared_files(host):
    """Records of the shared 'repos' folder as {label: text}; (files, granted-or-empty flag)."""
    out = {}
    for r in shared_items(host, "repos"):
        p, t = r.get("path"), r.get("text")
        if isinstance(p, str) and isinstance(t, str):
            out[f"{r.get('branch', '')}:{p}"[:80]] = t[:SHARED_TEXT]
    return out


def _pick_shared(host, what, on_text):
    files = _shared_files(host)
    if not files:
        return ("push", Message("Shared files", ["No files from Version Control are readable here.",
                "Either Version Control has not committed anything yet, or access was not granted "
                "(kos grant APP repos --level read). You can still paste text into " + what + "."]))
    names = sorted(files)
    return ("push", Lister("Files from Version Control", lambda: names,
                           {"enter": lambda i: ("pop", lambda: on_text(names[i], files[names[i]]))}, "Enter pick   Esc back"))


# =================================================================== Version Control ====
class RepoError(Exception): pass


MAX_FILES, MAX_FILE, MAX_REPO, MAX_COMMITS = 200, 100_000, 1_000_000, 500


def _h(s): return hashlib.sha256(s.encode("utf-8")).hexdigest()


def has_markers(t):
    L = t.split("\n")
    return any(x.startswith("<<<<<<< ") for x in L) and any(x.startswith(">>>>>>> ") for x in L)


def _hunks(base, new):
    sm = difflib.SequenceMatcher(None, base, new, autojunk=False)
    return [(i1, i2, new[j1:j2]) for tag, i1, i2, j1, j2 in sm.get_opcodes() if tag != "equal"]


def _apply(hunks, base, s, e):
    out, pos = [], s
    for i1, i2, rep in hunks:
        out += base[pos:i1] + rep
        pos = i2
    return out + base[pos:e]


def merge3(base, a, b, la="ours", lb="theirs"):
    """Three-way line merge. Lists of lines in, (lines, number of conflicts) out."""
    ha, hb = _hunks(base, a), _hunks(base, b)
    out, pos, i, j, nconf = [], 0, 0, 0, 0
    while i < len(ha) or j < len(hb):
        starts = [h[0] for h in (ha[i:i + 1] + hb[j:j + 1])]
        s = e = min(starts)
        ca, cb, grow = [], [], True
        while grow:
            grow = False
            if i < len(ha) and ha[i][0] <= e: ca.append(ha[i]); e = max(e, ha[i][1]); i += 1; grow = True
            if j < len(hb) and hb[j][0] <= e: cb.append(hb[j]); e = max(e, hb[j][1]); j += 1; grow = True
        out += base[pos:s]
        pos = e
        va = _apply(ca, base, s, e) if ca else None
        vb = _apply(cb, base, s, e) if cb else None
        if va is None or vb is None or va == vb:
            out += va if va is not None else vb
        else:
            nconf += 1
            out += [f"<<<<<<< {la}", *va, "=======", *vb, f">>>>>>> {lb}"]
    return out + base[pos:], nconf


def tree_merge(base, ours, theirs):
    """Merge three {path: text} maps. Returns (result, conflicted paths); conflicts carry markers."""
    res, bad = {}, []
    for p in sorted(set(base) | set(ours) | set(theirs)):
        b, o, t = base.get(p), ours.get(p), theirs.get(p)
        if o == t: r = o
        elif o == b: r = t
        elif t == b: r = o
        elif o is None or t is None:
            ol = o.split("\n") if o is not None else []
            tl = t.split("\n") if t is not None else []
            r = "\n".join(["<<<<<<< ours", *ol, "=======", *tl, ">>>>>>> theirs"]); bad.append(p)
        else:
            lines, n = merge3(b.split("\n") if b is not None else [], o.split("\n"), t.split("\n"))
            r = "\n".join(lines)
            if n: bad.append(p)
        if r is not None: res[p] = r
    return res, bad


class Repo:
    def __init__(self, data=None):
        d = data if isinstance(data, dict) else {}
        def dct(k):
            v = d.get(k)
            return {a: b for a, b in v.items() if isinstance(a, str)} if isinstance(v, dict) else {}
        self.objects, self.branches, self.tags = dct("objects"), dct("branches"), dct("tags")
        self.work = {k: v for k, v in dct("work").items() if isinstance(v, str)}
        c = d.get("commits")
        self.commits = [x for x in c if isinstance(x, str)] if isinstance(c, list) else []
        self.head = d.get("head") if isinstance(d.get("head"), str) else "main"
        self.detached = d.get("detached") if isinstance(d.get("detached"), str) else None
        self.merge = d.get("merge") if isinstance(d.get("merge"), str) else None
        if not self.detached and self.head not in self.branches: self.branches.setdefault(self.head or "main", None); self.head = self.head or "main"

    def to_data(self):
        return {"objects": self.objects, "branches": self.branches, "tags": self.tags, "work": self.work,
                "commits": self.commits, "head": self.head, "detached": self.detached, "merge": self.merge}

    # -- objects
    def obj(self, i):
        t = self.objects.get(i)
        if not isinstance(t, str) or _h(t) != i:
            raise RepoError(f"object {str(i)[:10]} is missing or corrupted - refusing to use it")
        return t

    def commit_data(self, cid):
        if cid not in self.commits: raise RepoError(f"unknown commit {str(cid)[:10]}")
        try: c = json.loads(self.obj(cid))
        except ValueError: raise RepoError(f"commit {cid[:10]} is corrupted")
        if not (isinstance(c, dict) and isinstance(c.get("tree"), dict) and isinstance(c.get("parents"), list)):
            raise RepoError(f"commit {cid[:10]} is malformed")
        return c

    def files_of(self, cid):
        if cid is None: return {}
        return {p: self.obj(b) for p, b in self.commit_data(cid)["tree"].items()}

    def tip(self): return self.detached if not self.head else self.branches.get(self.head)

    def ancestors(self, cid):
        seen, st = set(), [cid] if cid else []
        while st:
            c = st.pop()
            if c in seen: continue
            seen.add(c)
            st += [p for p in self.commit_data(c)["parents"] if isinstance(p, str)]
        return seen

    def resolve(self, ref):
        ref = (ref or "").strip()
        if ref in ("", "HEAD"):
            if self.tip() is None: raise RepoError("no commits yet")
            return self.tip()
        for m in (self.branches, self.tags):
            if ref in m:
                if m[ref] is None: raise RepoError(f"{ref} has no commits")
                return m[ref]
        hit = [c for c in self.commits if len(ref) >= 4 and c.startswith(ref)]
        if len(hit) == 1: return hit[0]
        raise RepoError(f"no branch, tag or commit matches '{ref[:40]}'" if not hit else f"'{ref}' matches several commits")

    # -- working tree
    @staticmethod
    def check_path(p):
        if not (isinstance(p, str) and re.fullmatch(r"[A-Za-z0-9._/ -]{1,100}", p)) or ".." in p or p[0] in "/ ." or p.endswith(("/", " ")) or "//" in p:
            raise RepoError("path must be 1-100 of letters, digits, . _ - / space; no '..', no leading '/' or '.'")

    @staticmethod
    def check_name(n):
        if not (isinstance(n, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,39}", n)) or ".." in n:
            raise RepoError("name must be 1-40 of letters, digits, . _ - and start with a letter or digit")

    def size(self): return sum(map(len, self.objects.values())) + sum(map(len, self.work.values()))

    def set_file(self, p, text):
        self.check_path(p)
        if not isinstance(text, str) or "\x00" in text: raise RepoError("text files only (no NUL characters)")
        if len(text) > MAX_FILE: raise RepoError(f"file too large (limit {MAX_FILE} characters)")
        if p not in self.work and len(self.work) >= MAX_FILES: raise RepoError(f"too many files (limit {MAX_FILES})")
        if self.size() - len(self.work.get(p, "")) + len(text) > MAX_REPO: raise RepoError("repository size limit reached")
        self.work[p] = text

    def del_file(self, p):
        if p not in self.work: raise RepoError("no such file")
        del self.work[p]

    def status(self):
        base = self.files_of(self.tip())
        w = self.work
        return {"added": sorted(set(w) - set(base)), "deleted": sorted(set(base) - set(w)),
                "modified": sorted(p for p in w if p in base and w[p] != base[p]),
                "conflicts": sorted(p for p in w if has_markers(w[p]))}

    def dirty(self): return any(self.status()[k] for k in ("added", "deleted", "modified"))

    # -- history
    def commit(self, msg, author, when):
        msg, author = (msg or "").strip(), (author or "").strip()
        if not msg or len(msg) > 500: raise RepoError("message required (max 500 characters)")
        if not author or len(author) > 60 or "\n" in author: raise RepoError("author required (max 60 characters, one line)")
        if self.detached: raise RepoError("detached HEAD: make a branch first (Branches and tags)")
        if self.status()["conflicts"]: raise RepoError("resolve the conflict markers first")
        if len(self.commits) >= MAX_COMMITS: raise RepoError(f"history limit reached ({MAX_COMMITS} commits)")
        tip = self.tip()
        tree = {p: _h(t) for p, t in self.work.items()}
        if not self.merge and tip and tree == self.commit_data(tip)["tree"]: raise RepoError("nothing to commit")
        if not self.merge and tip is None and not tree: raise RepoError("nothing to commit")
        new = {_h(t): t for t in self.work.values()}
        parents = [x for x in (tip, self.merge) if x]
        body = json.dumps({"tree": tree, "parents": parents, "msg": msg, "author": author, "time": str(when)[:40]},
                          sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        cid = _h(body)
        if sum(len(v) for k, v in new.items() if k not in self.objects) + len(body) + sum(map(len, self.objects.values())) > MAX_REPO:
            raise RepoError("repository size limit reached")
        self.objects.update(new); self.objects[cid] = body
        self.commits.append(cid); self.branches[self.head] = cid; self.merge = None
        return cid

    def log(self, limit=100):
        tip = self.tip()
        anc = self.ancestors(tip) if tip else set()
        return [c for c in reversed(self.commits) if c in anc][:limit]

    def diff_files(self, old, new, limit=2000):
        out = []
        for p in sorted(set(old) | set(new)):
            if old.get(p) == new.get(p): continue
            a = old[p].split("\n") if p in old else []
            b = new[p].split("\n") if p in new else []
            out += list(difflib.unified_diff(a, b, f"a/{p}" if p in old else "/dev/null", f"b/{p}" if p in new else "/dev/null", lineterm="", n=3))
            if len(out) > limit: return out[:limit] + ["... diff truncated"]
        return out

    def diff_work(self): return self.diff_files(self.files_of(self.tip()), self.work)

    def diff_commit(self, cid):
        ps = self.commit_data(cid)["parents"]
        return self.diff_files(self.files_of(ps[0]) if ps else {}, self.files_of(cid))

    # -- moving around
    def checkout(self, ref):
        cid = self.resolve(ref)
        if self.dirty() or self.merge: raise RepoError("uncommitted changes: commit them or restore the files first")
        files = self.files_of(cid)
        if ref.strip() in self.branches: self.head, self.detached = ref.strip(), None
        else: self.head, self.detached = "", cid
        self.work = files
        return f"now on {self.head or 'detached ' + cid[:8]}"

    def restore(self, path, ref=""):
        files = self.files_of(self.resolve(ref))
        if path in files: self.work[path] = files[path]
        elif path in self.work: del self.work[path]
        else: raise RepoError("file is in neither the commit nor the working tree")

    def branch(self, name, ref=""):
        self.check_name(name)
        if name in self.branches or len(self.branches) >= 50: raise RepoError("branch exists or too many branches (limit 50)")
        self.branches[name] = self.resolve(ref)

    def delete_branch(self, name):
        if name == self.head or name not in self.branches: raise RepoError("cannot delete the current or an unknown branch")
        del self.branches[name]

    def tag(self, name, ref=""):
        self.check_name(name)
        if name in self.tags or len(self.tags) >= 100: raise RepoError("tag exists (tags never move) or too many tags (limit 100)")
        self.tags[name] = self.resolve(ref)

    def revert(self, ref, author, when):
        cid = self.resolve(ref)
        ps = self.commit_data(cid)["parents"]
        if len(ps) > 1: raise RepoError("cannot revert a merge commit")
        if self.dirty() or self.merge: raise RepoError("uncommitted changes: commit them first")
        res, bad = tree_merge(self.files_of(cid), self.files_of(self.tip()), self.files_of(ps[0]) if ps else {})
        if res == self.work and not bad: raise RepoError("nothing to revert (already undone?)")
        self.work = res
        if bad: return f"conflicts in {', '.join(bad)}: fix the markers, then commit"
        msg = "Revert: " + self.commit_data(cid)["msg"].split("\n")[0][:200]
        return "reverted as " + self.commit(msg, author, when)[:8]

    def merge_branch(self, ref, author, when):
        other = self.resolve(ref)
        tip = self.tip()
        if self.dirty() or self.merge: raise RepoError("uncommitted changes: commit them first")
        if self.detached: raise RepoError("detached HEAD: check out a branch to merge into")
        if tip is None:
            self.branches[self.head] = other; self.work = self.files_of(other); return "fast-forwarded"
        mine, theirs = self.ancestors(tip), self.ancestors(other)
        if other in mine: return "already up to date"
        if tip in theirs:
            self.branches[self.head] = other; self.work = self.files_of(other); return "fast-forwarded"
        common = mine & theirs
        base = self.files_of(max(common, key=self.commits.index)) if common else {}
        res, bad = tree_merge(base, self.files_of(tip), self.files_of(other))
        self.work = res
        if bad:
            self.merge = other
            return f"CONFLICTS in {', '.join(bad)}: fix the markers, then commit"
        self.merge = other
        return "merged as " + self.commit(f"Merge {str(ref).strip()[:40]}", author, when)[:8]

    def verify(self):
        bad = [f"object {i[:10]} does not match its hash" for i, t in sorted(self.objects.items()) if not isinstance(t, str) or _h(t) != i]
        for c in self.commits:
            try:
                for b in self.commit_data(c)["tree"].values(): self.obj(b)
            except RepoError as e: bad.append(str(e))
        return bad

    def shared_records(self):
        tip = self.tip()
        branch = self.head or "detached"
        return [{"path": p, "text": t[:SHARED_TEXT], "branch": branch} for p, t in sorted(self.files_of(tip).items())] if tip else []


def publish_repos(host, repo):
    """Mirror the current branch's committed files into the shared 'repos' folder (one record per path)."""
    try: d = json.loads(host.get("records", "repos") or "null")
    except (ValueError, TypeError): d = None
    old = {r.get("path"): r.get("_id") for r in (d.get("items") if isinstance(d, dict) and isinstance(d.get("items"), list) else []) if isinstance(r, dict)}
    nxt = d.get("next") if isinstance(d, dict) and isinstance(d.get("next"), int) else 1
    items = []
    for r in repo.shared_records():
        i = old.get(r["path"])
        if not isinstance(i, int): i, nxt = nxt, nxt + 1
        items.append({**r, "_id": i, "_at": now_stamp()})
    return bool(host.put("records", json.dumps({"next": nxt, "items": items}, separators=(",", ":"), ensure_ascii=False), "repos"))


class VC(Menu):
    def __init__(self, host):
        self.host, self.st, self.note = host, Store(host), ""
        self.repo = Repo(self.st.load("repo"))
        super().__init__("Version Control", [
            ("Files (add, edit, delete)", self.files), ("Status", self.show_status), ("Commit", self.commit), ("Log", self.log),
            ("Diff against last commit", lambda: _tv("Diff", self.repo.diff_work() or ["no changes"])),
            ("Branches and tags", self.refs),
            ("Checkout a branch, tag or commit", lambda: self.ask("Checkout", "Branch, tag or commit id:", lambda r: self.do(self.repo.checkout, r))),
            ("Restore a file from the last commit", lambda: self.ask("Restore", "File path:", lambda p: self.do(self.repo.restore, p))),
            ("Revert a commit", lambda: self.ask("Revert", "Commit id or tag:", lambda r: self.do(self.repo.revert, r, self.author(), now_stamp()))),
            ("Merge a branch into this one", lambda: self.ask("Merge", "Branch, tag or commit id:", lambda r: self.do(self.repo.merge_branch, r, self.author(), now_stamp()))),
            ("Verify every object (hashes)", lambda: self.do(lambda: "repository OK" if not self.repo.verify() else "PROBLEMS: " + "; ".join(self.repo.verify()[:3]))),
            ("About and limits", self.about)])

    def ask(self, title, label, fn, initial=""): return _ask(title, label, fn, initial)
    def author(self): return self.host.get("author") or "me"

    def render(self, w, h):
        r = self.repo
        s = r.status()
        self.intro = [f"  on {r.head or 'detached ' + str(r.tip())[:8]}  commits {len(r.commits)}  changed {len(s['added']) + len(s['modified']) + len(s['deleted'])}"
                      + (f"  CONFLICTS {len(s['conflicts'])}" if s["conflicts"] else "") + ("  (merge pending: commit to finish)" if r.merge else "")]
        if self.note: self.intro.append("  " + self.note[:w - 4])
        return super().render(w, h)

    def key(self, k):
        self.note = "" if k in ("up", "down") else self.note
        return super().key(k)

    def save(self):
        ok = self.st.save("repo", self.repo.to_data())
        if ok and self.repo.tip(): publish_repos(self.host, self.repo)
        return ok

    def do(self, fn, *a):
        try: msg = fn(*a)
        except RepoError as e: self.note = str(e); return None
        if not self.save(): self.note = "could not save: " + (self.host.error or "vault refused")
        elif isinstance(msg, str): self.note = msg
        return None

    def save_file(self, p, t): return self.do(self.repo.set_file, p, t)

    def files(self):
        r = self.repo
        def rows():
            s = r.status()
            return [("A " if p in s["added"] else "M " if p in s["modified"] else "  ") + p for p in sorted(r.work)]
        def edit(i):
            ns = sorted(r.work)
            return _edit(ns[i], r.work[ns[i]], lambda t, p=ns[i]: self.save_file(p, t)) if ns else None
        def new(i):
            def got(p):
                try: r.check_path(p)
                except RepoError as e: return ("push", Message("Not allowed", [str(e)]))
                return _edit(p, r.work.get(p, ""), lambda t: self.save_file(p, t))
            return _ask("New file", "Path (e.g. notes/todo.txt):", got)
        def rm(i):
            ns = sorted(r.work)
            if ns: self.do(r.del_file, ns[i])
        return ("push", Lister("Files", rows, {"enter": edit, "a": new, "d": rm}, "Enter edit  a add  d delete from working copy (restore brings it back)", "(no files: press a)"))

    def show_status(self):
        s = self.repo.status()
        lines = [f"on {self.repo.head or 'detached'}"] + [f"{k}: {', '.join(s[k])}" for k in ("added", "modified", "deleted", "conflicts") if s[k]]
        return _tv("Status", lines if len(lines) > 1 else lines + ["clean"])

    def commit(self):
        return _ask("Commit", "Message:", lambda m: _ask("Commit", "Author:", lambda a: (self.host.put("author", a[:60]), self.do(self.repo.commit, m, a, now_stamp()))[1], self.author()))

    def log(self):
        r = self.repo
        def rows():
            out = []
            for c in r.log():
                d = r.commit_data(c)
                out.append(f"{c[:8]} {d.get('time', '')} {d.get('author', '')}: {str(d.get('msg', '')).splitlines()[0][:50] if d.get('msg') else ''}" + ("  (merge)" if len(d["parents"]) > 1 else ""))
            return out
        def show(i):
            ids = r.log()
            if not ids: return None
            try: d = r.commit_data(ids[i]); body = r.diff_commit(ids[i])
            except RepoError as e: return ("push", Message("Refused", [str(e)]))
            return _tv(ids[i][:8], [f"commit {ids[i]}", f"author {d.get('author')}", f"time   {d.get('time')}", "", *str(d.get("msg", "")).split("\n"), "", *body])
        return ("push", Lister("Log", rows, {"enter": show}, "Enter show commit", "(no commits yet)"))

    def refs(self):
        r = self.repo
        def items(): return [("branch", n) for n in sorted(r.branches)] + [("tag", n) for n in sorted(r.tags)]
        def rows():
            return [("* " if k == "branch" and n == r.head else "  ") + f"{k} {n} -> {str((r.branches if k == 'branch' else r.tags)[n])[:8]}" for k, n in items()]
        def co(i):
            it = items()
            if it: self.do(r.checkout, it[i][1]); return ("pop", None)
        def rm(i):
            it = items()
            if it and it[i][0] == "branch": self.do(r.delete_branch, it[i][1])
        return ("push", Lister("Branches and tags", rows, {"n": lambda i: _ask("New branch", "Name (starts at the current commit):", lambda n: self.do(r.branch, n)),
                                                           "t": lambda i: _ask("New tag", "Name:", lambda n: self.do(r.tag, n)), "c": co, "d": rm},
                               "n branch  t tag  c checkout  d delete branch"))

    def about(self):
        return ("push", Message("Version Control", [
            "A local, single-user history of text files kept in the vault. Objects are named by the SHA-256 of their content and re-checked on every read; a corrupted object is refused.",
            f"Limits: {MAX_FILES} files, {MAX_FILE} characters per file, {MAX_COMMITS} commits, about {MAX_REPO // 1000} KB in all.",
            "Merge is a line-based three-way merge with conflict markers. No remotes: nothing is pushed or pulled, and it cannot read your real files; paste text in.",
            "The committed files of the current branch are shared read-only with Code Review, Config Editor and Build Planner (folder 'repos')."]))


# ======================================================================= Code Review ====
MAX_SRC = 200_000
_BUILTINS = {n for n in dir(builtins) if n[0].islower() and not n.startswith("_")}
_SECRET_KV = re.compile(r"""(?i)\b([\w.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)[\w.-]*)['"]?\s*[:=]\s*(['"])([^'"\s]{6,})\2""")
_PLACEHOLDER = re.compile(r"(?i)^(changeme|change-me|xxx+|\*+|<.*>|\$\{.*\}|\{\{.*\}\}|your[-_ ].*|example.*|none|null|placeholder|todo)$")
_SECRET_TOKENS = [(re.compile(p), n) for p, n in (
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"), (r"ghp_[A-Za-z0-9]{36}", "GitHub token"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "private key block"), (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"))]
_PK, _EV, _EX, _SP = "pick" + "le", "ev" + "al", "ex" + "ec", "sub" + "process"      # spelled apart: this module never uses them
_DANGER = {_EV: ("error", _EV + "() runs arbitrary code"), _EX: ("error", _EX + "() runs arbitrary code"), "os.sys" + "tem": ("warn", "runs a shell command"),
           "os.popen": ("warn", "os.popen runs a shell command"), _PK + ".load": ("warn", _PK + " can run code while loading"),
           _PK + ".loads": ("warn", _PK + " can run code while loading"), "marshal.loads": ("warn", "marshal loading is unsafe on untrusted data"),
           "__import__": ("warn", "dynamic import"), "shelve.open": ("warn", "shelve uses " + _PK)}


def _f(line, sev, rule, msg): return {"line": int(line or 1), "sev": sev, "rule": rule, "msg": msg}


def _dotted(n):
    parts = []
    while isinstance(n, ast.Attribute): parts.append(n.attr); n = n.value
    if isinstance(n, ast.Name): parts.append(n.id)
    else: return ""
    return ".".join(reversed(parts))


def _scope(fn):
    """Nodes of one function body, not descending into nested functions, lambdas or classes."""
    st, out = list(fn.body), []
    while st:
        n = st.pop()
        out.append(n)
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            st += list(ast.iter_child_nodes(n))
    return out


def _complexity(fn):
    c = 1
    for n in _scope(fn):
        if isinstance(n, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp)): c += 1
        elif isinstance(n, ast.BoolOp): c += len(n.values) - 1
        elif isinstance(n, ast.comprehension): c += 1 + len(n.ifs)
        elif isinstance(n, ast.match_case): c += 1
    return c


def _py(text, docstrings):
    try: tree = ast.parse(text)
    except SyntaxError as e: return [_f(e.lineno, "error", "syntax", e.msg)]
    except (RecursionError, MemoryError, ValueError, OverflowError): return [_f(1, "error", "too-deep", "cannot analyse: nesting too deep or invalid characters")]
    out, nodes = [], list(ast.walk(tree))
    loaded = {n.id for n in nodes if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    for n in nodes:                                           # names exported by __all__ count as used
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in n.targets):
            loaded |= {c.value for c in ast.walk(n.value) if isinstance(c, ast.Constant) and isinstance(c.value, str)}
    for n in nodes:
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            if isinstance(n, ast.ImportFrom) and n.module == "__future__": continue
            for a in n.names:
                nm = (a.asname or a.name).split(".")[0]
                if nm != "*" and nm not in loaded: out.append(_f(n.lineno, "warn", "unused-import", f"'{nm}' is imported but never used"))
                if nm in _BUILTINS: out.append(_f(n.lineno, "info", "shadow-builtin", f"import shadows builtin '{nm}'"))
        elif isinstance(n, ast.ExceptHandler):
            if n.type is None: out.append(_f(n.lineno, "warn", "bare-except", "bare 'except:' also catches KeyboardInterrupt and SystemExit"))
            elif _dotted(n.type) in ("Exception", "BaseException") and all(isinstance(b, ast.Pass) for b in n.body):
                out.append(_f(n.lineno, "warn", "swallowed-error", "broad exception silently ignored"))
        elif isinstance(n, ast.Call):
            d = _dotted(n.func)
            if d in _DANGER: out.append(_f(n.lineno, _DANGER[d][0], "dangerous-call", f"{d}: {_DANGER[d][1]}"))
            if d.startswith(_SP + ".") and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in n.keywords):
                out.append(_f(n.lineno, "error", "shell-true", f"{d} with shell=True allows command injection"))
        elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id in _BUILTINS:
            out.append(_f(n.lineno, "info", "shadow-builtin", f"assignment shadows builtin '{n.id}'"))
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name in _BUILTINS:
            out.append(_f(n.lineno, "info", "shadow-builtin", f"definition shadows builtin '{n.name}'"))
        elif isinstance(n, ast.arg) and n.arg in _BUILTINS:
            out.append(_f(n.lineno, "info", "shadow-builtin", f"argument shadows builtin '{n.arg}'"))
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = n.args
            for d in a.defaults + [x for x in a.kw_defaults if x is not None]:
                if isinstance(d, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)) or (isinstance(d, ast.Call) and _dotted(d.func) in ("list", "dict", "set", "defaultdict", "deque")):
                    out.append(_f(d.lineno, "warn", "mutable-default", f"mutable default argument in '{n.name}' is shared between calls"))
            cx, ln = _complexity(n), (n.end_lineno or n.lineno) - n.lineno + 1
            if cx > 10: out.append(_f(n.lineno, "warn" if cx <= 20 else "error", "complexity", f"'{n.name}' has cyclomatic complexity {cx} (over 10)"))
            if ln > 60: out.append(_f(n.lineno, "warn", "long-function", f"'{n.name}' is {ln} lines long (over 60)"))
            if docstrings and not ast.get_docstring(n): out.append(_f(n.lineno, "info", "no-docstring", f"'{n.name}' has no docstring"))
            sc = _scope(n)
            if not any(isinstance(x, ast.Call) and _dotted(x.func) in ("locals", "vars") for x in sc):
                declared = {x for g in sc if isinstance(g, (ast.Global, ast.Nonlocal)) for x in g.names}
                used = {x.id for x in ast.walk(n) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)}
                seen = set()
                for x in sorted((x for x in sc if isinstance(x, (ast.Assign, ast.AnnAssign))), key=lambda x: x.lineno):
                    for t in (x.targets if isinstance(x, ast.Assign) else [x.target]):
                        if isinstance(t, ast.Name) and t.id not in used and t.id not in declared and not t.id.startswith("_") and t.id not in seen:
                            seen.add(t.id); out.append(_f(x.lineno, "info", "unused-variable", f"local '{t.id}' is assigned but never used"))
        elif isinstance(n, ast.ClassDef) and docstrings and not ast.get_docstring(n): out.append(_f(n.lineno, "info", "no-docstring", f"class '{n.name}' has no docstring"))
    return out


def _lines_rules(text, lang):
    out, L = [], text.split("\n")
    if lang == "shell":
        if L and not L[0].startswith("#!"): out.append(_f(1, "info", "no-shebang", "no #! line: which shell runs this?"))
        if not re.search(r"^\s*set\s+-\w*[eu]", text, re.M): out.append(_f(1, "info", "no-set-e", "no 'set -e' / 'set -u': errors are ignored silently"))
    for i, raw in enumerate(L, 1):
        s = raw.strip()
        if lang == "js" and not s.startswith("//"):
            c = re.sub(r"""(['"`])(?:\\.|(?!\1).)*\1""", '""', raw)
            for pat, sev, rule, msg in ((r"\b" + _EV + r"\s*\(", "error", "eval", _EV + "() runs arbitrary code"), (r"\bnew\s+Function\s*\(", "error", "eval", "new Function() runs arbitrary code"),
                                        (r"\.innerHTML\s*=", "warn", "innerhtml", "innerHTML assignment can inject script (XSS)"), (r"\bdocument\.write\s*\(", "warn", "document-write", "document.write is unsafe"),
                                        (r"[^=!<>]==[^=]|!=[^=]", "info", "loose-equality", "use === / !== instead of == / !="), (r"\bvar\s+\w", "info", "var", "prefer let/const over var"),
                                        (r"\bconsole\.log\b", "info", "console-log", "leftover console.log"), (r"\bdebugger\b", "warn", "debugger", "debugger statement")):
                if re.search(pat, c): out.append(_f(i, sev, rule, msg))
        elif lang == "shell" and not s.startswith("#"):
            for pat, sev, rule, msg in ((r"\b(?:curl|wget)\b[^|#]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", "error", "pipe-to-shell", "downloads and runs code without looking at it"),
                                        (r"\brm\s+-\w+\s+(?:\S+\s+)*[^\"'\s]*\$[{\w]", "warn", "rm-variable", "rm with an unquoted variable can delete the wrong thing"),
                                        (r"\bchmod\s+(?:-\w+\s+)?0?777\b", "warn", "chmod-777", "world-writable permissions"), (r"\beval\s", "warn", "eval", "eval in shell")):
                if re.search(pat, raw): out.append(_f(i, sev, rule, msg))
        if re.search(r"\b(TODO|FIXME|HACK|XXX)\b", raw): out.append(_f(i, "info", "todo", "unfinished-work marker"))
        for m in _SECRET_KV.finditer(raw):
            if not _PLACEHOLDER.match(m.group(3)): out.append(_f(i, "error", "secret", f"possible hard-coded secret in '{m.group(1)[:30]}'"))
        for rx, nm in _SECRET_TOKENS:
            if rx.search(raw): out.append(_f(i, "error", "secret", f"looks like a {nm}"))
    return out


def detect_lang(text):
    if re.match(r"#!.*\b(ba|z|da)?sh\b", text): return "shell"
    if re.search(r"^\s*(def |import |from \w+ import|class )", text, re.M): return "python"
    if re.search(r"\b(function|const|let|=>)\b", text): return "js"
    return "python"


def review(text, lang="", docstrings=False):
    """Static review of pasted code; never runs it. Returns findings sorted by line."""
    if not isinstance(text, str): return [_f(1, "error", "input", "text expected")]
    if len(text) > MAX_SRC: return [_f(1, "error", "too-large", f"input over {MAX_SRC} characters: split it")]
    if "\x00" in text: return [_f(1, "error", "input", "NUL characters: not text")]
    lang = (lang or detect_lang(text)).lower()
    out = (_py(text, docstrings) if lang == "python" else []) + _lines_rules(text, lang)
    seen, res = set(), []
    for f in sorted(out, key=lambda f: (f["line"], f["rule"], f["msg"])):
        k = (f["line"], f["rule"], f["msg"])
        if k not in seen: seen.add(k); res.append(f)
    return res[:500]


def merge_items(old, findings):
    """Carry comments and resolved flags over to a fresh run (matched by rule, message and occurrence)."""
    prev, count, out = {}, {}, []
    for it in old:
        prev[(it.get("rule"), it.get("msg"), it.get("n", 0))] = it
    for f in findings:
        k0 = (f["rule"], f["msg"])
        n = count[k0] = count.get(k0, -1) + 1
        o = prev.get((f["rule"], f["msg"], n), {})
        out.append({**f, "n": n, "comments": o.get("comments", []), "resolved": bool(o.get("resolved"))})
    return out


def _review_app(host, entry):
    st = Store(host)
    me = [host.get("reviewer") or "reviewer"]
    def names(): return sorted(k[4:] for k in host.keys() if k.startswith("rev-"))
    def save(rec): return st.save("rev-" + rec["name"], rec)

    def rerun(rec):
        rec["items"] = merge_items(rec.get("items", []), review(rec["code"], rec["lang"]))
        save(rec)

    def new(i):
        def got(n):
            n = slug(n, "review")
            if n not in names() and len(names()) >= 50: return ("push", Message("Full", ["At most 50 reviews: delete one first."]))
            rec = st.load("rev-" + n) or {"name": n, "lang": "", "code": "", "items": []}
            def saved(t):
                rec["code"] = t[:MAX_SRC]; rec["lang"] = rec["lang"] or detect_lang(t); rerun(rec)
            def from_repo(label, t):
                return _edit(n, t, saved)
            return ("push", Menu("New review: " + n, [("Paste or type code", lambda: _edit(n, rec["code"], saved)),
                                                      ("Pick a file from Version Control", lambda: _pick_shared(host, "the editor", lambda lab, t: _edit(n, t, saved)))]))
        return _ask("New review", "Name:", got)

    def open_(i):
        ns = names()
        if not ns: return None
        rec = st.load("rev-" + ns[i])
        if not isinstance(rec, dict) or not isinstance(rec.get("code"), str): return ("push", Message("Refused", ["that review is damaged"]))
        rec.setdefault("items", []); rec.setdefault("lang", "python")
        flt = {"open": False}
        def shown(): return [x for x in rec["items"] if not (flt["open"] and x["resolved"])]
        def rows():
            return [f"[{'x' if x['resolved'] else ' '}] {x['line']:>4} {x['sev']:<5} {x['rule']}: {x['msg']}" + (f" ({len(x['comments'])}c)" if x["comments"] else "") for x in shown()]
        def cur(i):
            s = shown(); return s[i] if s else None
        def toggle(i):
            x = cur(i)
            if x: x["resolved"] = not x["resolved"]; save(rec)
        def comment(i):
            x = cur(i)
            if not x: return None
            def who(n):
                me[0] = (n.strip() or "reviewer")[:40]; host.put("reviewer", me[0])
                def txt(t):
                    if t.strip() and len(x["comments"]) < 20: x["comments"].append({"by": me[0], "text": t.strip()[:300]}); save(rec)
                return _ask("Comment", "Comment:", txt)
            return _ask("Comment", "Your name:", who, me[0])
        def detail(i):
            x = cur(i)
            if not x: return None
            src = rec["code"].split("\n")
            ctx = [f"{n:>4} {'>' if n == x['line'] else ' '} {src[n - 1]}" for n in range(max(1, x["line"] - 2), min(len(src), x["line"] + 2) + 1)]
            return ("push", Message(x["rule"], [f"{x['sev']}: {x['msg']}", "", *ctx, "", *(f"{c['by']}: {c['text']}" for c in x["comments"]), "resolved" if x["resolved"] else "open"]))
        def edit(i): return _edit(rec["name"], rec["code"], lambda t: (rec.__setitem__("code", t[:MAX_SRC]), rerun(rec)))
        def lang(i):
            rec["lang"] = {"python": "js", "js": "shell"}.get(rec["lang"], "python"); rerun(rec); lv.msg = "language: " + rec["lang"]
        def filt(i): flt["open"] = not flt["open"]; lv.msg = "showing open only" if flt["open"] else "showing all"
        def summary(i):
            n = len(rec["items"]); r = sum(x["resolved"] for x in rec["items"])
            by = {}
            for x in rec["items"]: by[x["sev"]] = by.get(x["sev"], 0) + 1
            return ("push", Message("Summary", [f"{rec['name']} ({rec['lang']}): {n} findings, {r} resolved, {n - r} open", ", ".join(f"{k} {v}" for k, v in sorted(by.items())) or "clean"]))
        lv = Lister("Review " + rec["name"], rows, {"enter": detail, "c": comment, "r": toggle, "e": edit, "l": lang, "f": filt, "s": summary},
                    "Enter detail  c comment  r resolve  e edit code  l language  f open only  s summary", "(no findings)")
        return ("push", lv)

    def rm(i):
        ns = names()
        if ns: return ("push", Confirm(f"Delete review {ns[i]}?", lambda: host.delete("rev-" + ns[i]) and None))
    return Lister("Code Review", names, {"enter": open_, "n": new, "d": rm}, "n new review  Enter open  d delete", "(no reviews: press n)")


# ===================================================================== Package Manager ====
_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$")
_PART = re.compile(r"^[v=]*(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def parse_version(s):
    """'1.2.3-rc.1+build' -> (1, 2, 3, ('rc', '1')). Strict semver 2.0.0; ValueError otherwise."""
    m = _SEMVER.match(s.strip()) if isinstance(s, str) and len(s) <= 100 else None
    if not m: raise ValueError(f"not a semantic version: {str(s)[:40]!r}")
    return int(m[1]), int(m[2]), int(m[3]), tuple(m[4].split(".")) if m[4] else ()


def vkey(v):
    """Sort key implementing semver precedence (build metadata is ignored by parse_version)."""
    if isinstance(v, str): v = parse_version(v)
    return (v[0], v[1], v[2], 1 if not v[3] else 0, tuple((0, int(i), "") if i.isdigit() else (1, 0, i) for i in v[3]))


def compare(a, b):
    ka, kb = vkey(a), vkey(b)
    return (ka > kb) - (ka < kb)


def _partial(s):
    m = _PART.match(s)
    if not m: raise ValueError(f"bad version in range: {s[:30]!r}")
    n = [None if x is None or x in "xX*" else int(x) for x in m.groups()[:3]]
    if n[0] is None: n = [None] * 3
    elif n[1] is None: n[2] = None
    pre = ()
    if m[4] and None not in n:
        pre = tuple(m[4].split("."))
        if any(not p or (p.isdigit() and len(p) > 1 and p[0] == "0") for p in pre): raise ValueError(f"bad pre-release in range: {s[:30]!r}")
    return n, pre


_ANY = ((">=", (0, 0, 0, ())),)
_NONE = (("<", (0, 0, 0, ("0",))),)


def _desugar(op, s):
    n, pre = _partial(s)
    M, m, p = n
    z = lambda a, b=None, c=None, pr=(): (a, b or 0, c or 0, pr)
    if M is None: return list(_NONE if op in (">", "<") else _ANY)
    full = (M, m, p, pre) if p is not None else None
    if op in ("", "="):
        if m is None: return [(">=", z(M)), ("<", z(M + 1))]
        if p is None: return [(">=", z(M, m)), ("<", z(M, m + 1))]
        return [("=", full)]
    if op == "^":
        lo = full or z(M, m)
        if m is None or M > 0: hi = z(M + 1)
        elif p is None or m > 0: hi = z(0, m + 1)
        else: hi = z(0, 0, p + 1)
        return [(">=", lo), ("<", hi)]
    if op == "~": return [(">=", full or z(M, m)), ("<", z(M, m + 1) if m is not None else z(M + 1))]
    if op == ">": return [(">", full)] if full else [(">=", z(M + 1) if m is None else z(M, m + 1))]
    if op == ">=": return [(">=", full or z(M, m))]
    if op == "<": return [("<", full or z(M, m))]
    return [("<=", full)] if full else [("<", z(M + 1) if m is None else z(M, m + 1))]


def parse_range(s):
    """A range string -> list of comparator sets (OR of ANDs). ValueError if malformed."""
    if not isinstance(s, str) or len(s) > 200: raise ValueError("range too long")
    sets = []
    for part in s.split("||")[:20]:
        part = part.strip()
        h = re.fullmatch(r"(\S+)\s+-\s+(\S+)", part)
        if part in ("", "*", "x", "X"): cs = list(_ANY)
        elif h:
            (M, m, p), pre = _partial(h[1])
            lo = [] if M is None else [(">=", (M, m or 0, p or 0, pre if p is not None else ()))]
            cs = lo + (_desugar("<=", h[2]) if _partial(h[2])[0][0] is not None else [])
        else:
            toks = re.sub(r"(>=|<=|>|<|=|\^|~>|~)\s+", r"\1", part).split()
            if len(toks) > 10: raise ValueError("too many comparators")
            cs = []
            for t in toks:
                m = re.match(r"^(>=|<=|>|<|=|\^|~>?|)(.*)$", t)
                cs += _desugar("~" if m[1] == "~>" else m[1], m[2])
        sets.append(cs)
    return sets


def satisfies(version, rng, include_pre=False):
    v = parse_version(version)
    k = vkey(v)
    for cs in parse_range(rng):
        ok = True
        for op, c in cs:
            ck = vkey(c)
            ok = ok and {">=": k >= ck, "<=": k <= ck, ">": k > ck, "<": k < ck, "=": k == ck}[op]
        if ok and v[3] and not include_pre and not any(c[3] and c[:3] == v[:3] for _, c in cs): ok = False
        if ok: return True
    return False


def load_index(text):
    """JSON {name: {version: {dep: range}}} -> (index, errors)."""
    if len(text) > 200_000: return {}, ["index too large (200 KB limit)"]
    try: d = json.loads(text)
    except (ValueError, RecursionError) as e: return {}, [f"index is not valid JSON: {e}"]
    if not isinstance(d, dict) or len(d) > 200: return {}, ["index must be an object of at most 200 packages"]
    errs = []
    for name, vs in d.items():
        if not isinstance(vs, dict) or len(vs) > 100: errs.append(f"{name}: versions must be an object (at most 100)"); continue
        for v, deps in vs.items():
            try: parse_version(v)
            except ValueError: errs.append(f"{name}@{v}: not a semantic version")
            if not isinstance(deps, dict) or len(deps) > 50: errs.append(f"{name}@{v}: dependencies must be an object"); continue
            for dn, dr in deps.items():
                try: parse_range(dr)
                except (ValueError, TypeError): errs.append(f"{name}@{v}: bad range for {dn}: {str(dr)[:30]!r}")
    return ({} if errs else d), errs


def parse_roots(text):
    out, errs = [], []
    for n, raw in enumerate(text.split("\n")[:200], 1):
        line = raw.split("#")[0].strip()
        if not line: continue
        name, _, r = line.partition(" ")
        try: parse_range(r.strip())
        except ValueError as e: errs.append(f"line {n}: {e}"); continue
        out.append((name, r.strip()))
    return out, errs


class _Limit(Exception): pass


def resolve(index, roots, max_steps=20000):
    """Backtracking resolver, newest version first, one version per package.
    Returns {"ok", "chosen", "lock" (lines), "problems" (lines)}."""
    vers = {n: sorted(v, key=vkey, reverse=True) for n, v in index.items()}
    steps, fails = [0], []

    def note(depth, msg):
        if not fails or depth >= fails[0][0]: fails[:] = [(depth, msg)]

    def go(chosen, cons, order):
        name = next((n for n in order if n not in chosen), None)
        if name is None: return chosen
        steps[0] += 1
        if steps[0] > max_steps: raise _Limit()
        wants = "; ".join(f"{r} (from {w})" for r, w in cons[name])
        if name not in index: note(len(chosen), f"package '{name}' is not in the index; wanted: {wants}"); return None
        cands = [v for v in vers[name] if all(satisfies(v, r) for r, _ in cons[name])]
        if not cands: note(len(chosen), f"no version of {name} satisfies all of: {wants}. Available: {', '.join(vers[name]) or 'none'}"); return None
        for v in cands:
            nch, ncons, ok = {**chosen, name: v}, {k: list(x) for k, x in cons.items()}, True
            for dn, dr in index[name][v].items():
                ncons.setdefault(dn, []).append((dr, f"{name}@{v}"))
                if dn in nch and not satisfies(nch[dn], dr):
                    note(len(chosen), f"{name}@{v} needs {dn} {dr} but {dn}@{nch[dn]} is already chosen ({'; '.join(f'{r} from {w}' for r, w in cons.get(dn, []))})")
                    ok = False; break
            if ok:
                r = go(nch, ncons, order + [d for d in index[name][v] if d not in order])
                if r is not None: return r
        return None

    cons = {}
    for n, r in roots: cons.setdefault(n, []).append((r, "(root)"))
    if not roots: return {"ok": True, "chosen": {}, "lock": ["(nothing requested)"], "problems": []}
    if len(roots) > 100: return {"ok": False, "chosen": {}, "lock": [], "problems": ["too many root requirements (100)"]}
    try: res = go({}, cons, list(dict.fromkeys(n for n, _ in roots)))
    except _Limit: return {"ok": False, "chosen": {}, "lock": [], "problems": [f"gave up after {max_steps} steps: the search is too large"]}
    if res is None: return {"ok": False, "chosen": {}, "lock": [], "problems": ["CONFLICT: " + (fails[0][1] if fails else "no solution")]}
    lock = [f"{n} {v}" + (f"   requires {', '.join(f'{d} {r}' for d, r in sorted(index[n][v].items()))}" if index[n][v] else "") for n, v in sorted(res.items())]
    return {"ok": True, "chosen": res, "lock": lock, "problems": []}


SAMPLE_INDEX = json.dumps({"app-lib": {"1.0.0": {"util": "^1.0.0"}, "2.0.0": {"util": "^2.0.0"}},
                           "util": {"1.0.0": {}, "1.4.2": {}, "2.0.0-beta.1": {}, "2.0.0": {"core": "~1.2.0"}},
                           "core": {"1.2.0": {}, "1.2.9": {}, "1.3.0": {}}}, indent=1)


def _pm_app(host, entry):
    st = Store(host)
    def get(k, d): return host.get(k) or d
    def edit(title, key, dflt):
        return lambda: _edit(title, get(key, dflt), lambda t: host.put(key, t[:200_000]))
    def run():
        idx, errs = load_index(get("index", SAMPLE_INDEX))
        roots, rerrs = parse_roots(get("roots", "app-lib ^1.0.0\n"))
        if errs or rerrs: return _tv("Resolve", ["Cannot resolve:", *errs[:20], *rerrs[:20]])
        r = resolve(idx, roots)
        host.put("lock", "\n".join(r["lock"]))
        return _tv("Resolve", (["RESOLVED (newest versions that satisfy every constraint):"] if r["ok"] else []) + r["problems"] + r["lock"] + ["", "Nothing was downloaded or installed."])
    def check(txt):
        v, _, r = txt.strip().partition(" ")
        try: return _tv("Satisfies?", [f"{v}  vs  '{r.strip()}'  ->  {'YES' if satisfies(v, r.strip()) else 'NO'}"])
        except ValueError as e: return ("push", Message("Not understood", [str(e)]))
    def cmp_(txt):
        p = txt.split()
        try: c = compare(p[0], p[1]); return _tv("Compare", [f"{p[0]} {'<' if c < 0 else '>' if c > 0 else '='} {p[1]}"])
        except (ValueError, IndexError) as e: return ("push", Message("Not understood", [str(e) or "give two versions"]))
    return Menu("Package Manager", [
        ("Package index (JSON: name -> version -> deps)", edit("Index", "index", SAMPLE_INDEX)),
        ("What I want (one 'name range' per line)", edit("Requirements", "roots", "app-lib ^1.0.0\n")),
        ("Resolve and show lock listing", run),
        ("Does a version satisfy a range?", lambda: _ask("Satisfies", "version range  (e.g. 1.4.2 ^1.2.0 || >=3):", check)),
        ("Compare two versions", lambda: _ask("Compare", "two versions, e.g. 1.0.0-rc.1 1.0.0:", cmp_)),
        ("About and limits", lambda: ("push", Message("Package Manager", ["Semantic versions and ranges, plus a dependency resolver over an index YOU paste. It cannot download, install or look anything up: there is no network.",
                                                                         "One version per package; newest first with backtracking. Ranges: ^ ~ >= <= < > = *, x-ranges, hyphen, ||. Pre-releases match only a range that names the same major.minor.patch."]))),
    ])


# ======================================================================== Build Planner ====
def parse_rules(text):
    """'target: dep dep @3  # comment' lines -> ({target: {deps, dur, line}}, errors)."""
    g, errs = {}, []
    if len(text) > 200_000: return {}, ["rules too large (200 KB limit)"]
    edges = 0
    for n, raw in enumerate(text.split("\n")[:5000], 1):
        line = raw.split("#", 1)[0].strip()
        if not line: continue
        name, colon, rest = line.partition(":")
        name = name.strip()
        if not colon or not name or len(name.split()) != 1 or len(name) > 100: errs.append(f"line {n}: expected 'target: dep dep @duration'"); continue
        deps, dur = [], 1.0
        for t in rest.split():
            if t.startswith("@"):
                try: dur = float(t[1:])
                except ValueError: dur = -1
                if not 0 <= dur <= 1e6: errs.append(f"line {n}: bad duration {t[:20]!r}"); dur = 1.0
            elif len(t) > 100: errs.append(f"line {n}: name too long")
            else: deps.append(t)
        if name in g: errs.append(f"line {n}: duplicate target {name}"); continue
        edges += len(deps)
        if edges > 5000 or len(g) >= 2000: return {}, errs + [f"line {n}: too large (2000 targets, 5000 dependencies)"]
        g[name] = {"deps": list(dict.fromkeys(deps)), "dur": dur, "line": n}
    return g, errs


def find_cycle(g):
    color = {}
    for s in g:
        if color.get(s): continue
        color[s] = 1; path, st = [s], [iter(g[s]["deps"])]
        while st:
            for d in st[-1]:
                if d not in g: continue
                c = color.get(d, 0)
                if c == 1: return path[path.index(d):] + [d]
                if c == 0: color[d] = 1; path.append(d); st.append(iter(g[d]["deps"])); break
            else:
                color[path.pop()] = 2; st.pop()
    return None


def needed(g, goal):
    seen, st = set(), [goal]
    while st:
        t = st.pop()
        if t in seen or t not in g: continue
        seen.add(t); st += g[t]["deps"]
    return {t: g[t] for t in g if t in seen}


def plan(g):
    """Waves (parallel groups), critical path and totals for an acyclic graph; {'cycle': [...]} if cyclic."""
    cyc = find_cycle(g)
    if cyc: return {"cycle": cyc}
    pos = {t: i for i, t in enumerate(g)}
    indeg = {t: len({d for d in g[t]["deps"] if d in g}) for t in g}
    rev = {}
    for t in g:
        for d in set(g[t]["deps"]):
            if d in g: rev.setdefault(d, []).append(t)
    wave, waves, finish, pred = [t for t in g if indeg[t] == 0], [], {}, {}
    while wave:
        waves.append(wave); nxt = []
        for t in wave:
            ds = [d for d in g[t]["deps"] if d in g]
            best = max(ds, key=lambda d: (finish[d], -pos[d]), default=None)
            finish[t] = g[t]["dur"] + (finish[best] if best else 0); pred[t] = best
            for r in rev.get(t, []):
                indeg[r] -= 1
                if indeg[r] == 0: nxt.append(r)
        wave = sorted(nxt, key=pos.get)
    end = max(finish, key=lambda t: (finish[t], -pos[t]), default=None)
    path = []
    while end: path.append(end); end = pred[end]
    return {"cycle": None, "waves": waves, "order": [t for w in waves for t in w], "critical": path[::-1],
            "critical_time": max(finish.values(), default=0), "serial_time": sum(v["dur"] for v in g.values())}


def rebuild_set(g, changed):
    """Targets that must rebuild when the named files/targets change, in build order; plus unknown names."""
    names = set(g) | {d for v in g.values() for d in v["deps"]}
    unknown = sorted(c for c in changed if c not in names)
    rev = {}
    for t, v in g.items():
        for d in v["deps"]: rev.setdefault(d, []).append(t)
    hit, st = set(), [c for c in changed if c in names]
    while st:
        for r in rev.get(st.pop(), []):
            if r not in hit: hit.add(r); st.append(r)
    p = plan(g)
    order = p["order"] if not p.get("cycle") else sorted(g)
    return [t for t in order if t in hit], unknown


def _fmt(x): return f"{x:g}"


SAMPLE_RULES = "app: main.o util.o lib.a @2\nmain.o: main.c util.h @3\nutil.o: util.c util.h @2\nlib.a: util.o @1\ntest: app @4\n"


def _bp_app(host, entry):
    def rules():
        g, errs = parse_rules(host.get("rules") or SAMPLE_RULES)
        return g, errs
    def bad(errs): return _tv("Rules", ["Fix these first:", *errs[:30]])
    def show(goal=""):
        g, errs = rules()
        if errs: return bad(errs)
        goal = goal.strip()
        if goal:
            if goal not in g: return ("push", Message("Unknown target", [f"'{goal[:40]}' is not a target"]))
            g = needed(g, goal)
        p = plan(g)
        if p["cycle"]: return _tv("Plan", ["CYCLE: " + " -> ".join(p["cycle"]), "No build order exists until it is broken."])
        out = ["BUILD ORDER: " + "  ".join(p["order"]), ""]
        out += [f"wave {i}: {'  '.join(w)}" + ("   (can run in parallel)" if len(w) > 1 else "") for i, w in enumerate(p["waves"], 1)]
        out += ["", "CRITICAL PATH: " + " -> ".join(p["critical"]), f"shortest possible time {_fmt(p['critical_time'])} (serial {_fmt(p['serial_time'])}); this plans only, nothing is run"]
        return _tv("Plan", out)
    def impact(txt):
        g, errs = rules()
        if errs: return bad(errs)
        r, unk = rebuild_set(g, txt.split())
        return _tv("Rebuild", [f"{len(r)} target(s) rebuild:", *r] + ([f"unknown names: {', '.join(unk)}"] if unk else []))
    return Menu("Build Planner", [
        ("Edit rules", lambda: _edit("Rules", host.get("rules") or SAMPLE_RULES, lambda t: host.put("rules", t[:200_000]))),
        ("Pick rules from a Version Control file", lambda: _pick_shared(host, "the rules", lambda lab, t: _edit("Rules", t, lambda x: host.put("rules", x[:200_000])))),
        ("Plan everything", lambda: show()),
        ("Plan one target (and what it needs)", lambda: _ask("Plan", "Target:", show)),
        ("What rebuilds if these change?", lambda: _ask("Rebuild", "Changed files/targets (space separated):", impact)),
        ("About and limits", lambda: ("push", Message("Build Planner", ["Rules look like 'target: dep dep @seconds' (# comments). Files that are not targets are sources. "
                                                                     "It computes order, parallel waves, the critical path and rebuild impact. It never runs a build or a command."]))),
    ])


# ======================================================================== Config Editor ====
FORMATS = ("json", "toml", "ini", "env", "properties")
STRINGLY = ("ini", "env", "properties")
MAX_CFG = 200_000
_SECRETY = re.compile(r"(?i)pass|secret|token|key|credential")


def _unesc_props(s, errs, n):
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            d = s[i + 1]; i += 2
            if d == "u":
                h = s[i:i + 4]
                if re.fullmatch(r"[0-9a-fA-F]{4}", h): out.append(chr(int(h, 16))); i += 4
                else: errs.append((n, "bad \\u escape"))
            else: out.append({"n": "\n", "t": "\t", "r": "\r", "f": "\f"}.get(d, d))
        else: out.append(c); i += 1
    return "".join(out)


def _props(text):
    out, errs, L, i = {}, [], text.split("\n"), 0
    while i < len(L):
        raw, start = L[i].lstrip(" \t\f"), i + 1
        i += 1
        if not raw or raw[0] in "#!": continue
        while len(raw) - len(raw.rstrip("\\")) & 1:
            raw = raw[:-1] + (L[i].lstrip(" \t\f") if i < len(L) else ""); i += 1 if i < len(L) else 0
            if i >= len(L): break
        j = 0
        while j < len(raw) and raw[j] not in "=: \t\f":
            j += 2 if raw[j] == "\\" else 1
        key, rest = raw[:j], raw[j:].lstrip(" \t\f")
        if rest[:1] in ("=", ":") and rest: rest = rest[1:].lstrip(" \t\f")
        key = _unesc_props(key, errs, start)
        if not key: errs.append((start, "empty key")); continue
        if key in out: errs.append((start, f"duplicate key {key}")); continue
        out[key] = _unesc_props(rest, errs, start)
    return out, errs


def _env(text):
    out, errs = {}, []
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"): continue
        if line.startswith("export "): line = line[7:].lstrip()
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if not m: errs.append((n, "expected KEY=VALUE")); continue
        k, v = m.groups()
        if v[:1] == '"':
            q = re.match(r'"((?:\\.|[^"\\])*)"\s*(?:#.*)?$', v)
            if not q: errs.append((n, "unterminated quote or text after the closing quote (multi-line values are not supported)")); continue
            v = re.sub(r"\\(.)", lambda x: {"n": "\n", "t": "\t", "r": "\r"}.get(x[1], x[1]), q[1])
        elif v[:1] == "'":
            q = re.match(r"'([^']*)'\s*(?:#.*)?$", v)
            if not q: errs.append((n, "unterminated quote or text after the closing quote")); continue
            v = q[1]
        else: v = re.split(r"\s+#", v, maxsplit=1)[0].strip()
        if k in out: errs.append((n, f"duplicate key {k}")); continue
        out[k] = v
    return out, errs


def _ini(text):
    cp = configparser.ConfigParser(interpolation=None, strict=True, default_section="\0")
    cp.optionxform = str
    try: cp.read_string(text)
    except configparser.ParsingError as e:
        if getattr(e, "lineno", None): return None, [(e.lineno, str(e).splitlines()[0][:80])]
        errs = [(a, f"cannot parse: {b.strip()[:60]!r}") for a, b in (getattr(e, "errors", None) or []) if isinstance(a, int)]
        return None, errs or [(None, str(e).splitlines()[0])]
    except configparser.Error as e: return None, [(getattr(e, "lineno", None), str(e).splitlines()[0])]
    return {s: dict(cp.items(s)) for s in cp.sections()}, []


def parse(fmt, text):
    """-> (data, [(line or None, message)]). data is None when there are errors."""
    if not isinstance(text, str) or len(text) > MAX_CFG: return None, [(None, f"input must be text of at most {MAX_CFG} characters")]
    if "\x00" in text: return None, [(None, "NUL character: not a text config")]
    text = text.replace("\r\n", "\n")
    try:
        if fmt == "json":
            def bad(c): raise ValueError(f"{c} is not valid JSON")
            return json.loads(text, parse_constant=bad), []
        if fmt == "toml": return tomllib.loads(text), []
        if fmt == "ini": return _ini(text)
        if fmt in ("env", "properties"):
            d, e = _env(text) if fmt == "env" else _props(text)
            return (None, e) if e else (d, [])
    except json.JSONDecodeError as e: return None, [(e.lineno, e.msg)]
    except tomllib.TOMLDecodeError as e:
        m = re.search(r"\(at line (\d+)", str(e))
        return None, [(int(m[1]) if m else None, re.sub(r"\s*\(at .*", "", str(e)))]
    except RecursionError: return None, [(None, "nested too deeply")]
    except ValueError as e: return None, [(None, str(e))]
    return None, [(None, f"unknown format {fmt!r}")]


def err_lines(errs): return [(f"line {n}: " if n else "") + m for n, m in errs]


def flatten(d, sep=".", brackets=True, limit=20000):
    out = {}
    st = [("", d, 0)]
    while st:
        p, v, depth = st.pop()
        if depth > 40: raise ValueError("nested too deeply")
        if isinstance(v, dict) and v:
            for k, x in v.items(): st.append((f"{p}{sep}{k}" if p else str(k), x, depth + 1))
        elif isinstance(v, list) and v:
            for i, x in enumerate(v): st.append((f"{p}[{i}]" if brackets else f"{p}{sep}{i}", x, depth + 1))
        else: out[p] = "{}" if v == {} else "[]" if v == [] else v
        if len(out) > limit: raise ValueError("too many keys")
    return dict(sorted(out.items()))


def infer(d):
    def one(v):
        if isinstance(v, dict): return {k: one(x) for k, x in v.items()}
        if isinstance(v, list): return [one(x) for x in v]
        if isinstance(v, str):
            if v in ("true", "false"): return v == "true"
            if re.fullmatch(r"-?(0|[1-9]\d{0,17})", v): return int(v)
            if re.fullmatch(r"-?(0|[1-9]\d{0,17})\.\d{1,17}", v): return float(v)
        return v
    return one(d)


_BARE = re.compile(r"[A-Za-z0-9_-]+$")


def _tk(k): return k if _BARE.match(k) else json.dumps(k, ensure_ascii=False)


def _tval(v, depth=0):
    if depth > 40: raise ValueError("nested too deeply")
    if isinstance(v, bool): return "true" if v else "false"
    if isinstance(v, int): return str(v)
    if isinstance(v, float): return "nan" if v != v else "inf" if v == float("inf") else "-inf" if v == float("-inf") else repr(v)
    if isinstance(v, str): return json.dumps(v, ensure_ascii=False).replace("\x7f", "\\u007f")
    if hasattr(v, "isoformat"): return v.isoformat()
    if isinstance(v, list): return "[" + ", ".join(_tval(x, depth + 1) for x in v) + "]"
    if isinstance(v, dict): return "{" + ", ".join(f"{_tk(k)} = {_tval(x, depth + 1)}" for k, x in v.items()) + "}"
    raise ValueError("TOML has no null (or this value type)")


def dump_toml(d):
    lines = []
    def table(path, t, depth):
        if depth > 40: raise ValueError("nested too deeply")
        for k, v in t.items():
            if not isinstance(v, dict): lines.append(f"{_tk(k)} = {_tval(v)}")
        for k, v in t.items():
            if isinstance(v, dict):
                lines.extend(["", "[" + ".".join(_tk(p) for p in path + [k]) + "]"]); table(path + [k], v, depth + 1)
    table([], d, 0)
    return "\n".join(lines).lstrip("\n") + "\n"


def _scalar(v): return "" if v is None else "true" if v is True else "false" if v is False else str(v)


def dump(fmt, data):
    """-> (text, errors)."""
    try:
        if fmt == "json": return json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n", []
        if not isinstance(data, dict): return "", [f"{fmt} needs an object at the top level"]
        if fmt == "toml": return dump_toml(data), []
        if fmt == "ini":
            secs, top = {}, {}
            for k, v in data.items():
                if isinstance(v, dict): secs[k] = flatten(v)
                else: top[k] = v
            if top: secs = {"main": {**flatten(top), **secs.get("main", {})}, **{k: v for k, v in secs.items() if k != "main"}}
            out = []
            for s, kv in secs.items():
                if not re.fullmatch(r"[^\[\]\n]+", str(s)): return "", [f"section name {str(s)[:30]!r} cannot be written to INI"]
                out.append(f"[{s}]")
                for k, v in kv.items():
                    t = _scalar(v)
                    if "\n" in t or not k or re.search(r"[=:\n]|^[\[#;]", k): return "", [f"key/value {k[:30]!r} cannot be written to INI"]
                    out.append(f"{k} = {t}")
                out.append("")
            return "\n".join(out), ([] if not top else ["note: top-level keys were placed in section [main]"])
        if fmt == "env":
            out, errs = [], []
            for k, v in flatten(data, "_", False).items():
                key = re.sub(r"[^A-Za-z0-9_]", "_", k).upper()
                if not re.fullmatch(r"[A-Za-z_]\w*", key): errs.append(f"key {k[:30]!r} cannot be an environment variable"); continue
                s = _scalar(v)
                if re.search(r"[\s#\"'\\$=]", s) or s != s.strip(): s = '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r") + '"'
                out.append(f"{key}={s}")
            return "\n".join(out) + "\n", errs
        if fmt == "properties":
            def esc(s, key=False):
                s = s.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
                if key: s = re.sub(r"([ =:#!])", r"\\\1", s)
                return re.sub(r"^ ", r"\\ ", s)
            return "\n".join(f"{esc(k, True)}={esc(_scalar(v))}" for k, v in flatten(data, ".", False).items()) + "\n", []
    except (ValueError, TypeError, RecursionError) as e: return "", [str(e)]
    return "", [f"unknown format {fmt!r}"]


def convert(src, text, dst):
    data, errs = parse(src, text)
    if errs: return "", err_lines(errs)
    if src in STRINGLY and dst in ("json", "toml"): data = infer(data)
    return dump(dst, data)


def diff_config(fa, ta, fb, tb):
    a, ea = parse(fa, ta)
    b, eb = parse(fb, tb)
    if ea or eb: return (["first: " + x for x in err_lines(ea)] + ["second: " + x for x in err_lines(eb)])
    try: x, y = flatten(a), flatten(b)
    except ValueError as e: return [str(e)]
    show = lambda k, v: "<hidden>" if _SECRETY.search(k) else (repr(v) if not isinstance(v, str) else v)[:60]
    out = [f"- {k} = {show(k, x[k])}" for k in x if k not in y] + [f"+ {k} = {show(k, y[k])}" for k in y if k not in x]
    out += [f"~ {k}: {show(k, x[k])} -> {show(k, y[k])}" for k in x if k in y and x[k] != y[k]]
    return out or ["no differences in keys or values"]


_TYPES = {"str": lambda v, s: isinstance(v, str), "int": lambda v, s: (isinstance(v, int) and not isinstance(v, bool)) or (s and isinstance(v, str) and re.fullmatch(r"[+-]?\d+", v) is not None),
          "float": lambda v, s: (isinstance(v, (int, float)) and not isinstance(v, bool)) or (s and isinstance(v, str) and re.fullmatch(r"[+-]?\d+(\.\d+)?([eE][+-]?\d+)?", v) is not None),
          "bool": lambda v, s: isinstance(v, bool) or (s and isinstance(v, str) and v.lower() in ("true", "false", "yes", "no", "on", "off", "1", "0")),
          "list": lambda v, s: isinstance(v, list), "dict": lambda v, s: isinstance(v, dict)}
_TYPES["number"] = _TYPES["float"]


def parse_schema(text):
    rules, errs = [], []
    for n, raw in enumerate(text.split("\n")[:500], 1):
        p = raw.split("#")[0].split()
        if not p: continue
        if p[0] == "required" and len(p) == 2: rules.append(("required", p[1], None))
        elif p[0] == "type" and len(p) == 3 and p[2] in _TYPES: rules.append(("type", p[1], p[2]))
        elif p[0] == "enum" and len(p) == 3: rules.append(("enum", p[1], p[2].split("|")))
        else: errs.append((n, "expected: required PATH | type PATH (str|int|float|number|bool|list|dict) | enum PATH a|b|c"))
    return rules, errs


def _lookup(d, path):
    parts, cur, i = path.split("."), d, 0
    while i < len(parts):
        for j in range(len(parts), i, -1):
            k = ".".join(parts[i:j])
            if isinstance(cur, dict) and k in cur: cur, i = cur[k], j; break
            if isinstance(cur, list) and j == i + 1 and k.isdigit() and int(k) < len(cur): cur, i = cur[int(k)], j; break
        else: return False, None
    return True, cur


def check_schema(data, rules, stringly=False):
    out = []
    for kind, path, arg in rules:
        ok, v = _lookup(data, path)
        if not ok:
            if kind == "required": out.append(f"missing required key {path}")
            continue
        if kind == "type" and not _TYPES[arg](v, stringly): out.append(f"{path}: expected {arg}, found {type(v).__name__}")
        if kind == "enum" and _scalar(v) not in arg: out.append(f"{path}: {_scalar(v)[:30]!r} is not one of {', '.join(arg)}")
    return out


def validate(fmt, text, schema=""):
    data, errs = parse(fmt, text)
    if errs: return ["SYNTAX ERRORS:", *err_lines(errs)]
    rules, serrs = parse_schema(schema)
    out = [f"syntax OK ({fmt}, {len(flatten(data)) if isinstance(data, (dict, list)) else 1} value(s))"]
    if serrs: out += ["schema problems:", *err_lines(serrs)]
    probs = check_schema(data, rules, fmt in STRINGLY)
    return out + (["SCHEMA PROBLEMS:", *probs] if probs else ["schema OK" if rules else "(no schema rules set)"])


def _cfg_app(host, entry):
    st = Store(host)
    s = st.load("cfg", {})
    s = s if isinstance(s, dict) else {}
    s.setdefault("text", '{\n  "server": {"host": "localhost", "port": 8080},\n  "debug": false\n}\n'); s.setdefault("fmt", "json"); s.setdefault("schema", "required server.host\ntype server.port int\n")
    if s["fmt"] not in FORMATS: s["fmt"] = "json"

    def save(): st.save("cfg", s)
    def setter(k, cap=MAX_CFG): return lambda t: (s.__setitem__(k, t[:cap]), save())
    menu = Menu("Config Editor", [])

    def fmt_set(f):
        f = f.strip().lower()
        if f in FORMATS: s["fmt"] = f; save()
        else: return ("push", Message("Unknown format", ["Choose one of: " + ", ".join(FORMATS)]))
    def conv(dst):
        dst = dst.strip().lower()
        if dst not in FORMATS: return ("push", Message("Unknown format", ["Choose one of: " + ", ".join(FORMATS)]))
        out, errs = convert(s["fmt"], s["text"], dst)
        if not out: return _tv("Convert", errs or ["nothing to convert"])
        def use(t): s["text"], s["fmt"] = t[:MAX_CFG], dst; save()
        return _edit(f"as {dst}" + (f"  ({'; '.join(errs)})" if errs else ""), out, use, False)
    def keys():
        d, errs = parse(s["fmt"], s["text"])
        if errs: return _tv("Keys", err_lines(errs))
        try: return _tv("Keys", [f"{k} = {v if not _SECRETY.search(k) else '<hidden>'}" for k, v in flatten(d).items()] or ["(empty)"])
        except ValueError as e: return _tv("Keys", [str(e)])
    def diff():
        return ("push", Editor("Paste the other version, then Esc", "", None, hint="(format: current)", extra_keys={"escape": lambda ed: ("pop", lambda: _tv("Diff", diff_config(s["fmt"], s["text"], s["fmt"], ed.area.text)))}))
    def pick(lab, t):
        ext = lab.rsplit(".", 1)[-1]
        s["text"] = t[:MAX_CFG]
        if ext in FORMATS: s["fmt"] = ext
        save()
    def intro():
        menu.intro = [f"  format: {s['fmt']}   {len(s['text'])} characters"]
    entries = [
        ("Edit text", lambda: _edit("Config " + s["fmt"], s["text"], setter("text"), True)),
        ("Pick text from a Version Control file", lambda: _pick_shared(host, "the editor", pick)),
        ("Set format (json toml ini env properties)", lambda: _ask("Format", "Format:", fmt_set, s["fmt"])),
        ("Validate: syntax and schema", lambda: _tv("Validate", validate(s["fmt"], s["text"], s["schema"]))),
        ("Convert to another format", lambda: _ask("Convert", "Convert to (json toml ini env properties):", conv)),
        ("Show every key and value", keys),
        ("Diff against another version", diff),
        ("Edit schema rules", lambda: _edit("Schema", s["schema"], setter("schema", 20_000), False)),
        ("About and limits", lambda: ("push", Message("Config Editor", [
            "Parses, validates, converts and compares JSON, TOML (read with tomllib, written by a small tested writer), INI (configparser), .env and Java .properties. Errors carry line numbers.",
            "No YAML: it is not in the Python standard library. INI, .env and .properties hold only strings; converting to JSON/TOML guesses numbers and true/false. TOML null, INI nesting beyond flat keys and multi-line .env values are not supported.",
            "Schema rules: 'required PATH', 'type PATH int', 'enum PATH a|b|c'. Secret-looking values are hidden in diffs and key lists."]))),
    ]
    menu.entries = entries
    menu.nav = ListNav(len(entries))
    orig = menu.render
    menu.render = lambda w, h: (intro(), orig(w, h))[1]
    return menu


ENTRIES = [
    app("Version Control", lambda host, e: VC(host), "partial",
        "Local history of text files in the vault: commit, log, diff, branches, tags, revert, three-way merge. No remotes, no push/pull, no real files.", owns=["repos"]),
    app("Code Review", lambda host, e: _review_app(host, e), "partial",
        "Static review of pasted Python (ast only), plus light JS and shell regex checks. Never runs code; no type checking or data-flow analysis.", uses=["repos"]),
    app("Package Manager", lambda host, e: _pm_app(host, e), "partial",
        "Semver, ranges and a resolver over an index you paste. Cannot download or install anything (no network); one version per package.", ),
    app("Build Planner", lambda host, e: _bp_app(host, e), "full",
        "Order, parallel waves, cycles, critical path and rebuild impact for Makefile-like rules. It plans; it never runs a build.", uses=["repos"]),
    app("Config Editor", lambda host, e: _cfg_app(host, e), "partial",
        "Parse, validate, convert and diff JSON, TOML, INI, .env and .properties with line-numbered errors and light schema rules. No YAML (not in the standard library).", uses=["repos"]),
]
