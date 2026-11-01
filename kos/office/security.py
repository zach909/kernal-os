"""Security-flavoured engines: password/TOTP authentication, role-based access
control with deny-overrides, and a hash-chained tamper-evident audit log.
They are *registries and decision engines*: they hold the policy and answer
'would this be allowed?'. They do not enforce anything on other software."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import struct
import time

from .ui import (Editor, ListNav, Menu, Message, Prompt, Screen, Store, TextInput, TextView, now_stamp, table)


# ------------------------------------------------------------------ TOTP ----
def totp(secret_b32: str, t: float | None = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    counter = int((time.time() if t is None else t) // step)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 10 ** digits).zfill(digits)


def totp_ok(secret: str, code: str, t: float | None = None, window: int = 1) -> bool:
    now = time.time() if t is None else t
    return any(hmac.compare_digest(totp(secret, now + d * 30), code.strip()) for d in range(-window, window + 1))


def new_secret() -> str: return base64.b32encode(os.urandom(10)).decode().rstrip("=")


def hash_password(pw: str, n: int = 2 ** 14) -> dict:
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=8, p=1, dklen=32)
    return {"salt": salt.hex(), "hash": h.hex(), "n": n}


def verify_password(pw: str, rec: dict) -> bool:
    h = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(rec["salt"]), n=rec["n"], r=8, p=1, dklen=32)
    return hmac.compare_digest(h.hex(), rec["hash"])


DEFAULT_POLICY = {"min_length": 10, "classes": 3, "max_fails": 5, "lock_seconds": 900}


def policy_problems(pw: str, pol: dict) -> list:
    out = []
    if len(pw) < pol["min_length"]: out.append(f"at least {pol['min_length']} characters")
    cls = sum(bool(re.search(rx, pw)) for rx in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w\s]"))
    if cls < pol["classes"]: out.append(f"mix at least {pol['classes']} of: lower, upper, digit, symbol")
    if pw.lower() in ("password", "password1", "qwerty123", "letmein123"): out.append("too common")
    return out


class AuthSystem(Menu):
    """User registry with scrypt-hashed passwords, optional TOTP, lockout and
    a login simulator. Passwords are never stored or shown."""

    def __init__(self, host, title="Authentication"):
        self.host, self.st = host, Store(host)
        self.users: dict = self.st.load("users", {})
        self.pol: dict = {**DEFAULT_POLICY, **self.st.load("policy", {})}
        self.n = int(self.st.load("scrypt_n", 2 ** 14))
        super().__init__(title, [("Add user", self.add), ("Login test (simulate)", self.login), ("Enable TOTP for a user", self.enable),
                                 ("Unlock a user", self.unlock), ("Users", self.listing), ("Policy", self.policy)],
                         ["  Credential registry & login simulator (scrypt, TOTP, lockout)."])

    def save(self): self.st.save("users", self.users)

    def add(self): return ("push", Prompt("Add user", "Username:", "", self._add_name))

    def _add_name(self, u):
        u = u.strip().lower()
        if not u or u in self.users: return ("push", Message("Add user", ["empty or existing username"]))
        return ("push", Prompt("Add user", f"Password for {u}:", "", lambda p: self._add_pw(u, p), secret=True))

    def _add_pw(self, u, p):
        probs = policy_problems(p, self.pol)
        if probs: return ("push", Message("Rejected by policy", probs))
        self.users[u] = {"pw": hash_password(p, self.n), "totp": "", "fails": 0, "locked_until": 0, "created": now_stamp()}; self.save()
        return ("push", Message("Add user", [f"{u} created"]))

    def login(self): return ("push", Prompt("Login", "Username:", "", lambda u: ("push", Prompt("Login", "Password:", "", lambda p: self._login(u.strip().lower(), p), secret=True))))

    def _login(self, u, p):
        rec = self.users.get(u)
        if not rec: return ("push", Message("Login", ["denied"]))     # same answer as a wrong password
        if rec["locked_until"] > time.time(): return ("push", Message("Login", [f"locked for another {int(rec['locked_until'] - time.time())}s"]))
        if not verify_password(p, rec["pw"]):
            rec["fails"] += 1
            if rec["fails"] >= self.pol["max_fails"]: rec["locked_until"] = time.time() + self.pol["lock_seconds"]; rec["fails"] = 0
            self.save(); return ("push", Message("Login", ["denied"]))
        if rec["totp"]:
            return ("push", Prompt("Login", "6-digit code:", "", lambda c: self._login2(u, c)))
        rec["fails"] = 0; self.save(); return ("push", Message("Login", ["granted (password only - consider enabling TOTP)"]))

    def _login2(self, u, code):
        rec = self.users[u]
        ok = totp_ok(rec["totp"], code)
        if not ok: rec["fails"] += 1; self.save()
        return ("push", Message("Login", ["granted" if ok else "denied"]))

    def enable(self): return ("push", Prompt("TOTP", "Username:", "", self._enable))

    def _enable(self, u):
        rec = self.users.get(u.strip().lower())
        if not rec: return ("push", Message("TOTP", ["no such user"]))
        rec["totp"] = new_secret(); self.save()
        return ("push", Message("TOTP enabled", [f"secret: {rec['totp']}", f"otpauth://totp/KOS:{u.strip().lower()}?secret={rec['totp']}&issuer=KOS", "", "Add it to an authenticator app now; it is not shown again."]))

    def unlock(self): return ("push", Prompt("Unlock", "Username:", "", self._unlock))

    def _unlock(self, u):
        rec = self.users.get(u.strip().lower())
        if rec: rec["locked_until"] = 0; rec["fails"] = 0; self.save()

    def listing(self):
        return ("push", TextView("Users", table([[u, "yes" if r["totp"] else "no", "LOCKED" if r["locked_until"] > time.time() else "ok", r["created"]] for u, r in sorted(self.users.items())],
                                                 ["user", "totp", "state", "created"]) if self.users else ["no users"]))

    def policy(self): return ("push", Prompt("Policy", "min_length classes max_fails lock_seconds:", " ".join(str(self.pol[k]) for k in ("min_length", "classes", "max_fails", "lock_seconds")), self._policy))

    def _policy(self, v):
        try:
            a, b, c, d = (int(x) for x in v.split())
            if min(a, b, c, d) < 1 or b > 4: raise ValueError
            self.pol.update(min_length=a, classes=b, max_fails=c, lock_seconds=d); self.st.save("policy", self.pol)
        except ValueError:
            return ("push", Message("Policy", ["four positive numbers; classes at most 4"]))


# ------------------------------------------------------------------ RBAC ----
RBAC_SAMPLE = """# role NAME: [inherits A, B;] allow p1, p2; deny p3
role viewer: allow doc:read, report:read
role editor: inherits viewer; allow doc:write; deny doc:delete
role admin: allow *
# user NAME: role, role
user ann: viewer, editor
user bob: admin
"""


def parse_rbac(text: str) -> tuple[dict, dict]:
    roles, users = {}, {}
    for raw in text.split("\n"):
        line = raw.split("#")[0].strip()
        m = re.match(r"^role\s+([\w.-]+)\s*:\s*(.*)$", line)
        if m:
            r = {"inherits": [], "allow": [], "deny": []}
            for part in m.group(2).split(";"):
                k, _, v = part.strip().partition(" ")
                if k in r: r[k] += [x.strip() for x in v.split(",") if x.strip()]
            roles[m.group(1)] = r; continue
        m = re.match(r"^user\s+([\w.@-]+)\s*:\s*(.*)$", line)
        if m: users[m.group(1)] = [x.strip() for x in m.group(2).split(",") if x.strip()]
    return roles, users


def _pmatch(pat: str, action: str) -> bool:
    return pat == "*" or pat == action or (pat.endswith(":*") and action.startswith(pat[:-1]))


def role_closure(roles: dict, name: str, seen=None) -> list:
    seen = seen if seen is not None else []
    if name in seen or name not in roles: return seen
    seen.append(name)
    for p in roles[name]["inherits"]: role_closure(roles, p, seen)
    return seen


def check(roles: dict, users: dict, user: str, action: str) -> tuple[bool, str]:
    if user not in users: return False, f"unknown user '{user}'"
    chain = []
    for r in users[user]: chain += [x for x in role_closure(roles, r) if x not in chain]
    allow = deny = None
    for r in chain:
        for pat in roles[r]["deny"]:
            if _pmatch(pat, action): deny = deny or f"role '{r}' denies {pat}"
        for pat in roles[r]["allow"]:
            if _pmatch(pat, action): allow = allow or f"role '{r}' allows {pat}"
    if deny: return False, deny + " (deny overrides allow)"
    if allow: return True, allow
    return False, "no role grants it (default deny)" + ("" if chain else "; user has no roles")


class RbacApp(Menu):
    def __init__(self, host, title="Access control"):
        self.host, self.st = host, Store(host)
        self.src = self.st.load("policy", RBAC_SAMPLE)
        super().__init__(title, [("Edit policy", self.edit), ("Can USER do ACTION?", self.ask), ("Who can do ACTION?", self.who),
                                 ("Effective permissions of a user", self.effective), ("Review: users with wildcard access", self.review)],
                         ["  Roles, inheritance, deny-overrides. Default deny."])

    def edit(self): return ("push", Editor("Policy", self.src, on_save=self._save, hint="role / user lines"))
    def _save(self, t): self.src = t; self.st.save("policy", t)

    def ask(self):
        return ("push", Prompt("Check", "user action  (e.g. ann doc:delete):", "", self._ask))

    def _ask(self, v):
        p = v.split()
        if len(p) != 2: return ("push", Message("Check", ["format: user action"]))
        roles, users = parse_rbac(self.src); ok, why = check(roles, users, p[0], p[1])
        return ("push", Message("ALLOW" if ok else "DENY", [f"{p[0]} -> {p[1]}", why]))

    def who(self):
        return ("push", Prompt("Who", "action:", "", lambda a: ("push", TextView("Who can " + a, [u for u in parse_rbac(self.src)[1] if check(*parse_rbac(self.src), u, a.strip())[0]] or ["nobody"]))))

    def effective(self):
        return ("push", Prompt("Effective", "user:", "", self._eff))

    def _eff(self, u):
        roles, users = parse_rbac(self.src); u = u.strip()
        if u not in users: return ("push", Message("Effective", ["unknown user"]))
        chain = []
        for r in users[u]: chain += [x for x in role_closure(roles, r) if x not in chain]
        return ("push", TextView(u, [f"roles (with inheritance): {', '.join(chain)}", "", *(f"allow {p}   [{r}]" for r in chain for p in roles[r]["allow"]), *(f"deny  {p}   [{r}]" for r in chain for p in roles[r]["deny"])]))

    def review(self):
        roles, users = parse_rbac(self.src)
        return ("push", TextView("Wildcard access", [f"{u}: {', '.join(rs)}" for u, rs in users.items() if check(roles, users, u, "anything:at-all")[0]] or ["nobody has wildcard access"]))


# --------------------------------------------------------------- audit log ----
def entry_hash(prev: str, e: dict) -> str:
    body = json.dumps({k: e[k] for k in ("seq", "at", "actor", "action", "target", "detail")}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + body).encode()).hexdigest()


def verify_chain(entries: list) -> int:
    """-> index of the first broken entry, or -1 if the chain is intact."""
    prev = "0" * 64
    for i, e in enumerate(entries):
        if e.get("seq") != i + 1 or e.get("prev") != prev or entry_hash(prev, e) != e.get("hash"): return i
        prev = e["hash"]
    return -1


class AuditLog(Screen):
    def __init__(self, host, title="Audit log"):
        self.host, self.title, self.st = host, title, Store(host)
        self.entries: list = self.st.load("chain", [])
        self.nav = ListNav(0)
        self.q = ""
        self.msg = ""
        self.help = "a append  / search  v verify chain  x export JSON lines  (append-only: no edit, no delete)"

    def append(self, actor, action, target="", detail=""):
        prev = self.entries[-1]["hash"] if self.entries else "0" * 64
        e = {"seq": len(self.entries) + 1, "at": now_stamp(), "actor": actor, "action": action, "target": target, "detail": detail, "prev": prev}
        e["hash"] = entry_hash(prev, e); self.entries.append(e); self.st.save("chain", self.entries)

    def shown(self):
        es = self.entries
        if self.q: es = [e for e in es if self.q.lower() in json.dumps(e).lower()]
        return es

    def render(self, w, h):
        es = self.shown(); self.nav.resize(len(es)); bad = verify_chain(self.entries)
        out = [f" {len(self.entries)} entries   chain: " + ("INTACT" if bad < 0 else f"BROKEN at entry {bad + 1}") + (f"   filter='{self.q}'" if self.q else ""), ""]
        top, end = self.nav.window(h - 5)
        for i in range(top, end):
            e = es[i]; out.append(f"{'>' if i == self.nav.sel else ' '} {e['seq']:>4} {e['at']}  {e['actor'][:12]:<12} {e['action'][:16]:<16} {e['target'][:20]}")
        if self.msg: out += ["", " " + self.msg]
        return out

    def key(self, k):
        self.msg = ""
        if self.nav.key(k): return
        if k == "a": return ("push", Prompt("Append", "actor | action | target | detail:", "", self._add))
        if k == "/": return ("push", Prompt("Search", "Search:", self.q, lambda v: setattr(self, "q", v.strip())))
        if k == "v": bad = verify_chain(self.entries); self.msg = "chain intact" if bad < 0 else f"TAMPERING DETECTED at entry {bad + 1}"
        if k == "x": self.host.put("export.jsonl", "\n".join(json.dumps(e) for e in self.entries)); self.msg = "wrote vault key export.jsonl"
        if k == "enter" and self.shown(): return ("push", TextView("Entry", [f"{k}: {v}" for k, v in self.shown()[self.nav.sel].items()]))
        if k == "escape": return ("quit",)

    def _add(self, v):
        p = [x.strip() for x in v.split("|")] + ["", "", "", ""]
        if p[0] and p[1]: self.append(p[0], p[1], p[2], p[3])
