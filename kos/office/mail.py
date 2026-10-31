"""Mail: a message store with a real delivery pipeline (aliases, rules, quotas,
bounces, relay queue), an RFC 5322/mbox exporter, a client and a server console.

What this is NOT: it opens no sockets. KOS apps have no network by default and
a mail server needs a listening port, so this is the mail *system* (store,
routing, administration) without SMTP/IMAP on the wire. Outbound mail to
other domains waits in the relay queue and is sent by `relay` only if an SMTP
relay is configured and the app was given network access. The client and the
server are separate apps with separate vaults and do not exchange mail with
each other (see docs/IDEAS.md: shared spaces)."""

from __future__ import annotations

import email.message
import email.utils
import re
import smtplib

from .records import Data, Field, RecordForm, RecordList, Spec
from .ui import (Confirm, Editor, ListNav, Menu, Message, Prompt, Screen, Store, TextInput, TextView,
                 now_stamp, slug, table, wrap)

USERS = Spec("users", "Mailboxes", "mailbox", [Field("addr", "Address", "email", required=True), Field("name", "Name"),
                                               Field("quota", "Quota (messages)", "number", default="500"), Field("active", "Active", "bool", default="yes")],
             list_cols=("addr", "name", "quota"))
ALIASES = Spec("aliases", "Aliases", "alias", [Field("alias", "Alias address", "email", required=True), Field("targets", "Deliver to (comma separated)", required=True)],
               list_cols=("alias", "targets"))
RULES = Spec("rules", "Rules", "rule", [Field("field", "If field", "choice", ("from", "to", "subject", "body"), "subject"), Field("contains", "contains", required=True),
                                        Field("action", "Then", "choice", ("folder", "forward", "discard"), "folder"), Field("arg", "Folder / address")],
             list_cols=("field", "contains", "action", "arg"))
FOLDERS = ("inbox", "sent", "drafts", "trash", "spam")


def addr_of(s: str) -> str: return email.utils.parseaddr(s)[1].lower()


class MailStore:
    def __init__(self, host):
        self.host, self.st = host, Store(host)
        self.users = Data(host, USERS, "users"); self.aliases = Data(host, ALIASES, "aliases"); self.rules = Data(host, RULES, "rules")
        self.queue: list = self.st.load("queue", [])
        self.cfg = self.st.load("mailcfg", {"domain": "kos.local", "relay": ""})
        self.log: list = self.st.load("maillog", [])

    def user(self, a):
        return next((u for u in self.users.items if u["addr"].lower() == a and u.get("active", "yes") == "yes"), None)

    def domains(self): return {self.cfg["domain"]} | {u["addr"].split("@")[1].lower() for u in self.users.items}
    def box(self, a): return self.st.load("mb-" + slug(a), [])
    def save_box(self, a, msgs): self.st.save("mb-" + slug(a), msgs)
    def _log(self, s): self.log = (self.log + [f"{now_stamp()} {s}"])[-200:]; self.st.save("maillog", self.log)

    def expand(self, a: str, depth: int = 0) -> list:
        al = next((x for x in self.aliases.items if x["alias"].lower() == a), None)
        if not al or depth > 4: return [a]
        out = []
        for t in al["targets"].split(","):
            if t.strip(): out += self.expand(addr_of(t), depth + 1)
        return out

    def submit(self, msg: dict, folder_for_sender: str | None = "sent") -> list:
        """Run a message through the pipeline. -> list of result lines."""
        res = []
        msg = {**msg, "id": msg.get("id") or f"{int(__import__('time').time() * 1000)}", "date": msg.get("date") or now_stamp()}
        sender = addr_of(msg["from"])
        if folder_for_sender and self.user(sender):
            sb = self.box(sender); sb.append({**msg, "folder": folder_for_sender, "read": True}); self.save_box(sender, sb)
        for rcpt in [addr_of(x) for x in msg["to"]]:
            for r in self.expand(rcpt):
                res.append(self.deliver(msg, r))
        self._log(f"submit {msg['subject'][:30]!r} from {sender}: " + "; ".join(res))
        return res

    def deliver(self, msg: dict, rcpt: str, hops: int = 0, force: bool = False) -> str:
        dom = rcpt.split("@")[-1]
        if dom not in self.domains():
            self.queue.append({**msg, "rcpt": rcpt, "state": "queued", "tries": 0}); self.st.save("queue", self.queue)
            return f"{rcpt}: queued for relay"
        u = self.user(rcpt)
        if not u:
            self.bounce(msg, rcpt, "550 no such user"); return f"{rcpt}: bounced (no such user)"
        folder = "inbox"
        for r in self.rules.items:
            hay = {"from": msg["from"], "to": ", ".join(msg["to"]), "subject": msg["subject"], "body": msg["body"]}[r["field"]]
            if r["contains"].lower() in hay.lower():
                if r["action"] == "discard": return f"{rcpt}: discarded by rule"
                if r["action"] == "forward" and hops < 3 and r.get("arg"): return self.deliver(msg, addr_of(r["arg"]), hops + 1) + " (forwarded)"
                if r["action"] == "folder" and r.get("arg") in FOLDERS: folder = r["arg"]
                break
        box = self.box(rcpt)
        if not force and len([m for m in box if m["folder"] != "trash"]) >= int(float(u.get("quota") or 500)):
            self.bounce(msg, rcpt, "552 mailbox full"); return f"{rcpt}: bounced (mailbox full)"
        box.append({**msg, "folder": folder, "read": False}); self.save_box(rcpt, box)
        return f"{rcpt}: delivered to {folder}"

    def bounce(self, msg, rcpt, why):
        s = addr_of(msg["from"])
        if s.split("@")[-1] in self.domains() and self.user(s) and not msg["from"].startswith("MAILER-DAEMON"):
            self.deliver({"from": f"MAILER-DAEMON@{self.cfg['domain']}", "to": [s], "subject": f"Undelivered: {msg['subject']}",
                          "body": f"Your message to {rcpt} could not be delivered.\n{why}\n", "id": msg["id"] + "b", "date": now_stamp()}, s, force=True)

    def relay(self) -> list:
        host = self.cfg.get("relay", "")
        if not host: return ["no SMTP relay configured (mail settings: relay host:port)"]
        out = []
        try:
            h, _, p = host.partition(":")
            with smtplib.SMTP(h, int(p or 25), timeout=15) as s:
                for q in self.queue:
                    if q["state"] != "queued": continue
                    try:
                        s.sendmail(addr_of(q["from"]), [q["rcpt"]], to_rfc822(q)); q["state"] = "sent"; out.append(f"sent to {q['rcpt']}")
                    except (smtplib.SMTPException, OSError) as e:
                        q["tries"] += 1; q["state"] = "failed" if q["tries"] >= 3 else "queued"; out.append(f"{q['rcpt']}: {e}")
        except (smtplib.SMTPException, OSError) as e:
            out.append(f"cannot reach relay: {type(e).__name__} (does this app have network access?)")
        self.st.save("queue", self.queue)
        return out or ["queue is empty"]


def to_rfc822(m: dict) -> str:
    e = email.message.EmailMessage()
    e["From"], e["To"], e["Subject"] = m["from"], ", ".join(m["to"]), m["subject"]
    e["Message-ID"] = f"<{m['id']}@kos.local>"
    e.set_content(m["body"])
    return e.as_string()


def to_mbox(msgs: list) -> str:
    out = []
    for m in msgs:
        out.append(f"From {addr_of(m['from'])} {m.get('date', '')}\n" + re.sub(r"(?m)^From ", ">From ", to_rfc822(m)) + "\n")
    return "".join(out)


# ---------------------------------------------------------------- client ----
class MailClient(Screen):
    def __init__(self, host, title="Mail"):
        self.host, self.title, self.ms, self.st = host, title, MailStore(host), Store(host)
        self.acct = self.st.load("account", "")
        if not self.acct and self.ms.users.items: self.acct = self.ms.users.items[0]["addr"]
        self.folder = "inbox"
        self.nav = ListNav(0)
        self.q = ""
        self.msg = "" if self.acct else "No account yet: press n to create one."
        self.help = "c compose  Enter read  r reply  f forward  d delete  ! flag  Tab folder  / search  a account  n new account  s send queue"

    def msgs(self):
        if not self.acct: return []
        ms = [m for m in self.ms.box(self.acct.lower()) if m["folder"] == self.folder]
        if self.q: ms = [m for m in ms if self.q.lower() in (m["subject"] + m["from"] + m["body"]).lower()]
        return sorted(ms, key=lambda m: m["date"], reverse=True)

    def render(self, w, h):
        ms = self.msgs(); self.nav.resize(len(ms))
        box = self.ms.box(self.acct.lower()) if self.acct else []
        tabs = "  ".join(f"[{f}{' ' + str(sum(1 for m in box if m['folder'] == f and not m['read'])) if f == 'inbox' else ''}]" if f == self.folder else f
                         for f in FOLDERS)
        out = [f" {self.acct or '(no account)'}   {tabs}" + (f"   search='{self.q}'" if self.q else ""), ""]
        top, end = self.nav.window(h - 5)
        for i in range(top, end):
            m = ms[i]
            out.append(f"{'>' if i == self.nav.sel else ' '}{' ' if m['read'] else '*'}{'!' if m.get('flag') else ' '} {m['date'][5:]}  {addr_of(m['from'])[:22]:<22} {m['subject'][:34]}")
        if not ms: out.append("  (empty)")
        if self.msg: out += ["", " " + self.msg]
        return out

    def key(self, k):
        self.msg = ""
        if self.nav.key(k): return
        ms = self.msgs(); cur = ms[self.nav.sel] if ms else None
        if k == "tab": self.folder = FOLDERS[(FOLDERS.index(self.folder) + 1) % len(FOLDERS)]; self.nav.sel = 0
        elif k == "c" and self.acct: return self.compose()
        elif k == "enter" and cur: return self.read(cur)
        elif k == "r" and cur: return self.compose([addr_of(cur["from"])], ("Re: " if not cur["subject"].startswith("Re:") else "") + cur["subject"], "\n\n> " + cur["body"].replace("\n", "\n> "))
        elif k == "f" and cur: return self.compose([], "Fwd: " + cur["subject"], "\n\n---- forwarded ----\n" + cur["body"])
        elif k == "d" and cur: self.trash(cur)
        elif k == "!" and cur: self.update(cur, flag=not cur.get("flag"))
        elif k == "/": return ("push", Prompt("Search", "Search mail for:", self.q, lambda v: setattr(self, "q", v.strip())))
        elif k == "a":
            accts = [u["addr"] for u in self.ms.users.items]
            if accts: self.acct = accts[(accts.index(self.acct) + 1) % len(accts)] if self.acct in accts else accts[0]; self.st.save("account", self.acct)
        elif k == "n": return ("push", RecordForm(self.ms.users, None, self.new_account))
        elif k == "s": return ("push", TextView("Send queue", self.ms.relay()))
        elif k == "escape": return ("quit",)

    def new_account(self, rec):
        self.ms.users.add(rec); self.acct = self.acct or rec["addr"]; self.st.save("account", self.acct); self.msg = "account created"

    def update(self, cur, **kw):
        box = self.ms.box(self.acct.lower())
        for m in box:
            if m["id"] == cur["id"] and m["folder"] == cur["folder"]: m.update(kw)
        self.ms.save_box(self.acct.lower(), box)

    def trash(self, cur):
        box = self.ms.box(self.acct.lower())
        if cur["folder"] == "trash": box = [m for m in box if not (m["id"] == cur["id"] and m["folder"] == "trash")]
        else:
            for m in box:
                if m["id"] == cur["id"] and m["folder"] == cur["folder"]: m["folder"] = "trash"
        self.ms.save_box(self.acct.lower(), box)

    def read(self, m):
        self.update(m, read=True)
        return ("push", TextView(m["subject"], [f"From: {m['from']}", f"To: {', '.join(m['to'])}", f"Date: {m['date']}", "", *m["body"].split("\n")]))

    def compose(self, to=None, subject="", body=""):
        def got_to(v):
            rcpts = [x.strip() for x in v.split(",") if x.strip()]
            return ("push", Prompt("Compose", "Subject:", subject, lambda s: got_subject(rcpts, s)))
        def got_subject(rcpts, s):
            def send(ed):
                if not rcpts: ed.flash = "no recipients"; return None
                res = self.ms.submit({"from": self.acct, "to": rcpts, "subject": s, "body": ed.area.text})
                self.msg = " | ".join(res)
                return ("pop", None)
            return ("push", Editor("Compose: " + s, body, extra_keys={"ctrl-x": send}, hint="Ctrl-X send   Esc discard"))
        if to: return ("push", Prompt("Compose", "To (comma separated):", ", ".join(to), got_to))
        return ("push", Prompt("Compose", "To (comma separated):", "", got_to))


# ---------------------------------------------------------------- server ----
class MailAdmin(Menu):
    def __init__(self, host, title="Mail server"):
        self.host, self.ms = host, MailStore(host)
        entries = [("Mailboxes", lambda: ("push", RecordList(self.ms.users))), ("Aliases", lambda: ("push", RecordList(self.ms.aliases))),
                   ("Routing rules", lambda: ("push", RecordList(self.ms.rules))), ("Relay queue", self.queue), ("Send a test message", self.test),
                   ("Settings (domain, relay)", self.settings), ("Server log", lambda: ("push", TextView("Log", self.ms.log[::-1] or ["empty"]))),
                   ("Export all mail as mbox", self.export), ("Statistics", self.stats)]
        super().__init__(title, entries, ["  Local mail system: store, routing, quotas, relay queue. No SMTP/IMAP sockets."])

    def queue(self):
        q = self.ms.queue
        return ("push", TextView("Relay queue", [f"{x['state']:<7} to {x['rcpt']}  {x['subject'][:30]}" for x in q] or ["queue is empty"]))

    def test(self):
        return ("push", Prompt("Test", "Deliver a test to (address):", "", lambda a: self.run_test(a)))

    def run_test(self, a):
        res = self.ms.submit({"from": f"postmaster@{self.ms.cfg['domain']}", "to": [a], "subject": "Test message", "body": "Hello from the KOS mail system.\n"}, None)
        return ("push", TextView("Delivery result", res))

    def settings(self):
        return ("push", Prompt("Settings", "domain relayhost:port (relay optional):", f"{self.ms.cfg['domain']} {self.ms.cfg.get('relay', '')}".strip(), self.set_cfg))

    def set_cfg(self, v):
        p = v.split()
        if p: self.ms.cfg["domain"] = p[0].lower(); self.ms.cfg["relay"] = p[1] if len(p) > 1 else ""; self.ms.st.save("mailcfg", self.ms.cfg)

    def export(self):
        allm = [m for u in self.ms.users.items for m in self.ms.box(u["addr"].lower())]
        self.host.put("export.mbox", to_mbox(allm)); return ("push", Message("Export", [f"{len(allm)} message(s) written to vault key export.mbox"]))

    def stats(self):
        rows = [[u["addr"], len(self.ms.box(u["addr"].lower())), u.get("quota", "")] for u in self.ms.users.items]
        return ("push", TextView("Statistics", table(rows, ["mailbox", "messages", "quota"]) + ["", f"relay queue: {len(self.ms.queue)}"]))
