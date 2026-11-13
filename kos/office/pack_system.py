"""pack_system: the OS's own commands, as apps.

``kos audit``, ``kos security``, ``kos ls``, ``kos scan``, ``kos cell``, ``kos optimize`` ... used to be
built into the OS. Each is an app now: a sandboxed program that can read nothing and change nothing by
itself, and *asks* the OS for what it needs with ``host.call("audit.tail", ...)`` (kos/servicespec.py is the
list of what it may ask; kos/services.py answers). The password for each ask is typed in the OS's own
prompt, which the app cannot see or draw over. An app here holds no OS logic: it formats what it is told.

Five of these answer titles in docs/REQUESTED2.txt (Firewall Management, System Information and
Diagnostics, Storage and Disk Management, Process and Resource Monitor, Software Updates); pack_os.py
declares those and borrows the screens from here. The rest are in ENTRIES below.

Nothing here opens a socket, runs a program or touches a file: tests/test_system_apps.py holds this module
to the same syntax guard as every pack."""

from __future__ import annotations

from ..launchmap import STILL_THE_OS, app_for
from .packkit import app
from .ui import Confirm, ListNav, Message, Prompt, Screen, TextInput, TextView, wrap


class Refused(Exception):
    """The OS said no (wrong password, no such file, not allowed): the reason is the message."""


def ask(_host, _service, /, **args) -> dict:
    """Call a service. The parameters are positional-only because services have arguments of their own
    called 'host' and 'name'."""
    r = _host.call(_service, **args)
    if not r.get("ok"):
        raise Refused(r.get("detail") or "the OS did not say why")
    return r.get("data") or {}


def _s(v, n=200) -> str:
    return str(v)[:n]


def message(title, lines):
    return ("push", Message(title, [str(l) for l in lines]))


def ask_chain(title, questions, done, values=()):
    """Prompts one after another; ``done(values)`` runs after the last answer and returns an Action."""
    label, initial = questions[0]

    def got(text):
        vals = (*values, text.strip())
        return done(vals) if len(questions) == 1 else ask_chain(title, questions[1:], done, vals)
    return ("push", Prompt(title, label, initial, got))


def run_service(host, title, name, args, show):
    """Call a service now (the OS asks for the password first); show the outcome in a Message."""
    try:
        data = ask(host, name, **args)
    except Refused as e:
        return message(title, [f"Refused: {e}", "", "Nothing was changed."])
    return message(title, show(data))


# ---------------------------------------------------------------------------------------------------------
# Screens
# ---------------------------------------------------------------------------------------------------------
class Report(Screen):
    """A read-only report the OS fills in when you press r (and asks your password for, each time)."""

    def __init__(self, host, title, intro, fetch, keys=None, hint="", root=True):
        self.host, self.title, self.fetch, self.intro, self.root = host, title, fetch, list(intro), root
        self.lines, self.top, self.msg, self.extra = list(intro), 0, "", dict(keys or {})
        self.help = hint or "r read (asks your password)   up/down scroll   Esc back"

    def load(self):
        try:
            self.lines, self.msg = [str(l) for l in self.fetch(self.host)], ""
        except Refused as e:
            self.msg = "refused: " + _s(e, 160)
        self.top = 0

    def render(self, w, h):
        self.top = max(0, min(self.top, max(0, len(self.lines) - h)))
        return [("  " + l)[:w] for l in self.lines[self.top:self.top + h]]

    def status(self): return self.msg or self.help

    def key(self, k):
        if k == "r": self.load()
        elif k == "up": self.top -= 1
        elif k == "down": self.top += 1
        elif k == "pageup": self.top -= 15
        elif k == "pagedown": self.top += 15
        elif k == "home": self.top = 0
        elif k == "end": self.top = 10 ** 6
        elif k == "escape": return None if self.root else ("pop", None)
        elif k in self.extra: return self.extra[k](self)


class Manager(Screen):
    """A cursor list of things the OS holds (rules, apps, cells ...), with one-key actions on the selected one."""

    def __init__(self, host, title, intro, fetch, keys, hint, empty="(nothing - press r to read)"):
        self.host, self.title, self.intro, self.fetch, self.extra = host, title, list(intro), fetch, dict(keys)
        self.rows, self.items, self.nav, self.msg, self.empty = [], [], ListNav(0), "", empty
        self.help = hint

    def load(self):
        try:
            self.rows, self.items = self.fetch(self.host)
            self.msg = ""
        except Refused as e:
            self.msg = "refused: " + _s(e, 160)
        self.nav.resize(len(self.rows))

    def current(self):
        return self.items[self.nav.sel] if self.items and 0 <= self.nav.sel < len(self.items) else None

    def render(self, w, h):
        out = [("  " + l)[:w] for l in self.intro] + ([""] if self.intro else [])
        top, end = self.nav.window(max(1, h - len(out)))
        if not self.rows:
            return out + ["  " + self.empty]
        return out + [(("> " if i == self.nav.sel else "  ") + self.rows[i])[:w - 2] for i in range(top, end)]

    def status(self): return self.msg or self.help

    def key(self, k):
        if self.nav.key(k): return None
        if k == "r": self.load()
        elif k == "escape": return None
        elif k in self.extra: return self.extra[k](self)


# ---------------------------------------------------------------------------------------------------------
# The apps
# ---------------------------------------------------------------------------------------------------------
def make_audit(host, entry=None):
    def fetch(h):
        d = ask(h, "audit.tail", n=200)
        return ([f"{e['t']}  {e['outcome']:13} {e['action']:15} {e['target']}" for e in d["entries"]]
                or ["(the log is empty)"])

    def verify(screen):
        try:
            d = ask(screen.host, "audit.verify")
        except Refused as e:
            return message("Verify", [f"Refused: {e}"])
        lines = [f"{d['entries']} line(s): {d['chained']} chained, {d['anchored']} anchored to your password, "
                 f"{d['legacy']} older unprotected"]
        if d["trimmed"]:
            lines.append("note: older lines were trimmed by disk care; the chain is checked from the first one left")
        lines += ([f"TAMPERED at line {d['bad_line']}: {d['problem']}"] if not d["ok"] else
                  ["intact: no line was edited, deleted or reordered, and every anchor matches your password",
                   "(a log cut short at the very end cannot be detected - nothing else remembers its length)"])
        return message("Verify the log", lines)
    return Report(host, "Audit Log", ["", "Every password decision KOS has made, newest last.", "",
                                      "r  read the log   v  check it for tampering"],
                  fetch, {"v": verify}, "r read   v verify   up/down scroll   Esc quit")


def make_activity(host, entry=None):
    def fetch(h):
        d = ask(h, "activity.feed", n=60)
        return [f"{('now' if i['live'] else i['t']):>10}  {i['text']}" for i in d["items"]] or ["nothing has happened yet"]
    return Report(host, "Activity", ["", "Open apps and recent password decisions, newest first.", "", "r  read"], fetch)


def make_security(host, entry=None):
    def fetch(h):
        d = ask(h, "security.check")
        tag = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}
        return [f"{tag.get(c['level'], '????')}  {c['name']:12} {c['detail']}" for c in d["checks"]] + [
            "", f"Result: {len(d['checks']) - d['failed'] - d['warned']} passed, {d['warned']} warning(s), "
                f"{d['failed']} failed"]
    return Report(host, "Security Check", ["", "Everything KOS can verify about itself. Read-only: nothing is changed.",
                                           "", "r  run the check"], fetch)


def make_system(host, entry=None):
    def report(h):
        d = ask(h, "system.report")
        k = d["kos_kernel"]
        yn = lambda b: "yes" if b else "NO"
        lines = [f"Landlock ABI          : {d['landlock_abi'] or 'NOT AVAILABLE (apps will refuse to run)'}",
                 f"seccomp filter (apps) : {yn(d['seccomp_filter'])}",
                 f"user namespaces       : {yn(d['user_namespaces'])}",
                 f"KVM (kernel cells)    : {yn(d['kvm'])}",
                 f"vhost-vsock (cells)   : {yn(d['vhost_vsock'])}",
                 f"framebuffer /dev/fb0  : {yn(d['framebuffer'])}",
                 f"evdev /dev/input      : {yn(d['evdev'])}",
                 f"firmware control      : " + ("yes" if d["firmware"]["ok"] and not d["firmware"]["blocking"] else
                                                "NO - " + ", ".join(d["firmware"]["blocking"] or [d["firmware"]["reason"]])),
                 f"password configured   : {yn(d['password_configured'])}", ""]
        if not k["present"]:
            lines += ["KOS kernel           : NOT PRESENT - this is a stock kernel.",
                      "                       Apps run in the sandbox only: no firewall, no device gate."]
        else:
            lines += ["KOS kernel           : present",
                      f"  this process       : {k['role']}",
                      f"  core               : {k.get('core', '?')}",
                      f"  firewall rules     : {k.get('rules', '?')} live",
                      f"  connections logged : {k.get('logged', '?')} (lost before read: {k.get('dropped', '?')})"]
        lines.append(f"  this boot requires it: {yn(k['required'])}")
        return lines

    def firmware(plan):
        def go(screen):
            def fetch(h):
                d = ask(h, "system.firmware", plan=plan)
                lines = [f"policy: kos.firmware={d['policy']}", *d["lines"],
                         "boot: " + ("allowed" if d["ok"] else "REFUSED - " + d["reason"]), ""]
                if plan:
                    lines += [d.get("platform", ""), ""]
                    for i in d.get("plan", []):
                        lines += [f"- {i['name']} [{i['state']}] open replacement: {i['open']}", f"    {i['advice']}"]
                    lines += ["", d.get("summary", ""), "", "This plan is read-only. KOS never writes to a chip."]
                else:
                    lines += ["what the chips we cannot remove can still see:"]
                    for p in d["protections"]:
                        lines += [f"  {p['name']:24} {p['status']}", f"      {p['note']}"]
                return lines
            rep = Report(screen.host, "Firmware", ["", "r  read"], fetch, root=False)
            rep.load()                                  # you asked for it by pressing the key: ask now
            return ("push", rep)
        return go
    return Report(host, "System Information and Diagnostics",
                  ["", "What this machine and this kernel can enforce.", "", "r  read   f  firmware   p  firmware plan"],
                  report, {"f": firmware(False), "p": firmware(True)}, "r read   f firmware   p plan   Esc quit")


def make_disk(host, entry=None):
    def fetch(h):
        owed = ask(h, "maintenance.owed")["owed"]
        return (["nothing is owed"] if not owed else
                [f"{e['target']}  ({e['trigger']}) still owes: {', '.join(e['pending'])}" for e in owed])

    def act(name, what):
        def go(screen):
            return ("push", Confirm(f"{what}? The OS asks for your password.",
                                    lambda: run_service(screen.host, what.capitalize(), name, {},
                                                        lambda d: d.get("lines") or [d.get("summary", "done")]),
                                    title=what.capitalize()))
        return go
    return Report(host, "Storage and Disk Management",
                  ["", "What earlier writes still owe (a security scan, a disk optimize).", "",
                   "r  see what is owed   s  settle it   o  optimize: recompress apps, prune dead state, trim the log"],
                  fetch, {"s": act("maintenance.settle", "settle what is owed"),
                          "o": act("maintenance.optimize", "optimize the disk")},
                  "r owed   s settle   o optimize   Esc quit")


def make_files(host, entry=None):
    state = {"path": "/"}

    def fetch(h):
        d = ask(h, "files.list", path=state["path"])
        state["path"] = d["path"]
        rows = [".." + "/"] + [e["name"] + ("/" if e["dir"] else (" (zip)" if e["zip"] else "")) for e in d["entries"]]
        return rows, [{"up": True}] + d["entries"]

    def title(): return f"Files  {state['path']}"

    def open_it(screen):
        it = screen.current()
        if it is None:
            return None
        if it.get("up"):
            state["path"] = state["path"].rsplit("/", 1)[0] or "/"
            screen.load(); screen.title = title()
            return None
        target = state["path"].rstrip("/") + "/" + it["name"]
        if it["dir"] or it["zip"]:
            state["path"] = target
            screen.load(); screen.title = title()
            return None
        try:
            d = ask(screen.host, "files.read", path=target)
        except Refused as e:
            return message("Open", [f"Refused: {e}"])
        head = [f"{it['name']}  ({d['size']} bytes" + (", binary" if d["binary"] else "") + (f", first {d['shown']} shown" if d["shown"] < d["size"] else "") + ")", ""]
        body = ["(binary data: not shown)"] if d["binary"] else d["text"].splitlines()
        return ("push", TextView(it["name"], head + body))

    def go_to(screen):
        def got(vals):
            state["path"] = vals[0] or "/"
            screen.load(); screen.title = title()
        return ask_chain("Go to", [("Directory, file or zip to list:", state["path"])], lambda v: (got(v), None)[1])

    def scan_it(screen):
        it = screen.current()
        if it is None or it.get("up"):
            return None
        target = state["path"].rstrip("/") + "/" + it["name"]
        return run_service(screen.host, "Scan", "scan.file", {"path": target}, _scan_lines)

    m = Manager(host, title(), ["Browse folders and zip files as one tree. A zip is never extracted."], fetch,
                {"enter": open_it, "g": go_to, "s": scan_it},
                "r list   Enter open   g go to a path   s scan this   Esc quit", "(press r to list; the OS asks your password)")
    return m


def _scan_lines(d):
    out = [d["summary"], f"sha256 {d['sha256']}", ""]
    out += [f"[{f['severity']}] {f['rule']} in {f['path']}: {f['note']}" for f in d["findings"]]
    return out


def make_scanner(host, entry=None):
    def ask_path(screen):
        return ask_chain("Scan", [("File or zip to scan:", "")],
                         lambda v: run_service(screen.host, "Scan result", "scan.file", {"path": v[0]}, _scan_lines)
                         if v[0] else None)
    return Report(host, "Scanner", ["", "Check a file or a zip for known-bad patterns, without extracting it.", "",
                                    "p  scan a path   (the OS asks your password to read it)", "",
                                    "Watching a folder for new files is still `kos scan watch`."],
                  lambda h: [], {"p": ask_path, "enter": ask_path}, "p scan a path   Esc quit")


def make_firewall(host, entry=None):
    def fetch(h):
        d = ask(h, "firewall.list")
        k = d["kernel"]
        state = {"ok": "", "empty": "", "tampered": "THE RULE FILE FAILED ITS SEAL: its rules are ignored. "}[d["state"]]
        mgr.intro[:] = ["Everything is blocked unless a rule below allows it. One app, one protocol, one address, one port.",
                         state + ("KOS kernel: enforcing (%s live rule(s))" % k.get("rules", "?") if k["present"] else
                                  "KOS kernel: NOT PRESENT - rules are kept but nothing enforces them yet."), ""]
        rows = [f"{r['app']:16} {r['proto']} {r['direction']:7} {r['host']}:{r['port']}" for r in d["rules"]]
        log = [f"{e['t']}  {e['outcome']:8} {e['target']}" for e in d["log"]]
        mgr.log = log
        return rows, d["rules"]

    def add(screen):
        def done(v):
            if not v[4].isdigit():
                return message("Add a rule", ["The port must be a number from 1 to 65535."])
            return run_service(screen.host, "Add a rule", "firewall.allow",
                               {"app": v[0], "proto": v[1], "direction": v[2], "host": v[3], "port": int(v[4])},
                               lambda d: [("Rule added." if d["added"] else "That rule already exists."), d["note"]])
        return ask_chain("Add a rule", [("App name:", ""), ("Protocol (tcp or udp):", "tcp"),
                                        ("Direction (connect or listen):", "connect"),
                                        ("IP address, typed out (no names, no ranges):", ""), ("Port:", "")], done)

    def remove(screen):
        r = screen.current()
        if r is None:
            return None
        return ("push", Confirm(f"Remove {r['app']} {r['proto']} {r['direction']} {r['host']}:{r['port']}?",
                                lambda: run_service(screen.host, "Remove a rule", "firewall.remove", dict(r),
                                                    lambda d: ["Rule removed." if d["removed"] else "No such rule.", d["note"]])))

    def show_log(screen):
        return ("push", TextView("Connection log", mgr.log or ["(nothing logged yet - press r first)"]))
    mgr = Manager(host, "Firewall Management", [], fetch, {"a": add, "d": remove, "l": show_log},
                   "r read   a add   d remove   l connection log   Esc quit", "(no rules: everything is blocked)")
    mgr.log = []
    return mgr


def make_cells(host, entry=None):
    def fetch(h):
        cells = ask(h, "cells.list")["cells"]
        return [f"{c['name']:16} cid={c['cid']:<4} cpus={c['cpus']} {c['memory_mb']}M {'running' if c['running'] else 'dead'}"
                for c in cells], cells

    def new(screen):
        def done(v):
            if not v[3].isdigit():
                return message("Start a cell", ["Memory must be a number of MiB."])
            return run_service(screen.host, "Start a cell", "cells.start",
                               {"name": v[0], "kernel": v[1], "initrd": v[2], "memory": int(v[3]),
                                "cpus": [c.strip() for c in v[4].split(",") if c.strip()]},
                               lambda d: [f"cell {d['name']} started: its own kernel on cores {d['cpus']}, vsock cid {d['cid']}"])
        return ask_chain("Start a cell", [("Name:", ""), ("Kernel image path:", ""), ("Initrd path:", ""),
                                         ("Memory (MiB):", "256"), ("Cores, e.g. 2,3:", "2")], done)

    def stop(screen):
        c = screen.current()
        return None if c is None else ("push", Confirm(f"Stop cell {c['name']}?", lambda: run_service(
            screen.host, "Stop a cell", "cells.stop", {"name": c["name"]}, lambda d: [f"cell {d['stopped']} stopped"])))
    return Manager(host, "Kernel Cells", ["A cell is a separate Linux kernel on its own cores, reached only by vsock."],
                   fetch, {"n": new, "x": stop}, "r read   n new cell   x stop   Esc quit", "(no cells - press r, or n to start one)")


def make_packages(host, entry=None):
    def fetch(h):
        apps = ask(h, "packages.list")["apps"]
        return ([f"{a['name']:20} {a['version']:8} {'permitted' if a['permitted'] else 'NOT permitted':14} {a['kind']}" for a in apps],
                apps)

    def path_action(title, name, what):
        def go(screen):
            return ask_chain(title, [(f"Path of the .kapp to {what}:", "")], lambda v: run_service(
                screen.host, title, name, {"path": v[0]}, lambda d: [f"{d['name']} {d.get('version', d.get('to', ''))}: done"])
                if v[0] else None)
        return go

    def permit(screen):
        a = screen.current()
        if a is None:
            return None
        rev = bool(a["permitted"])
        return run_service(screen.host, "Permit", "packages.permit", {"name": a["name"], "revoke": rev},
                           lambda d: [f"{d['name']} may {'now' if d['permitted'] else 'no longer'} run",
                                      "It still asks for your password every time."])

    def remove(screen):
        a = screen.current()
        return None if a is None else ("push", Confirm(f"Remove {a['name']}?", lambda: run_service(
            screen.host, "Remove", "packages.remove", {"name": a["name"]}, lambda d: [f"removed {d['removed']}"])))
    return Manager(host, "Software Updates", ["Installed apps. Install and update scan the file first, then ask your password."],
                   fetch, {"i": path_action("Install", "packages.install", "install"),
                           "u": path_action("Update", "packages.update", "update to (must be newer)"),
                           "p": permit, "d": remove},
                   "r read   i install   u update   p permit/revoke   d remove   Esc quit", "(press r)")


def make_permissions(host, entry=None):
    def fetch(h):
        g = ask(h, "permissions.list")["grants"]
        return [f"{x['space']:20} {x['app']:20} {x['level']}" for x in g], g

    def grant(screen):
        return ask_chain("Grant", [("App:", ""), ("Shared folder:", ""), ("Level (read or write):", "read")], lambda v: run_service(
            screen.host, "Grant", "permissions.grant", {"app": v[0], "space": v[1], "level": v[2]},
            lambda d: [f"{d['app']} may now {d['level']} {d['space']}"]))

    def revoke(screen):
        g = screen.current()
        return None if g is None or g["level"] == "own" else ("push", Confirm(
            f"Take {g['app']} out of {g['space']}?", lambda: run_service(
                screen.host, "Revoke", "permissions.grant", {"app": g["app"], "space": g["space"], "revoke": True},
                lambda d: ["revoked" if d["revoked"] else "nothing to revoke"])))
    return Manager(host, "Shared Folders", ["Who may use which shared folder. Only the app that creates a folder owns it."],
                   fetch, {"g": grant, "x": revoke}, "r read   g grant   x revoke   Esc quit", "(none yet - press r)")


def make_converter(host, entry=None):
    def go(screen):
        return ask_chain(
            "Convert", [("Debian package (.deb):", ""), ("Write the app to (a new file):", ""),
                        ("Which program inside, if there are several (else leave empty):", "")],
            lambda v: run_service(
                screen.host, "Convert", "packages.convert",
                {"path": v[0], "out": v[1], **({"exe": v[2]} if v[2] else {})},
                lambda d: [d["summary"], "", f"wrote {d['wrote']}",
                           "Next: install it with Software Updates (it is scanned again)."])
            if v[0] and v[1] else None)
    return Report(host, "Debian Converter", ["", "Turn a .deb into an app. Only statically linked programs convert.", "",
                                             "Maintainer scripts are never run. The result gets no permissions.", "",
                                             "c  convert a package"], lambda h: [], {"c": go, "enter": go}, "c convert   Esc quit")


def make_skills(host, entry=None):
    def fetch(h):
        d = ask(h, "skills.make")
        lines = []
        for rel, txt in d["files"].items():
            lines += [f"=== {rel}", *txt.splitlines(), ""]
        return lines + [f"(left out: {s})" for s in d["skipped"]] or ["(nothing to show)"]
    return Report(host, "Skill Maker", ["", "Agent skills made from the installed apps and the commands, shown here.", "",
                                        "r  make them (one password verifies every app's seal)", "",
                                        "Writing them to disk is still `kos skills --out DIR`: it needs the administrator keyboard."],
                  fetch)


class Terminal(Screen):
    """The line shell as an app: you type a line in your language; it is one command, never a shell string."""
    title = "Terminal"
    help = "Enter run   Esc quit   (help lists the commands)"

    def __init__(self, host):
        self.host, self.inp, self.out = host, TextInput(""), ["Every line is a command, in your own language. Type 'help'."]

    def render(self, w, h):
        lines = [l for o in self.out[-200:] for l in wrap(o, max(20, w - 4))]
        return ["  " + l for l in lines[-(h - 2):]] + ["", "  kos> " + self.inp.render()]

    def key(self, k):
        if k == "escape":
            return None
        if k != "enter":
            self.inp.key(k)
            return None
        line, self.inp = self.inp.value.strip(), TextInput("")
        if line:
            self.out.append("kos> " + line)
            self.run_line(line)
        return None

    def run_line(self, line):
        from ..lang import HELP, interpret
        try:
            parsed = interpret(line)
        except Exception as e:                      # the interpreter must never end the session
            self.out.append(f"error: {type(e).__name__}")
            return
        if parsed.kind == "help":
            self.out += HELP.splitlines()
        elif parsed.kind == "unknown":
            self.out.append("I don't know that command." + (f" Did you mean '{parsed.hint}'?" if parsed.hint else ""))
        elif parsed.kind == "code":
            r = self.host.call("code.run", code=line[:20_000])
            self.out += (r["data"].get("output") or ["(no output)"]) if r["ok"] else [f"refused: {r['detail']}"]
        elif parsed.kind == "command":
            self.dispatch(list(parsed.argv))

    def dispatch(self, argv):
        name = argv[0] if argv else ""
        if name in ("run", "open") and len(argv) >= 2 and argv[-1]:
            target = argv[-1]
        elif name == "go" and len(argv) == 2:
            self.host.open_address(argv[1])
            self.out.append(f"asked the OS to open {argv[1]} (it asks for your password)")
            return
        else:
            target = app_for(name)
        if not target:
            why = STILL_THE_OS.get(name)
            self.out.append(f"'{name}' is the OS's own command: type `kos {name}` in the console. ({why})" if why
                            else f"no app for '{name}'")
            return
        self.host.open_app(target)
        self.out.append(f"asked the OS to open the app '{target}' (it asks for your password)")


def make_terminal(host, entry=None):
    return Terminal(host)


# ---------------------------------------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------------------------------------
ENTRIES: list = [
    app("Audit Log", make_audit, "full",
        "Reads the authorization log and checks its hash chain for tampering. Replaces `kos audit`.",
        name="audit-log", services=["audit"]),
    app("Security Check", make_security, "full",
        "Everything KOS can verify about itself; changes nothing. Replaces `kos security`.",
        name="security-check", services=["security"]),
    app("Files", make_files, "partial",
        "Browse folders and zip files (never extracted), read text, scan what is selected. Replaces `kos ls`, `cat`, `explore`, "
        "`view`. Writing a file stays `kos write`: it needs the exclusive administrator keyboard.",
        name="files", services=["files", "scan"]),
    app("Scanner", make_scanner, "partial",
        "Scans one file or zip for known-bad patterns. Replaces `kos scan file`. Watching a folder is still `kos scan watch`.",
        name="scanner", services=["scan"]),
    app("Kernel Cells", make_cells, "full",
        "List, start and stop cells: separate Linux kernels on their own cores. Needs KVM. Replaces `kos cell`.",
        name="cells", services=["cells"]),
    app("Shared Folders", make_permissions, "partial",
        "Who may use which shared folder; grant and revoke. Replaces `kos grant` and `kos spaces`. Run permits are in Software Updates.",
        name="permissions", services=["permissions"]),
    app("Debian Converter", make_converter, "partial",
        "Turns a .deb into an app (static programs only, no scripts run, no permissions). Replaces `kos convert`. The package "
        "is still read and parsed by the OS, not inside this app.",
        name="deb-converter", services=["packages"]),
    app("Skill Maker", make_skills, "partial",
        "Shows agent skills made from the installed apps and the commands. Replaces `kos skills` without `--out`; writing "
        "them to disk is still `kos skills --out` (it needs the administrator keyboard).",
        name="skill-maker", services=["skills"]),
    app("Terminal", make_terminal, "partial",
        "The line shell as an app: a line in your language becomes one command, run by opening the app that now holds it. "
        "Replaces `kos line`. Output of other apps is not shown here; they open in their own screen.",
        name="terminal", services=["code"], system=True),
]
