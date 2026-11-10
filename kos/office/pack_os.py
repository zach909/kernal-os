"""pack_os: OS-management titles. Eight are real apps that ask the OS for facts with the narrow `sysinfo`
permission (the OS reads them after the owner's password, audited; the app never opens /proc, /sys or a
device), and one (Firewall Management) uses the narrow `firewall` permission, where every change goes through
the OS's own password prompt. None has `system` or a network of its own. Four stay `none`."""

from __future__ import annotations

import re

from .packkit import app, none
from .ui import bar, table, Screen, Prompt


def _size(n) -> str:
    n = float(n)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or u == "TiB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def _mib(n) -> str:
    return _size(float(n) * 1048576)


def _get(host, topics) -> tuple:
    """-> ({topic: data}, [problems]). One password prompt covers all topics for this app run."""
    out, bad = {}, []
    for t in topics:
        try:
            ok, d = host.sysinfo(t)
        except Exception:
            ok, d = False, "unavailable"
        if ok and isinstance(d, dict):
            out[t] = d
        else:
            bad.append(f"{t}: the OS did not give this ({d if isinstance(d, str) else 'unavailable'})")
    return out, bad


class Report(Screen):
    """A read-only report. Loads on entry; `r` reloads (no background polling); up/down scroll."""

    def __init__(self, title, topics, build, intro):
        self.title, self.topics, self.build, self.intro = title, topics, build, intro
        self.lines, self.top = [], 0
        self.help = "r refresh   up/down scroll   Esc quit"

    def on_enter(self):
        self.load()

    def load(self):
        data, bad = _get(self.host_, self.topics)
        body = self.build(data) if data else []
        self.lines = [*self.intro, "", *body, *([""] + bad if bad else [])]
        if bad and not data:
            self.lines += ["", "Nothing was shown. The OS asks for your password before an app may read",
                           "facts about this computer; if you declined, open the app again to be asked."]

    def render(self, w, h):
        self.top = max(0, min(self.top, max(0, len(self.lines) - h)))
        return self.lines[self.top:self.top + h]

    def key(self, k):
        if k == "r": self.load()
        elif k == "up": self.top -= 1
        elif k == "down": self.top += 1
        elif k == "pageup": self.top -= 15
        elif k == "pagedown": self.top += 15
        elif k == "home": self.top = 0
        elif k == "end": self.top = 10 ** 6
        elif k == "q": return ("quit",)


def _screen(host, title, topics, build, intro):
    s = Report(title, topics, build, intro)
    s.host_ = host
    return s


def _verdict(ok, good, bad, note=""):
    return f"  {'OK    ' if ok else 'NOT OK'}  {good if ok else bad}" + ("" if ok or not note else f"  ({note})")


def _make_sysinfo(host, e):
    def build(d):
        out = []
        o = d.get("os", {})
        out += ["This computer", f"  kernel   {o.get('kernel', '?')}   machine {o.get('machine', '?')}",
                f"  Python   {o.get('python', '?')}   KOS {o.get('kos', '?')}", ""]
        m = d.get("memory", {})
        if "total_mib" in m:
            out += [f"  memory   {_mib(m['total_mib'])} total, {_mib(m.get('available_mib', 0))} available"]
        ld = d.get("load", {})
        if "load1" in ld:
            out += [f"  load     {ld['load1']} / {ld.get('load5', '?')} / {ld.get('load15', '?')} (1/5/15 min)"
                    f"   up {int(ld.get('uptime_s', 0)) // 3600} h"]
        sb = d.get("sandbox")
        if sb is not None:
            abi = sb.get("landlock_abi")
            out += ["", "Checks (like `kos doctor`)",
                    _verdict(bool(abi), f"Landlock ABI {abi}", "Landlock not available", "apps will refuse to run"),
                    _verdict(sb.get("seccomp_filter") is True, "seccomp filter for apps", "no seccomp filter",
                             "Landlock and namespaces still apply"),
                    _verdict(sb.get("user_namespaces") is True, "user namespaces", "no user namespaces"),
                    _verdict(sb.get("kvm") is True, "KVM for kernel cells", "no KVM", "only kernel cells need it"),
                    _verdict(sb.get("vhost_vsock") is True, "vhost-vsock for cells", "no vhost-vsock",
                             "only kernel cells need it")]
            out += ["", "Overall: " + ("OK - the sandbox can protect apps." if abi and sb.get("user_namespaces")
                                       else "NOT OK - the sandbox cannot fully protect apps here.")]
        return out
    return _screen(host, "System Information", ("os", "sandbox", "memory", "load"), build,
                   ["Read-only. Facts come from the OS after your password; this app reads no files itself.",
                    "It shows no host name, user names, addresses or paths."])


def _make_storage(host, e):
    def build(d):
        s = d.get("storage", {})
        out = []
        if "total_bytes" in s:
            tot, free = s["total_bytes"], s.get("free_bytes", 0)
            out += [f"Disk holding KOS data: {_size(tot)} total, {_size(free)} free",
                    "  used [" + bar(tot - free, tot, 40).ljust(40) + f"] {100 * (tot - free) // max(1, tot)}%", ""]
        apps = [a for a in s.get("apps", []) if isinstance(a, dict)]
        top = max([a.get("bytes", 0) for a in apps] + [1])
        out += ["Space used by each app's own data (biggest first)"]
        for a in apps[:20]:
            out.append(f"  {str(a.get('name', '?'))[:24]:24} {bar(a.get('bytes', 0), top, 24):24} {_size(a.get('bytes', 0))}"
                       + ("" if a.get("complete", True) else " (at least)"))
        if not apps:
            out.append("  (no installed apps)")
        return out
    return _screen(host, "Storage", ("storage",), build,
                   ["READ-ONLY: this app cannot delete, partition or format anything.",
                    "Use `kos optimize` (password) to reclaim app disk space."])


def _make_monitor(host, e):
    def build(d):
        out = ["KOS apps opened with `kos open`"]
        rows = [[a.get("name", "?"), a.get("mode", "?"), a.get("status", "?")]
                for a in d.get("apps", {}).get("open", []) if isinstance(a, dict)]
        out += ["  " + l for l in (table(rows, ["app", "mode", "status"]) if rows else ["(none open)"])]
        m = d.get("memory", {})
        if "total_mib" in m:
            used = m["total_mib"] - m.get("available_mib", 0)
            out += ["", f"Memory  {_mib(used)} used of {_mib(m['total_mib'])}",
                    "  [" + bar(used, m["total_mib"], 40).ljust(40) + "]"]
            if m.get("swap_total_mib"):
                out.append(f"  swap {_mib(m['swap_total_mib'] - m.get('swap_free_mib', 0))} used of {_mib(m['swap_total_mib'])}")
        ld = d.get("load", {})
        if "load1" in ld:
            out += ["", f"Load average  {ld['load1']} / {ld.get('load5', '?')} / {ld.get('load15', '?')}"]
        return out
    return _screen(host, "Resource Monitor", ("apps", "memory", "load"), build,
                   ["It can NOT see or manage other processes; it cannot stop anything.",
                    "Press r to refresh; nothing updates in the background."])


def _make_battery(host, e):
    def build(d):
        bs = d.get("battery", {}).get("batteries", [])
        if not bs:
            return ["No battery found. That is a normal answer on a desktop, server or virtual machine."]
        out = []
        for i, b in enumerate(bs, 1):
            pct = b.get("percent")
            out.append(f"  {b.get('type', '?')} {i}: " + (f"{pct}% " + "[" + bar(pct, 100, 20).ljust(20) + "] " if pct is not None else "")
                       + b.get("status", ""))
        return out
    return _screen(host, "Battery and Power", ("battery",), build,
                   ["Read-only. It cannot change power settings, sleep or brightness."])


# ---- Network and Wireless -------------------------------------------------------------------------------
def _make_network(host, e):
    def build(d):
        n = d.get("network", {})
        out = ["Apps that declare the `network` permission (they may ASK the OS to fetch over https)"]
        apps = [str(a) for a in n.get("declared_network_apps", [])]
        out += ["  " + ", ".join(apps)] if apps else ["  (none)"]
        out += ["", "Firewall rules the owner typed (everything else is blocked)"]
        rules = [r for r in n.get("rules", []) if isinstance(r, dict)]
        rows = [[r.get("who", "?"), "WILDCARD" if r.get("host") == "*" else r.get("host", "?"), r.get("port", "?"),
                 r.get("proto", "?")] for r in rules]
        out += ["  " + l for l in table(rows, ["who", "host", "port", "proto"])] if rows else ["  (no rules: nothing is allowed)"]
        a = n.get("assistant", {}) if isinstance(n.get("assistant"), dict) else {}
        out += ["", "Assistant"]
        if a.get("active"):
            out.append(f"  endpoint {a.get('endpoint_host_port') or '?'}   firewall: "
                       + ("allows it" if a.get("firewall_allows") else "BLOCKS it (no rule)"))
        else:
            out.append("  off")
        r = n.get("recent", {}) if isinstance(n.get("recent"), dict) else {}
        out += ["", f"Last 200 connection decisions: {r.get('allowed', 0)} allowed, {r.get('blocked', 0)} blocked"]
        return out
    return _screen(host, "Network and Wireless", ("network",), build,
                   ["A read-only view of network POLICY. Apps have no network of their own: the OS fetches for them,",
                    "and only where a firewall rule allows. There is no Wi-Fi or Bluetooth management in KOS.",
                    "Rules change with `kos firewall` or the Firewall Management app."])


# ---- Device Settings --------------------------------------------------------------------------------------
def _make_settings(host, e):
    def build(d):
        s = d.get("settings", {})
        out = ["Assistant: " + ("ON" if s.get("assistant_active") else "off"),
               "    change: `kos assistant status` / `kos assistant use off|local|api`",
               "", f"Apps allowed to run: {s.get('permitted_apps', 0)}",
               "    change: `kos permit NAME` (allow) or `kos permit NAME --revoke`", "", "Shared folder grants"]
        g = [x for x in s.get("shared_folder_grants", []) if isinstance(x, dict)]
        out += [f"  {x.get('app', '?')}  space:{x.get('space', '?')}  {x.get('level', '?')}" for x in g] or ["  (none)"]
        out += ["    change: `kos grant APP space:NAME --level read|write` or add --revoke", "", "Extensions and mods switched on"]
        x = [x for x in s.get("extensions_on", []) if isinstance(x, dict)]
        out += [f"  {i.get('name', '?')}  ({i.get('kind', '?')} for {i.get('host_app', '?')})" for i in x] or ["  (none)"]
        out += ["    change: `kos extend NAME` or `kos extend NAME --revoke`", "",
                f"Firewall rules: {s.get('firewall_rules', 0)}",
                "    change: `kos firewall allow WHO HOST PORT --proto https|loopback` / `kos firewall remove WHO HOST PORT`",
                "", "Your password", "    change: `kos passwd`"]
        return out
    return _screen(host, "Device Settings", ("settings",), build,
                   ["A read-only summary of what KOS is set to do. This app changes nothing: each item names the",
                    "`kos` command that does, and each of those asks for your password."])


# ---- Software Updates ------------------------------------------------------------------------------------
_VER_RE = re.compile(r"([0-9]+(?:\.[0-9]+){0,7})(?:[-_.]?([A-Za-z][0-9A-Za-z._-]*))?(?:\+[0-9A-Za-z._-]*)?")
MAX_UPDATE_TEXT = 20000
MAX_UPDATE_LINES = 400


def parse_version(v):
    """(numbers, suffix) or None. A version is dotted numbers (1.9, 1.10.2) with an optional suffix that
    starts with a letter, after an optional - _ or .  (1.2-rc1, 2.0b3). `+build` metadata is ignored.
    Anything else (empty, leading/trailing dots, 'latest', 'v1') is None = unknown."""
    if not isinstance(v, str) or not 1 <= len(v) <= 32:
        return None
    m = _VER_RE.fullmatch(v.strip())
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".")]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()                         # 1.0 == 1.0.0
    return tuple(nums), (m.group(2) or "").lower()


def _natural(s):
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.findall(r"[0-9]+|[^0-9]+", s)]


def compare_versions(a, b):
    """-1 if a < b, 0 if equal, 1 if a > b, None if either is not a version.
    Numbers compare component by component as numbers (1.9 < 1.10; a missing component is 0).
    With equal numbers, a suffix means PRE-RELEASE: 1.0-rc1 < 1.0. Two suffixes compare naturally
    (rc2 < rc10; letters alphabetically: alpha < beta < rc)."""
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return None
    if pa[0] != pb[0]:
        n = max(len(pa[0]), len(pb[0]))
        x = pa[0] + (0,) * (n - len(pa[0])); y = pb[0] + (0,) * (n - len(pb[0]))
        return -1 if x < y else 1
    if pa[1] == pb[1]:
        return 0
    if not pa[1]:
        return 1
    if not pb[1]:
        return -1
    ka, kb = _natural(pa[1]), _natural(pb[1])
    return -1 if ka < kb else 1 if ka > kb else 0


def parse_available(text):
    """{name: version} from lines `name version`. Garbage lines (wrong word count, bad name or version) are ignored;
    only the first MAX_UPDATE_LINES lines of the first MAX_UPDATE_TEXT characters are looked at; the last line for a name wins."""
    out = {}
    if not isinstance(text, str):
        return out
    for line in text[:MAX_UPDATE_TEXT].splitlines()[:MAX_UPDATE_LINES]:
        parts = line.split()
        if len(parts) == 2 and re.fullmatch(r"[a-z][a-z0-9-]{0,31}", parts[0]) and parse_version(parts[1]) is not None:
            out[parts[0]] = parts[1]
    return out


def update_rows(installed, available):
    """[(name, installed version, available version or '-', verdict, command or '')] for every installed app."""
    rows = []
    for a in installed[:200]:
        if not isinstance(a, dict) or not isinstance(a.get("name"), str):
            continue
        name, have, want = a["name"], str(a.get("version", "?")), available.get(a["name"])
        c = compare_versions(have, want) if want else None
        if c is None:
            rows.append((name, have, want or "-", "unknown", ""))
        elif c == 0:
            rows.append((name, have, want, "up to date", ""))
        elif c < 0:
            rows.append((name, have, want, "update available", f"kos update {name}-{want}.kapp"))
        else:
            rows.append((name, have, want, "would be a downgrade (KOS refuses)", ""))
    return rows


class Updates(Screen):
    """Paste `name version` lines, then Ctrl-D. Compare only: nothing is downloaded or installed."""

    def __init__(self, host):
        self.host_, self.title, self.buf, self.lines, self.top, self.mode = host, "Software Updates", "", [], 0, "input"
        self.help = "paste or type lines   Ctrl-D compare   Esc quit"

    def _installed(self):
        try:
            ok, d = self.host_.sysinfo("apps")
        except Exception:
            ok, d = False, "unavailable"
        if ok and isinstance(d, dict) and isinstance(d.get("installed"), list):
            return d["installed"], ""
        return [], f"apps: the OS did not give this ({d if isinstance(d, str) else 'unavailable'})"

    def _compare(self):
        installed, bad = self._installed()
        rows = update_rows(installed, parse_available(self.buf))
        self.lines = ["Comparison (versions: dotted numbers; a suffix such as -rc1 means pre-release, older than the plain release)", ""]
        if bad:
            self.lines += [bad, "Nothing was compared. The OS asks for your password before an app may read the installed list."]
        elif not rows:
            self.lines.append("(no installed apps)")
        else:
            self.lines += ["  " + l for l in table([r[:4] for r in rows], ["app", "installed", "available", "result"])]
            cmds = [r[4] for r in rows if r[4]]
            if cmds:
                self.lines += ["", "To update (the file must be that version's .kapp; `kos update` asks for your password):"]
                self.lines += ["  " + c for c in cmds]
        self.lines += ["", "This app cannot download or install anything, and KOS has no OS updater."]
        self.mode, self.top, self.help = "result", 0, "e edit list   up/down scroll   Esc quit"

    def render(self, w, h):
        if self.mode == "input":
            head = ["Software Updates", "  Paste the versions you have available, one `name version` per line, then press Ctrl-D.",
                    "  Lines that are not `name version` are ignored.", ""]
            body = (self.buf[-2000:] + "_").split("\n")
            return (head + body)[-h:]
        self.top = max(0, min(self.top, max(0, len(self.lines) - h)))
        return self.lines[self.top:self.top + h]

    def key(self, k):
        if self.mode == "input":
            if k == "ctrl-d":
                self._compare()
            elif k == "enter":
                self.buf = (self.buf + "\n")[:MAX_UPDATE_TEXT]
            elif k == "backspace":
                self.buf = self.buf[:-1]
            elif len(k) == 1 and k.isprintable():
                self.buf = (self.buf + k)[:MAX_UPDATE_TEXT]
            return None
        if k == "e": self.mode, self.help = "input", "paste or type lines   Ctrl-D compare   Esc quit"
        elif k == "up": self.top -= 1
        elif k == "down": self.top += 1
        elif k == "pageup": self.top -= 15
        elif k == "pagedown": self.top += 15
        elif k == "home": self.top = 0
        elif k == "end": self.top = 10 ** 6
        elif k == "q": return ("quit",)


def _make_updates(host, e):
    return Updates(host)


# ---- Firewall Management ---------------------------------------------------------------------------------
class FirewallScreen(Screen):
    """Shows the rules and recent decisions; a / d add or remove an app: or os: rule. Every change is made by the OS
    after ITS password prompt, which shows the exact rule. A front end over `kos firewall`; not a packet filter."""

    def __init__(self, host):
        self.host_, self.title = host, "Firewall Management"
        self.rules, self.log, self.problems, self.note, self.top = [], [], [], "", 0
        self.help = "a add rule   d remove rule   r refresh   up/down scroll   Esc quit"

    def on_enter(self):
        self.load()

    def _ask(self, *a):
        try:
            ok, d = self.host_.firewall(*a)
        except Exception:
            ok, d = False, "unavailable"
        return ok and isinstance(d, dict), d

    def load(self):
        self.problems = []
        ok, d = self._ask("list")
        rs = d.get("rules") if ok else None
        self.rules = [r for r in rs if isinstance(r, dict)][:200] if isinstance(rs, list) else []
        if not ok:
            self.problems.append(f"rules: the OS did not give this ({d if isinstance(d, str) else 'unavailable'})")
        ok, d = self._ask("log")
        lg = d.get("log") if ok else None
        self.log = [r for r in lg if isinstance(r, dict)][-30:] if isinstance(lg, list) else []
        if not ok:
            self.problems.append(f"log: the OS did not give this ({d if isinstance(d, str) else 'unavailable'})")

    def render(self, w, h):
        out = ["A front end over `kos firewall`. It is NOT a packet filter: it governs connections KOS apps and the OS make.",
               "Every connection is blocked unless a rule allows it. Changes need your password, asked by the OS.", ""]
        if self.note:
            out += ["  >> " + self.note, ""]
        out += ["Rules"]
        rows = [[i, r.get("who", "?"), "WILDCARD" if r.get("host") == "*" else r.get("host", "?"), r.get("port", "?"),
                 r.get("proto", "?")] for i, r in enumerate(self.rules, 1)]
        out += ["  " + l for l in table(rows, ["#", "who", "host", "port", "proto"])] if rows else ["  (no rules)"]
        out += ["", "Recent decisions (newest last)"]
        rows = [[r.get("time", "?"), r.get("outcome", "?"), r.get("who", "?"),
                 f"{r.get('host', '?')}:{r.get('port', '?')}", r.get("proto", "?")] for r in self.log[-15:]]
        out += ["  " + l for l in table(rows, ["time", "result", "who", "host:port", "proto"])] if rows else ["  (none)"]
        if self.problems:
            out += [""] + self.problems
        out += ["", "Wildcard rules and rules for other parties can only be made or removed with `kos firewall`."]
        self.top = max(0, min(self.top, max(0, len(out) - h)))
        return out[self.top:self.top + h]

    def _done(self, res):
        ok, d = res
        self.note = d.get("detail", "done") if ok and isinstance(d, dict) else f"not changed ({d if isinstance(d, str) else 'refused'})"
        self.load()

    def _add_flow(self):
        st = {}

        def who(v):
            st["who"] = v.strip(); return ("push", Prompt("Add rule", "Host (an exact name or IP; no wildcard):", on_done=host))

        def host(v):
            st["host"] = v.strip().lower(); return ("push", Prompt("Add rule", "Port (1-65535):", on_done=port))

        def port(v):
            st["port"] = int(v) if v.strip().isascii() and v.strip().isdigit() else 0
            return ("push", Prompt("Add rule", "Protocol (https or loopback):", on_done=proto))

        def proto(v):
            from .. import firewall as F
            try:
                if st["host"] == F.WILDCARD:
                    raise F.FirewallError("no wildcard")
                r = F.check_rule(st["who"], st["host"], st["port"], v.strip().lower())
            except F.FirewallError as ex:
                self.note = f"not sent: {ex}"; return None
            self.note = "waiting for the OS password prompt..."
            self._done(self.host_.firewall("allow", r["who"], r["host"], r["port"], r["proto"]))
            return None
        return ("push", Prompt("Add rule", "Who (app:NAME, os:assistant or os:aios):", on_done=who))

    def _remove_flow(self):
        def pick(v):
            v = v.strip()
            if not (v.isascii() and v.isdigit() and 1 <= int(v) <= len(self.rules)):
                self.note = "not sent: no such rule number"; return None
            r = self.rules[int(v) - 1]
            if r.get("host") == "*":
                self.note = "not sent: a wildcard rule can only be removed with `kos firewall remove`"; return None
            self._done(self.host_.firewall("remove", r.get("who", ""), r.get("host", ""), r.get("port", 0)))
            return None
        return ("push", Prompt("Remove rule", "Rule number to remove (the OS asks your password and shows the rule):", on_done=pick))

    def key(self, k):
        if k == "r": self.note = ""; self.load()
        elif k == "a": return self._add_flow()
        elif k == "d": return self._remove_flow()
        elif k == "up": self.top -= 1
        elif k == "down": self.top += 1
        elif k == "pageup": self.top -= 15
        elif k == "pagedown": self.top += 15
        elif k == "home": self.top = 0
        elif k == "end": self.top = 10 ** 6
        elif k == "q": return ("quit",)


def _make_firewall(host, e):
    return FirewallScreen(host)


ENTRIES: list = [
    app("Device Settings", _make_settings, "partial",
        "A read-only summary: assistant on/off, permitted apps, shared-folder grants, extensions, firewall rule count. "
        "Each line names the `kos` command that changes it. This app changes nothing; the OS reads the facts after your password.",
        perms=("sysinfo",)),
    app("Battery and Power", _make_battery, "partial",
        "Shows battery level and charging state if there is one; 'no battery found' is normal on servers and VMs. "
        "Read-only: it cannot change power settings. The OS reads the data after your password.",
        perms=("sysinfo",)),
    app("Storage and Disk Management", _make_storage, "partial",
        "Shows free and total space and each app's own data as a bar chart. Read-only: it cannot delete, partition "
        "or format. The OS reads the sizes after your password. `kos optimize` reclaims space.",
        name="storage-and-disk", perms=("sysinfo",)),
    app("Network and Wireless", _make_network, "partial",
        "Read-only network POLICY: which apps may ask to fetch, the firewall rules, the assistant's endpoint and whether "
        "the firewall allows it, allowed/blocked counts. Apps have no network of their own; no Wi-Fi or Bluetooth management. Read after your password.",
        perms=("sysinfo",)),
    none("Printer Management",
         "Not an app: apps cannot reach printers or drivers, and KOS has no printing support. No `kos` "
         "command or other app covers it; nothing in KOS talks to a printer."),
    app("Process and Resource Monitor", _make_monitor, "partial",
        "Shows KOS apps opened with `kos open`, memory and load; refresh with r. It can NOT see or manage other "
        "processes. The OS reads the facts after your password. `kos ps` lists the same apps.",
        name="process-monitor", perms=("sysinfo",)),
    app("System Information and Diagnostics", _make_sysinfo, "partial",
        "Shows kernel, Python and KOS versions, memory, load and sandbox checks with OK / NOT OK verdicts, like "
        "`kos doctor`. Read-only; the OS reads the facts after your password. No host name or user names.",
        name="system-information", perms=("sysinfo",)),
    app("Software Updates", _make_updates, "partial",
        "Reads installed versions, you paste `name version` lines, it shows up to date, update available, would-be downgrade "
        "or unknown, and the `kos update FILE` command. It cannot download or install; `kos update` needs your password.",
        name="software-updates", perms=("sysinfo",)),
    app("Firewall Management", _make_firewall, "partial",
        "Shows firewall rules and recent allowed/blocked decisions; adds or removes app: and os: rules. Each change goes "
        "through the OS password prompt with the exact rule. A front end over `kos firewall`, NOT a packet filter.",
        name="firewall-management", perms=("firewall",)),
    none("Credential Manager",
         "Not built: nothing in KOS is encrypted yet, and storing secrets safely needs a vetted crypto "
         "library, which is an open owner decision (README). No `kos` command covers it."),
    none("Device Pairing",
         "Not an app: apps cannot reach Bluetooth or other devices, and KOS has no pairing support. "
         "Nothing covers it; `kos usb` only writes boot images to USB sticks."),
    none("Window and Desktop Management",
         "Not an app: there is no window manager. `kos boot desktop` runs the taskbar and App Library, "
         "which are themselves apps that ask the OS to open, close or focus apps."),
]
