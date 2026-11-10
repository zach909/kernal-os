"""pack_os: OS-management titles. Four are real, read-only apps that ask the OS for facts about this
computer with the narrow `sysinfo` permission (the OS reads them after the owner's password, audited; the app
never opens /proc, /sys or a device). The other eight stay `none`: apps cannot change the system."""

from __future__ import annotations

from .packkit import app, none
from .ui import bar, table, Screen


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


ENTRIES: list = [
    none("Device Settings",
         "Not an app: sandboxed apps cannot read or change device or system settings, and the OS has no settings "
         "layer yet. Nothing covers it today; `kos passwd` changes only your password."),
    app("Battery and Power", _make_battery, "partial",
        "Shows battery level and charging state if there is one; 'no battery found' is normal on servers and VMs. "
        "Read-only: it cannot change power settings. The OS reads the data after your password.",
        perms=("sysinfo",)),
    app("Storage and Disk Management", _make_storage, "partial",
        "Shows free and total space and each app's own data as a bar chart. Read-only: it cannot delete, partition "
        "or format. The OS reads the sizes after your password. `kos optimize` reclaims space.",
        name="storage-and-disk", perms=("sysinfo",)),
    none("Network and Wireless",
         "Not an app: apps run in an empty network namespace and cannot configure networks. KOS has no "
         "network or Wi-Fi manager; `kos firewall` (rules, not an app) decides every connection. Nothing covers it."),
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
    none("Software Updates",
         "Not an app: apps cannot replace themselves or the OS. `kos update` updates installed apps only "
         "(newer version, scanned first, downgrades refused). There is no OS update mechanism."),
    none("Firewall Management",
         "Not an app: the firewall is `kos firewall` (status, allow, remove, log; the password is needed to change a "
         "rule). Every connection is blocked until a rule allows it. An app cannot change rules."),
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
