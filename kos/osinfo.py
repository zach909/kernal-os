"""Facts about the running system, read straight from the kernel.

One function per core operating-system service, each returning plain,
bounded, JSON-able data for the system apps (``examples/system/*``):

    processes()   process table + scheduling (state, nice, CPU time, context switches)
    memory()      RAM, buffers/cache, swap, paging counters, pressure
    mounts()      file systems, capacity, flags;   stat_path() permissions of one path
    devices()     input devices, disks, drivers, modules, display
    network()     interfaces, protocol counters, connections, unix sockets (IPC)
    isolation()   how each KOS app is confined; sysctl hardening; auth throttle
    health()      temperatures, power, link/disk errors, faulty-app log lines
    resources()   CPU/memory/disk accounting, per-KOS-app usage

Everything here is **read-only** and tolerant: a missing file (a container
without ``/sys/block``, a kernel without PSI) gives an empty section, never an
exception. Roots are parameters so the parsers are tested against fixtures.
Actions that *change* things (signal, renice, file changes, the internet
check) live in ``system.py`` behind the password.
"""

from __future__ import annotations

import fcntl
import grp
import os
import pwd
import socket
import stat as statmod
import struct
import time
from pathlib import Path
from typing import Optional

from .paths import Paths
from .protocol import clean_text

MAX_ROWS = 200
CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096


def _read(path: str | Path, limit: int = 1 << 20) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def _int(s: str, default: int = 0) -> int:
    try:
        return int(s)
    except (TypeError, ValueError):
        return default


def _user(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _group(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def _kv(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        k, _, v = line.partition(":")
        if v:
            out[k.strip()] = v.strip()
    return out


# --------------------------------------------------------------------- processes

def _stat_fields(raw: str) -> Optional[list[str]]:
    """/proc/PID/stat, robust against spaces and parentheses in the name."""
    if ")" not in raw:
        return None
    head, _, tail = raw.rpartition(")")
    name = head.partition("(")[2]
    return [name] + tail.split()


def processes(proc: str = "/proc") -> dict:
    rows = []
    for entry in os.listdir(proc) if os.path.isdir(proc) else []:
        if not entry.isdigit():
            continue
        f = _stat_fields(_read(f"{proc}/{entry}/stat"))
        if not f or len(f) < 22:
            continue
        # f[0]=comm f[1]=state f[2]=ppid ... f[12]=utime f[13]=stime f[16]=priority f[17]=nice f[18]=threads
        status = _kv(_read(f"{proc}/{entry}/status"))
        uid = _int(status.get("Uid", "0").split()[0] if status.get("Uid") else "0")
        rss_kb = _int(status.get("VmRSS", "0 kB").split()[0])
        cmd = _read(f"{proc}/{entry}/cmdline", 4096).replace("\x00", " ").strip()
        rows.append({
            "pid": int(entry), "name": clean_text(f[0], 40), "state": f[1], "ppid": _int(f[2]),
            "user": _user(uid), "uid": uid, "cpu_ticks": _int(f[12]) + _int(f[13]),
            "priority": _int(f[16]), "nice": _int(f[17]), "threads": _int(f[18]),
            "start_ticks": _int(f[20]), "rss_kb": rss_kb,
            "vol_switches": _int(status.get("voluntary_ctxt_switches", "0")),
            "invol_switches": _int(status.get("nonvoluntary_ctxt_switches", "0")),
            "cmd": clean_text(cmd, 120),
        })
    rows.sort(key=lambda r: (-r["rss_kb"], r["pid"]))
    load = _read(f"{proc}/loadavg").split()
    states = {}
    for r in rows:
        states[r["state"]] = states.get(r["state"], 0) + 1
    return {"processes": rows[:MAX_ROWS], "total": len(rows), "states": states,
            "load": [float(x) for x in load[:3]] if len(load) >= 3 else [],
            "running_now": load[3] if len(load) > 3 else "", "clk_tck": CLK_TCK,
            "cpus": os.cpu_count() or 1, "me": os.getpid(), "uid": os.getuid(),
            "uptime": float((_read(f"{proc}/uptime").split() or ["0"])[0])}


# ------------------------------------------------------------------------ memory

def memory(proc: str = "/proc") -> dict:
    info = {k: _int(v.split()[0]) for k, v in _kv(_read(f"{proc}/meminfo")).items()}
    vm = {}
    for line in _read(f"{proc}/vmstat").splitlines():
        k, _, v = line.partition(" ")
        if k in ("pswpin", "pswpout", "pgfault", "pgmajfault", "oom_kill", "pgscan_kswapd",
                 "pgsteal_kswapd"):
            vm[k] = _int(v)
    swaps = []
    for line in _read(f"{proc}/swaps").splitlines()[1:]:
        p = line.split()
        if len(p) >= 5:
            swaps.append({"file": p[0], "type": p[1], "size_kb": _int(p[2]), "used_kb": _int(p[3])})
    pressure = {}
    for kind in ("memory", "cpu", "io"):
        line = (_read(f"{proc}/pressure/{kind}").splitlines() or [""])[0]
        if line.startswith("some"):
            pressure[kind] = {k: v for k, v in (kv.split("=") for kv in line.split()[1:] if "=" in kv)}
    return {"kb": {k: info.get(k, 0) for k in (
        "MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "SwapTotal", "SwapFree",
        "Dirty", "Writeback", "Slab", "Shmem", "AnonPages", "Mapped", "SwapCached",
        "CommitLimit", "Committed_AS", "VmallocUsed", "HugePages_Total")},
        "vm": vm, "swaps": swaps, "pressure": pressure,
        "swappiness": _int(_read(f"{proc}/sys/vm/swappiness").strip(), -1),
        "overcommit": _int(_read(f"{proc}/sys/vm/overcommit_memory").strip(), -1),
        "page_size": PAGE}


# ------------------------------------------------------------------- file systems

_PSEUDO = {"proc", "sysfs", "devpts", "cgroup", "cgroup2", "mqueue", "debugfs", "tracefs",
           "securityfs", "pstore", "bpf", "configfs", "fusectl", "autofs", "binfmt_misc",
           "hugetlbfs", "devtmpfs", "overlay"}


def mounts(proc: str = "/proc") -> dict:
    rows = []
    for line in _read(f"{proc}/mounts").splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        dev, mp, fstype, opts = p[0], p[1].replace("\\040", " "), p[2], p[3].split(",")
        try:
            sv = os.statvfs(mp)
        except OSError:
            continue
        total = sv.f_blocks * sv.f_frsize
        if total == 0 and fstype in _PSEUDO:
            continue
        rows.append({"device": clean_text(dev, 60), "mount": clean_text(mp, 80), "type": fstype,
                     "total": total, "free": sv.f_bavail * sv.f_frsize,
                     "inodes": sv.f_files, "inodes_free": sv.f_ffree,
                     "ro": "ro" in opts, "nosuid": "nosuid" in opts, "noexec": "noexec" in opts,
                     "nodev": "nodev" in opts})
    return {"mounts": rows[:MAX_ROWS]}


def _mode_string(mode: int) -> str:
    kind = ("d" if statmod.S_ISDIR(mode) else "l" if statmod.S_ISLNK(mode) else
            "c" if statmod.S_ISCHR(mode) else "b" if statmod.S_ISBLK(mode) else
            "p" if statmod.S_ISFIFO(mode) else "s" if statmod.S_ISSOCK(mode) else "-")
    bits = "".join(("r" if mode & r else "-") + ("w" if mode & w else "-") + ("x" if mode & x else "-")
                   for r, w, x in ((0o400, 0o200, 0o100), (0o040, 0o020, 0o010), (0o004, 0o002, 0o001)))
    chars = list(bits)
    if mode & statmod.S_ISUID:
        chars[2] = "s" if chars[2] == "x" else "S"
    if mode & statmod.S_ISGID:
        chars[5] = "s" if chars[5] == "x" else "S"
    if mode & statmod.S_ISVTX:
        chars[8] = "t" if chars[8] == "x" else "T"
    return kind + "".join(chars)


def stat_path(path: str) -> dict:
    """Permissions of one path, and what *this* user may do with it."""
    st = os.lstat(path)
    entries = None
    if statmod.S_ISDIR(st.st_mode):
        try:
            entries = len(os.listdir(path))
        except OSError:
            entries = None
    return {"path": clean_text(path, 300), "mode": _mode_string(st.st_mode),
            "octal": format(statmod.S_IMODE(st.st_mode), "04o"), "uid": st.st_uid,
            "owner": _user(st.st_uid), "group": _group(st.st_gid), "size": st.st_size,
            "mtime": st.st_mtime, "links": st.st_nlink, "entries": entries,
            "setuid": bool(st.st_mode & statmod.S_ISUID), "setgid": bool(st.st_mode & statmod.S_ISGID),
            "can_read": os.access(path, os.R_OK), "can_write": os.access(path, os.W_OK),
            "can_exec": os.access(path, os.X_OK), "symlink": statmod.S_ISLNK(st.st_mode)}


# --------------------------------------------------------------------- I/O devices

def devices(proc: str = "/proc", sys: str = "/sys") -> dict:
    from .devices import _read_proc_devices
    inputs = [{"name": clean_text(d.get("name", "?"), 60), "handlers": d.get("handlers", [])}
              for d in _read_proc_devices(_read(f"{proc}/bus/input/devices"))]
    disks = []
    try:
        names = sorted(os.listdir(f"{sys}/block"))
    except OSError:
        names = []
    for name in names:
        if name.startswith(("loop", "ram", "zram")):
            continue
        base = f"{sys}/block/{name}"
        st = _read(f"{base}/stat").split()
        disks.append({
            "name": name, "size": _int(_read(f"{base}/size").strip()) * 512,
            "rotational": _read(f"{base}/queue/rotational").strip() == "1",
            "removable": _read(f"{base}/removable").strip() == "1",
            "model": clean_text(_read(f"{base}/device/model").strip(), 40),
            "scheduler": clean_text(_read(f"{base}/queue/scheduler").strip(), 60),
            "read_ahead_kb": _int(_read(f"{base}/queue/read_ahead_kb").strip()),
            "reads": _int(st[0]) if len(st) > 0 else 0, "read_bytes": _int(st[2]) * 512 if len(st) > 2 else 0,
            "writes": _int(st[4]) if len(st) > 4 else 0, "write_bytes": _int(st[6]) * 512 if len(st) > 6 else 0,
            "in_flight": _int(st[8]) if len(st) > 8 else 0,
        })
    drivers = {"char": [], "block": []}
    section = None
    for line in _read(f"{proc}/devices").splitlines():
        if line.startswith("Character"):
            section = "char"
        elif line.startswith("Block"):
            section = "block"
        elif section and line.strip():
            p = line.split(None, 1)
            if len(p) == 2:
                drivers[section].append(f"{p[0]} {clean_text(p[1], 30)}")
    modules = [l.split()[0] for l in _read(f"{proc}/modules").splitlines() if l.strip()][:60]
    fb = {}
    if os.path.isdir(f"{sys}/class/graphics/fb0"):
        fb = {"size": _read(f"{sys}/class/graphics/fb0/virtual_size").strip(),
              "bpp": _read(f"{sys}/class/graphics/fb0/bits_per_pixel").strip(),
              "name": clean_text(_read(f"{sys}/class/graphics/fb0/name").strip(), 30)}
    mem = {k: _int(v.split()[0]) for k, v in _kv(_read(f"{proc}/meminfo")).items()
           if k in ("Buffers", "Cached", "Dirty", "Writeback")}
    return {"input": inputs[:MAX_ROWS], "disks": disks[:MAX_ROWS], "drivers": drivers,
            "modules": modules, "framebuffer": fb, "buffers_kb": mem,
            "tty": os.path.exists("/dev/tty")}


# ------------------------------------------------------------ networking and IPC

_TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
               "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
               "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}


def _addr(hexaddr: str) -> str:
    ip, _, port = hexaddr.partition(":")
    try:
        if len(ip) == 8:
            ip_s = socket.inet_ntoa(struct.pack("<I", int(ip, 16)))
        else:
            raw = bytes.fromhex(ip)
            ip_s = socket.inet_ntop(socket.AF_INET6, b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
        return f"{ip_s}:{int(port, 16)}"
    except (ValueError, OSError):
        return hexaddr


def _iface_ipv4(name: str) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            packed = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", name[:15].encode()))
            return socket.inet_ntoa(packed[20:24])
        finally:
            s.close()
    except OSError:
        return ""


def network(proc: str = "/proc", sys: str = "/sys") -> dict:
    ifaces = []
    for line in _read(f"{proc}/net/dev").splitlines()[2:]:
        name, _, rest = line.partition(":")
        c = rest.split()
        if len(c) < 16:
            continue
        name = name.strip()
        base = f"{sys}/class/net/{name}"
        ifaces.append({
            "name": name, "state": _read(f"{base}/operstate").strip() or "unknown",
            "mac": _read(f"{base}/address").strip(), "mtu": _int(_read(f"{base}/mtu").strip()),
            "ipv4": _iface_ipv4(name),
            "rx_bytes": _int(c[0]), "rx_packets": _int(c[1]), "rx_errors": _int(c[2]), "rx_drop": _int(c[3]),
            "tx_bytes": _int(c[8]), "tx_packets": _int(c[9]), "tx_errors": _int(c[10]), "tx_drop": _int(c[11]),
        })
    gateway = ""
    for line in _read(f"{proc}/net/route").splitlines()[1:]:
        p = line.split()
        if len(p) > 2 and p[1] == "00000000":
            gateway = f"{socket.inet_ntoa(struct.pack('<I', int(p[2], 16)))} via {p[0]}"
            break
    dns = [l.split()[1] for l in _read("/etc/resolv.conf").splitlines()
           if l.startswith("nameserver") and len(l.split()) > 1][:3]
    snmp, lines = {}, _read(f"{proc}/net/snmp").splitlines()
    for hdr, val in zip(lines[0::2], lines[1::2]):
        proto, _, names = hdr.partition(":")
        snmp[proto] = dict(zip(names.split(), (_int(v) for v in val.partition(":")[2].split())))
    wanted = {"Ip": ("InReceives", "OutRequests", "InDiscards", "ForwDatagrams"),
              "Tcp": ("ActiveOpens", "PassiveOpens", "CurrEstab", "RetransSegs", "InErrs"),
              "Udp": ("InDatagrams", "OutDatagrams", "InErrors")}
    protocols = {p: {k: snmp.get(p, {}).get(k, 0) for k in keys} for p, keys in wanted.items()}
    conns = []
    for kind in ("tcp", "tcp6", "udp", "udp6"):
        for line in _read(f"{proc}/net/{kind}").splitlines()[1:]:
            p = line.split()
            if len(p) < 10:
                continue
            state = _TCP_STATES.get(p[3], "UNCONN" if kind.startswith("udp") and p[3] == "07" else p[3])
            conns.append({"proto": kind, "local": _addr(p[1]), "remote": _addr(p[2]),
                          "state": state, "uid": _int(p[7]), "inode": _int(p[9])})
    unix = []
    for line in _read(f"{proc}/net/unix").splitlines()[1:]:
        p = line.split(None, 7)
        if len(p) >= 7:
            unix.append({"type": {"0001": "STREAM", "0002": "DGRAM", "0005": "SEQPACKET"}.get(p[4], p[4]),
                         "state": {"01": "unconnected", "03": "connected"}.get(p[5], p[5]),
                         "path": clean_text(p[7].strip() if len(p) > 7 else "", 120)})
    return {"interfaces": ifaces, "gateway": gateway, "dns": dns, "protocols": protocols,
            "connections": conns[:MAX_ROWS], "unix": unix[:MAX_ROWS],
            "hostname": socket.gethostname()}


def net_check(host: str = "1.1.1.1", port: int = 443, timeout: float = 3.0) -> tuple[bool, str]:
    """Open one TCP connection to prove the internet is reachable. This touches
    the outside world, so the bridge only calls it after the password."""
    t0 = time.monotonic()
    try:
        socket.create_connection((host, port), timeout).close()
    except OSError as e:
        return False, f"no route to the internet ({e.strerror or e})"
    return True, f"internet reachable ({(time.monotonic() - t0) * 1000:.0f} ms to {host})"


# ----------------------------------------------------- protection and isolation

_SYSCTLS = ("kernel/yama/ptrace_scope", "kernel/kptr_restrict", "kernel/dmesg_restrict",
            "kernel/unprivileged_bpf_disabled", "kernel/kexec_load_disabled", "kernel/sysrq",
            "fs/protected_symlinks", "fs/protected_hardlinks", "fs/suid_dumpable",
            "vm/unprivileged_userfaultfd")
_NS = ("user", "net", "ipc", "uts", "mnt", "pid")


def _ns(proc: str, pid: str) -> dict:
    out = {}
    for n in _NS:
        try:
            out[n] = os.readlink(f"{proc}/{pid}/ns/{n}")
        except OSError:
            out[n] = ""
    return out


def kos_instances(paths: Paths):
    from .registry import Registry
    try:
        return [i for i in Registry(paths).list() if i.status == "running" and i.app_pid]
    except OSError:
        return []


def isolation(paths: Paths, proc: str = "/proc") -> dict:
    mine = _ns(proc, "self")
    apps = []
    for inst in kos_instances(paths):
        pid = str(inst.app_pid)
        st = _kv(_read(f"{proc}/{pid}/status"))
        if not st:
            continue
        ns = _ns(proc, pid)
        limits = {}
        for line in _read(f"{proc}/{pid}/limits").splitlines()[1:]:
            parts = line.split()
            if line.startswith(("Max core", "Max open files", "Max address", "Max processes")):
                limits[" ".join(parts[:3])] = parts[-3] if parts[-1] in ("files", "bytes", "processes") else parts[-2]
        apps.append({
            "id": inst.id, "name": inst.name, "pid": inst.app_pid,
            "uid": _int((st.get("Uid") or "0").split()[0]),
            "no_new_privs": st.get("NoNewPrivs", "?") == "1",
            "seccomp": st.get("Seccomp", "?"), "cap_effective": st.get("CapEff", "?"),
            "own_memory_kb": _int((st.get("VmRSS") or "0").split()[0]),
            "separate_namespaces": sorted(n for n in _NS if ns.get(n) and ns[n] != mine.get(n)),
            "shared_namespaces": sorted(n for n in _NS if not ns.get(n) or ns[n] == mine.get(n)),
            "limits": limits})
    hard = {k: clean_text(_read(f"{proc}/sys/{k}").strip(), 20) for k in _SYSCTLS}
    from .auth import Throttle
    from .admin import AdminKeyboard
    th = Throttle(paths)
    failures, last = th._read()
    from .permit import PermitStore
    return {"apps": apps, "hardening": hard,
            "auth": {"failed_attempts": failures, "wait_s": round(th.delay(), 1),
                     "admin_keyboard": clean_text(AdminKeyboard(paths).status(), 120),
                     "permitted_apps": [p.name for p in PermitStore(paths).list()],
                     "uid": os.getuid(), "root": os.getuid() == 0}}


# ---------------------------------------------------- errors and hardware health

FAULT_WORDS = ("protocol violation", "Traceback", "killing app", "Error", "denied", "tampered", "SECURITY")


def health(paths: Paths, proc: str = "/proc", sys: str = "/sys") -> dict:
    temps = []
    for base in sorted(Path(f"{sys}/class/hwmon").glob("hwmon*")) if os.path.isdir(f"{sys}/class/hwmon") else []:
        chip = _read(base / "name").strip()
        for f in sorted(base.glob("temp*_input")):
            label = _read(str(f).replace("_input", "_label")).strip() or f.name
            temps.append({"chip": chip, "label": clean_text(label, 24), "c": _int(_read(f).strip()) / 1000})
    for z in sorted(Path(f"{sys}/class/thermal").glob("thermal_zone*")) if os.path.isdir(f"{sys}/class/thermal") else []:
        temps.append({"chip": "thermal", "label": _read(z / "type").strip(), "c": _int(_read(z / "temp").strip()) / 1000})
    power = []
    for p in sorted(Path(f"{sys}/class/power_supply").glob("*")) if os.path.isdir(f"{sys}/class/power_supply") else []:
        power.append({"name": p.name, "type": _read(p / "type").strip(),
                      "status": _read(p / "status").strip(), "capacity": _int(_read(p / "capacity").strip(), -1)})
    disk_errors = []
    for p in Path(f"{sys}/block").glob("*/device/ioerr_cnt") if os.path.isdir(f"{sys}/block") else []:
        disk_errors.append({"disk": p.parts[-3], "io_errors": _int(_read(p).strip(), 0)})
    links = [{"name": i["name"], "state": i["state"], "errors": i["rx_errors"] + i["tx_errors"],
              "dropped": i["rx_drop"] + i["tx_drop"]} for i in network(proc, sys)["interfaces"]]
    ro = [m["mount"] for m in mounts(proc)["mounts"] if m["ro"] and m["type"] not in _PSEUDO][:10]
    pressure = memory(proc)["pressure"]
    faults = []
    logs = paths.logs
    for f in sorted(logs.glob("*.log"), key=lambda p: p.stat().st_mtime)[-30:] if logs.exists() else []:
        if f.name == "audit.log":
            continue
        for line in _read(f, 1 << 16).splitlines()[-200:]:
            if any(w in line for w in FAULT_WORDS):
                faults.append({"source": f.name[:40], "line": clean_text(line, 160), "t": f.stat().st_mtime})
    from .registry import Registry
    exited = [i.id for i in Registry(paths).list() if i.status == "exited"]
    from .auth import AuditLog
    bad = [e for e in AuditLog(paths).entries()[-300:] if e["outcome"] in ("bad-password", "denied", "blocked-by-scan",
                                                                           "quarantined-by-scan")]
    return {"temps": temps[:30], "power": power, "disk_errors": disk_errors, "links": links,
            "read_only_mounts": ro, "pressure": pressure, "faults": faults[-40:], "exited_apps": exited,
            "security_events": [{"t": e["t"], "action": e["action"], "target": clean_text(e["target"], 60),
                                 "outcome": e["outcome"]} for e in bad[-20:]],
            "load": [float(x) for x in _read(f"{proc}/loadavg").split()[:3]] or []}


# --------------------------------------------------------------------- accounting

def resources(paths: Paths, proc: str = "/proc") -> dict:
    cpu = [_int(x) for x in (_read(f"{proc}/stat").splitlines() or ["cpu"])[0].split()[1:]]
    mem = memory(proc)["kb"]
    apps = []
    for inst in kos_instances(paths):
        f = _stat_fields(_read(f"{proc}/{inst.app_pid}/stat"))
        st = _kv(_read(f"{proc}/{inst.app_pid}/status"))
        if not f or len(f) < 22:
            continue
        io = _kv(_read(f"{proc}/{inst.app_pid}/io"))
        apps.append({"id": inst.id, "name": inst.name, "pid": inst.app_pid,
                     "cpu_ticks": _int(f[12]) + _int(f[13]), "nice": _int(f[17]),
                     "rss_kb": _int((st.get("VmRSS") or "0").split()[0]),
                     "threads": _int(f[18]), "read_bytes": _int(io.get("read_bytes", "0")),
                     "write_bytes": _int(io.get("write_bytes", "0")),
                     "age_s": max(0, time.time() - inst.started)})
    try:
        sv = os.statvfs(paths.state if paths.state.exists() else "/")
        disk = {"total": sv.f_blocks * sv.f_frsize, "free": sv.f_bavail * sv.f_frsize}
    except OSError:
        disk = {"total": 0, "free": 0}
    state_bytes = 0
    for root, _, files in os.walk(paths.state) if paths.state.exists() else []:
        for n in files:
            try:
                state_bytes += os.lstat(os.path.join(root, n)).st_size
            except OSError:
                pass
    model = next((clean_text(l.partition(":")[2].strip(), 60) for l in _read(f"{proc}/cpuinfo").splitlines()
                  if l.startswith(("model name", "Model", "Hardware"))), "")
    return {"cpu_model": model, "cpu_ticks": cpu, "cpus": os.cpu_count() or 1, "clk_tck": CLK_TCK, "mem_kb": mem,
            "load": [float(x) for x in _read(f"{proc}/loadavg").split()[:3]] or [], "disk": disk,
            "kos_state_bytes": state_bytes, "apps": apps,
            "uptime": float((_read(f"{proc}/uptime").split() or ["0"])[0])}


KINDS = {"processes": lambda paths, arg: processes(), "memory": lambda paths, arg: memory(),
         "mounts": lambda paths, arg: mounts(), "stat": lambda paths, arg: stat_path(arg or "/"),
         "devices": lambda paths, arg: devices(), "network": lambda paths, arg: network(),
         "isolation": lambda paths, arg: isolation(paths), "health": lambda paths, arg: health(paths),
         "resources": lambda paths, arg: resources(paths)}
