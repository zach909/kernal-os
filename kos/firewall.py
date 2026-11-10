"""The firewall: every connection KOS makes is denied until a rule recognises it (README Rule 3).

There is ONE decision point, :func:`decide`. Every connection - an app's, the OS's own - asks it
first, and nothing is connected when it says no. There is no switch for the default: this module
has no "allow all" mode, no "disable", no "log only". The only way a connection happens is that a
rule *the owner typed* matches it exactly.

A rule names one party, one host, one port and one protocol::

    {"who": "app:web", "host": "example.com", "port": 443, "proto": "https"}

* ``who``   ``app:NAME`` (a KOS app; brokered by ``netfetch.py``) or one of OS_PARTIES, the OS's own
            connections: ``os:assistant`` (the model endpoint), ``os:aios`` (the NeuroClaw engine).
* ``host``  an exact DNS name or IP literal. Matching is exact (case-insensitive); there is no suffix,
            prefix or pattern matching. The single character ``*`` means every host; it exists only
            because the owner typed it, covers one ``who`` and one port, only with ``https``, and is
            shown as WILDCARD everywhere.
* ``proto`` ``https`` (verified TLS: default SSL context, the certificate AND the host name are
            checked; no off switch anywhere) or ``loopback`` (http or https, but ONLY to this
            computer: 127.0.0.0/8, ``::1`` or the literal ``localhost``). Plain http to anything else
            can never be a rule, so it can never happen.

Every decision, allowed or blocked, is written to the audit log as ``firewall.connect`` with the
target ``WHO HOST:PORT PROTO`` - never a URL path, query, header, body or key. If that record cannot
be written, the answer is "blocked": a connection that cannot be logged does not happen.

The rules live in ``<state>/firewall.json`` (mode 0600, written atomically, at most 200 rules).
A missing, damaged or odd file means NO rules: deny everything (fail closed).

What this is NOT: a packet filter. It governs connections made by KOS apps (through ``netfetch``) and
by the OS's own code. It does not see other processes on the machine. Unix sockets (the app channel,
the broker) and the kernel-cell vsock are not IP networks and are not governed here.

Standard library only.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Optional

from .paths import Paths, atomic_write

PROTOS = ("https", "loopback")
OS_PARTIES = ("os:assistant", "os:aios")
MAX_RULES = 200
WILDCARD = "*"
_APP_RE = re.compile(r"app:[a-z][a-z0-9-]{0,31}")
_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
# a DNS name has at least two labels and an alphabetic last label: so 0x7f.1, 127.1 and 2130706433 are
# never names (they are not valid IP literals either, so they are refused outright)
_DNS_RE = re.compile(rf"(?=.{{1,253}}\Z)({_LABEL}\.)+[a-z]{{2,63}}")


class FirewallError(Exception):
    """A rule that cannot exist. The message is for the owner and never echoes more than the rule."""


def rules_path(paths: Paths) -> Path:
    return paths.state / "firewall.json"


# ------------------------------------------------------------------ parsing ----
def parse_host(host: object) -> Optional[str]:
    """The canonical (lower-case) host if it is a DNS name, ``localhost`` or an IP literal, else None.
    No trailing dot, no unicode, no brackets, no userinfo, no numeric tricks."""
    if not isinstance(host, str) or not 1 <= len(host) <= 253 or not host.isascii():
        return None
    h = host.lower()
    if h == "localhost":
        return h
    try:
        ip = ipaddress.ip_address(h)
        # canonical spelling only; 0.0.0.0 / :: are never a host (0.0.0.0 reaches this computer: a loopback bypass)
        return str(ip) if str(ip) == h and not ip.is_unspecified else None
    except ValueError:
        pass
    return h if _DNS_RE.fullmatch(h) else None


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (ip.version == 4 and ip.is_loopback) or ip == ipaddress.IPv6Address("::1")


def _who_ok(who: object) -> bool:
    return isinstance(who, str) and (who in OS_PARTIES or bool(_APP_RE.fullmatch(who)))


def _port_ok(port: object) -> bool:
    return type(port) is int and 1 <= port <= 65535


def check_rule(who: object, host: object, port: object, proto: object) -> dict:
    """The rule as it will be stored, or FirewallError. This is the only place a rule is validated."""
    if not _who_ok(who):
        raise FirewallError("who must be app:NAME or one of " + ", ".join(OS_PARTIES))
    if not _port_ok(port):
        raise FirewallError("the port must be a number from 1 to 65535")
    if proto not in PROTOS:
        raise FirewallError("the protocol must be https or loopback (plain http to other hosts can never be a rule)")
    if host == WILDCARD:
        if proto != "https":
            raise FirewallError("the wildcard * is only allowed with https")
        return {"who": who, "host": WILDCARD, "port": port, "proto": proto}
    h = parse_host(host)
    if h is None:
        raise FirewallError("the host must be an exact DNS name or IP address (no URL, port, pattern or unicode)")
    if proto == "loopback" and not is_loopback(h):
        raise FirewallError("loopback is only for 127.0.0.0/8, ::1 or localhost (this computer)")
    return {"who": who, "host": h, "port": port, "proto": proto}


# -------------------------------------------------------------------- state ----
def load(paths: Paths) -> list[dict]:
    """The rules. A missing, damaged, oversized or odd file gives NO rules at all (deny all)."""
    try:
        raw = json.loads(rules_path(paths).read_text())
        rows = raw["rules"] if isinstance(raw, dict) else None
        if not isinstance(rows, list) or len(rows) > MAX_RULES:
            return []
        out = []
        for r in rows:
            if not isinstance(r, dict) or set(r) != {"who", "host", "port", "proto"}:
                return []                       # one odd row: the whole file is not trusted
            out.append(check_rule(r["who"], r["host"], r["port"], r["proto"]))
        return out
    except (OSError, ValueError, KeyError, TypeError, FirewallError, RecursionError):
        return []


def _save(paths: Paths, rules: list[dict]) -> None:
    paths.state.mkdir(parents=True, exist_ok=True)
    atomic_write(rules_path(paths), json.dumps({"rules": rules}, indent=2).encode(), mode=0o600)


def add_rule(paths: Paths, who: object, host: object, port: object, proto: object) -> dict:
    """Store a rule. The CALLER must already have the owner's password (``firewall.change``); this
    function validates, it does not authorise. Adding an existing rule changes nothing."""
    rule = check_rule(who, host, port, proto)
    rules = load(paths)
    if rule in rules:
        return rule
    if len(rules) >= MAX_RULES:
        raise FirewallError(f"at most {MAX_RULES} rules")
    _save(paths, rules + [rule])
    return rule


def check_key(who: object, host: object, port: object) -> tuple:
    """(who, host, port) of a rule to remove, validated, or FirewallError."""
    h = WILDCARD if host == WILDCARD else parse_host(host)
    if not _who_ok(who) or not _port_ok(port) or h is None:
        raise FirewallError("not a valid who, host and port")
    return who, h, port


def remove_rule(paths: Paths, who: object, host: object, port: object) -> int:
    """Remove every rule for this who+host+port (any protocol). Returns how many went."""
    who, h, port = check_key(who, host, port)
    rules = load(paths)
    keep = [r for r in rules if not (r["who"] == who and r["host"] == h and r["port"] == port)]
    if len(keep) != len(rules):
        _save(paths, keep)
    return len(rules) - len(keep)


def describe(rule: dict) -> str:
    """One line for the owner; a wildcard is never quiet."""
    host = "WILDCARD (every host)" if rule["host"] == WILDCARD else rule["host"]
    return f"{rule['who']}  {host}:{rule['port']}  {rule['proto']}"


# ----------------------------------------------------------------- decision ----
def _audit_host(host: object) -> str:
    h = host if host == WILDCARD else parse_host(host)
    return h if h else "invalid-host"            # nothing an app typed is ever written raw


def decide(paths: Paths, who: str, host: str, port: int, proto: str) -> bool:
    """THE decision. True only if a rule matches exactly AND the decision was written to the audit log."""
    h = parse_host(host)
    who_ok, port_ok = _who_ok(who), _port_ok(port)
    allowed = False
    if h is not None and who_ok and port_ok and proto in PROTOS and (proto != "loopback" or is_loopback(h)):
        for r in load(paths):
            if (r["who"] == who and r["port"] == port and r["proto"] == proto
                    and (r["host"] == h or (r["host"] == WILDCARD and proto == "https"))):
                allowed = True
                break
    target = "{} {}:{} {}".format(who if who_ok else "invalid-who", _audit_host(host),
                                  port if port_ok else 0, proto if proto in PROTOS else "invalid-proto")
    try:
        from .auth import AuditLog
        AuditLog(paths).record("firewall.connect", target, "allowed" if allowed else "blocked")
    except Exception:
        return False                         # cannot log it, so it does not happen
    return allowed


def allows_now(paths: Paths, who: str, host: str, port: int, proto: str) -> bool:
    """Would a rule match? Read-only and NOT audited: only for ``status`` displays, never a gate."""
    h = parse_host(host)
    if h is None or proto not in PROTOS or (proto == "loopback" and not is_loopback(h)):
        return False
    return any(r["who"] == who and r["port"] == port and r["proto"] == proto
               and (r["host"] == h or (r["host"] == WILDCARD and proto == "https")) for r in load(paths))
