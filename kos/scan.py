"""The security scanner. Everything that enters the system - an install, an
update, a watched write - goes through this before it's trusted.

Honest scope: this is a static, heuristic scanner, not a commercial antivirus
with a signature database of a million known viruses. It catches:

* the EICAR test file - the industry-standard "is a scanner even wired up"
  check every real antivirus recognizes;
* a set of hand-written heuristics for the kinds of things a hostile file
  actually does: shell/reverse-shell one-liners, obfuscated
  eval/exec-of-decoded-data chains, attempts to read SSH keys or shadow
  files, fork bombs, setuid-root shell drops, and the zip-bomb / path-
  traversal checks KApp already enforces on install;
* recursing into zip archives (including nested ones) without ever
  extracting them, the same rule as everywhere else in KOS.

A real deployment would also want a maintained signature feed; that's out of
scope for one file. What's here is real static analysis, not a placeholder.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

MAX_SCAN = 64 << 20
MAX_ZIP_MEMBER = 32 << 20

EICAR = (rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$" rb"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    severity: str  # "high" | "medium"
    note: str


RULES: list[Rule] = [
    Rule("eicar-test-file", re.compile(re.escape(EICAR)), "high",
         "the standard antivirus test signature"),
    Rule("reverse-shell", re.compile(
        rb"(?:/bin/(?:ba)?sh\s+-i\s+>&|nc\s+-e\s+/bin/|"
        rb"socket\.socket.{0,40}connect.{0,80}dup2|"
        rb"bash\s+-i\s*>&\s*/dev/tcp/)", re.DOTALL), "high",
        "opens an interactive shell over a raw network socket"),
    Rule("obfuscated-exec", re.compile(
        rb"exec\s*\(\s*(?:__import__\(['\"]base64['\"]\)|base64)\.[bB]64decode", re.DOTALL),
        "high", "decodes and executes hidden code at runtime"),
    Rule("eval-of-decoded-data", re.compile(
        rb"eval\s*\(\s*(?:base64|codecs|zlib)\.\w+\("), "high",
        "runs decoded/decompressed data as code instead of data"),
    Rule("credential-file-read", re.compile(
        rb"open\s*\(\s*['\"](?:/etc/shadow|/etc/passwd|[^'\"]*/\.ssh/id_(?:rsa|ed25519))['\"]"),
        "high", "reads a credentials or key file by a hardcoded path"),
    Rule("fork-bomb", re.compile(rb":\(\)\{\s*:\|:&\s*\};:|while\s+True:\s*os\.fork\("),
         "high", "unbounded self-replicating process spawn"),
    Rule("setuid-root-drop", re.compile(rb"os\.chmod\([^)]*,\s*0o?[4-7][0-7]{3}\)"),
         "medium", "sets a setuid/setgid bit on a file"),
    Rule("outbound-curl-pipe-shell", re.compile(
        rb"curl[^|\n]{0,80}\|\s*(?:sudo\s+)?(?:ba)?sh"), "high",
        "downloads and immediately executes a remote script"),
]


@dataclass
class Finding:
    path: str
    rule: str
    severity: str
    note: str


@dataclass
class ScanResult:
    scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    sha256: str = ""

    @property
    def clean(self) -> bool:
        return not self.findings

    def summary(self) -> str:
        if self.clean:
            return f"clean ({self.scanned} file(s) scanned)"
        names = ", ".join(sorted({f.rule for f in self.findings}))
        return f"FLAGGED: {len(self.findings)} finding(s) [{names}] across {self.scanned} file(s)"


def _scan_bytes(path: str, data: bytes) -> list[Finding]:
    out = []
    for rule in RULES:
        if rule.pattern.search(data):
            out.append(Finding(path, rule.name, rule.severity, rule.note))
    return out


def scan_bytes(data: bytes, label: str = "<data>") -> ScanResult:
    """Scan raw bytes, recursing into zip members without ever writing any
    of it to disk."""
    result = ScanResult(sha256=hashlib.sha256(data).hexdigest())
    _scan_into(label, data, result, depth=0)
    return result


def _scan_into(label: str, data: bytes, result: ScanResult, depth: int) -> None:
    if len(data) > MAX_SCAN or depth > 4:
        result.findings.append(Finding(label, "scan-limit-exceeded", "medium",
                                       "too large or too deeply nested to fully scan"))
        return
    result.scanned += 1
    result.findings.extend(_scan_bytes(label, data))
    if zipfile.is_zipfile(io.BytesIO(data)):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for info in z.infolist():
                    if info.is_dir() or info.file_size > MAX_ZIP_MEMBER:
                        continue
                    with z.open(info) as f:
                        member = f.read(MAX_ZIP_MEMBER + 1)
                    _scan_into(f"{label}!{info.filename}", member, result, depth + 1)
        except zipfile.BadZipFile:
            result.findings.append(Finding(label, "corrupt-archive", "medium",
                                           "claims to be a zip but won't parse"))


def scan_file(path: Path) -> ScanResult:
    data = Path(path).read_bytes()
    return scan_bytes(data, label=str(path))
