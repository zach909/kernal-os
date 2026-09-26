"""``kos optimize``: reclaim disk space.

Nothing here is guessing - every step either removes something that's
provably dead (a broker that's gone, a quarantined file older than the
retention window) or re-packs something losslessly (recompressing an
installed .kapp to the best zip compression, which is byte-identical when
unzipped, so the seal - and the install itself - is untouched by it, only
re-derived and re-sealed at the new bytes).
"""

from __future__ import annotations

import hashlib
import json
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .auth import Authority
from .kapp import KApp, compute_seal
from .paths import Paths, atomic_write
from .registry import Registry
from .store import SEAL_KEY_LABEL

QUARANTINE_RETENTION_S = 30 * 24 * 3600
AUDIT_RETENTION_LINES = 5000


@dataclass
class OptimizeReport:
    bytes_reclaimed: int = 0
    apps_recompressed: int = 0
    quarantine_removed: int = 0
    dead_instances_pruned: int = 0
    audit_lines_trimmed: int = 0

    def summary(self) -> str:
        return (f"reclaimed {self.bytes_reclaimed:,} bytes - "
               f"{self.apps_recompressed} app(s) recompressed, "
               f"{self.quarantine_removed} old quarantine file(s) removed, "
               f"{self.dead_instances_pruned} dead instance(s) pruned, "
               f"{self.audit_lines_trimmed} old audit line(s) trimmed")


def _recompress_kapp(kapp_path: Path, seal_path: Path, seal_key: bytes) -> int:
    """Rewrite a .kapp with every entry at maximum deflate compression, and
    re-seal it at the new bytes in the same step - recompression changes the
    sha256 the seal covers, so the two must move together or a later run
    would see the app as tampered. Returns bytes saved (0 if not smaller)."""
    data = kapp_path.read_bytes()
    original = len(data)
    try:
        meta = json.loads(seal_path.read_text())
    except (OSError, ValueError):
        return 0  # no seal to preserve; leave the app alone
    import io
    src = zipfile.ZipFile(io.BytesIO(data))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as dst:
        for info in src.infolist():
            content = src.read(info.filename)
            zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = info.external_attr
            dst.writestr(zi, content, compresslevel=9)
    new_data = out.getvalue()
    if len(new_data) >= original:
        return 0
    app = KApp(new_data)  # never write back something that doesn't verify
    new_digest = hashlib.sha256(new_data).hexdigest()
    meta["sha256"] = new_digest
    meta["seal"] = compute_seal(seal_key, app.manifest.name, app.manifest.version, new_digest)
    atomic_write(kapp_path, new_data)
    atomic_write(seal_path, json.dumps(meta, indent=2).encode())
    return original - len(new_data)


def optimize(paths: Paths, grant_or_authority) -> OptimizeReport:
    """`grant_or_authority` is an `Authority` (live password) or an
    already-open grant (e.g. a redeemed privileged autonomy token)."""
    report = OptimizeReport()

    # 1. Recompress every installed app's zip to the best compression, and
    #    re-seal it at the new bytes so it still verifies afterward.
    cm = grant_or_authority.authorize("disk.optimize") \
        if isinstance(grant_or_authority, Authority) else grant_or_authority
    with cm as grant:
        seal_key = grant.key(SEAL_KEY_LABEL)
    for kapp_path in sorted(paths.apps.glob("*.kapp")):
        seal_path = kapp_path.with_suffix(".seal")
        saved = _recompress_kapp(kapp_path, seal_path, seal_key)
        if saved > 0:
            report.bytes_reclaimed += saved
            report.apps_recompressed += 1

    # 2. Drop quarantined files past their retention window.
    qdir = paths.state / "quarantine"
    if qdir.exists():
        cutoff = time.time() - QUARANTINE_RETENTION_S
        for f in qdir.glob("*.kapp"):
            if f.stat().st_mtime < cutoff:
                report.bytes_reclaimed += f.stat().st_size
                f.unlink()
                report.quarantine_removed += 1

    # 3. Prune registry entries for brokers that are already gone.
    report.dead_instances_pruned = Registry(paths).prune()

    # 4. Trim the audit log to the most recent N lines.
    audit_file = paths.logs / "audit.log"
    if audit_file.exists():
        lines = audit_file.read_text().splitlines()
        if len(lines) > AUDIT_RETENTION_LINES:
            keep = lines[-AUDIT_RETENTION_LINES:]
            before = audit_file.stat().st_size
            atomic_write(audit_file, ("\n".join(keep) + "\n").encode())
            report.audit_lines_trimmed = len(lines) - len(keep)
            report.bytes_reclaimed += max(0, before - audit_file.stat().st_size)

    return report
