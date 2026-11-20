"""The security chip (TPM 2.0) as a second factor next to the password.

What it does
------------
``kos chip enroll`` makes a random 32-byte *chip secret*, seals it inside the TPM, and mixes it into
the master key:

    master = HMAC(chip_secret, "kos:chip:v1:" + scrypt(password))

From then on the password alone derives the wrong master, so the verifier in ``auth.json`` does not
match and every seal and audit anchor stays closed. A copy of the disk or of ``auth.json`` is useless
on another machine, however good the password guess. The chip *adds to* the password; it never
replaces it (README rule 1).

Deleting the ``chip`` block from ``auth.json`` does not downgrade anything: the verifier was made from
the chip-mixed master, so a plain password no longer matches it.

The lock-out problem, and the recovery key
------------------------------------------
Sealing to a TPM means a dead board, a cleared TPM or (with a PCR policy) a changed Secure Boot state
makes the secret unreadable. So enrolling also prints a **recovery key** exactly once. It wraps the same
chip secret (ChaCha20-Poly1305, HKDF-SHA256) and is stored only in wrapped form. ``kos chip recover``
takes password + recovery key, proves them against the verifier, and seals the same secret to the
chip now present. The master does not change, so no app is re-sealed. Whoever holds the recovery key
but not the password still has nothing: the scrypt part of the master is missing.

Hardware rules (kos-hardware)
-----------------------------
* Detecting the chip reads sysfs only and opens no device (``status``).
* The device is opened only inside ``seal`` / ``unseal``, which the OS calls while a password is being
  checked (login, ``kos chip ...``). Nothing in an app can reach it: apps have no handle to ``/dev``
  and the guard's ``no-device-handles`` check would refuse one.
* The TPM is driven through the ``tpm2-tools`` programs, run as an argument list (never a shell), with
  the secret only on stdin/stdout, never on a command line or in a file.

Honest limits
-------------
* **The real TPM path has not run.** This container has no TPM, no ``swtpm`` and no ``tpm2-tools``.
  The tests use a fake backend; the exact ``tpm2_*`` command lines are written from the tool's
  documentation and still need a first run on a real machine (or ``swtpm``).
* A PCR policy (default ``sha256:7``, the Secure Boot state) ties the secret to boot state; any other
  firmware or boot-chain change then needs ``kos chip recover``. ``--pcr none`` seals with no policy.
* The password and chip secret meet in Python memory, which cannot be wiped reliably (see ``secret.py``).
* An attacker who owns the running machine after it unlocks can use the chip like the OS does.
* Not in the TPM: the recovery key is the owner's to keep offline. Lose it and the chip, and the
  disk is gone, by design.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .auth import AuthError

SYSFS_TPM = Path("/sys/class/tpm/tpm0")
DEVICE = "/dev/tpmrm0"
SECRET_LEN = 32
DEFAULT_PCR = "sha256:7"
PCR_RE = re.compile(r"^(sha256|sha384):[0-9]{1,2}(,[0-9]{1,2}){0,7}$")
MIX_LABEL = b"kos:chip:v1:"
WRAP_LABEL = b"kos:chip:recovery:v1"
TOOL_TIMEOUT = 20


class ChipError(AuthError):
    """The chip could not do what was asked. Subclasses AuthError so a login that needs the chip
    stops with a message; it is never counted as a wrong password."""


class Backend(Protocol):
    def seal(self, secret: bytes, pcr: str) -> dict: ...
    def unseal(self, blob: dict, pcr: str) -> bytes: ...


# --- the key mixing and the recovery wrap (pure functions: testable, provable) ---

def mix(chip_secret: bytes, scrypt_key: bytes) -> bytes:
    """The master key when a chip is enrolled."""
    if len(chip_secret) != SECRET_LEN:
        raise ChipError("the chip secret has the wrong length")
    return hmac.new(chip_secret, MIX_LABEL + bytes(scrypt_key), hashlib.sha256).digest()


def _wrap_key(recovery: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=WRAP_LABEL).derive(recovery)


def wrap_secret(recovery: bytes, chip_secret: bytes) -> str:
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(_wrap_key(recovery)).encrypt(nonce, chip_secret, WRAP_LABEL)
    return base64.b64encode(nonce + ct).decode()


def unwrap_secret(recovery: bytes, wrapped: str) -> bytes:
    try:
        raw = base64.b64decode(wrapped, validate=True)
        return ChaCha20Poly1305(_wrap_key(recovery)).decrypt(raw[:12], raw[12:], WRAP_LABEL)
    except (InvalidTag, ValueError):
        raise ChipError("that recovery key does not open this computer's chip secret") from None


def new_recovery_key() -> bytes:
    return os.urandom(32)


def format_recovery(key: bytes) -> str:
    """52 base32 characters in groups of four, so it can be written down and read back."""
    text = base64.b32encode(key).decode().rstrip("=")
    return "-".join(text[i:i + 4] for i in range(0, len(text), 4))


def parse_recovery(text: str) -> bytes:
    clean = re.sub(r"[\s-]", "", text or "").upper()
    if not re.fullmatch(r"[A-Z2-7]{52}", clean):
        raise ChipError("a recovery key is 52 letters and digits (groups of four, dashes optional)")
    return base64.b32decode(clean + "====")


def check_pcr(pcr: str) -> str:
    if pcr in ("", "none"):
        return ""
    if not PCR_RE.match(pcr):
        raise ChipError("PCR selection looks like sha256:7 or sha256:0,2,7 (or 'none')")
    return pcr


# --- detection: read-only, opens nothing under /dev ---

def status(sysfs: Path = SYSFS_TPM, device: str = DEVICE) -> dict:
    """What the kernel says about the chip. Reads two sysfs attributes and stats the device node."""
    out = {"present": False, "version": "", "device": False, "tools": _tool("tpm2_unseal") is not None}
    try:
        out["version"] = sysfs.joinpath("tpm_version_major").read_text(errors="replace").strip()[:3]
        out["present"] = True
    except OSError:
        pass
    out["device"] = os.path.exists(device)
    out["usable"] = out["present"] and out["version"] == "2" and out["device"] and out["tools"]
    return out


def _tool(name: str) -> Optional[str]:
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, name)
        if d and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


# --- the real chip, through tpm2-tools (not run in this container: see the module note) ---

class Tpm2Tools:
    def __init__(self, device: str = DEVICE):
        self.device = device

    def _run(self, argv: list[str], stdin: bytes = b"", cwd: Optional[str] = None) -> bytes:
        exe = _tool(argv[0])
        if exe is None:
            raise ChipError("tpm2-tools is not installed (need tpm2_createprimary, tpm2_create, "
                            "tpm2_load, tpm2_unseal, tpm2_createpolicy)")
        env = {"PATH": os.environ.get("PATH", ""), "TPM2TOOLS_TCTI": f"device:{self.device}"}
        try:
            p = subprocess.run([exe] + argv[1:], input=stdin, capture_output=True, cwd=cwd, env=env,
                               timeout=TOOL_TIMEOUT, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise ChipError(f"the chip did not answer ({argv[0]}: {type(e).__name__})") from None
        if p.returncode != 0:
            raise ChipError(f"the chip refused ({argv[0]} exit {p.returncode}); if its boot state "
                            f"changed, use: kos chip recover")
        return p.stdout

    def _primary(self, d: str) -> None:
        self._run(["tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", "primary.ctx"], cwd=d)

    def seal(self, secret: bytes, pcr: str) -> dict:
        pcr = check_pcr(pcr)
        with tempfile.TemporaryDirectory(prefix="kos-chip-") as d:
            os.chmod(d, 0o700)
            self._primary(d)
            argv = ["tpm2_create", "-C", "primary.ctx", "-i", "-", "-u", "seal.pub", "-r", "seal.priv"]
            if pcr:
                self._run(["tpm2_createpolicy", "--policy-pcr", "-l", pcr, "-L", "policy.dat"], cwd=d)
                # no userwithauth: with it an empty password would unseal and skip the PCR policy
                argv += ["-L", "policy.dat", "-a", "fixedtpm|fixedparent|adminwithpolicy|noda"]
            self._run(argv, stdin=secret, cwd=d)
            return {"pub": base64.b64encode(Path(d, "seal.pub").read_bytes()).decode(),
                    "priv": base64.b64encode(Path(d, "seal.priv").read_bytes()).decode()}

    def unseal(self, blob: dict, pcr: str) -> bytes:
        pcr = check_pcr(pcr)
        try:
            pub = base64.b64decode(blob["pub"], validate=True)
            priv = base64.b64decode(blob["priv"], validate=True)
        except (KeyError, TypeError, ValueError):
            raise ChipError("the sealed chip secret in auth.json is damaged") from None
        with tempfile.TemporaryDirectory(prefix="kos-chip-") as d:
            os.chmod(d, 0o700)
            Path(d, "seal.pub").write_bytes(pub)
            Path(d, "seal.priv").write_bytes(priv)
            self._primary(d)
            self._run(["tpm2_load", "-C", "primary.ctx", "-u", "seal.pub", "-r", "seal.priv",
                       "-c", "seal.ctx"], cwd=d)
            argv = ["tpm2_unseal", "-c", "seal.ctx"] + (["-p", f"pcr:{pcr}"] if pcr else [])
            secret = self._run(argv, cwd=d)
        if len(secret) != SECRET_LEN:
            raise ChipError("the chip returned a secret of the wrong length")
        return secret


_backend: Optional[Backend] = None      # tests put a fake here; nothing else ever sets it


def backend() -> Backend:
    return _backend if _backend is not None else Tpm2Tools()


# --- what auth.py and the CLI use ---

def unseal_for(block: dict) -> bytes:
    """The chip secret, read from the chip. Called while a password is being checked."""
    try:
        return backend().unseal(block["blob"], block.get("pcr", ""))
    except KeyError:
        raise ChipError("the chip block in auth.json is damaged") from None


def make_block(secret: bytes, pcr: str, recovery: bytes) -> dict:
    pcr = check_pcr(pcr)
    return {"kind": "tpm2", "pcr": pcr, "blob": backend().seal(secret, pcr),
            "recovery": wrap_secret(recovery, secret)}


def reseal_block(old: dict, secret: bytes, pcr: Optional[str] = None) -> dict:
    """The same secret sealed to the chip that is here now; the recovery wrap is kept."""
    pcr = check_pcr(old.get("pcr", "") if pcr is None else pcr)
    return {"kind": "tpm2", "pcr": pcr, "blob": backend().seal(secret, pcr), "recovery": old["recovery"]}
