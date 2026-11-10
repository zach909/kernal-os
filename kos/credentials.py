"""The Credential Manager's store: ``<state>/credentials.bin`` (mode 0600), sealed JSON.

Sealed with kos.crypto under the purpose ``credentials`` (the key is a subkey of the DEK that only a
password-granted block can open). The plaintext is JSON ``{"next": N, "entries": [{id, label, username,
secret, url, notes}]}``. At most 500 entries; every field is bounded and free of control characters. No
function here logs or raises with a label, a secret or a value. An app reaches this only through the OS
(system.py ``_credential``); it never touches the file.
"""

from __future__ import annotations

import json
import re

from . import crypto
from .paths import Paths, atomic_write

PURPOSE = "credentials"
MAX_ENTRIES = 500
LIMITS = {"label": 80, "username": 160, "secret": 1024, "url": 512, "notes": 1000}
REQUIRED = ("label", "secret")
OPS = ("list", "get", "add", "delete")
FIELDS = ("label", "username", "secret", "url", "notes")
# C0, DEL, C1, line/paragraph separators and bidi overrides/isolates: none may appear in any field.
_BAD = re.compile("[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩‎‏]")


class CredentialError(Exception):
    """``code`` is one of: refused, not-found, exists, full. The text is only that code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def check_field(name: str, value) -> str:
    if type(value) is not str or len(value) > LIMITS[name] or _BAD.search(value) or (name in REQUIRED and not value):
        raise CredentialError("refused")
    return value


def check_entry(d) -> dict:
    if not isinstance(d, dict) or set(d) != set(FIELDS):
        raise CredentialError("refused")
    return {f: check_field(f, d[f]) for f in FIELDS}


def _load_doc(paths: Paths, dek) -> dict:
    try:
        blob = paths.credentials_file.read_bytes()
    except FileNotFoundError:
        return {"next": 1, "entries": []}
    except OSError:
        raise crypto.CryptoError() from None
    raw = crypto.open_(dek, PURPOSE, blob)
    try:
        doc = json.loads(raw.decode("utf-8"))
        ents = doc["entries"]
        if not isinstance(ents, list) or not isinstance(doc["next"], int) or len(ents) > MAX_ENTRIES:
            raise ValueError
        for e in ents:
            if not isinstance(e.get("id"), int):
                raise ValueError
            check_entry({k: e[k] for k in FIELDS})
    except (ValueError, KeyError, TypeError, AttributeError, CredentialError):
        ok = False
    else:
        ok = True
    if not ok:
        raise crypto.CryptoError()
    return doc


def _save_doc(paths: Paths, dek, doc: dict) -> None:
    blob = crypto.seal(dek, PURPOSE, json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    paths.state.mkdir(parents=True, exist_ok=True)
    atomic_write(paths.credentials_file, blob, mode=0o600)


def exists(paths: Paths) -> bool:
    return paths.credentials_file.exists()


def rows(doc: dict) -> list:
    """What `list` may return: never a secret or notes."""
    return [{"id": e["id"], "label": e["label"], "username": e["username"], "url": e["url"]} for e in doc["entries"]]


def list_rows(paths: Paths, dek) -> list:
    return rows(_load_doc(paths, dek))


def get(paths: Paths, dek, label: str) -> dict:
    for e in _load_doc(paths, dek)["entries"]:
        if e["label"] == label:
            return {f: e[f] for f in FIELDS}
    raise CredentialError("not-found")


def add(paths: Paths, dek, entry: dict) -> list:
    entry = check_entry(entry)
    doc = _load_doc(paths, dek)
    if any(e["label"] == entry["label"] for e in doc["entries"]):
        raise CredentialError("exists")
    if len(doc["entries"]) >= MAX_ENTRIES:
        raise CredentialError("full")
    doc["entries"].append({"id": doc["next"], **entry})
    doc["next"] += 1
    _save_doc(paths, dek, doc)
    return rows(doc)


def delete(paths: Paths, dek, label: str) -> list:
    doc = _load_doc(paths, dek)
    keep = [e for e in doc["entries"] if e["label"] != label]
    if len(keep) == len(doc["entries"]):
        raise CredentialError("not-found")
    doc["entries"] = keep
    _save_doc(paths, dek, doc)
    return rows(doc)
