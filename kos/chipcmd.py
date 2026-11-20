"""``kos chip``: enroll, remove and recover the security chip (see kos/chip.py for what and why).

Every change to the master key re-seals the installed apps first, exactly like ``kos passwd``, and
writes ``auth.json`` last. A crash between the two leaves apps sealed under a key that no longer
matches (same window ``kos passwd`` has; ``kos run`` then refuses them, it never runs them wrongly).
"""

from __future__ import annotations

import os

from . import chip
from .auth import AuditLog, Grant, PasswordStore, AuthError, KdfParams, derive_master, subkey, AUDIT_KEY_LABEL
from .chip import ChipError
from .paths import Paths
from .store import SEAL_KEY_LABEL, AppStore


def describe(paths: Paths) -> list[str]:
    """Lines for ``kos chip`` (no password: reads sysfs and auth.json's chip block, opens no device)."""
    st = chip.status()
    lines = []
    if not st["present"]:
        lines.append("security chip : none found (no /sys/class/tpm/tpm0)")
    else:
        lines.append(f"security chip : TPM {st['version'] or '?'} present; device node "
                     f"{'yes' if st['device'] else 'NO'}; tpm2-tools {'yes' if st['tools'] else 'NO'}")
    store = PasswordStore(paths)
    block = store.chip_block() if store.exists() else None
    if block is None:
        lines.append("enrolled      : no (the password alone protects this computer)")
    else:
        lines.append(f"enrolled      : yes, secret sealed to the chip; boot-state policy "
                     f"{block.get('pcr') or 'none'}; recovery key wrapped on disk")
    return lines


def _confirm_recovery(prompter, recovery: bytes) -> None:
    prompter.info("\nRECOVERY KEY - shown once. Write it down and keep it OFF this computer:\n\n"
                  f"    {chip.format_recovery(recovery)}\n\n"
                  "Without it, a replaced or cleared chip means the disk is gone.")
    again = prompter.password("Type the recovery key to confirm you saved it: ")
    if again is None:
        raise ChipError("cancelled; nothing changed")
    if chip.parse_recovery(again.decode(errors="replace")) != recovery:
        raise ChipError("the recovery key did not match; nothing changed")


def enroll(paths: Paths, authority, prompter, pcr: str = chip.DEFAULT_PCR) -> int:
    store = authority.store
    if store.chip_block() is not None:
        raise ChipError("a chip is already enrolled (kos chip remove first, to change it)")
    if not chip.status()["usable"]:
        raise ChipError("no usable TPM 2.0 here (need /sys/class/tpm/tpm0, /dev/tpmrm0 and tpm2-tools); "
                        "run: kos chip")
    pcr = chip.check_pcr(pcr)
    with authority.authorize("chip.enroll", "this computer") as old:
        params = store.params()
        secret, recovery = os.urandom(chip.SECRET_LEN), chip.new_recovery_key()
        block = chip.make_block(secret, pcr, recovery)
        if chip.unseal_for(block) != secret:                  # prove it reads back before committing
            raise ChipError("the chip did not give the same secret back; nothing changed")
        _confirm_recovery(prompter, recovery)
        with old.chip_master(secret) as master:
            n = AppStore(paths).reseal_all(old, subkey(master, SEAL_KEY_LABEL))
            store.write(params, master, store.throttle_base(), chip=block)
    print(f"Chip enrolled; {n} app(s) re-sealed. The password now only works on this computer's chip.")
    return 0


def remove(paths: Paths, authority, prompter) -> int:
    """Back to the password alone. Needs the chip to work now (else: kos chip recover --drop-chip)."""
    store = authority.store
    if store.chip_block() is None:
        raise ChipError("no chip is enrolled")
    from .cli import _new_password
    with authority.authorize("chip.remove", "this computer") as old:
        params = store.params()
        new_pw = _new_password(prompter)
        with derive_master(new_pw, params) as master:
            n = AppStore(paths).reseal_all(old, subkey(master, SEAL_KEY_LABEL))
            store.write(params, master, store.throttle_base(), chip=None)
    print(f"Chip no longer used; {n} app(s) re-sealed. The old recovery key is now useless.")
    return 0


def recover(paths: Paths, authority, prompter, drop_chip: bool = False) -> int:
    """Password + recovery key, when the chip cannot be read (replaced board, cleared TPM, changed
    boot state). Puts the same secret on the chip that is here now, or (--drop-chip) leaves the chip.
    It checks the pair itself, through the throttle and the audit log, because authorize() needs the
    chip this is for. The master does not change unless --drop-chip."""
    store = authority.store
    block = store.chip_block()
    if block is None:
        raise ChipError("no chip is enrolled, nothing to recover")
    if not drop_chip and not chip.status()["usable"]:
        raise ChipError("no usable TPM 2.0 to put the secret on (use --drop-chip to leave the chip instead)")
    audit = AuditLog(paths)
    authority.throttle.wait(prompter.info)
    password = prompter.password("Password: ")
    rkey = prompter.password("Recovery key: ")
    if password is None or rkey is None:
        audit.record("chip.recover", "this computer", "cancelled")
        raise ChipError("cancelled; nothing changed")
    try:
        secret = chip.unwrap_secret(chip.parse_recovery(rkey.decode(errors="replace")), block["recovery"])
        master = derive_master(password, store.params(), secret)
        if not store.matches(master):
            master.wipe()
            raise ChipError("the password and recovery key do not match this computer")
    except ChipError:
        authority.throttle.fail()
        audit.record("chip.recover", "this computer", "bad-credentials")
        raise
    authority.throttle.success()
    audit.record("chip.recover", "this computer", "granted", key=subkey(master, AUDIT_KEY_LABEL))
    params = store.params()
    with Grant("chip.recover", "this computer", master) as old:
        if not drop_chip:
            store.write(params, master, store.throttle_base(),
                        chip=chip.reseal_block(block, secret))
            print("The same secret is now sealed to the chip in this computer. Nothing was re-sealed.")
            return 0
        from .cli import _new_password
        new_pw = _new_password(prompter)
        with derive_master(new_pw, params) as new_master:
            n = AppStore(paths).reseal_all(old, subkey(new_master, SEAL_KEY_LABEL))
            store.write(params, new_master, store.throttle_base(), chip=None)
    print(f"Chip dropped; {n} app(s) re-sealed. The password alone protects this computer now.")
    return 0
