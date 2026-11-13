#!/bin/bash
# Boot-test the KOS security module in a throwaway kernel under QEMU.
#
#   kernel/test/run.sh [--cache DIR] [--keep DIR]
#
# Builds Linux (pinned, checksum-verified, KOS patches applied) from tinyconfig + test.config,
# packs kos_lsm_test.c as PID 1 of an initramfs, boots it, and requires:
#   - at least one "ok" line, no "not ok" line, no oops/panic, and
#   - the final line KOS-LSM-TEST-DONE failures=0.
# No KVM is needed (QEMU's software emulation runs it in about a minute).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
kdir=$(dirname "$here")
repo=$(dirname "$kdir")
cache="$repo/build/cache" keep=""
while [ $# -gt 0 ]; do
    case "$1" in
        --cache) cache=$2; shift 2 ;;
        --keep) keep=$2; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done
for t in qemu-system-x86_64 gcc make flex bison bc cpio gzip patch; do
    command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 2; }
done

ver=$(cat "$kdir/KERNEL_VERSION"); want=$(cat "$kdir/KERNEL_SHA256")
tar="linux-$ver.tar.xz"
mkdir -p "$cache"
[ -f "$cache/$tar" ] || curl -fsSL --proto '=https' --tlsv1.2 -o "$cache/$tar" \
    "https://cdn.kernel.org/pub/linux/kernel/v${ver%%.*}.x/$tar"
[ "$(sha256sum "$cache/$tar" | cut -d' ' -f1)" = "$want" ] || { echo "REFUSED: bad checksum for $tar" >&2; exit 1; }

work=$(mktemp -d)
trap '[ -n "$keep" ] && { mkdir -p "$keep"; cp -r "$work/." "$keep/"; }; rm -rf "$work"' EXIT
mkdir "$work/src" "$work/initram"
tar -xf "$cache/$tar" -C "$work/src" --strip-components=1
cd "$work/src"
for p in "$kdir"/patches/*.patch; do patch -p1 -s < "$p"; done
make tinyconfig >/dev/null
scripts/kconfig/merge_config.sh -m .config "$here/test.config" >/dev/null
make olddefconfig >/dev/null
grep -qx 'CONFIG_SECURITY_KOS=y' .config || { echo "CONFIG_SECURITY_KOS did not stick" >&2; exit 1; }
make -j"$(nproc)" bzImage >"$work/build.log" 2>&1 || { tail -30 "$work/build.log"; exit 1; }
if grep -q "security/kos.*warning" "$work/build.log"; then grep "security/kos.*warning" "$work/build.log"; exit 1; fi

gcc -static -O1 -Wall -Wextra -Wno-unused-parameter -o "$work/initram/init" "$here/kos_lsm_test.c"
mkdir "$work/initram"/{proc,sys,tmp,dev}
(cd "$work/initram" && find . | cpio -o -H newc 2>/dev/null | gzip -9 > "$work/test.cpio.gz")

timeout 300 qemu-system-x86_64 -m 256 -nographic -no-reboot -display none -monitor none -serial stdio \
    -kernel arch/x86/boot/bzImage -initrd "$work/test.cpio.gz" \
    -append "console=ttyS0 panic=-1 rdinit=/init lsm=kos" > "$work/boot.log" 2>&1 || true

tr -d '\r' < "$work/boot.log" > "$work/boot.clean" && mv "$work/boot.clean" "$work/boot.log"   # serial console sends CRLF
oks=$(grep -c '^ok - ' "$work/boot.log" || true)
bad=$(grep -c '^not ok - ' "$work/boot.log" || true)
grep -E '^not ok - ' "$work/boot.log" || true
if grep -qE 'Oops|BUG:|Kernel panic' "$work/boot.log"; then echo "kernel oops/panic:"; grep -E -A12 'Oops|BUG:|Kernel panic' "$work/boot.log" | head -30; exit 1; fi
# The kernel prints reboot messages after the test's last line, so look for it anywhere.
[ "$(grep -c '^KOS-LSM-TEST-DONE failures=0$' "$work/boot.log")" = 1 ] && ! grep -q '^KOS-LSM-TEST-DONE failures=[1-9]' "$work/boot.log" \
    || { echo "no clean DONE line"; tail -8 "$work/boot.log"; exit 1; }
[ "$oks" -gt 0 ] && [ "$bad" = 0 ] || { echo "ok=$oks not-ok=$bad"; exit 1; }
echo "KOS LSM boot test: $oks checks passed, 0 failed (Linux $ver)"
