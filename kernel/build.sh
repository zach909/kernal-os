#!/bin/bash
# Build the KOS kernel: pinned upstream Linux, checksum-verified, the KOS patches applied.
#
#   kernel/build.sh [--out DIR] [--jobs N] [--cache DIR]
#
# Result: DIR/bzImage and DIR/config (default DIR: build/kernel). The source is downloaded
# once into the cache and refused unless its SHA-256 equals kernel/KERNEL_SHA256. The patches
# in kernel/patches/ are applied in name order; a patch that does not apply stops the build.
# Afterwards the script checks that every option in kernel/kos.config is really in the final
# .config, because a Kconfig option that is hidden or renamed is dropped without a word.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
out="$repo/build/kernel" cache="$repo/build/cache" jobs=$(nproc)
while [ $# -gt 0 ]; do
    case "$1" in
        --out) out=$2; shift 2 ;;
        --jobs) jobs=$2; shift 2 ;;
        --cache) cache=$2; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done

ver=$(cat "$here/KERNEL_VERSION")
want=$(cat "$here/KERNEL_SHA256")
tar="linux-$ver.tar.xz"
mkdir -p "$cache" "$out"

if [ ! -f "$cache/$tar" ]; then
    echo "fetching $tar"
    curl -fsSL --proto '=https' --tlsv1.2 -o "$cache/$tar.part" \
        "https://cdn.kernel.org/pub/linux/kernel/v${ver%%.*}.x/$tar"
    mv "$cache/$tar.part" "$cache/$tar"
fi
got=$(sha256sum "$cache/$tar" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then
    echo "REFUSED: $tar has sha256 $got, expected $want" >&2
    exit 1
fi

work=$(mktemp -d "$out/src.XXXXXX")
trap 'rm -rf "$work"' EXIT
tar -xf "$cache/$tar" -C "$work" --strip-components=1
cd "$work"
for p in "$here"/patches/*.patch; do
    echo "applying $(basename "$p")"
    patch -p1 -s < "$p"
done

make defconfig >/dev/null
scripts/kconfig/merge_config.sh -m .config "$here/kos.config" >/dev/null
make olddefconfig >/dev/null

missing=0
while IFS== read -r k v; do
    grep -qxF "$k=$v" .config || { echo "NOT IN FINAL CONFIG: $k=$v" >&2; missing=1; }
done < <(grep -E '^CONFIG_[A-Z0-9_]+=' "$here/kos.config")
while read -r k; do
    if grep -qE "^$k=[ym]" .config; then echo "STILL ENABLED: $k" >&2; missing=1; fi
done < <(sed -nE 's/^# (CONFIG_[A-Z0-9_]+) is not set/\1/p' "$here/kos.config")
[ "$missing" = 0 ] || { echo "kernel/kos.config was not applied in full" >&2; exit 1; }

make -j"$jobs" bzImage
cp arch/x86/boot/bzImage "$out/bzImage"
cp .config "$out/config"
echo "built $out/bzImage (Linux $ver + KOS)"
