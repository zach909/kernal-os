#!/bin/bash
# Build the KOS pre-boot initramfs.
#
#   boot/mkinitramfs.sh OUTPUT.cpio.gz
#
# Needs on the build machine: a static busybox, cryptsetup, blkid and cpio.
# Dynamically linked tools are copied together with the libraries ldd reports.
set -euo pipefail

out=${1:?usage: mkinitramfs.sh OUTPUT.cpio.gz}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work"/{bin,sbin,dev,proc,sys,newroot,run,lib,lib64,usr/lib}

busybox=$(command -v busybox) || { echo "need busybox (static)" >&2; exit 1; }
cp "$busybox" "$work/bin/busybox"
for applet in sh mount umount mkdir sleep cat clear switch_root poweroff blkid echo; do
    ln -sf busybox "$work/bin/$applet"
done

copy_with_libs() {
    local bin=$1
    install -D -m 0755 "$bin" "$work/sbin/$(basename "$bin")"
    ldd "$bin" 2>/dev/null | grep -o '/[^ ]*' | while read -r lib; do
        install -D -m 0644 "$lib" "$work$lib"
    done
}
copy_with_libs "$(command -v cryptsetup)"

install -m 0755 "$here/initramfs/init" "$work/init"
mknod -m 600 "$work/dev/console" c 5 1 2>/dev/null || true

(cd "$work" && find . -print0 | sort -z | cpio --null -o -H newc --reproducible 2>/dev/null) \
    | gzip -9n > "$out"
echo "wrote $out"
