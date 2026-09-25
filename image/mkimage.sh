#!/bin/bash
# Build a bootable KOS disk image:
#
#   partition 1  EFI system partition: one signed Unified Kernel Image
#                (kernel + pre-boot initramfs + kernel command line)
#   partition 2  LUKS2 (Argon2id) encrypted root filesystem
#
#   sudo image/mkimage.sh --kernel bzImage --rootfs rootfs.tar --out kos.img \
#        [--size 8G] [--sb-key db.key --sb-cert db.crt]
#
# rootfs.tar is any minimal Linux userland that contains python3 (Alpine's
# minirootfs + `apk add python3` works). KOS itself is installed on top.
# You will be asked to choose the disk password; use the same password you
# will choose at first boot for KOS itself.
#
# Needs: sgdisk, losetup, cryptsetup, mkfs.ext4, mkfs.vfat, ukify (systemd),
#        and sbsign if signing for Secure Boot.
set -euo pipefail

size=8G kernel="" rootfs="" out="" sb_key="" sb_cert=""
while [ $# -gt 0 ]; do
    case "$1" in
        --kernel) kernel=$2; shift 2 ;;
        --rootfs) rootfs=$2; shift 2 ;;
        --out) out=$2; shift 2 ;;
        --size) size=$2; shift 2 ;;
        --sb-key) sb_key=$2; shift 2 ;;
        --sb-cert) sb_cert=$2; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 1 ;;
    esac
done
[ -n "$kernel" ] && [ -n "$rootfs" ] && [ -n "$out" ] || { sed -n '2,20p' "$0"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root (needs loop devices)" >&2; exit 1; }

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
loop=""
cleanup() {
    umount "$work/root" 2>/dev/null || true
    cryptsetup close kos-build 2>/dev/null || true
    [ -n "$loop" ] && losetup -d "$loop" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

truncate -s "$size" "$out"
sgdisk --zap-all \
       --new=1:0:+512M --typecode=1:ef00 --change-name=1:KOS-ESP \
       --new=2:0:0     --typecode=2:8309 --change-name=2:KOS-ROOT "$out"
loop=$(losetup --find --show --partscan "$out")

echo "Choose the disk password:"
cryptsetup luksFormat --type luks2 --pbkdf argon2id --iter-time 2000 \
    --cipher aes-xts-plain64 --key-size 512 --hash sha512 "${loop}p2"
uuid=$(cryptsetup luksUUID "${loop}p2")
echo "Unlock it once more to install the system:"
cryptsetup open "${loop}p2" kos-build

mkfs.ext4 -q -L kos-root /dev/mapper/kos-build
mkdir -p "$work/root"
mount /dev/mapper/kos-build "$work/root"
tar -xpf "$rootfs" -C "$work/root"

# KOS userland
install -d "$work/root/opt/kos" "$work/root/opt/kos/bin"
cp -r "$repo/kos" "$work/root/opt/kos/"
cp "$repo/bin/kos" "$repo/bin/run" "$work/root/opt/kos/bin/"
cat > "$work/root/sbin/kos-init" <<'INIT'
#!/usr/bin/python3 -I
import sys
sys.path.insert(0, "/opt/kos")
from kos.init import main
main()
INIT
chmod 0755 "$work/root/sbin/kos-init"
install -d -o 1000 -g 1000 -m 0700 "$work/root/home/owner" \
    "$work/root/etc/kos" "$work/root/var/lib/kos"
grep -q '^owner:' "$work/root/etc/passwd" || \
    echo 'owner:x:1000:1000:KOS owner:/home/owner:/bin/sh' >> "$work/root/etc/passwd"
grep -q '^owner:' "$work/root/etc/group" || echo 'owner:x:1000:' >> "$work/root/etc/group"
# No root password, no login services, no autostart of any kind.
sed -i 's/^root:[^:]*:/root:!:/' "$work/root/etc/shadow" 2>/dev/null || true
rm -rf "$work/root/etc/init.d" "$work/root/etc/runlevels" "$work/root/etc/systemd" 2>/dev/null || true
# The app loader needs an unprivileged helper group-free path; no setuid binaries at all:
find "$work/root" -xdev -perm /6000 -type f -exec chmod ug-s {} +

umount "$work/root"
cryptsetup close kos-build

# Pre-boot environment + kernel -> one UKI on the ESP
"$repo/boot/mkinitramfs.sh" "$work/initramfs.cpio.gz"
sed "s/@LUKS_UUID@/$uuid/" "$repo/kernel/cmdline.txt" > "$work/cmdline"
ukify build --linux "$kernel" --initrd "$work/initramfs.cpio.gz" \
    --cmdline "@$work/cmdline" --output "$work/kos.efi"
if [ -n "$sb_key" ]; then
    sbsign --key "$sb_key" --cert "$sb_cert" --output "$work/kos.efi" "$work/kos.efi"
else
    echo "WARNING: UKI is not signed; enable Secure Boot signing for tamper-proof pre-boot." >&2
fi
mkfs.vfat -n KOS-ESP "${loop}p1" >/dev/null
mkdir -p "$work/esp"
mount "${loop}p1" "$work/esp"
install -D "$work/kos.efi" "$work/esp/EFI/BOOT/BOOTX64.EFI"
umount "$work/esp"
echo "done: $out (root LUKS UUID $uuid)"
