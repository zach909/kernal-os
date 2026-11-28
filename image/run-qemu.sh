#!/bin/bash
# Boot a KOS image in QEMU with UEFI firmware (OVMF), a framebuffer, and a
# USB keyboard/mouse so graphical mode and device booting can be tried.
#   image/run-qemu.sh kos.img          image as a virtio disk
#   image/run-qemu.sh --usb kos.img    image as a USB mass-storage stick on an
#                                      xHCI controller (what a real stick looks like)
set -euo pipefail
usb=0
if [ "${1:-}" = "--usb" ]; then usb=1; shift; fi
img=${1:?usage: run-qemu.sh [--usb] kos.img}
[ -f "$img" ] || { echo "no such image: $img" >&2; exit 1; }

ovmf=${OVMF:-}
if [ -z "$ovmf" ]; then
    for f in /usr/share/OVMF/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/edk2/ovmf/OVMF_CODE.fd \
             /usr/share/edk2-ovmf/x64/OVMF_CODE.fd /usr/share/qemu/OVMF.fd; do
        [ -f "$f" ] && { ovmf=$f; break; }
    done
fi
[ -n "$ovmf" ] || { echo "OVMF firmware not found; install ovmf or set OVMF=/path/OVMF_CODE.fd" >&2; exit 1; }

accel=()
[ -w /dev/kvm ] && accel=(-enable-kvm -cpu host) || accel=(-cpu max)

if [ $usb = 1 ]; then
    disk=(-device qemu-xhci,id=xhci
          -drive if=none,id=stick,file="$img",format=raw
          -device usb-storage,bus=xhci.0,drive=stick,bootindex=0,removable=on)
else
    disk=(-drive file="$img",format=raw,if=virtio -device qemu-xhci)
fi

exec qemu-system-x86_64 "${accel[@]}" -smp 4 -m 2G \
    -drive if=pflash,format=raw,readonly=on,file="$ovmf" \
    "${disk[@]}" \
    -device virtio-vga -device usb-kbd -device usb-mouse \
    -nic none
