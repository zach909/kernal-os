#!/bin/bash
# Boot a KOS image in QEMU with UEFI firmware (OVMF), a framebuffer, and a
# USB keyboard/mouse so graphical mode and device booting can be tried.
#   image/run-qemu.sh kos.img
set -euo pipefail
img=${1:?usage: run-qemu.sh kos.img}
ovmf=${OVMF:-/usr/share/OVMF/OVMF_CODE.fd}
exec qemu-system-x86_64 -enable-kvm -cpu host -smp 4 -m 2G \
    -drive if=pflash,format=raw,readonly=on,file="$ovmf" \
    -drive file="$img",format=raw,if=virtio \
    -device virtio-vga -device qemu-xhci -device usb-kbd -device usb-mouse \
    -nic none
