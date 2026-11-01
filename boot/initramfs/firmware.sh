#!/bin/sh
# KOS pre-boot firmware gate. Sourced by /init (as /firmware.sh) before the disk
# is touched. Same rule as kos/firmware.py, which runs again once the OS is up:
# if a management processor (Intel ME, AMD PSP, a BMC) is running and not
# provably off, the machine does not boot.
#
# Honest limits (see kos/firmware.py for the long version): the OS cannot switch
# these off. All this does is detach the OS from them. "Off" is only believed for
# an Intel ME whose own status register says "disabled".
#
# FW_ROOT is a prefix for every path it reads (empty in the real pre-boot
# environment; the tests point it at a fake sysfs). Needs only busybox: sh,
# cat, echo, od.

FW_ROOT=${FW_ROOT:-}
fw_active=0

fw_read() {
    fw_val=""
    if [ -r "$1" ]; then read -r fw_val < "$1" || true; fi
}

# Prints one machine-readable line per finding:  FINDING <kind> <state> <path>
# and sets fw_active=1 if any is running. Never run in a subshell.
kos_firmware_scan() {
    fw_active=0
    for dev in "$FW_ROOT"/sys/bus/pci/devices/*; do
        [ -e "$dev/vendor" ] || continue
        fw_read "$dev/vendor"; fw_v=$fw_val
        fw_read "$dev/class";  fw_c=$fw_val
        rel=${dev#"$FW_ROOT"/}
        case "$fw_v:$fw_c" in
            0x8086:0x0780*)
                # HFSTS1 (config offset 0x40), bits 19:16 = operation mode;
                # 3 means disabled. Unreadable or anything else = running.
                fw_mode=""
                fw_bytes=$(od -An -tx1 -j64 -N4 "$dev/config" 2>/dev/null || true)
                set -- $fw_bytes
                if [ $# -eq 4 ]; then fw_mode=$((0x$3 & 15)); fi
                if [ "$fw_mode" = 3 ]; then
                    echo "FINDING intel-me neutralized $rel"
                else
                    echo "FINDING intel-me active $rel"
                    fw_active=1
                fi
                ;;
            0x1022:0x1080*)
                echo "FINDING amd-psp active $rel"
                fw_active=1
                ;;
        esac
    done
    for n in "$FW_ROOT"/dev/ipmi* "$FW_ROOT"/dev/ipmi/* "$FW_ROOT"/sys/class/ipmi/ipmi* \
             "$FW_ROOT"/sys/firmware/dmi/entries/38-*; do
        [ -e "$n" ] || continue
        echo "FINDING bmc-ipmi active ${n#"$FW_ROOT"/}"
        fw_active=1
        break
    done
}

# kos.firmware=enforce (default; any unknown value too) | warn
kos_firmware_policy() {
    fw_policy=enforce
    fw_line=""
    if [ -r "$FW_ROOT/proc/cmdline" ]; then read -r fw_line < "$FW_ROOT/proc/cmdline" || true; fi
    for fw_w in $fw_line; do
        case "$fw_w" in
            kos.firmware=warn) fw_policy=warn ;;
            kos.firmware=*) fw_policy=enforce ;;
        esac
    done
}

# Best effort: unbind the OS driver from each running PCI management function.
# The thing keeps running; we only stop this kernel talking to it.
fw_detach() {
    for dev in "$FW_ROOT"/sys/bus/pci/devices/*; do
        [ -e "$dev/vendor" ] || continue
        fw_read "$dev/vendor"; fw_v=$fw_val
        fw_read "$dev/class";  fw_c=$fw_val
        case "$fw_v:$fw_c" in
            0x8086:0x0780*|0x1022:0x1080*)
                if [ -e "$dev/driver" ]; then
                    echo "${dev##*/}" > "$dev/driver/unbind" 2>/dev/null \
                        && echo "kos-preboot: detached the OS from ${dev##*/} (it is still running)"
                fi
                echo kos-none > "$dev/driver_override" 2>/dev/null || true
                ;;
        esac
    done
}

# Returns 0 if the machine may boot, 1 if it must not.
kos_firmware_gate() {
    kos_firmware_scan
    [ "$fw_active" -eq 0 ] && return 0
    kos_firmware_policy
    echo
    echo "kos-preboot: WARNING - this machine has a management processor running below the OS"
    echo "kos-preboot: (Intel ME / AMD PSP / BMC). KOS cannot see or stop what it does."
    fw_detach
    if [ "$fw_policy" = warn ]; then
        echo "kos-preboot: kos.firmware=warn - continuing anyway."
        return 0
    fi
    echo "kos-preboot: the OS does not have complete control of this machine."
    return 1
}
