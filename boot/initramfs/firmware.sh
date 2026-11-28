#!/bin/sh
# KOS pre-boot firmware gate. Sourced by /init (as /firmware.sh) before the disk
# is touched. Same rule as kos/firmware.py, which runs again once the OS is up:
# if a management processor (Intel ME, AMD PSP, a BMC) is running and not
# provably off, the machine does not boot.
#
# Besides the ME/PSP/BMC, any other chip with its own firmware (Thunderbolt, USB-C
# port controller, EC, NIC, GPU, NVMe, wireless) also stops the boot; there is no
# resident checker, this runs once.
#
# Honest limits (see kos/firmware.py for the long version): the OS cannot switch
# these off. All this does is detach the OS from them. "Off" is only believed for
# an Intel ME whose own status register says "disabled".
#
# FW_ROOT is a prefix for every path it reads (empty in the real pre-boot
# environment; the tests point it at a fake sysfs). Needs only busybox: sh,
# cat, echo, od.

FW_ROOT=${FW_ROOT:-}
FW_ALLOW=${FW_ALLOW:-/firmware.allow}    # the owner's allow list, inside the signed image
fw_active=0
fw_pci=""
fw_kinds=""

# Load "pci VVVV:DDDD" and "kind NAME" lines. Unknown lines allow nothing.
fw_load_allow() {
    fw_pci=" "; fw_kinds=" "
    [ -r "$FW_ALLOW" ] || return 0
    while read -r fw_a fw_b fw_rest; do
        case "$fw_a:$fw_b" in
            pci:?*)   # lowercase hex, "0x" optional on either half
                fw_b=${fw_b#0x}
                case "$fw_b" in *:0x*) fw_b="${fw_b%%:*}:${fw_b#*:0x}" ;; esac
                fw_pci="$fw_pci$fw_b " ;;
            kind:?*) fw_kinds="$fw_kinds$fw_b " ;;
        esac
    done < "$FW_ALLOW"
}

# fw_emit KIND STATE PATH: prints the finding; an owner-allowed active chip becomes "allowed".
fw_emit() {
    fw_st=$2
    if [ "$fw_st" = active ]; then
        case "$fw_pci" in *" $fw_id "*) fw_st=allowed ;; esac
        case "$fw_kinds" in *" $1 "*) fw_st=allowed ;; esac
    fi
    echo "FINDING $1 $fw_st $3"
    if [ "$fw_st" = active ]; then fw_active=1; fi
    if [ "$fw_st" = active ] || [ "$fw_st" = allowed ]; then fw_dma=1; fi   # allowed chips still do DMA
}

fw_read() {
    fw_val=""
    if [ -r "$1" ]; then read -r fw_val < "$1" || true; fi
}

# Prints one machine-readable line per finding:  FINDING <kind> <state> <path>
# and sets fw_active=1 if any is running. Never run in a subshell.
kos_firmware_scan() {
    fw_active=0
    fw_vm=0
    if [ -r "$FW_ROOT/proc/cpuinfo" ]; then
        while read -r fw_l; do
            case "$fw_l" in flags*" hypervisor"*) fw_vm=1; break ;; esac
        done < "$FW_ROOT/proc/cpuinfo"
    fi
    fw_dma=0
    fw_load_allow
    fw_id=""
    for dev in "$FW_ROOT"/sys/bus/pci/devices/*; do
        [ -e "$dev/vendor" ] || continue
        fw_read "$dev/vendor"; fw_v=$fw_val
        fw_read "$dev/class";  fw_c=$fw_val
        fw_read "$dev/device"; fw_id="${fw_v#0x}:${fw_val#0x}"
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
                    fw_emit intel-me neutralized "$rel"
                else
                    fw_emit intel-me active "$rel"
                fi
                ;;
            0x1022:0x1080*)
                fw_emit amd-psp active "$rel"
                ;;
            *:0x0c0340*) fw_kind=thunderbolt ;;
            *:0x02*) fw_kind=network ;;
            *:0x03*) fw_kind=display ;;
            *:0x0108*) fw_kind=nvme ;;
            *:0x0d*) fw_kind=wireless ;;
        esac
        if [ -n "$fw_kind" ]; then
            if [ "$fw_vm" -eq 0 ]; then
                fw_off=0
                case "$fw_kind" in
                    thunderbolt|wireless)   # optional peripherals: believed off only if D3cold
                        fw_read "$dev/power_state"
                        case "$fw_val" in D3cold|d3cold) fw_off=1 ;; esac ;;
                esac
                if [ "$fw_off" -eq 1 ]; then
                    fw_emit "$fw_kind" neutralized "$rel"
                else
                    fw_emit "$fw_kind" active "$rel"
                fi
            fi
            fw_kind=""
        fi
    done
    if [ "$fw_vm" -eq 0 ]; then
        for pair in typec-port:sys/class/typec/port* embedded-controller:sys/bus/acpi/devices/PNP0C09* \
                    thunderbolt:sys/bus/thunderbolt/devices/domain*; do
            for n in "$FW_ROOT"/${pair#*:}; do
                [ -e "$n" ] || continue
                fw_id=""; fw_save=$fw_dma
                fw_emit "${pair%%:*}" active "${n#"$FW_ROOT"/}"
                case "${pair%%:*}" in thunderbolt) ;; *) fw_dma=$fw_save ;; esac   # only Thunderbolt counts as DMA here
                break
            done
        done
    fi
    for n in "$FW_ROOT"/dev/ipmi* "$FW_ROOT"/dev/ipmi/* "$FW_ROOT"/sys/class/ipmi/ipmi* \
             "$FW_ROOT"/sys/firmware/dmi/entries/38-*; do
        [ -e "$n" ] || continue
        fw_id=""; fw_save=$fw_dma
        fw_emit bmc-ipmi active "${n#"$FW_ROOT"/}"
        fw_dma=$fw_save
        break
    done
    # kos.machine=framework (signed command line): boot only on Framework hardware
    fw_cl=""
    if [ -r "$FW_ROOT/proc/cmdline" ]; then read -r fw_cl < "$FW_ROOT/proc/cmdline" || true; fi
    case " $fw_cl " in
        *" kos.machine=framework "*)
            fw_read "$FW_ROOT/sys/class/dmi/id/sys_vendor"
            case "$fw_val" in
                Framework|framework) ;;
                *) echo "FINDING wrong-machine active sys/class/dmi/id/sys_vendor"; fw_active=1 ;;
            esac ;;
    esac
    if [ "$fw_dma" -eq 1 ] || [ -e "$FW_ROOT"/sys/bus/thunderbolt/devices/domain0 ]; then
        fw_grp=0
        for g in "$FW_ROOT"/sys/kernel/iommu_groups/*; do
            [ -e "$g" ] && fw_grp=1 && break
        done
        if [ "$fw_grp" -eq 0 ]; then
            echo "FINDING no-iommu active sys/kernel/iommu_groups"
            fw_active=1
        fi
    fi
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
            *:0x0c0340*|*:0x0d*)   # Thunderbolt/USB4, wireless: unbind and ask for D3cold
                if [ -e "$dev/driver" ]; then
                    echo "${dev##*/}" > "$dev/driver/unbind" 2>/dev/null || true
                fi
                echo kos-none > "$dev/driver_override" 2>/dev/null || true
                echo 1 > "$dev/d3cold_allowed" 2>/dev/null || true
                echo auto > "$dev/power/control" 2>/dev/null || true
                echo "kos-preboot: asked ${dev##*/} to power down (believed off only if it reads D3cold)"
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
    echo "kos-preboot: WARNING - chips with their own firmware (Intel ME, AMD PSP, BMC, Thunderbolt,"
    echo "kos-preboot: USB-C, EC, network, GPU, NVMe, wireless) run outside the OS's control."
    echo "kos-preboot: KOS cannot see inside them or stop what they do."
    fw_detach
    kos_firmware_scan >/dev/null     # the second look decides: did anything actually go off?
    if [ "$fw_active" -eq 0 ]; then
        echo "kos-preboot: everything that was running is now verifiably off."
        return 0
    fi
    if [ "$fw_policy" = warn ]; then
        echo "kos-preboot: kos.firmware=warn - continuing anyway."
        return 0
    fi
    echo "kos-preboot: the OS does not have complete control of this machine."
    return 1
}
