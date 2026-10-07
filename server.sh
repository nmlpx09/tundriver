#!/bin/bash

set -exu

TUN_DEVICE=tnet0
TUN_IP=10.0.3.1

OUT_DEVICE=$(ip -o route get 1.1.1.1 | awk '{for(i=1; i<=NF; i++) if($i=="dev") print $(i+1)}')
SRC_PORT=69
KEY=

MODULE=tnet

check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo "run on sudo"
        exit 1
    fi
}

check_interface() {
    ip link show "$TUN_DEVICE" &> /dev/null || return 1
    return 0
}

add_rules() {
    ip address add "$TUN_IP"/24 dev "$TUN_DEVICE" || return 1
    ip link set "$TUN_DEVICE" up  || return 1

    sysctl net.ipv4.ip_forward=1  || return 1

    iptables -w -t nat -A POSTROUTING -s "$TUN_IP"/24 -o "$OUT_DEVICE" -j MASQUERADE  || return 1
    return 0
}

remove_rules() {
    iptables -w -t nat -D POSTROUTING -s "$TUN_IP"/24 -o "$OUT_DEVICE" -j MASQUERADE || :
}

check_vars() {
    local empty_vars=()

    [[ -z "$TUN_DEVICE" ]] && empty_vars+=(TUN_DEVICE)
    [[ -z "$TUN_IP" ]]     && empty_vars+=(TUN_IP)
    [[ -z "$OUT_DEVICE" ]] && empty_vars+=(OUT_DEVICE)
    [[ -z "$SRC_PORT" ]]   && empty_vars+=(SRC_PORT)
    [[ -z "$MODULE" ]]     && empty_vars+=(MODULE)
    [[ -z "$KEY" ]]        && empty_vars+=(KEY)

    if [[ ${#empty_vars[@]} -gt 0 ]]; then
        echo "empty vars: ${empty_vars[*]}"
        exit 1
    fi
}

check_sudo
check_vars

case "${1:-}" in
    "c")
        check_interface && echo "interface $TUN_DEVICE exists" && exit 1

        modprobe "$MODULE" src_port="$SRC_PORT" key="$KEY"

        if ! add_rules; then
            echo "unsuccess add_rules"
            remove_rules
            modprobe -r "$MODULE"
            exit 1
        fi
        ;;

    "d")
        ! check_interface && echo "interface $TUN_DEVICE not exists" && exit 1

        remove_rules
        modprobe -r "$MODULE"
        ;;
    *)
        echo "usage: $0 {c|d}"
        ;;
esac
