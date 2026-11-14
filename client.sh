#!/bin/sh

set -eu

DEST_IP=
DEST_PORT=69
KEY=

TUN_DEVICE=tnet0
TUN_IP=10.0.3.2

MODULE=tnet

check_sudo() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "run as root" >&2
        exit 1
    fi
}
check_interface() {
    ip link show "$TUN_DEVICE" > /dev/null 2>&1
}

add_rules() {
    ip address add "$TUN_IP"/24 dev "$TUN_DEVICE" || return 1
    ip link set "$TUN_DEVICE" up || return 1

    ip route add "$DEST_IP" via "$(ip route show default | awk '{print $3; exit}')" || return 1
    ip route add 128.0.0.0/1 dev "$TUN_DEVICE" || return 1
    ip route add 0.0.0.0/1 dev "$TUN_DEVICE" || return 1
}

remove_rules() {
    ip route del 128.0.0.0/1 dev "$TUN_DEVICE" || :
    ip route del 0.0.0.0/1 dev "$TUN_DEVICE" || :
    ip route del "$DEST_IP" || :
}

check_vars() {
    empty_vars=""

    [ -z "$DEST_IP" ]    && empty_vars="$empty_vars DEST_IP"
    [ -z "$DEST_PORT" ]  && empty_vars="$empty_vars DEST_PORT"
    [ -z "$TUN_DEVICE" ] && empty_vars="$empty_vars TUN_DEVICE"
    [ -z "$TUN_IP" ]     && empty_vars="$empty_vars TUN_IP"
    [ -z "$MODULE" ]     && empty_vars="$empty_vars MODULE"
    [ -z "$KEY" ]        && empty_vars="$empty_vars KEY"

    if [ -n "$empty_vars" ]; then
        echo "empty vars:$empty_vars"
        exit 1
    fi
}

check_sudo
check_vars

case "${1:-}" in
    "c")
        if check_interface; then
            echo "interface $TUN_DEVICE exists" >&2
            exit 1
        fi

        modprobe "$MODULE" dest_ip="$DEST_IP" dest_port="$DEST_PORT" key="$KEY"

        if ! add_rules; then
            echo "unsuccess add_rules" >&2
            remove_rules
            modprobe -r "$MODULE"
            exit 1
        fi
        ;;

    "d")
        if ! check_interface; then
            echo "interface $TUN_DEVICE not exists" >&2
            exit 1
        fi

        remove_rules
        modprobe -r "$MODULE"
        ;;
    *)
        echo "usage: $0 {c|d}"
        ;;
esac
