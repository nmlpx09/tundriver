#!/bin/bash

set -exu

TUN_DEVICE=tnet0
TUN_IP=10.0.3.1

OUT_DEVICE=`ip route get 1.1.1.1 | head -1 | cut -d ' ' -f 5`
SRC_PORT=69

MODULE=tnet

function check_sudo {
    if [ $EUID -ne 0 ]; then
        echo "run on sudo"
        exit 1
    fi
}

function check_interface {
    ip link show $TUN_DEVICE &> /dev/null || return 1
    return 0
}

function add_rules {
    ip address add $TUN_IP/24 dev $TUN_DEVICE
    ip link set $TUN_DEVICE up

    sysctl net.ipv4.ip_forward=1

    iptables -t nat -A POSTROUTING -s $TUN_IP/24 -o $OUT_DEVICE -j MASQUERADE
}

function remove_rules {
    iptables -t nat -D POSTROUTING -s $TUN_IP/24 -o $OUT_DEVICE -j MASQUERADE
    sysctl net.ipv4.ip_forward=0
}

function check_vars {
    local empty_vars=()

    [[ -z $TUN_DEVICE ]] && empty_vars+=(TUN_DEVICE)
    [[ -z $TUN_IP ]]     && empty_vars+=(TUN_IP)
    [[ -z $OUT_DEVICE ]] && empty_vars+=(OUT_DEVICE)
    [[ -z $SRC_PORT ]] && empty_vars+=(SRC_PORT)
    [[ -z $MODULE ]]     && empty_vars+=(MODULE)

    if [[ ${#empty_vars[@]} -gt 0 ]]; then
        echo "empty vars: ${empty_vars[*]}"
        exit 1
    fi
}

check_sudo
check_vars

case $1 in
    "c")
        check_interface && echo "interface $TUN_DEVICE exists" && exit 1

        modprobe $MODULE src_port=$SRC_PORT

        add_rules
        ;;

    "d")
        ! check_interface && echo "interface $TUN_DEVICE not exists" && exit 1

        modprobe -r $MODULE

        remove_rules
        ;;

    "r")
        ! check_interface && echo "interface $TUN_DEVICE not exists" && exit 1

        modprobe -r $MODULE
        modprobe $MODULE src_port=$SRC_PORT

        add_rules

        ;;
    *)
        echo "Usage: $0 {c|d}"
        ;;
esac
