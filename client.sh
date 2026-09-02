#!/bin/bash

set -exu

DEST_IP=139.60.162.149
DEST_PORT=69

TUN_DEVICE=tnet0
TUN_IP=10.0.3.2

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

    ip route add $DEST_IP `ip route | grep '^default' | cut -d ' ' -f 2-`
    ip route add 128.0.0.0/1 dev $TUN_DEVICE
    ip route add 0.0.0.0/1 dev $TUN_DEVICE
}

function remove_rules {
    ip route del $DEST_IP
}

function check_vars {
    local empty_vars=()

    [[ -z $DEST_IP ]]   && empty_vars+=(DEST_IP)
    [[ -z $DEST_PORT ]] && empty_vars+=(DEST_PORT)
    [[ -z $TUN_DEVICE ]]  && empty_vars+=(TUN_DEVICE)
    [[ -z $TUN_IP ]]      && empty_vars+=(TUN_IP)
    [[ -z $MODULE ]]      && empty_vars+=(MODULE)

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

        modprobe $MODULE dest_ip=$DEST_IP dest_port=$DEST_PORT

        add_rules
        ;;

    "d")
        ! check_interface && echo "interface $TUN_DEVICE not exists" && exit 1

        modprobe -r $MODULE

        remove_rules || :
        ;;
    *)
        echo "Usage: $0 {c|d}"
        ;;
esac
