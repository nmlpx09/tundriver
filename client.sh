#!/bin/bash

set -exu

REMOTE_IP=66.248.207.187
REMOTE_PORT=69

TUN_DEVICE=tnet0
TUN_IP=10.0.3.2
TUN_MTU=1472

MODULE=tnet.ko

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

    ip route add $REMOTE_IP `ip route | grep '^default' | cut -d ' ' -f 2-`
    ip route add 128.0.0.0/1 dev $TUN_DEVICE
    ip route add 0.0.0.0/1 dev $TUN_DEVICE
}

function remove_rules {
    ip route del $REMOTE_IP
}

function check_vars {
    local empty_vars=()

    [[ -z $REMOTE_IP ]]   && empty_vars+=(REMOTE_IP)
    [[ -z $REMOTE_PORT ]] && empty_vars+=(REMOTE_PORT)
    [[ -z $TUN_DEVICE ]]  && empty_vars+=(TUN_DEVICE)
    [[ -z $TUN_IP ]]      && empty_vars+=(TUN_IP)
    [[ -z $TUN_MTU ]]     && empty_vars+=(TUN_MTU)
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

        insmod $MODULE dest_ip=$REMOTE_IP dest_port=$REMOTE_PORT src_port=0

        if [ $? -ne 0 ]; then
            echo "tun not start"
            remove_rules
            exit 1
        fi

        add_rules
        ;;

    "d")
        ! check_interface && echo "interface $TUN_DEVICE not exists" && exit 1

        rmmod $MODULE

        remove_rules || :
        ;;
    *)
        echo "Usage: $0 {c|d}"
        ;;
esac
