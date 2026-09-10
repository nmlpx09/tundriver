/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - tun_struct definition
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#ifndef TYPES_H
#define TYPES_H

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <net/dst_cache.h>

#include <ips/types.h>

struct tun_struct {
    struct net_device* dev;

    struct socket* sock;

    struct ips_storage* ips;

    struct dst_cache dst_cache;

    struct napi_struct napi;
    struct sk_buff_head rx_queue;

    __be32 dip;
    __be16 dport;
};

#endif
