/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - tun_struct definition
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#ifndef TYPES_H
#define TYPES_H

#include <linux/netdevice.h>
#include <linux/ptr_ring.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <net/dst_cache.h>

#include <ips/types.h>

struct worker {
    void* ptr;
    struct work_struct work;
};

struct tun_struct {
    struct net_device* dev;

    struct socket* sock;

    struct ips_storage* ips;

    struct dst_cache dst_cache;

    struct ptr_ring tx_ring;
    struct workqueue_struct* tx_wq;
    struct worker __percpu* tx_workers;
    int tx_last_cpu;

    struct ptr_ring rx_ring;
    struct workqueue_struct* rx_wq;
    struct worker __percpu* rx_workers;
    int rx_last_cpu;

    __be32 tip;
    __be16 tport;
};

#endif
