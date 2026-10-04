/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - tun_ctx definition
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#ifndef TYPES_H
#define TYPES_H

#include <linux/netdevice.h>
#include <linux/ptr_ring.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <net/dst_cache.h>

#include <ips/types.h>

struct worker {
    void* ptr;
    struct work_struct work;
};

struct work_ctx {
    struct ptr_ring ring;
    struct workqueue_struct* wq;
    struct worker __percpu* workers;
    int last_cpu;
};

struct tun_ctx {
    struct net_device* dev;

    struct socket* sock;

    struct ips_storage* ips;

    struct dst_cache dst_cache;

    struct work_ctx tx;
    struct work_ctx rx;

    __be32 tip;
    __be16 tport;
};

#endif
