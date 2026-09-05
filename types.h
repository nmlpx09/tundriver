/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - tun_struct definition
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#ifndef TYPES_H
#define TYPES_H

#include <linux/kfifo.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include <ips/types.h>

struct tun_struct {
    struct net_device* dev;

    struct socket* sock;

    struct workqueue_struct* wq;

    DECLARE_KFIFO_PTR(tx_fifo, struct sk_buff*);
    spinlock_t tx_lock;
    struct work_struct tx_work;

    DECLARE_KFIFO_PTR(rx_fifo, struct sk_buff*);
    spinlock_t rx_lock;
    struct work_struct rx_work;

    struct ips_storage* ips;

    __be32 dip;
    __be16 dport;
};

#endif
