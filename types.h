/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - tun_struct definition
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#ifndef TYPES_H
#define TYPES_H

#include <linux/netdevice.h>
#include <linux/kfifo.h>
#include <linux/socket.h>
#include <linux/types.h>

#include <ips/types.h>

#define MAX_BUFFER_SIZE 1472

struct tun_struct {
    struct net_device* dev;

    struct socket* sock;
    u8 srb[MAX_BUFFER_SIZE];

    struct workqueue_struct* wq;

    DECLARE_KFIFO_PTR(tx_fifo, struct sk_buff*);
    spinlock_t tx_lock;
    struct work_struct tx_work;

    struct work_struct rx_work;
    void (*orig_data_ready)(struct sock* sk);

    u8 encrb[MAX_BUFFER_SIZE];
    u8 decrb[MAX_BUFFER_SIZE];

    struct ips_storage* ips;

    __be32 dip;
    __be16 dport;
};

#endif
