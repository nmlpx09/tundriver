#ifndef TYPES_H
#define TYPES_H

#include <linux/netdevice.h>
#include <linux/kfifo.h>
#include <linux/socket.h>
#include <linux/types.h>

struct dest_addr {
    __be32 ip;
    __be16 port;
};

struct tun_priv {
    struct net_device *dev;

    struct socket *sock;

    DECLARE_KFIFO_PTR(send_fifo, struct sk_buff *);
    spinlock_t send_lock;
    struct work_struct send_work;

    struct work_struct recv_work;
    void (*orig_data_ready)(struct sock *sk);

   struct  dest_addr dest;
};

#endif
