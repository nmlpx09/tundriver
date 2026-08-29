// SPDX-License-Identifier: GPL-2.0
/*
 * tnet - virtual network interface over encrypted UDP tunnels
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <net/sock.h>

#include <crypt/impl.h>
#include <ips/impl.h>
#include <sock/impl.h>
#include <utils/impl.h>

#include "types.h"

#define DEV_NAME "tnet%d"
#define MTU MAX_BUFFER_SIZE
#define SEND_FIFO_SIZE 4096

static char* dest_ip = "0.0.0.0";
static int dest_port = 1;
static int src_port = 0;

module_param(dest_ip, charp, 0444);
MODULE_PARM_DESC(dest_ip, "Destination IP address");
module_param(dest_port, int, 0444);
MODULE_PARM_DESC(dest_port, "Destination UDP port");
module_param(src_port, int, 0444);
MODULE_PARM_DESC(src_port, "Source UDP port");

static struct net_device* tdev;

static void tx(struct work_struct* work)
{
    struct tun_struct* tun = container_of(work, struct tun_struct, tx_work);
    struct sk_buff* skb = NULL;
    unsigned long flags = 0;

    while (true) {
        struct net_device* dev = tun->dev;

        if (unlikely(!netif_running(dev))) {
            break;
        }

        struct socket* sock = READ_ONCE(tun->sock);

        if (unlikely(!sock)) {
            break;
        }

        spin_lock_irqsave(&tun->tx_lock, flags);
        if (unlikely(!kfifo_get(&tun->tx_fifo, &skb))) {
            spin_unlock_irqrestore(&tun->tx_lock, flags);
            break;
        }
        spin_unlock_irqrestore(&tun->tx_lock, flags);

        if (unlikely(skb->len < ETH_HLEN)) {
            dev->stats.tx_errors++;
            dev_kfree_skb_any(skb);
            continue;
        }

        if (unlikely(skb_linearize(skb))) {
            dev->stats.tx_errors++;
            dev_kfree_skb_any(skb);
            continue;
        }

        u8* buf = skb->data + ETH_HLEN;
        size_t bufl = skb->len - ETH_HLEN;

        if (unlikely(!valid_ipv4_packet(buf, bufl))) {
            dev->stats.tx_dropped++;
            dev_kfree_skb_any(skb);
            continue;
        }

    #ifdef SERVER
        __be32 ip = get_dst_ip_from_ipv4_packet(buf, bufl);
        if (unlikely(!ip)) {
            dev->stats.tx_dropped++;
            dev_kfree_skb_any(skb);
            continue;
        }

        rcu_read_lock();

        struct ips_storage* ips = READ_ONCE(tun->ips);

        if (unlikely(!ips)) {
            dev->stats.tx_errors++;
            dev_kfree_skb_any(skb);
            rcu_read_unlock();
            break;
        }

        struct ips_entry* entry = ips_get(ips, ip);

        if (unlikely(IS_ERR_OR_NULL(entry))) {
            dev->stats.tx_errors++;
            dev_kfree_skb_any(skb);
            rcu_read_unlock();
            continue;
        }

        __be32 dip = READ_ONCE(entry->ip);
        __be16 dport = READ_ONCE(entry->port);
        rcu_read_unlock();
    #else
        __be32 dip = tun->dip;
        __be16 dport = tun->dport;
    #endif

        int enl = encrypt(tun->encrb, sizeof(tun->encrb), buf, bufl);

        if (unlikely(enl <= 0)) {
            dev->stats.tx_errors++;
            dev_kfree_skb_any(skb);
            continue;
        }

        int swl = sock_write(sock, tun->encrb, enl, dip, dport);

        if (unlikely(swl < 0)) {
            dev->stats.tx_errors++;
        } else {
            dev->stats.tx_packets++;
            dev->stats.tx_bytes += swl;
        }

        dev_kfree_skb_any(skb);
    }
}

static void rx(struct work_struct* work)
{
    struct tun_struct* tun = container_of(work, struct tun_struct, rx_work);
    __be32 tip = 0;
    __be16 tport = 0;

    while (true) {
        struct net_device* dev = tun->dev;

        if (unlikely(!netif_running(dev))) {
            break;
        }

        struct socket* sock = READ_ONCE(tun->sock);

        if (unlikely(!sock)) {
            break;
        }

        int srl = sock_read(sock, tun->srb, sizeof(tun->srb), &tip, &tport);

        if (unlikely(srl < 0)) {
            dev->stats.rx_errors++;
            break;
        } else if (unlikely(srl == 0)) {
            break;
        }

        int dcl = decrypt(tun->decrb, sizeof(tun->decrb), tun->srb, srl);

        if (unlikely(dcl <= 0)) {
            dev->stats.rx_errors++;
            continue;
        }

        if (unlikely(!valid_ipv4_packet(tun->decrb, dcl))) {
            dev->stats.rx_dropped++;
            continue;
        }

    #ifdef SERVER
        __be32 sip = get_src_ip_from_ipv4_packet(tun->decrb, dcl);
        if (unlikely(!sip)) {
            dev->stats.rx_dropped++;
            continue;
        }

        struct ips_storage* ips = READ_ONCE(tun->ips);

        if (unlikely(!ips)) {
            dev->stats.rx_errors++;
            break;
        }

        ips_add(ips, sip, tip, tport);
    #endif

        struct sk_buff* skb = netdev_alloc_skb(dev, dcl + ETH_HLEN + NET_IP_ALIGN);
        if (unlikely(!skb)) {
            dev->stats.rx_errors++;
            continue;
        }

        skb_reserve(skb, NET_IP_ALIGN);

        struct ethhdr* eth = skb_put(skb, ETH_HLEN);
        memcpy(eth->h_dest, dev->dev_addr, ETH_ALEN);
        memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
        eth->h_proto = htons(ETH_P_IP);

        skb_put_data(skb, tun->decrb, dcl);

        skb->dev = dev;
        skb->protocol = eth_type_trans(skb, dev);
        skb->ip_summed = CHECKSUM_UNNECESSARY;

        dev->stats.rx_packets++;
        dev->stats.rx_bytes += skb->len;

        netif_rx(skb);
    }
}

static void dready(struct sock* sk)
{
    struct tun_struct* tun = READ_ONCE(sk->sk_user_data);
    if (likely(tun)) {
        schedule_work(&tun->rx_work);
    }
}

static int dopen(struct net_device* dev)
{
    netif_carrier_on(dev);
    netif_start_queue(dev);
    pr_info("tnet: device opened\n");
    return 0;
}

static int dstop(struct net_device* dev)
{
    struct tun_struct* tun = netdev_priv(dev);
    struct sk_buff* skb;

    netif_stop_queue(dev);
    netif_carrier_off(dev);

    cancel_work_sync(&tun->tx_work);
    cancel_work_sync(&tun->rx_work);

    unsigned long flags = 0;
    spin_lock_irqsave(&tun->tx_lock, flags);
    while (kfifo_get(&tun->tx_fifo, &skb)) {
        dev_kfree_skb_any(skb);
    }
    spin_unlock_irqrestore(&tun->tx_lock, flags);

    pr_info("tnet: device stopped\n");
    return 0;
}

static netdev_tx_t dsxmit(struct sk_buff* skb, struct net_device* dev)
{
    struct tun_struct* tun = netdev_priv(dev);
    unsigned long flags;

    spin_lock_irqsave(&tun->tx_lock, flags);
    if (unlikely(kfifo_is_full(&tun->tx_fifo))) {
        spin_unlock_irqrestore(&tun->tx_lock, flags);
        dev_kfree_skb_any(skb);
        dev->stats.tx_dropped++;
        return NETDEV_TX_OK;
    }

    kfifo_put(&tun->tx_fifo, skb);

    spin_unlock_irqrestore(&tun->tx_lock, flags);

    schedule_work(&tun->tx_work);

    return NETDEV_TX_OK;
}

static const struct net_device_ops ops = {
    .ndo_open       = dopen,
    .ndo_stop       = dstop,
    .ndo_start_xmit = dsxmit,
};

static void dsetup(struct net_device* dev)
{
    ether_setup(dev);

    dev->netdev_ops = &ops;
    dev->flags |= IFF_NOARP;
    dev->flags &= ~IFF_MULTICAST;
    dev->features &= ~NETIF_F_IP_CSUM;
    dev->features &= ~NETIF_F_IPV6_CSUM;
    dev->features &= ~NETIF_F_TSO;
    dev->features &= ~NETIF_F_GSO;
    dev->features &= ~NETIF_F_GRO;
    dev->mtu = MTU;

    eth_hw_addr_random(dev);
}

static int __init minit(void)
{
    __be32 dip;
    int err;

    if (!in4_pton(dest_ip, -1, (u8*)&dip, -1, NULL)) {
        pr_err("tnet: invalid dest_ip: %s\n", dest_ip);
        return -EINVAL;
    }

    if (dest_port < 1 || dest_port > 65535) {
        pr_err("tnet: invalid dest_port: %d (must be 1-65535)\n", dest_port);
        return -EINVAL;
    }

    if (src_port < 0 || src_port > 65535) {
        pr_err("tnet: invalid src_port: %d (must be 0-65535)\n", src_port);
        return -EINVAL;
    }

    tdev = alloc_netdev(sizeof(struct tun_struct), DEV_NAME, NET_NAME_UNKNOWN, dsetup);
    if (!tdev) {
        pr_err("tnet: failed to allocate net device\n");
        return -ENOMEM;
    }

    struct tun_struct* tun = netdev_priv(tdev);

    tun->dev = tdev;
    tun->dip = dip;
    tun->dport = htons(dest_port);

    spin_lock_init(&tun->tx_lock);
    INIT_KFIFO(tun->tx_fifo);
    INIT_WORK(&tun->tx_work, tx);
    INIT_WORK(&tun->rx_work, rx);

    struct socket* sock = sock_init(htons(src_port));
    if (IS_ERR(sock)) {
        err = PTR_ERR(sock);
        pr_err("tnet: sock init failed: %d\n", err);
        goto err_netdev;
    }

    WRITE_ONCE(tun->sock, sock);

    struct ips_storage* ips = ips_init();
    if (IS_ERR(ips)) {
        err = PTR_ERR(ips);
        pr_err("tnet: ips init failed: %d\n", err);
        goto err_sock;
    }

    WRITE_ONCE(tun->ips, ips);

    err = kfifo_alloc(&tun->tx_fifo, SEND_FIFO_SIZE, GFP_KERNEL);
    if (err) {
        pr_err("tnet: failed to allocate tx fifo: %d\n", err);
        goto err_ips;
    }

    err = register_netdev(tdev);
    if (err) {
        pr_err("tnet: failed to register net device: %d\n", err);
        goto err_fifo;
    }

    struct sock* sk = tun->sock->sk;
    write_lock_bh(&sk->sk_callback_lock);
    tun->orig_data_ready = sk->sk_data_ready;
    sk->sk_data_ready = dready;
    sk->sk_user_data = tun;
    write_unlock_bh(&sk->sk_callback_lock);

    pr_info("tnet: module loaded, device %s registered\n", tdev->name);
    return 0;

err_fifo:
    kfifo_free(&tun->tx_fifo);
err_ips:
    ips_close(tun->ips);
err_sock:
    sock_close(tun->sock);
err_netdev:
    free_netdev(tdev);
    return err;
}

static void __exit mexit(void)
{
    if (!tdev) {
        return;
    }

    struct tun_struct* tun = netdev_priv(tdev);
    struct socket* sock = READ_ONCE(tun->sock);

    if (sock) {
        struct sock* sk = sock->sk;
        write_lock_bh(&sk->sk_callback_lock);
        sk->sk_data_ready = tun->orig_data_ready;
        sk->sk_user_data = NULL;
        write_unlock_bh(&sk->sk_callback_lock);
    }

    unregister_netdev(tdev);

    disable_work_sync(&tun->tx_work);
    disable_work_sync(&tun->rx_work);

    struct sk_buff* skb;
    while (kfifo_get(&tun->tx_fifo, &skb)) {
        dev_kfree_skb_any(skb);
    }

    kfifo_free(&tun->tx_fifo);

    struct ips_storage* ips = READ_ONCE(tun->ips);
    if (ips) {
        WRITE_ONCE(tun->ips, NULL);
        ips_close(ips);
    }

    if (sock) {
        WRITE_ONCE(tun->sock, NULL);
        sock_close(sock);
    }

    free_netdev(tdev);

    pr_info("tnet: module unloaded\n");
}

module_init(minit);
module_exit(mexit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nlmpx09");
MODULE_DESCRIPTION("tunnel driver");
