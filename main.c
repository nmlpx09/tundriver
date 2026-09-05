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
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <net/udp.h>

#include <crypt/impl.h>
#include <ips/impl.h>
#include <sock/impl.h>
#include <utils/impl.h>

#include "types.h"

#define DEV_NAME "tnet%d"
#define MTU 1472
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

        if (unlikely(skb_linearize(skb))) {
            dev->stats.tx_errors++;
            dev_kfree_skb_any(skb);
            continue;
        }

        if (unlikely(!skb_pull(skb, ETH_HLEN))) {
            dev->stats.tx_errors++;
            dev_kfree_skb_any(skb);
            continue;
        }

        if (unlikely(!valid_ipv4_packet(skb->data, skb->len))) {
            dev->stats.tx_dropped++;
            dev_kfree_skb_any(skb);
            continue;
        }

    #ifdef SERVER
        __be32 ip = get_dst_ip_from_ipv4_packet(skb->data, skb->len);
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

        if (unlikely(encrypt(skb->data, skb->len) < 0)) {
            dev->stats.tx_errors++;
            dev_kfree_skb_any(skb);
            continue;
        }

        if (unlikely(sock_send(sock, skb, dip, dport))) {
            dev->stats.tx_errors++;
            dev_kfree_skb_any(skb);
        } else {
            dev->stats.tx_packets++;
            dev->stats.tx_bytes += skb->len;
        }
    }
}

static void rx(struct work_struct* work)
{
    struct tun_struct* tun = container_of(work, struct tun_struct, rx_work);
    struct net_device* dev = tun->dev;
    struct sk_buff* skb = NULL;
    unsigned long flags;

    while (true) {

        if (unlikely(!netif_running(dev))) {
            break;
        }

        struct socket* sock = READ_ONCE(tun->sock);

        if (unlikely(!sock)) {
            break;
        }

        spin_lock_irqsave(&tun->rx_lock, flags);
        if (unlikely(!kfifo_get(&tun->rx_fifo, &skb))) {
            spin_unlock_irqrestore(&tun->rx_lock, flags);
            break;
        }
        spin_unlock_irqrestore(&tun->rx_lock, flags);

        if (unlikely(!skb_pull(skb, sizeof(struct udphdr)))) {
            dev->stats.rx_dropped++;
            dev_kfree_skb_any(skb);
            continue;
        }

        if (unlikely(skb_linearize(skb))) {
            dev->stats.rx_dropped++;
            dev_kfree_skb_any(skb);
            continue;
        }

        if (unlikely(decrypt(skb->data, skb->len) < 0)) {
            dev->stats.rx_errors++;
            dev_kfree_skb_any(skb);
            continue;
        }

        if (unlikely(!valid_ipv4_packet(skb->data, skb->len))) {
            dev->stats.rx_dropped++;
            dev_kfree_skb_any(skb);
            continue;
        }

    #ifdef SERVER
        __be32 tip = ip_hdr(skb)->saddr;
        __be16 tport = udp_hdr(skb)->source;
        __be32 sip = get_src_ip_from_ipv4_packet(skb->data, skb->len);
        if (unlikely(!sip)) {
            dev->stats.rx_dropped++;
            dev_kfree_skb_any(skb);
            continue;
        }

        struct ips_storage* ips = READ_ONCE(tun->ips);

        if (unlikely(!ips)) {
            dev->stats.rx_errors++;
            dev_kfree_skb_any(skb);
            continue;
        }

        ips_add(ips, sip, tip, tport);
    #endif

        if (unlikely(skb_headroom(skb) < ETH_HLEN)) {
            dev->stats.rx_errors++;
            dev_kfree_skb_any(skb);
            continue;
        }

        skb_dst_drop(skb);

        struct ethhdr* eth = skb_push(skb, ETH_HLEN);
        memcpy(eth->h_dest, dev->dev_addr, ETH_ALEN);
        memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
        eth->h_proto = htons(ETH_P_IP);

        skb->dev = dev;
        skb->protocol = eth_type_trans(skb, dev);
        skb->ip_summed = CHECKSUM_UNNECESSARY;

        dev->stats.rx_packets++;
        dev->stats.rx_bytes += skb->len;

        netif_rx(skb);
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

    spin_lock_irqsave(&tun->rx_lock, flags);
    while (kfifo_get(&tun->rx_fifo, &skb)) {
        dev_kfree_skb_any(skb);
    }
    spin_unlock_irqrestore(&tun->rx_lock, flags);

    pr_info("tnet: device stopped\n");
    return 0;
}

static netdev_tx_t dsxmit(struct sk_buff* skb, struct net_device* dev)
{
    struct tun_struct* tun = netdev_priv(dev);
    unsigned long flags;

    if (unlikely(!tun)) {
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    spin_lock_irqsave(&tun->tx_lock, flags);
    if (unlikely(kfifo_is_full(&tun->tx_fifo))) {
        spin_unlock_irqrestore(&tun->tx_lock, flags);
        dev_kfree_skb_any(skb);
        dev->stats.tx_dropped++;
        return NETDEV_TX_OK;
    }

    kfifo_put(&tun->tx_fifo, skb);

    spin_unlock_irqrestore(&tun->tx_lock, flags);

    queue_work(tun->wq, &tun->tx_work);

    return NETDEV_TX_OK;
}


static int tenrecv(struct sock* sk, struct sk_buff* skb)
{
    struct tun_struct* tun = READ_ONCE(sk->sk_user_data);
    unsigned long flags;

    if (unlikely(!tun)) {
        dev_kfree_skb_any(skb);
        return 0;
    }

    struct net_device* dev = tun->dev;

    if (unlikely(!dev)) {
        dev_kfree_skb_any(skb);
        return 0;
    }

    spin_lock_irqsave(&tun->rx_lock, flags);
    if (unlikely(kfifo_is_full(&tun->rx_fifo))) {
        spin_unlock_irqrestore(&tun->rx_lock, flags);
        dev->stats.rx_dropped++;
        dev_kfree_skb_any(skb);
        return 0;
    }

    kfifo_put(&tun->rx_fifo, skb);

    spin_unlock_irqrestore(&tun->rx_lock, flags);

    queue_work(tun->wq, &tun->rx_work);

    return 0;
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
    dev->needed_headroom = sizeof(struct iphdr) + sizeof(struct udphdr);

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
    spin_lock_init(&tun->rx_lock);
    INIT_KFIFO(tun->rx_fifo);
    INIT_WORK(&tun->tx_work, tx);
    INIT_WORK(&tun->rx_work, rx);

    tun->sock = sock_init(htons(src_port));
    if (IS_ERR(tun->sock)) {
        err = PTR_ERR(tun->sock);
        pr_err("tnet: sock init failed: %d\n", err);
        goto err_netdev;
    }

    tun->ips = ips_init();
    if (IS_ERR(tun->ips)) {
        err = PTR_ERR(tun->ips);
        pr_err("tnet: ips init failed: %d\n", err);
        goto err_sock;
    }

    err = kfifo_alloc(&tun->tx_fifo, SEND_FIFO_SIZE, GFP_KERNEL);
    if (err) {
        pr_err("tnet: failed to allocate tx fifo: %d\n", err);
        goto err_ips;
    }

    err = kfifo_alloc(&tun->rx_fifo, SEND_FIFO_SIZE, GFP_KERNEL);
    if (err) {
        pr_err("tnet: failed to allocate rx fifo: %d\n", err);
        goto err_txfifo;
    }

    tun->wq = alloc_workqueue("tnet", WQ_UNBOUND, 0);
    if (!tun->wq) {
        pr_err("tnet: failed to allocate workqueue\n");
        err = -ENOMEM;
        goto err_rxfifo;
    }

    err = register_netdev(tdev);
    if (err) {
        pr_err("tnet: failed to register net device: %d\n", err);
        goto err_wq;
    }

    struct sock* sk = tun->sock->sk;
    lock_sock(sk);
    sk->sk_user_data = tun;
    udp_encap_enable();
    udp_sk(sk)->encap_rcv = tenrecv;
    udp_sk(sk)->encap_type = 1;
    release_sock(sk);

    pr_info("tnet: module loaded, device %s registered\n", tdev->name);
    return 0;

err_wq:
    destroy_workqueue(tun->wq);
err_rxfifo:
    kfifo_free(&tun->rx_fifo);
err_txfifo:
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

    if (tun->sock) {
        struct sock* sk = tun->sock->sk;
        lock_sock(sk);
        WRITE_ONCE(udp_sk(sk)->encap_rcv, NULL);
        WRITE_ONCE(sk->sk_user_data, NULL);
        release_sock(sk);
        udp_encap_disable();
        synchronize_net();
    }

    unregister_netdev(tdev);

    disable_work_sync(&tun->tx_work);
    disable_work_sync(&tun->rx_work);

    if (tun->wq) {
        destroy_workqueue(tun->wq);
        tun->wq = NULL;
    }

    struct sk_buff* skb;
    while (kfifo_get(&tun->tx_fifo, &skb)) {
        dev_kfree_skb_any(skb);
    }

    while (kfifo_get(&tun->rx_fifo, &skb)) {
        dev_kfree_skb_any(skb);
    }

    kfifo_free(&tun->tx_fifo);
    kfifo_free(&tun->rx_fifo);

    if (tun->ips) {
        ips_close(tun->ips);
        tun->ips = NULL;
    }

    if (tun->sock) {
        sock_close(tun->sock);
        tun->sock = NULL;
    }

    free_netdev(tdev);

    pr_info("tnet: module unloaded\n");
}

module_init(minit);
module_exit(mexit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nlmpx09");
MODULE_DESCRIPTION("tunnel driver");
