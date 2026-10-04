// SPDX-License-Identifier: GPL-2.0
/*
 * tnet - virtual network interface over encrypted UDP tunnels
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#include <linux/cpumask.h>
#include <linux/err.h>
#include <linux/etherdevice.h>
#include <linux/inet.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/ptr_ring.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <net/dst_cache.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>

#include <crypt/impl.h>
#include <ips/impl.h>
#include <sock/impl.h>

#include "types.h"

#define DEV_NAME "tnet%d"
#define MTU 1472
#define RING_SIZE 4096
#define BATCH 32

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
    struct worker* txw = container_of(work, struct worker, work);
    struct tun_ctx* tun = txw->ptr;
    struct net_device* dev = tun->dev;
    struct socket* sock = READ_ONCE(tun->sock);
    __maybe_unused struct ips_storage* ips = READ_ONCE(tun->ips);
    struct sk_buff* batch[BATCH];
    struct sk_buff* skb = NULL;

    int n, i;

    while ((n = ptr_ring_consume_batched_bh(&tun->tx.ring, (void**)batch, BATCH)) > 0) {
        if (netif_queue_stopped(dev)) {
            netif_wake_queue(dev);
        }

        for (i = 0; i < n; i++) {
            skb = batch[i];

            if (unlikely(!skb_pull(skb, ETH_HLEN))) {
                dev_dstats_tx_dropped(dev);
                dev_kfree_skb_any(skb);
                continue;
            }

            skb_reset_network_header(skb);

            if (unlikely(skb->len < sizeof(struct iphdr) || ip_hdr(skb)->version != 4)) {
                dev_dstats_tx_dropped(dev);
                dev_kfree_skb_any(skb);
                continue;
            }

            __maybe_unused __be32 daddr = ip_hdr(skb)->daddr;

            if (unlikely(encrypt(skb))) {
                dev_dstats_tx_dropped(dev);
                dev_kfree_skb_any(skb);
                continue;
            }

        #ifdef SERVER
            struct ips_entry* entry = ips_get(ips, daddr);

            if (unlikely(IS_ERR_OR_NULL(entry))) {
                dev_dstats_tx_dropped(dev);
                dev_kfree_skb_any(skb);
                continue;
            }

            __be64 peer = READ_ONCE(entry->peer);
            __be32 tip = (__be32)peer;
            __be16 tport = (__be16)(peer >> 32);
            struct dst_cache* dc = &entry->dst_cache;
        #else
            __be32 tip = READ_ONCE(tun->tip);
            __be16 tport = READ_ONCE(tun->tport);
            struct dst_cache* dc = &tun->dst_cache;
        #endif

            skb->mark = 0;
            skb->priority = 0;
            skb->encapsulation = 0;

            if (unlikely(sock_send(sock, skb, dc, tip, tport))) {
                dev_dstats_tx_dropped(dev);
                dev_kfree_skb_any(skb);
                continue;
            }
        }
        cond_resched();
    }
}

static void rx(struct work_struct* work)
{
    struct worker* rxw = container_of(work, struct worker, work);
    struct tun_ctx* tun = rxw->ptr;
    struct net_device* dev = tun->dev;
    __maybe_unused struct ips_storage* ips = READ_ONCE(tun->ips);
    struct sk_buff* batch[BATCH];
    struct sk_buff* skb = NULL;
    int n, i;

    while ((n = ptr_ring_consume_batched_bh(&tun->rx.ring, (void**)batch, BATCH)) > 0) {
        LIST_HEAD(list);

        for (i = 0; i < n; i++) {
            skb = batch[i];

            __maybe_unused __be32 tip = ip_hdr(skb)->saddr;
            __maybe_unused __be16 tport = udp_hdr(skb)->source;

            if (unlikely(!skb_pull(skb, sizeof(struct udphdr)))) {
                dev_dstats_rx_dropped(dev);
                dev_kfree_skb_any(skb);
                continue;
            }

            skb_reset_network_header(skb);

            if (unlikely(decrypt(skb))) {
                dev_dstats_rx_dropped(dev);
                dev_kfree_skb_any(skb);
                continue;
            }

            if (unlikely(skb->len < sizeof(struct iphdr) || ip_hdr(skb)->version != 4)) {
                dev_dstats_rx_dropped(dev);
                dev_kfree_skb_any(skb);
                continue;
            }

        #ifdef SERVER
            if (unlikely(ips_add(ips, ip_hdr(skb)->saddr, tip, tport))) {
                dev_dstats_rx_dropped(dev);
                dev_kfree_skb_any(skb);
                continue;
            }
        #endif
            if (unlikely(skb_headroom(skb) < ETH_HLEN)) {
                dev_dstats_rx_dropped(dev);
                dev_kfree_skb_any(skb);
                continue;
            }

            skb_dst_drop(skb);
            skb_orphan(skb);
            skb_clear_hash(skb);
            skb->mark = 0;
            skb->priority = 0;
            skb->encapsulation = 0;

            struct ethhdr* eth = skb_push(skb, ETH_HLEN);
            memcpy(eth->h_dest, dev->dev_addr, ETH_ALEN);
            memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
            eth->h_proto = htons(ETH_P_IP);

            skb->dev = dev;
            skb->protocol = eth_type_trans(skb, dev);
            skb->ip_summed = CHECKSUM_UNNECESSARY;

            dev_dstats_rx_add(dev, skb->len);

            list_add_tail(&skb->list, &list);
        }

        local_bh_disable();
        netif_receive_skb_list(&list);
        local_bh_enable();
        cond_resched();
    }
}

static netdev_tx_t dsxmit(struct sk_buff* skb, struct net_device* dev)
{
    struct tun_ctx* tun = netdev_priv(dev);

    skb_orphan(skb);
    if (unlikely(ptr_ring_produce_bh(&tun->tx.ring, skb))) {
        netif_stop_queue(dev);
        smp_mb();
        if (unlikely(!ptr_ring_full(&tun->tx.ring) && !ptr_ring_produce_bh(&tun->tx.ring, skb))) {
            netif_wake_queue(dev);
        } else {
            return NETDEV_TX_BUSY;
        }
    }

    int cpu = cpumask_next_wrap(READ_ONCE(tun->tx.last_cpu), cpu_online_mask, -1, 1);

    WRITE_ONCE(tun->tx.last_cpu, cpu);

    queue_work_on(cpu, tun->tx.wq, &per_cpu_ptr(tun->tx.workers, cpu)->work);

    return NETDEV_TX_OK;
}

static int tenrecv(struct sock* sk, struct sk_buff* skb)
{
    struct tun_ctx* tun = READ_ONCE(sk->sk_user_data);

    if (unlikely(!tun || !netif_running(tun->dev))) {
        dev_kfree_skb_any(skb);
        return 0;
    }

    if (unlikely(ptr_ring_produce_bh(&tun->rx.ring, skb))) {
        dev_dstats_rx_dropped(tun->dev);
        dev_kfree_skb_any(skb);
        return 0;
    }

    int cpu = cpumask_next_wrap(READ_ONCE(tun->rx.last_cpu), cpu_online_mask, -1, 1);

    WRITE_ONCE(tun->rx.last_cpu, cpu);

    queue_work_on(cpu, tun->rx.wq, &per_cpu_ptr(tun->rx.workers, cpu)->work);
    return 0;
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
    netif_stop_queue(dev);
    netif_carrier_off(dev);

    pr_info("tnet: device stopped\n");
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
    dev->pcpu_stat_type = NETDEV_PCPU_STAT_DSTATS;
    dev->mtu = MTU;
    dev->needed_headroom = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr);

    eth_hw_addr_random(dev);
}

static int work_ctx_init(struct work_ctx* ctx, const char* wq_name,
                         unsigned int ring_size,
                         void (*fn)(struct work_struct*),
                         struct tun_ctx* tun)
{
    int err, cpu;

    err = ptr_ring_init(&ctx->ring, ring_size, GFP_KERNEL);
    if (err)
        return err;

    ctx->workers = alloc_percpu(struct worker);
    if (!ctx->workers) {
        err = -ENOMEM;
        goto err_ring;
    }

    ctx->wq = alloc_workqueue(wq_name, WQ_HIGHPRI, 0);
    if (!ctx->wq) {
        err = -ENOMEM;
        goto err_percpu;
    }

    for_each_possible_cpu(cpu) {
        struct worker* w = per_cpu_ptr(ctx->workers, cpu);
        w->ptr = tun;
        INIT_WORK(&w->work, fn);
    }

    ctx->last_cpu = cpumask_first(cpu_online_mask);
    return 0;

err_percpu:
    free_percpu(ctx->workers);
err_ring:
    ptr_ring_cleanup(&ctx->ring, (void(*)(void*))dev_kfree_skb_any);
    return err;
}

static void work_ctx_destroy(struct work_ctx* ctx)
{
    destroy_workqueue(ctx->wq);
    ptr_ring_cleanup(&ctx->ring, (void(*)(void*))dev_kfree_skb_any);
    free_percpu(ctx->workers);
}

static int __init minit(void)
{
    __be32 tip;
    int err;

    if (!in4_pton(dest_ip, -1, (u8*)&tip, -1, NULL)) {
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

    tdev = alloc_netdev(sizeof(struct tun_ctx), DEV_NAME, NET_NAME_UNKNOWN, dsetup);
    if (!tdev) {
        pr_err("tnet: failed to allocate net device\n");
        return -ENOMEM;
    }

    struct tun_ctx* tun = netdev_priv(tdev);

    tun->dev = tdev;
    tun->tip = tip;
    tun->tport = htons(dest_port);

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

    err = dst_cache_init(&tun->dst_cache, GFP_KERNEL);
    if (err) {
        pr_err("tnet: dst_cache init failed: %d\n", err);
        goto err_ips;
    }

    err = work_ctx_init(&tun->tx, "tnet_tx", RING_SIZE, tx, tun);
    if (err) {
        pr_err("tnet: tx work ctx init failed: %d\n", err);
        goto err_cache;
    }

    err = work_ctx_init(&tun->rx, "tnet_rx", RING_SIZE, rx, tun);
    if (err) {
        pr_err("tnet: rx work ctx init failed: %d\n", err);
        goto err_tx_ctx;
    }

    struct udp_tunnel_sock_cfg sock_cfg = {
        .sk_user_data = tun,
        .encap_type = 1,
        .encap_rcv = tenrecv,
    };

    sock_setup(tun->sock, &sock_cfg);

    err = register_netdev(tdev);
    if (err) {
        pr_err("tnet: failed to register net device: %d\n", err);
        goto err_rx_ctx;
    }

    pr_info("tnet: module loaded\n");
    return 0;

err_rx_ctx:
    work_ctx_destroy(&tun->rx);
err_tx_ctx:
    work_ctx_destroy(&tun->tx);
err_cache:
    dst_cache_destroy(&tun->dst_cache);
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

    struct tun_ctx* tun = netdev_priv(tdev);

    unregister_netdev(tdev);

    work_ctx_destroy(&tun->tx);

    if (tun->sock) {
        struct sock* sk = tun->sock->sk;
        lock_sock(sk);
        WRITE_ONCE(udp_sk(sk)->encap_rcv, NULL);
        WRITE_ONCE(sk->sk_user_data, NULL);
        release_sock(sk);
        synchronize_net();
    }

    work_ctx_destroy(&tun->rx);

    dst_cache_destroy(&tun->dst_cache);

    if (tun->sock) {
        sock_close(tun->sock);
        WRITE_ONCE(tun->sock, NULL);
    }

    if (tun->ips) {
        ips_close(tun->ips);
        WRITE_ONCE(tun->ips, NULL);
    }

    free_netdev(tdev);

    pr_info("tnet: module unloaded\n");
}

module_init(minit);
module_exit(mexit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nlmpx09");
MODULE_DESCRIPTION("tunnel driver");
