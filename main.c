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
#define RX_Q_LIMIT 1024
#define TX_RING_SIZE 1024
#define TX_BATCH 32

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
    struct tx_worker* txw = container_of(work, struct tx_worker, work);
    struct tun_struct* tun = txw->ptr;
    struct net_device* dev = tun->dev;
    struct sk_buff* batch[TX_BATCH];
    struct sk_buff* skb = NULL;
    int n, i;

    while ((n = ptr_ring_consume_batched_bh(&tun->tx_ring, (void**)batch, TX_BATCH)) > 0) {
        for (i = 0; i < n; i++) {
            skb = batch[i];

            if (unlikely(!skb_pull(skb, ETH_HLEN))) {
                dev->stats.tx_dropped++;
                dev_kfree_skb_any(skb);
                return;
            }

            skb_reset_network_header(skb);

            if (unlikely(skb->len < sizeof(struct iphdr) || ip_hdr(skb)->version != 4)) {
                dev->stats.tx_dropped++;
                dev_kfree_skb_any(skb);
                return;
            }

            [[ maybe_unused ]] __be32 daddr = ip_hdr(skb)->daddr;

            if (unlikely(encrypt(skb->data, skb->len))) {
                dev->stats.tx_errors++;
                dev_kfree_skb_any(skb);
                return;
            }

        #ifdef SERVER
            struct ips_storage* ips = READ_ONCE(tun->ips);

            struct ips_entry* entry = ips_get(ips, daddr);

            if (unlikely(IS_ERR_OR_NULL(entry))) {
                dev->stats.tx_errors++;
                dev_kfree_skb_any(skb);
                return;
            }

            __be32 dip = READ_ONCE(entry->ip);
            __be16 dport = READ_ONCE(entry->port);
            struct dst_cache* dc = &entry->dst_cache;
        #else
            __be32 dip = READ_ONCE(tun->dip);
            __be16 dport = READ_ONCE(tun->dport);
            struct dst_cache* dc = &tun->dst_cache;
        #endif

            struct socket* sock = READ_ONCE(tun->sock);

            if (unlikely(sock_send(sock, skb, dc, dip, dport))) {
                dev->stats.tx_errors++;
                dev_kfree_skb_any(skb);
                return;
            }

            if (need_resched()) {
                cond_resched();
            }
        }
    }
}

static int rx(struct tun_struct* tun, struct sk_buff* skb)
{
    struct net_device* dev = tun->dev;

    if (unlikely(skb_linearize(skb))) {
        dev->stats.rx_dropped++;
        return -1;
    }

    if (unlikely(!skb_pull(skb, sizeof(struct udphdr)))) {
        dev->stats.rx_dropped++;
        return -1;
    }

    [[ maybe_unused ]] __be32 tip = ip_hdr(skb)->saddr;
    [[ maybe_unused ]] __be16 tport = udp_hdr(skb)->source;

    skb_reset_network_header(skb);

    if (unlikely(decrypt(skb->data, skb->len))) {
        dev->stats.rx_errors++;
        return -1;
    }

    if (unlikely(skb->len < sizeof(struct iphdr) || ip_hdr(skb)->version != 4)) {
        dev->stats.rx_dropped++;
        return -1;
    }

#ifdef SERVER
    struct ips_storage* ips = READ_ONCE(tun->ips);

    if (unlikely(ips_add(ips, ip_hdr(skb)->saddr, tip, tport))) {
        dev->stats.rx_errors++;
        return -1;
    }
#endif

    if (unlikely(skb_headroom(skb) < ETH_HLEN)) {
        dev->stats.rx_errors++;
        return -1;
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

    dev_sw_netstats_rx_add(dev, skb->len);

    napi_gro_receive(&tun->napi, skb);

    return 0;
}

static netdev_tx_t dsxmit(struct sk_buff* skb, struct net_device* dev)
{
    struct tun_struct* tun = netdev_priv(dev);

    skb_orphan(skb);
    if (unlikely(!tun || ptr_ring_produce_bh(&tun->tx_ring, skb))) {
        dev->stats.tx_dropped++;
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

    int cpu = cpumask_next_wrap(READ_ONCE(tun->last_cpu), cpu_online_mask, -1, 1);

    WRITE_ONCE(tun->last_cpu, cpu);

    queue_work_on(cpu, tun->tx_wq, &per_cpu_ptr(tun->tx_workers, cpu)->work);

    return NETDEV_TX_OK;
}

static int npoll(struct napi_struct* napi, int budget)
{
    struct tun_struct* tun = container_of(napi, struct tun_struct, napi);
    int work = 0;

    while (work < budget && netif_running(tun->dev)) {
        struct sk_buff* skb = skb_dequeue(&tun->rx_queue);
        if (unlikely(!skb)) {
            break;
        }

        if (unlikely(rx(tun, skb))) {
            dev_kfree_skb_any(skb);
        }

        work++;
    }

    if (unlikely(work < budget)) {
        napi_complete_done(napi, work);
    }

    return work;
}

static int tenrecv(struct sock* sk, struct sk_buff* skb)
{
    struct tun_struct* tun = READ_ONCE(sk->sk_user_data);

    if (unlikely(!tun || !netif_running(tun->dev))) {
        dev_kfree_skb_any(skb);
        return 0;
    }

    if (unlikely(skb_queue_len(&tun->rx_queue) >= RX_Q_LIMIT)) {
        tun->dev->stats.rx_dropped++;
        dev_kfree_skb_any(skb);
        return 0;
    }

    skb_queue_tail(&tun->rx_queue, skb);
    napi_schedule(&tun->napi);

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
    dev->features &= ~NETIF_F_IP_CSUM;
    dev->features &= ~NETIF_F_SG;
    dev->features &= ~NETIF_F_TSO;
    dev->features &= ~NETIF_F_GSO;
    dev->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;
    dev->mtu = MTU;
    dev->needed_headroom = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr);

    eth_hw_addr_random(dev);
}

static int __init minit(void)
{
    __be32 dip;
    int err, cpu;

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

    skb_queue_head_init(&tun->rx_queue);
    netif_napi_add(tdev, &tun->napi, npoll);
    napi_enable(&tun->napi);

    err = ptr_ring_init(&tun->tx_ring, TX_RING_SIZE, GFP_KERNEL);
    if (err) {
        pr_err("tnet: ptr_ring_init failed: %d\n", err);
        goto err_cache;
    }

    tun->tx_workers = alloc_percpu(struct tx_worker);
    if (!tun->tx_workers) {
        err = -ENOMEM;
        pr_err("tnet: alloc_percpu failed\n");
        goto err_ptr_ring;
    }

    tun->tx_wq = alloc_workqueue("tnet_tx", WQ_HIGHPRI, 0);
    if (!tun->tx_wq) {
        err = -ENOMEM;
        pr_err("tnet: alloc_workqueue failed\n");
        goto err_percpu;
    }

    for_each_possible_cpu(cpu) {
        struct tx_worker* txw = per_cpu_ptr(tun->tx_workers, cpu);
        txw->ptr = tun;
        INIT_WORK(&txw->work, tx);
    }

    tun->last_cpu = cpumask_first(cpu_online_mask);

    struct udp_tunnel_sock_cfg sock_cfg = {
        .sk_user_data = tun,
        .encap_type = 1,
        .encap_rcv = tenrecv,
    };

    sock_setup(tun->sock, &sock_cfg);

    err = register_netdev(tdev);
    if (err) {
        pr_err("tnet: failed to register net device: %d\n", err);
        goto err_wq;
    }

    pr_info("tnet: module loaded\n");
    return 0;

err_wq:
    destroy_workqueue(tun->tx_wq);
err_percpu:
    free_percpu(tun->tx_workers);
err_ptr_ring:
    ptr_ring_cleanup(&tun->tx_ring, (void(*)(void*))dev_kfree_skb_any);
err_cache:
    napi_disable(&tun->napi);
    skb_queue_purge(&tun->rx_queue);
    netif_napi_del(&tun->napi);
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

    struct tun_struct* tun = netdev_priv(tdev);

    unregister_netdev(tdev);

    destroy_workqueue(tun->tx_wq);

    ptr_ring_cleanup(&tun->tx_ring, (void(*)(void*))dev_kfree_skb_any);
    free_percpu(tun->tx_workers);

    if (tun->sock) {
        struct sock* sk = tun->sock->sk;
        lock_sock(sk);
        WRITE_ONCE(udp_sk(sk)->encap_rcv, NULL);
        WRITE_ONCE(sk->sk_user_data, NULL);
        release_sock(sk);
        synchronize_net();
    }

    dst_cache_destroy(&tun->dst_cache);

    if (tun->ips) {
        ips_close(tun->ips);
        tun->ips = NULL;
    }

    if (tun->sock) {
        sock_close(tun->sock);
        tun->sock = NULL;
    }

    napi_disable(&tun->napi);
    skb_queue_purge(&tun->rx_queue);
    netif_napi_del(&tun->napi);

    free_netdev(tdev);

    pr_info("tnet: module unloaded\n");
}

module_init(minit);
module_exit(mexit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nlmpx09");
MODULE_DESCRIPTION("tunnel driver");
