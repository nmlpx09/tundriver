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
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/udp.h>
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

static int tx(struct tun_struct* tun, struct sk_buff* skb)
{
    struct net_device* dev = tun->dev;

    if (unlikely(!netif_running(dev))) {
        return -1;
    }

    if (unlikely(skb_linearize(skb))) {
        dev->stats.tx_dropped++;
        return -1;
    }

    if (unlikely(!skb_pull(skb, ETH_HLEN))) {
        dev->stats.tx_dropped++;
        return -1;
    }

    skb_reset_network_header(skb);

    if (unlikely(skb->len < sizeof(struct iphdr) || ip_hdr(skb)->version != 4)) {
        dev->stats.tx_dropped++;
        return -1;
    }

    rcu_read_lock();
#ifdef SERVER
    struct ips_storage* ips = READ_ONCE(tun->ips);

    if (unlikely(!ips)) {
        dev->stats.tx_errors++;
        rcu_read_unlock();
        return -1;
    }

    struct ips_entry* entry = ips_get(ips, ip_hdr(skb)->daddr);

    if (unlikely(IS_ERR_OR_NULL(entry))) {
        dev->stats.tx_errors++;
        rcu_read_unlock();
        return -1;
    }

    __be32 dip = READ_ONCE(entry->ip);
    __be16 dport = READ_ONCE(entry->port);
    struct dst_cache* dc = &entry->dst_cache;
#else
    __be32 dip = tun->dip;
    __be16 dport = tun->dport;
    struct dst_cache* dc = &tun->dst_cache;
#endif

    if (unlikely(encrypt(skb->data, skb->len))) {
        dev->stats.tx_errors++;
        rcu_read_unlock();
        return -1;
    }

    struct socket* sock = READ_ONCE(tun->sock);

    if (unlikely(!sock)) {
        dev->stats.tx_errors++;
        rcu_read_unlock();
        return -1;
    }

    u32 len = skb->len;

    if (unlikely(sock_send(sock, skb, dc, dip, dport))) {
        dev->stats.tx_errors++;
        rcu_read_unlock();
        return -1;
    }

    dev->stats.tx_packets++;
    dev->stats.tx_bytes += len;

    rcu_read_unlock();

    return 0;
}

static int rx(struct tun_struct* tun, struct sk_buff* skb)
{
    struct net_device* dev = tun->dev;

    if (unlikely(!netif_running(dev))) {
        return -1;
    }

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

    if (unlikely(!ips)) {
        dev->stats.rx_errors++;
        return -1;
    }

    ips_add(ips, ip_hdr(skb)->saddr, tip, tport);
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

    dev->stats.rx_packets++;
    dev->stats.rx_bytes += skb->len;

    netif_rx(skb);

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

static netdev_tx_t dsxmit(struct sk_buff* skb, struct net_device* dev)
{
    struct tun_struct* tun = netdev_priv(dev);

    if (unlikely(!tun || tx(tun, skb))) {
        dev_kfree_skb_any(skb);
    }

    return NETDEV_TX_OK;
}

static int tenrecv(struct sock* sk, struct sk_buff* skb)
{
    struct tun_struct* tun = READ_ONCE(sk->sk_user_data);

    if (unlikely(!tun || rx(tun, skb))) {
        dev_kfree_skb_any(skb);
    }

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
    dev->needed_headroom = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr);

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

    err = register_netdev(tdev);
    if (err) {
        pr_err("tnet: failed to register net device: %d\n", err);
        goto err_cache;
    }

    struct udp_tunnel_sock_cfg sock_cfg = {
        .sk_user_data = tun,
        .encap_type = 1,
        .encap_rcv = tenrecv,
    };

    sock_setup(tun->sock, &sock_cfg);

    pr_info("tnet: module loaded, device %s registered\n", tdev->name);
    return 0;

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

    struct tun_struct* tun = netdev_priv(tdev);

    if (tun->sock) {
        struct sock* sk = tun->sock->sk;
        lock_sock(sk);
        WRITE_ONCE(udp_sk(sk)->encap_rcv, NULL);
        WRITE_ONCE(sk->sk_user_data, NULL);
        release_sock(sk);
        synchronize_net();
    }

    unregister_netdev(tdev);

    dst_cache_destroy(&tun->dst_cache);

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
