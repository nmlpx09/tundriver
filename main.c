#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/kfifo.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <sock/impl.h>
#include <utils/impl.h>

#include <crypt/impl.h>
#include <ips/impl.h>

#include "configs.h"
#include "types.h"

#define DEV_NAME "vnet%d"

static char* dest_ip = "";
static int dest_port = 0;
static int src_port = 0;

module_param(dest_ip, charp, 0644);
MODULE_PARM_DESC(dest_ip, "Destination IP address");
module_param(dest_port, int, 0644);
MODULE_PARM_DESC(dest_port, "Destination UDP port");
module_param(src_port, int, 0644);
MODULE_PARM_DESC(src_port, "Source UDP port");

static struct net_device* tdev;

static void tx(struct work_struct* work)
{
    struct tun_struct* tun = container_of(work, struct tun_struct, tx_work);
    struct sk_buff* skb;
    unsigned long flags;

    while (true) {
        if (unlikely(!READ_ONCE(tun->sock))) {
            break;
        }

        struct net_device* dev = tun->dev;

        if (unlikely(!netif_running(dev))) {
            break;
        }

        spin_lock_irqsave(&tun->send_lock, flags);
        if (unlikely(!kfifo_get(&tun->send_fifo, &skb))) {
            spin_unlock_irqrestore(&tun->send_lock, flags);
            break;
        }
        spin_unlock_irqrestore(&tun->send_lock, flags);

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
            dev->stats.tx_errors++;
            dev_kfree_skb_any(skb);
            continue;
        }

    #ifdef SERVER
        __be32 ip = get_dst_ip_from_ipv4_packet(buf, bufl);
        if (unlikely(!ip)) {
            dev->stats.tx_errors++;
            dev_kfree_skb_any(skb);
            continue;
        }

        rcu_read_lock();
        struct ips_entry* entry = ips_get(tun->ips, ip);

        if (unlikely(IS_ERR_OR_NULL(entry))) {
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

        int enl = encrypt(tun->encrb, buf, bufl);

        if (unlikely(enl <= 0)) {
            dev->stats.tx_errors++;
            dev_kfree_skb_any(skb);
            continue;
        }

        int swl = sock_write(READ_ONCE(tun->sock), tun->encrb, enl, dip, dport);

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
    struct net_device* dev = tun->dev;
    __be32 tip;
    __be16 tport;

    while (true) {
        if (unlikely(!netif_running(dev))) {
            break;
        }

        int srl = sock_read(READ_ONCE(tun->sock), tun->srb, sizeof(tun->srb), &tip, &tport);

        if (unlikely(srl <= 0)) {
            dev->stats.rx_errors++;
            break;
        }

        int dcl = decrypt(tun->decrb, tun->srb, srl);

        if (unlikely(dcl <= 0)) {
            dev->stats.rx_errors++;
            continue;
        }

        if (unlikely(!valid_ipv4_packet(tun->decrb, dcl))) {
            dev->stats.rx_errors++;
            continue;
        }

    #ifdef SERVER
        __be32 sip = get_src_ip_from_ipv4_packet(tun->decrb, dcl);
        if (unlikely(!sip)) {
            dev->stats.rx_errors++;
            continue;
        }

        ips_add(tun->ips, sip, tip, tport);
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

static void data_ready(struct sock* sk)
{
    struct tun_struct* tun = sk->sk_user_data;
    if (likely(tun)) {
        schedule_work(&tun->rx_work);
    }
}

static int open(struct net_device* dev)
{
    netif_carrier_on(dev);
    netif_start_queue(dev);
    pr_info("tun: device opened\n");
    return 0;
}

static int stop(struct net_device* dev)
{
    struct tun_struct* tun = netdev_priv(dev);
    struct sk_buff* skb;

    netif_stop_queue(dev);
    netif_carrier_off(dev);

    cancel_work_sync(&tun->tx_work);
    cancel_work_sync(&tun->rx_work);

    while (kfifo_get(&tun->send_fifo, &skb)) {
        dev_kfree_skb_any(skb);
    }

    pr_info("tun: device stopped\n");
    return 0;
}

static netdev_tx_t start_xmit(struct sk_buff* skb, struct net_device* dev)
{
    struct tun_struct* tun = netdev_priv(dev);
    unsigned long flags;

    spin_lock_irqsave(&tun->send_lock, flags);
    if (unlikely(kfifo_is_full(&tun->send_fifo))) {
        spin_unlock_irqrestore(&tun->send_lock, flags);
        dev_kfree_skb_any(skb);
        dev->stats.tx_dropped++;
        pr_warn("tun: send fifo full, tunnel packet dropped\n");
        return NETDEV_TX_OK;
    }

    kfifo_put(&tun->send_fifo, skb);

    spin_unlock_irqrestore(&tun->send_lock, flags);

    schedule_work(&tun->tx_work);

    return NETDEV_TX_OK;
}

static const struct net_device_ops ops = {
    .ndo_open       = open,
    .ndo_stop       = stop,
    .ndo_start_xmit = start_xmit,
};

static void setup(struct net_device* dev)
{
    struct tun_struct* tun;

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

    tun = netdev_priv(dev);
    spin_lock_init(&tun->send_lock);
    INIT_KFIFO(tun->send_fifo);
    INIT_WORK(&tun->tx_work, tx);
    INIT_WORK(&tun->rx_work, rx);
}

static int __init minit(void)
{
    int err;

    tdev = alloc_netdev(sizeof(struct tun_struct), DEV_NAME, NET_NAME_UNKNOWN, setup);
    
    if (!tdev) {
        pr_err("tun: failed to allocate net device\n");
        return -ENOMEM;
    }

    struct tun_struct* tun = netdev_priv(tdev);

    tun->dev = tdev;

    __be32 dip;
    if (!in4_pton(dest_ip, -1, (u8*)&dip, -1, NULL)) {
        pr_err("tun: invalid dest_ip: %s\n", dest_ip);
        return -EINVAL;
    }

    tun->dip = dip;

    if (dest_port < 1 || dest_port > 65535) {
        pr_err("tun: invalid dest_port: %d (must be 1-65535)\n", dest_port);
        return -EINVAL;
    }

    tun->dport = htons(dest_port);

    if (src_port < 0 || src_port > 65535) {
        pr_err("tun: invalid src_port: %d (must be 0-65535)\n", src_port);
        return -EINVAL;
    }

    tun->sock = sock_init(htons(src_port));
    if (IS_ERR(tun->sock)) {
        err = PTR_ERR(tun->sock);
        pr_err("tun: sock init failed: %d\n", err);
        free_netdev(tdev);
        return err;
    }

    tun->ips = ips_init();

    if (IS_ERR(tun->ips)) {
        err = PTR_ERR(tun->ips);
        pr_err("tun: ips failed: %d\n", err);
        sock_close(tun->sock);
        free_netdev(tdev);
        return err;
    }

    err = kfifo_alloc(&tun->send_fifo, SEND_FIFO_SIZE, GFP_KERNEL);
    if (err) {
        pr_err("tun: failed to allocate send fifo: %d\n", err);
        ips_close(tun->ips);
        sock_close(tun->sock);
        free_netdev(tdev);
        return err;
    }

    err = register_netdev(tdev);
    if (err) {
        pr_err("tun: failed to register net device: %d\n", err);
        kfifo_free(&tun->send_fifo);
        ips_close(tun->ips);
        sock_close(tun->sock);
        free_netdev(tdev);
        return err;
    }

    struct sock* sk = tun->sock->sk;
    write_lock_bh(&sk->sk_callback_lock);
    tun->orig_data_ready = sk->sk_data_ready;
    sk->sk_data_ready = data_ready;
    sk->sk_user_data = tun;
    write_unlock_bh(&sk->sk_callback_lock);

    pr_info("tun: module loaded, device %s registered\n", tdev->name);
    return 0;
}

static void __exit mexit(void)
{
    if (!tdev) {
        return;
    }

    struct tun_struct* tun = netdev_priv(tdev);

    unregister_netdev(tdev);

    cancel_work_sync(&tun->tx_work);
    cancel_work_sync(&tun->rx_work);

    struct sk_buff* skb;
    while (kfifo_get(&tun->send_fifo, &skb)) {
        dev_kfree_skb_any(skb);
    }

    if (tun->sock) {
        struct sock* sk = tun->sock->sk;
        write_lock_bh(&sk->sk_callback_lock);
        sk->sk_data_ready = tun->orig_data_ready;
        sk->sk_user_data = NULL;
        write_unlock_bh(&sk->sk_callback_lock);
    }

    kfifo_free(&tun->send_fifo);

    if (tun->ips) {
        ips_close(tun->ips);
        tun->ips = NULL;
    }

    if (tun->sock) {
        sock_close(tun->sock);
        tun->sock = NULL;
    }

    free_netdev(tdev);

    pr_info("tun: module unloaded\n");
}

module_init(minit);
module_exit(mexit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nlmpx09");
MODULE_DESCRIPTION("tunnel driver");
