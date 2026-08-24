#include <linux/err.h>
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/workqueue.h>
#include <linux/inet.h>
#include <net/sock.h>

#include <crypt/impl.h>
#include <ips/impl.h>
#include <sock/impl.h>
#include <utils/impl.h>

#include "configs.h"
#include "types.h"

#define DEV_NAME "vnet%d"

static char* dest_ip = "";
static int dest_port = 69;
static int src_port = 0;

module_param(dest_ip, charp, 0644);
MODULE_PARM_DESC(dest_ip, "Destination IP address");
module_param(dest_port, int, 0644);
MODULE_PARM_DESC(dest_port, "Destination UDP port");

static struct net_device* dev;

static void send_work(struct work_struct* work)
{
    struct tun_priv* priv = container_of(work, struct tun_priv, send_work);
    struct sk_buff* skb;
    unsigned long flags;
    __be32 tip;
    __be16 tport;

    while (true) {
        if (unlikely(!priv->sock)) {
            break;
        }

        spin_lock_irqsave(&priv->send_lock, flags);
        if (unlikely(!kfifo_get(&priv->send_fifo, &skb))) {
            spin_unlock_irqrestore(&priv->send_lock, flags);
            break;
        }
        spin_unlock_irqrestore(&priv->send_lock, flags);

        if (unlikely(skb_linearize(skb))) {
            pr_warn("tun: skb_linearize failed\n");
            dev_kfree_skb_any(skb);
            continue;
        }

        u8* buf = skb->data + ETH_HLEN;
        size_t bufl = skb->len - ETH_HLEN;

        if (likely(skb->len > ETH_HLEN)) {
            if (unlikely(!valid_ipv4_packet(buf, bufl))) {
                pr_warn("tun: not valid ipv4 packet\n");
                dev_kfree_skb_any(skb);
                continue;
            }

        #ifdef SERVER
            __be32 dip = get_dst_ip_from_ipv4_packet(buf, bufl);
            if (unlikely(!dip)) {
                pr_warn("tun: not valid dst ip\n");
                dev_kfree_skb_any(skb);
                continue;
            }

            rcu_read_lock();
            struct ips_entry* entry = ips_get(priv->ips, dip);

            if (unlikely(IS_ERR_OR_NULL(entry))) {
                pr_warn("tun: not have dst destination\n");
                dev_kfree_skb_any(skb);
                rcu_read_unlock();
                continue;
            }

            tip = READ_ONCE(entry->ip);
            tport = READ_ONCE(entry->port);
            rcu_read_unlock();
        #else
            tip = priv->dest.ip;
            tport = priv->dest.port;
        #endif

            int enl = encrypt(priv->encrb, buf, bufl);

            if (unlikely(enl <= 0)) {
                pr_warn("tun: encrypt failed\n");
                dev_kfree_skb_any(skb);
                continue;
            }

            int swl = sock_write(priv->sock, priv->encrb, enl, tip, tport);

            if (unlikely(swl < 0)) {
                pr_warn("tun: sock_write failed: %d\n", swl);
            }
        }

        dev_kfree_skb_any(skb);
    }
}

static void recv_work(struct work_struct* work)
{
    struct tun_priv* priv = container_of(work, struct tun_priv, recv_work);
    struct net_device* dev = priv->dev;
    __be32 tip;
    __be16 tport;

    while (true) {
        if (unlikely(!netif_running(dev))) {
            break;
        }

        int srl = sock_read(priv->sock, priv->srb, sizeof(priv->srb), &tip, &tport);

        if (unlikely(srl < 0)) {
            pr_warn("tun: sock_read failed: %d\n", srl);
            break;
        } else if (unlikely(srl == 0)) {
            break;
        }

        int dcl = decrypt(priv->decrb, priv->srb, srl);

        if (unlikely(dcl <= 0)) {
            pr_warn("tun: decrypt failed");
            continue;
        }

        if (unlikely(!valid_ipv4_packet(priv->decrb, dcl))) {
            pr_warn("tun: not valid ipv4 packet\n");
            continue;
        }

    #ifdef SERVER
        __be32 sip = get_src_ip_from_ipv4_packet(priv->decrb, dcl);
         if (unlikely(!sip)) {
            pr_warn("tun: not valid src ip\n");
            continue;
         }

        ips_add(priv->ips, sip, tip, tport);
    #endif

        struct sk_buff* skb = netdev_alloc_skb(dev, dcl + ETH_HLEN + NET_IP_ALIGN);
        if (unlikely(!skb)) {
            continue;
        }

        skb_reserve(skb, NET_IP_ALIGN);

        struct ethhdr* eth = skb_put(skb, ETH_HLEN);
        memcpy(eth->h_dest, dev->dev_addr, ETH_ALEN);
        memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
        eth->h_proto = htons(ETH_P_IP);

        skb_put_data(skb, priv->decrb, dcl);

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
    struct tun_priv* priv = sk->sk_user_data;
    if (likely(priv)) {
        schedule_work(&priv->recv_work);
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
    struct tun_priv* priv = netdev_priv(dev);
    struct sk_buff* skb;

    netif_stop_queue(dev);
    netif_carrier_off(dev);

    cancel_work_sync(&priv->send_work);
    cancel_work_sync(&priv->recv_work);

    while (kfifo_get(&priv->send_fifo, &skb)) {
        dev_kfree_skb_any(skb);
    }

    pr_info("tun: device stopped\n");
    return 0;
}

static netdev_tx_t start_xmit(struct sk_buff* skb, struct net_device* dev)
{
    struct tun_priv* priv = netdev_priv(dev);
    unsigned long flags;

    spin_lock_irqsave(&priv->send_lock, flags);
    if (unlikely(kfifo_is_full(&priv->send_fifo))) {
        spin_unlock_irqrestore(&priv->send_lock, flags);
        dev_kfree_skb_any(skb);
        dev->stats.tx_dropped++;
        pr_warn("tun: send fifo full, tunnel packet dropped\n");
        return NETDEV_TX_OK;
    }

    kfifo_put(&priv->send_fifo, skb);

    spin_unlock_irqrestore(&priv->send_lock, flags);

    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;

    schedule_work(&priv->send_work);

    return NETDEV_TX_OK;
}

static const struct net_device_ops ops = {
    .ndo_open       = open,
    .ndo_stop       = stop,
    .ndo_start_xmit = start_xmit,
};

static void setup(struct net_device* dev)
{
    struct tun_priv* priv;

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

    priv = netdev_priv(dev);
    spin_lock_init(&priv->send_lock);
    INIT_KFIFO(priv->send_fifo);
    INIT_WORK(&priv->send_work, send_work);
    INIT_WORK(&priv->recv_work, recv_work);
}

static int __init minit(void)
{
    int err;
    dev = alloc_netdev(sizeof(struct tun_priv), DEV_NAME, NET_NAME_UNKNOWN, setup);
    
    if (!dev) {
        pr_err("tun: failed to allocate net device\n");
        return -ENOMEM;
    }

    struct tun_priv* priv = netdev_priv(dev);
    priv->dev = dev;

    priv->sock = sock_init(htons(src_port));
    if (IS_ERR(priv->sock)) {
        err = PTR_ERR(priv->sock);
        pr_err("tun: sock init failed: %d\n", err);
        free_netdev(dev);
        return err;
    }

    priv->ips = ips_init();

    if (IS_ERR(priv->ips)) {
        err = PTR_ERR(priv->ips);
        pr_err("tun: ips failed: %d\n", err);
        free_netdev(dev);
        sock_close(priv->sock);
        return err;
    }

    err = kfifo_alloc(&priv->send_fifo, SEND_FIFO_SIZE, GFP_KERNEL);
    if (err) {
        pr_err("tun: failed to allocate send fifo: %d\n", err);
        free_netdev(dev);
        sock_close(priv->sock);
        ips_close(priv->ips);
        return err;
    }

    priv->dest.ip = in_aton(dest_ip);
    priv->dest.port = htons(dest_port);

    err = register_netdev(dev);
    if (err) {
        pr_err("tun: failed to register net device: %d\n", err);
        free_netdev(dev);
        sock_close(priv->sock);
        ips_close(priv->ips);
        kfifo_free(&priv->send_fifo);
        return err;
    }

    struct sock* sk = priv->sock->sk;
    write_lock_bh(&sk->sk_callback_lock);
    priv->orig_data_ready = sk->sk_data_ready;
    sk->sk_data_ready = data_ready;
    sk->sk_user_data = priv;
    write_unlock_bh(&sk->sk_callback_lock);

    pr_info("tun: module loaded, device %s registered\n", dev->name);
    return 0;
}

static void __exit mexit(void)
{
    if (!dev) {
        return;
    }

    struct tun_priv* priv = netdev_priv(dev);

    unregister_netdev(dev);

    cancel_work_sync(&priv->send_work);
    cancel_work_sync(&priv->recv_work);

    struct sk_buff* skb;
    while (kfifo_get(&priv->send_fifo, &skb)) {
        dev_kfree_skb_any(skb);
    }

    if (priv->sock) {
        struct sock* sk = priv->sock->sk;
        write_lock_bh(&sk->sk_callback_lock);
        sk->sk_data_ready = priv->orig_data_ready;
        sk->sk_user_data = NULL;
        write_unlock_bh(&sk->sk_callback_lock);
    }

    kfifo_free(&priv->send_fifo);

    if (priv->ips) {
        ips_close(priv->ips);
    }

    if (priv->sock) {
        sock_close(priv->sock);
    }

    free_netdev(dev);

    pr_info("tun: module unloaded\n");
}

module_init(minit);
module_exit(mexit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nlmpx09");
MODULE_DESCRIPTION("tunnel driver");
