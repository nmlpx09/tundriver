#include <linux/err.h>
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/inet.h>
#include <net/sock.h>

#include <crypt/impl.h>
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
    struct sock_data* sd = priv->sd;
    struct crypt_data* cd = priv->cd;
    struct sk_buff* skb;

    unsigned long flags;

    while (true) {
        if (unlikely(!sd || !cd)) {
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

        if (likely(skb->len > ETH_HLEN)) {
            if (unlikely(!valid_ipv4_packet(skb->data + ETH_HLEN, skb->len - ETH_HLEN))) {
                pr_warn("tun: not valid ipv4 packet\n");
                dev_kfree_skb_any(skb);
                continue;
            }

            encrypt(cd, skb->data + ETH_HLEN, skb->len - ETH_HLEN);

            if (unlikely(cd->encrbl == 0)) {
                pr_warn("tun: encrypt failed\n");
                dev_kfree_skb_any(skb);
                continue;
            }

            int ret = sock_write(sd, cd->encrb, cd->encrbl, priv->dest.ip, priv->dest.port);

            if (unlikely(ret < 0)) {
                pr_warn("tun: sock_write failed: %d\n", ret);
            }
        }

        dev_kfree_skb_any(skb);
    }
}

static void recv_work(struct work_struct* work)
{
    struct tun_priv* priv = container_of(work, struct tun_priv, recv_work);
    struct net_device* dev = priv->dev;
    struct sock_data* sd = priv->sd;
    struct crypt_data* cd = priv->cd;

    while (true) {
        if (unlikely(!netif_running(dev) || !sd || !cd)) {
            break;
        }

        sock_read(sd);

        if (unlikely(sd->readbl < 0)) {
            pr_warn("tun: sock_read failed: %d\n", sd->readbl);
            break;
        } else if (unlikely(sd->readbl == 0)) {
            break;
        }

        decrypt(cd, sd->readb, sd->readbl);

        if (unlikely(cd->decrbl == 0)) {
            pr_warn("tun: decrypt failed");
            continue;
        }

        if (unlikely(!valid_ipv4_packet(cd->decrb, cd->decrbl))) {
            pr_warn("tun: not valid ipv4 packet\n");
            continue;
        }

        struct sk_buff* skb = netdev_alloc_skb(dev, cd->decrbl + ETH_HLEN + NET_IP_ALIGN);
        if (unlikely(!skb)) {
            continue;
        }

        skb_reserve(skb, NET_IP_ALIGN);

        struct ethhdr* eth = skb_put(skb, ETH_HLEN);
        memcpy(eth->h_dest, dev->dev_addr, ETH_ALEN);
        memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
        eth->h_proto = htons(ETH_P_IP);

        skb_put_data(skb, cd->decrb, cd->decrbl);

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
    netif_start_queue(dev);
    pr_info("tun: device opened\n");
    return 0;
}

static int stop(struct net_device* dev)
{
    struct tun_priv* priv = netdev_priv(dev);
    struct sk_buff* skb;

    netif_stop_queue(dev);

    cancel_work_sync(&priv->send_work);
    cancel_work_sync(&priv->recv_work);

    while (kfifo_get(&priv->send_fifo, &skb))
        dev_kfree_skb_any(skb);

    pr_info("tun: device stopped\n");
    return 0;
}

static netdev_tx_t start_xmit(struct sk_buff* skb, struct net_device* dev)
{
    struct tun_priv* priv = netdev_priv(dev);

    if (unlikely(!priv->sd)) {
        dev_kfree_skb_any(skb);
        dev->stats.tx_dropped++;
        return NETDEV_TX_OK;
    }

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

    priv->sd = sock_init(htons(src_port));

    if (IS_ERR(priv->sd)) {
        err = PTR_ERR(priv->sd);
        pr_err("tun: sock_init failed: %d\n", err);
        free_netdev(dev);
        return err;
    }

    priv->cd = crypt_init();

    if (IS_ERR(priv->cd)) {
        err = PTR_ERR(priv->cd);
        pr_err("tun: crypt_init failed: %d\n", err);
        free_netdev(dev);
        sock_close(priv->sd);
        return err;
    }

    err = kfifo_alloc(&priv->send_fifo, SEND_FIFO_SIZE, GFP_KERNEL);
    if (err) {
        pr_err("tun: failed to allocate send fifo: %d\n", err);
        free_netdev(dev);
        sock_close(priv->sd);
        crypt_close(priv->cd);
        return err;
    }

    priv->dest.ip = in_aton(dest_ip);
    priv->dest.port = htons(dest_port);

    err = register_netdev(dev);
    if (err) {
        pr_err("tun: failed to register net device: %d\n", err);
        free_netdev(dev);
        sock_close(priv->sd);
        crypt_close(priv->cd);
        kfifo_free(&priv->send_fifo);
        return err;
    }

    struct sock* sk = priv->sd->sock->sk;
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

    if (priv->sd && priv->sd->sock) {
        struct sock* sk = priv->sd->sock->sk;
        write_lock_bh(&sk->sk_callback_lock);
        sk->sk_data_ready = priv->orig_data_ready;
        sk->sk_user_data = NULL;
        write_unlock_bh(&sk->sk_callback_lock);
    }

    kfifo_free(&priv->send_fifo);

    if (priv->sd) {
        sock_close(priv->sd);
    }

    if (priv->cd) {
        crypt_close(priv->cd);
    }

    free_netdev(dev);

    pr_info("tun: module unloaded\n");
}

module_init(minit);
module_exit(mexit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("nlmpx09");
MODULE_DESCRIPTION("tunnel driver");
