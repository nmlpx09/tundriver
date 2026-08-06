#include <linux/err.h>
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/inet.h>
#include <net/sock.h>

#include "types.h"

#include <sock/sock.h>

#define DEV_NAME "vnet%d"
#define SEND_FIFO_SIZE 256
#define MTU 1472

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

    while (true) {
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
            sock_write(priv->sock, skb->data + ETH_HLEN, skb->len - ETH_HLEN, in_aton(dest_ip), htons(dest_port));
        }

        dev_kfree_skb_any(skb);
    }
}

static void recv_work(struct work_struct* work)
{
    struct tun_priv* priv = container_of(work, struct tun_priv, recv_work);
    struct net_device* dev = priv->dev;
    char buf[MTU];

    while (true) {
        if (unlikely(!netif_running(dev))) {
            break;
        }

        int len = sock_read(priv->sock, buf, sizeof(buf));
        if (unlikely(len <= 0)) {
            break;
        }

        struct sk_buff* skb = netdev_alloc_skb(dev, len + ETH_HLEN + NET_IP_ALIGN);
        if (unlikely(!skb)) {
            continue;
        }

        skb_reserve(skb, NET_IP_ALIGN);

        struct ethhdr* eth = skb_put(skb, ETH_HLEN);
        memcpy(eth->h_dest, dev->dev_addr, ETH_ALEN);
        memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
        eth->h_proto = htons(ETH_P_IP);

        skb_put_data(skb, buf, len);

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

    if (unlikely(!priv->sock)) {
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

    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;

    kfifo_put(&priv->send_fifo, skb);
    spin_unlock_irqrestore(&priv->send_lock, flags);
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
    dev = alloc_netdev(sizeof(struct tun_priv), DEV_NAME, NET_NAME_UNKNOWN, setup);
    
    if (!dev) {
        pr_err("tun: failed to allocate net device\n");
        return -ENOMEM;
    }

    struct tun_priv* priv = netdev_priv(dev);
    priv->dev = dev;

    int err = kfifo_alloc(&priv->send_fifo, SEND_FIFO_SIZE, GFP_KERNEL);
    if (err) {
        pr_err("tun: failed to allocate send fifo: %d\n", err);
        free_netdev(dev);
        return err;
    }

    priv->sock = sock_init(htons(src_port));
    if (IS_ERR(priv->sock)) {
        kfifo_free(&priv->send_fifo);
        free_netdev(dev);
        return PTR_ERR(priv->sock);
    }

    err = register_netdev(dev);
    if (err) {
        pr_err("tun: failed to register net device: %d\n", err);
        sock_close(priv->sock);
        kfifo_free(&priv->send_fifo);
        free_netdev(dev);
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

    cancel_work_sync(&priv->send_work);
    cancel_work_sync(&priv->recv_work);

    kfifo_free(&priv->send_fifo);

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
