#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/kfifo.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/inet.h>
#include <net/sock.h>

#define VNET_NAME "vnet%d"
#define VNET_SEND_FIFO_SIZE 256
#define MTU 1472

static char *dest_ip = "158.255.0.70";
static int dest_port = 69;
static int src_port = 0;

module_param(dest_ip, charp, 0644);
MODULE_PARM_DESC(dest_ip, "Destination IP address");
module_param(dest_port, int, 0644);
MODULE_PARM_DESC(dest_port, "Destination UDP port");

static struct net_device *vnet_dev;

struct vnet_priv {
    struct net_device *vnet_dev;

    struct socket *sock;
    struct sockaddr_in dest_addr;

    DECLARE_KFIFO_PTR(send_fifo, struct sk_buff *);
    spinlock_t send_lock;
    struct work_struct send_work;

    struct work_struct recv_work;
    void (*orig_data_ready)(struct sock *sk);
};

static void vnet_send_work(struct work_struct *work)
{
    struct vnet_priv *priv = container_of(work, struct vnet_priv, send_work);
    struct sk_buff *skb;
    struct msghdr msg = {0};
    struct kvec kv;
    unsigned long flags;
    int len;

    while (true) {
        spin_lock_irqsave(&priv->send_lock, flags);
        if (!kfifo_get(&priv->send_fifo, &skb)) {
            spin_unlock_irqrestore(&priv->send_lock, flags);
            break;
        }
        spin_unlock_irqrestore(&priv->send_lock, flags);

        if (skb_linearize(skb)) {
            pr_warn("vnet: skb_linearize failed\n");
            dev_kfree_skb_any(skb);
            continue;
        }

        if (skb->len > ETH_HLEN) {
            len = skb->len - ETH_HLEN;

            kv.iov_base = skb->data + ETH_HLEN;
            kv.iov_len = len;

            msg.msg_name = &priv->dest_addr;
            msg.msg_namelen = sizeof(priv->dest_addr);

            int ret = kernel_sendmsg(priv->sock, &msg, &kv, 1, len);
            if (ret < 0) {
                pr_warn("vnet: kernel_sendmsg failed: %d\n", ret);
            }
        }

        dev_kfree_skb_any(skb);
    }
}

static void vnet_recv_work(struct work_struct *work)
{
    struct vnet_priv *priv = container_of(work, struct vnet_priv, recv_work);
    struct net_device *dev = priv->vnet_dev;
    char buf[MTU];

    while (true) {
        if (!netif_running(dev)) {
            break;
        }

        struct msghdr msg = {0};
        struct kvec kv;
        int len;

        kv.iov_base = buf;
        kv.iov_len = sizeof(buf);

        len = kernel_recvmsg(priv->sock, &msg, &kv, 1, sizeof(buf), MSG_DONTWAIT);
        if (len <= 0) {
            break;
        }

        struct sk_buff *skb = netdev_alloc_skb(dev, len + ETH_HLEN + NET_IP_ALIGN);
        if (!skb) {
            continue;
        }

        skb_reserve(skb, NET_IP_ALIGN);

        struct ethhdr *eth = skb_put(skb, ETH_HLEN);
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

static void vnet_data_ready(struct sock *sk)
{
    struct vnet_priv *priv = sk->sk_user_data;
    if (priv) {
        schedule_work(&priv->recv_work);
    }
}

static int vnet_open(struct net_device *dev)
{
    netif_start_queue(dev);
    pr_info("vnet: device opened\n");
    return 0;
}

static int vnet_stop(struct net_device *dev)
{
    struct vnet_priv *priv = netdev_priv(dev);
    struct sk_buff *skb;

    netif_stop_queue(dev);

    cancel_work_sync(&priv->send_work);
    cancel_work_sync(&priv->recv_work);

    while (kfifo_get(&priv->send_fifo, &skb))
        dev_kfree_skb_any(skb);

    pr_info("vnet: device stopped\n");
    return 0;
}

static netdev_tx_t vnet_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct vnet_priv *priv = netdev_priv(dev);
    unsigned long flags;

    if (!priv->sock) {
        dev_kfree_skb_any(skb);
        dev->stats.tx_dropped++;
        return NETDEV_TX_OK;
    }

    spin_lock_irqsave(&priv->send_lock, flags);
    if (kfifo_is_full(&priv->send_fifo)) {
        spin_unlock_irqrestore(&priv->send_lock, flags);
        dev_kfree_skb_any(skb);
        dev->stats.tx_dropped++;
        pr_warn("vnet: send fifo full, tunnel packet dropped\n");
        return NETDEV_TX_OK;
    }

    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;

    kfifo_put(&priv->send_fifo, skb);
    spin_unlock_irqrestore(&priv->send_lock, flags);
    schedule_work(&priv->send_work);

    return NETDEV_TX_OK;
}

static const struct net_device_ops vnet_ops = {
    .ndo_open       = vnet_open,
    .ndo_stop       = vnet_stop,
    .ndo_start_xmit = vnet_start_xmit,
};

static void vnet_setup(struct net_device *dev)
{
    struct vnet_priv *priv;

    ether_setup(dev);

    dev->netdev_ops = &vnet_ops;
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
    INIT_WORK(&priv->send_work, vnet_send_work);
    INIT_WORK(&priv->recv_work, vnet_recv_work);
}

static int vnet_init_sock(struct vnet_priv *priv)
{
    int err;
    struct sockaddr_in src_addr;
    struct sock *sk;

    err = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &priv->sock);
    if (err) {
        pr_err("vnet: sock_create failed: %d\n", err);
        return err;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sin_family = AF_INET;
    src_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    src_addr.sin_port = htons(src_port);

    err = kernel_bind(priv->sock, (struct sockaddr *)&src_addr, sizeof(src_addr));
    if (err) {
        pr_err("vnet: kernel_bind failed: %d\n", err);
        sock_release(priv->sock);
        priv->sock = NULL;
        return err;
    }

    memset(&priv->dest_addr, 0, sizeof(priv->dest_addr));
    priv->dest_addr.sin_family = AF_INET;
    priv->dest_addr.sin_port = htons(dest_port);
    priv->dest_addr.sin_addr.s_addr = in_aton(dest_ip);

    sk = priv->sock->sk;
    write_lock_bh(&sk->sk_callback_lock);
    priv->orig_data_ready = sk->sk_data_ready;
    sk->sk_data_ready = vnet_data_ready;
    sk->sk_user_data = priv;
    write_unlock_bh(&sk->sk_callback_lock);

    pr_info("vnet: socket created, bind=0.0.0.0:%d, dest=%s:%d\n", src_port, dest_ip, dest_port);
    return 0;
}

static int __init vnet_init(void)
{
    struct vnet_priv *priv;
    int err;

    vnet_dev = alloc_netdev(sizeof(struct vnet_priv), VNET_NAME, NET_NAME_UNKNOWN, vnet_setup);
    
    if (!vnet_dev) {
        pr_err("vnet: failed to allocate net device\n");
        return -ENOMEM;
    }

    priv = netdev_priv(vnet_dev);
    priv->vnet_dev = vnet_dev;

    err = kfifo_alloc(&priv->send_fifo, VNET_SEND_FIFO_SIZE, GFP_KERNEL);
    if (err) {
        pr_err("vnet: failed to allocate send fifo: %d\n", err);
        free_netdev(vnet_dev);
        return err;
    }

    err = vnet_init_sock(priv);
    if (err) {
        kfifo_free(&priv->send_fifo);
        free_netdev(vnet_dev);
        return err;
    }

    err = register_netdev(vnet_dev);
    if (err) {
        pr_err("vnet: failed to register net device: %d\n", err);
        sock_release(priv->sock);
        kfifo_free(&priv->send_fifo);
        free_netdev(vnet_dev);
        return err;
    }

    pr_info("vnet: module loaded, device %s registered\n", vnet_dev->name);
    return 0;
}

static void __exit vnet_exit(void)
{
    struct vnet_priv *priv;
    struct sk_buff *skb;
    struct sock *sk;

    if (!vnet_dev) {
        return;
    }

    priv = netdev_priv(vnet_dev);

    unregister_netdev(vnet_dev);

    while (kfifo_get(&priv->send_fifo, &skb)) {
        dev_kfree_skb_any(skb);
    }

    kfifo_free(&priv->send_fifo);

    if (priv->sock) {
        sk = priv->sock->sk;
        write_lock_bh(&sk->sk_callback_lock);
        sk->sk_data_ready = priv->orig_data_ready;
        sk->sk_user_data = NULL;
        write_unlock_bh(&sk->sk_callback_lock);
    }

    cancel_work_sync(&priv->send_work);
    cancel_work_sync(&priv->recv_work);

    if (priv->sock) {
        sock_release(priv->sock);
    }

    free_netdev(vnet_dev);

    pr_info("vnet: module unloaded\n");
}

module_init(vnet_init);
module_exit(vnet_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("vnet");
MODULE_DESCRIPTION("Virtual Network Device with UDP tunneling via sk_data_ready");
