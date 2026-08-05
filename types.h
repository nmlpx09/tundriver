#include <linux/netdevice.h>
#include <linux/kfifo.h>
#include <linux/socket.h>

struct tun_priv {
    struct net_device *dev;

    struct socket *sock;
    struct sockaddr_in dest_addr;

    DECLARE_KFIFO_PTR(send_fifo, struct sk_buff *);
    spinlock_t send_lock;
    struct work_struct send_work;

    struct work_struct recv_work;
    void (*orig_data_ready)(struct sock *sk);
};
