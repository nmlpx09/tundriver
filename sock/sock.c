#include "sock.h"

#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <net/net_namespace.h>

struct socket* sock_init(__be16 port)
{
    struct socket* sock;

    int err = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
    if (err) {
        pr_err("tun: sock_create failed: %d\n", err);
        return ERR_PTR(err);
    }

    struct sockaddr_in src_addr;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sin_family = AF_INET;
    src_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    src_addr.sin_port = port;

    err = kernel_bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if (err) {
        pr_err("tun: kernel_bind failed: %d\n", err);
        sock_release(sock);
        return ERR_PTR(err);
    }

    return sock;
}

void sock_close(struct socket *sock)
{
    sock_release(sock);
}

void sock_write(struct socket *sock, void* data, unsigned int len, __be32 ip, __be16 port)
{
    struct kvec kv;

    kv.iov_base = data;
    kv.iov_len = len;

    struct sockaddr_in dest_addr;
    
    struct msghdr msg = {0};
    msg.msg_name = &dest_addr;
    msg.msg_namelen = sizeof(dest_addr);

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port;
    dest_addr.sin_addr.s_addr = ip;

    int ret = kernel_sendmsg(sock, &msg, &kv, 1, len);
    if (unlikely(ret < 0)) {
        pr_warn("tun: kernel_sendmsg failed: %d\n", ret);
    }
}

int sock_read(struct socket *sock, void* data, unsigned int len)
{
    struct kvec kv;

    kv.iov_base = data;
    kv.iov_len = len;

    struct msghdr msg = {0};
    return kernel_recvmsg(sock, &msg, &kv, 1, len, MSG_DONTWAIT);
}
