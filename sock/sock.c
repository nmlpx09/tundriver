#include "sock.h"

#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/sockptr.h>
#include <net/sock.h>
#include <net/net_namespace.h>

struct socket* sock_init(__be16 port)
{
    struct socket* sock;

    int err = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
    if (err) {
        return ERR_PTR(err);
    }

    struct sockaddr_in src_addr = {
        .sin_family = AF_INET,
        .sin_port = port,
        .sin_addr = { .s_addr = htonl(INADDR_ANY) }
    };

    err = kernel_bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if (err) {
        sock_release(sock);
        return ERR_PTR(err);
    }

    int buffer_size = SOCKET_BUFFER_SIZE;

    err = sock_setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, KERNEL_SOCKPTR(&buffer_size), sizeof(buffer_size));
    if (unlikely(err)) {
        sock_release(sock);
        return ERR_PTR(err);
    }

    err = sock_setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, KERNEL_SOCKPTR(&buffer_size), sizeof(buffer_size));
    if (unlikely(err)) {
        sock_release(sock);
        return ERR_PTR(err);
    }

    return sock;
}

void sock_close(struct socket *sock)
{
    if (unlikely(!sock)) {
        return;
    }
    sock_release(sock);
}

int sock_write(struct socket *sock, void* data, size_t len, __be32 ip, __be16 port)
{
    if (unlikely(!sock)) {
        return -EINVAL;
    }

    struct kvec kv;

    kv.iov_base = data;
    kv.iov_len = len;

    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port = port,
        .sin_addr = { .s_addr = ip }
    };
    
    struct msghdr msg = {
        .msg_name = &dest_addr,
        .msg_namelen = sizeof(dest_addr)
    };

    int ret = kernel_sendmsg(sock, &msg, &kv, 1, len);

    if (unlikely(ret < 0)) {
        return ret;
    }

    if (unlikely((size_t)ret < len)) {
        return -EIO;
    }

    return ret;
}

int sock_read(struct socket *sock, void* data, size_t len)
{
    if (unlikely(!sock)) {
        return -EINVAL;
    }

    struct kvec kv;

    kv.iov_base = data;
    kv.iov_len = len;

    struct msghdr msg = {0};
    int ret = kernel_recvmsg(sock, &msg, &kv, 1, len, MSG_DONTWAIT);

    if (unlikely(ret == -EAGAIN)) {
        return 0;
    }

    return ret;
}
