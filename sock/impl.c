#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/sockptr.h>
#include <net/sock.h>
#include <net/net_namespace.h>

#include "impl.h"

#include <configs.h>

struct sock_data* sock_init(__be16 port)
{
    struct sock_data* res = kmalloc(sizeof(struct sock_data), GFP_KERNEL);

    if (!res) {
        return ERR_PTR(-ENOMEM);
    }

    res->mbs = MAX_BUFFER_SIZE;
    res->sock = NULL;
    res->readb = NULL;
    res->readbl = -1;
    res->sip = 0;
    res->sport = 0;

    struct socket* sock;

    int err = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
    if (err) {
        kfree(res);
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
        kfree(res);
        return ERR_PTR(err);
    }

    int buffer_size = SOCKET_BUFFER_SIZE;

    err = sock_setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, KERNEL_SOCKPTR(&buffer_size), sizeof(buffer_size));
    if (unlikely(err)) {
        sock_release(sock);
        kfree(res);
        return ERR_PTR(err);
    }

    err = sock_setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, KERNEL_SOCKPTR(&buffer_size), sizeof(buffer_size));
    if (unlikely(err)) {
        sock_release(sock);
        kfree(res);
        return ERR_PTR(err);
    }

    res->sock = sock;
    res->readb = kmalloc(res->mbs, GFP_KERNEL);

    if (!res->readb) {
        sock_release(sock);
        kfree(res);
        return ERR_PTR(-ENOMEM);
    }

    return res;
}

void sock_close(struct sock_data* sd)
{
    if (!sd) {
        return;
    }

    if (sd->sock) {
        sock_release(sd->sock);
    }

    kfree(sd->readb);
    kfree(sd);
}

int sock_write(struct sock_data* sd, u8* data, size_t len, __be32 ip, __be16 port)
{
    if (unlikely(!sd || !sd->sock)) {
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

    int ret = kernel_sendmsg(sd->sock, &msg, &kv, 1, len);

    if (unlikely(ret < 0)) {
        return ret;
    }

    if (unlikely((size_t)ret < len)) {
        return -EIO;
    }

    return ret;
}

int sock_read(struct sock_data* sd)
{
    if (unlikely(!sd || !sd->sock)) {
        return -EINVAL;
    }

    struct kvec kv;

    kv.iov_base = sd->readb;
    kv.iov_len = sd->mbs;

    struct sockaddr_in src_addr = {0};
    struct msghdr msg = {
        .msg_name = &src_addr,
        .msg_namelen = sizeof(src_addr)
    };

    int ret = kernel_recvmsg(sd->sock, &msg, &kv, 1, sd->mbs, MSG_DONTWAIT);

    if (likely(ret > 0)) {
        sd->sip = src_addr.sin_addr.s_addr;
        sd->sport = src_addr.sin_port;
        sd->readbl = ret;
    }

    if (unlikely(ret == -EAGAIN || ret == -EWOULDBLOCK || ret == 0)) {
        sd->readbl = 0;
    } else if (unlikely(ret < 0)) {
        return -EIO;
    }

    return ret;
}
