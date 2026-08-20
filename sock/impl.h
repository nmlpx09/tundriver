#ifndef SOCK_IMPL_H
#define SOCK_IMPL_H

#include <linux/socket.h>
#include <linux/types.h>

struct read_result {
    void* buf;
    int len;
};

struct socket* sock_init(__be16 port);

void sock_close(struct socket *sock);

int sock_write(struct socket *sock, void* data, size_t len, __be32 ip, __be16 port);

struct read_result sock_read(struct socket *sock);

#endif
