#ifndef SOCK_H
#define SOCK_H

#define SOCKET_BUFFER_SIZE (4 * 1024 * 1024)

#include <linux/socket.h>
#include <linux/types.h>

struct socket* sock_init(__be16 port);

void sock_close(struct socket *sock);

int sock_write(struct socket *sock, void* data, size_t len, __be32 ip, __be16 port);

int sock_read(struct socket *sock, void* data, size_t len);

#endif
