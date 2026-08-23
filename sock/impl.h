#ifndef SOCK_IMPL_H
#define SOCK_IMPL_H

#include "types.h"

struct socket* sock_init(__be16 port);

void sock_close(struct socket*);

int sock_write(struct socket *sock, u8* data, size_t len, __be32 ip, __be16 port);

int sock_read(struct socket *sock, u8* data, size_t len, __be32* ip, __be16* port);

#endif
