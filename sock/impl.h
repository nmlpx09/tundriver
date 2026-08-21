#ifndef SOCK_IMPL_H
#define SOCK_IMPL_H

#include "types.h"

struct sock_data* sock_init(__be16 port);

void sock_close(struct sock_data* sd);

int sock_write(struct sock_data* sd, u8* data, size_t len, __be32 ip, __be16 port);

void sock_read(struct sock_data* sd);

#endif
