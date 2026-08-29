/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - kernel UDP socket (bind, sendmsg, recvmsg)
 *
 * Copyright (c) 2026 nmlpx <nmlpx09@duck.com>
 */

#ifndef SOCK_IMPL_H
#define SOCK_IMPL_H

#include <linux/err.h>
#include <linux/types.h>

struct socket* sock_init(__be16 port);

void sock_close(struct socket*);

int sock_write(struct socket* sock, u8* data, size_t len, __be32 ip, __be16 port);

int sock_read(struct socket* sock, u8* data, size_t len, __be32* ip, __be16* port);

#endif
