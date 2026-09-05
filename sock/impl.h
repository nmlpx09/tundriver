/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - kernel UDP socket (bind, sendmsg, recvmsg)
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#ifndef SOCK_IMPL_H
#define SOCK_IMPL_H

#include <linux/skbuff.h>
#include <linux/types.h>
#include <net/udp_tunnel.h>

struct socket* sock_init(__be16 port);

void sock_setup(struct socket* sock, struct udp_tunnel_sock_cfg* cfg);

void sock_close(struct socket* sock);

int sock_send(struct socket* sock, struct sk_buff* skb, __be32 dip, __be16 dport);

#endif
