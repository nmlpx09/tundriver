// SPDX-License-Identifier: GPL-2.0
/*
 * tnet - kernel UDP socket (bind, sendmsg, recvmsg)
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/udp.h>
#include <net/dst.h>
#include <net/flow.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/udp_tunnel.h>

#include "impl.h"

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

    return sock;
}

void sock_close(struct socket* sock)
{
    if (!sock) {
        return;
    }

    sock_release(sock);
}

int sock_send(struct socket* sock, struct sk_buff* skb, __be32 dip, __be16 dport)
{
    if (unlikely(!sock || !skb || !dip)) {
        return -EINVAL;
    }

    struct sock* sk = sock->sk;
    struct flowi4 fl = {
        .flowi4_proto = IPPROTO_UDP,
        .daddr = dip,
        .fl4_sport = inet_sk(sk)->inet_sport,
        .fl4_dport = dport,
    };

    struct rtable* rt = ip_route_output_flow(sock_net(sk), &fl, sk);
    if (unlikely(IS_ERR(rt))) {
        return PTR_ERR(rt);
    }

    int err = skb_cow_head(skb,
        LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len + sizeof(struct iphdr) + sizeof(struct udphdr));
    if (unlikely(err)) {
        ip_rt_put(rt);
        return err;
    }

    udp_tunnel_xmit_skb(rt, sk, skb, fl.saddr, fl.daddr, 0,
        ip4_dst_hoplimit(&rt->dst), 0, fl.fl4_sport, fl.fl4_dport, false, true);

    return 0;
}
