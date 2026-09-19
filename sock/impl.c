// SPDX-License-Identifier: GPL-2.0
/*
 * tnet - kernel UDP socket (udp_sock_create4, setup_udp_tunnel_sock, udp_tunnel_xmit_skb)
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/udp.h>
#include <net/dst_cache.h>
#include <net/flow.h>
#include <net/inet_sock.h>
#include <net/ip.h>
#include <net/net_namespace.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/udp_tunnel.h>

#include "impl.h"

struct socket* sock_init(__be16 port)
{
    struct udp_port_cfg cfg = {
        .family = AF_INET,
        .local_udp_port = port,
        .local_ip.s_addr = htonl(INADDR_ANY),
    };

    struct socket* sock;
    int err = udp_sock_create4(&init_net, &cfg, &sock);
    if (err) {
        return ERR_PTR(err);
    }

    return sock;
}

void sock_setup(struct socket* sock, struct udp_tunnel_sock_cfg* cfg)
{
    setup_udp_tunnel_sock(&init_net, sock, cfg);
}

void sock_close(struct socket* sock)
{
    if (!sock) {
        return;
    }

    udp_tunnel_sock_release(sock);
}

int sock_send(struct socket* sock, struct sk_buff* skb,
              struct dst_cache* dc, __be32 dip, __be16 dport)
{
    if (unlikely(!sock || !skb || !dip)) {
        return -EINVAL;
    }

    struct sock* sk = sock->sk;
    struct rtable* rt;
    __be32 saddr;

    int err = skb_cow_head(skb,
        ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr));
    if (unlikely(err)) {
        return err;
    }

    local_bh_disable();
    rt = dst_cache_get_ip4(dc, &saddr);
    if (unlikely(!rt)) {
        struct flowi4 fl = {
            .flowi4_proto = IPPROTO_UDP,
            .daddr = dip,
            .fl4_sport = inet_sk(sk)->inet_sport,
            .fl4_dport = dport,
        };

        rt = ip_route_output_flow(sock_net(sk), &fl, sk);
        if (unlikely(IS_ERR(rt))) {
            local_bh_enable();
            return PTR_ERR(rt);
        }

        saddr = fl.saddr;
        dst_cache_set_ip4(dc, &rt->dst, saddr);
    }
    local_bh_enable();

    udp_tunnel_xmit_skb(rt, sk, skb, saddr, dip, 0,
        ip4_dst_hoplimit(&rt->dst), 0, inet_sk(sk)->inet_sport, dport, false, true);

    return 0;
}
