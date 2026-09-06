/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - ips_entry, ips_storage types
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#ifndef IPS_TYPES_H
#define IPS_TYPES_H

#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <net/dst_cache.h>

struct ips_entry {
    __be32 key;
    __be32 ip;
    __be16 port;
    u64 ts;
    struct hlist_node node;
    struct rcu_head rhf;
    struct dst_cache dst_cache;
};

#define IPS_HASH_BITS 8

struct ips_storage {
    DECLARE_HASHTABLE(table, IPS_HASH_BITS);
    u64 ts;
};

#endif
