/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - ips_entry, ips_storage types
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#ifndef IPS_TYPES_H
#define IPS_TYPES_H

#include <linux/hashtable.h>
#include <linux/types.h>
#include <net/dst_cache.h>

struct ips_entry {
    __be32 key;
    __be32 ip;
    __be16 port;
    struct hlist_node node;
    struct dst_cache dst_cache;
};

struct ips_storage {
    DECLARE_HASHTABLE(table, 8);
};

#endif
