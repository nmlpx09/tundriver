#ifndef IPS_TYPES_H
#define IPS_TYPES_H

#include <linux/hashtable.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

struct ips_entry {
    __be32 key;
    __be32 ip;
    __be16 port;
    u64 ts;
    struct hlist_node node;
    struct rcu_head rhf;
};

#define IPS_HASH_BITS 10

#define IPS_CHECK_DELAY_NS (600ull * NSEC_PER_SEC)
#define IPS_REMOVE_DELAY_NS (3600ull * NSEC_PER_SEC)

struct ips_storage {
    DECLARE_HASHTABLE(table, IPS_HASH_BITS);
    u64 ts;
};

#endif
