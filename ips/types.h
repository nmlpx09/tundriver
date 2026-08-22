#ifndef IPS_TYPES_H
#define IPS_TYPES_H

#include <linux/types.h>
#include <linux/hashtable.h>

struct ips_entry {
    __be32 key;
    __be32 ip;
    __be16 port;
    struct hlist_node node;
};

#define IPS_HASH_BITS 8
#define IPS_HASH_SIZE (1 << IPS_HASH_BITS)

struct ips_storage {
    DECLARE_HASHTABLE(table, IPS_HASH_BITS);
};

#endif
