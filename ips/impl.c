// SPDX-License-Identifier: GPL-2.0
/*
 * tnet - IPS table (hashtable, add/get)
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <net/dst_cache.h>

#include "impl.h"

static __be32 get_key8(__be32 key) {
    return key & 0xFF000000;
}

struct ips_storage* ips_init(void)
{
    struct ips_storage* storage = kmalloc(sizeof(struct ips_storage), GFP_KERNEL);

    if (!storage) {
        return ERR_PTR(-ENOMEM);
    }

    hash_init(storage->table);

    return storage;
}

void ips_close(struct ips_storage* storage)
{
    if (!storage) {
        return;
    }

    struct ips_entry* entry;
    struct hlist_node* tmp;
    int i;

    hash_for_each_safe(storage->table, i, tmp, entry, node) {
        hash_del(&entry->node);
        dst_cache_destroy(&entry->dst_cache);
        kfree(entry);
    }

    kfree(storage);
}

struct ips_entry* ips_get(struct ips_storage* storage, __be32 key)
{
    if (unlikely(!storage)) {
        return ERR_PTR(-EINVAL);
    }

    struct ips_entry* entry;

    __be32 key8 = get_key8(key);

    hash_for_each_possible(storage->table, entry, node, (__force u32)key8) {
        if (entry->key == key8) {
            return entry;
        }
    }

    return NULL;
}

int ips_add(struct ips_storage* storage, __be32 key, __be32 ip, __be16 port)
{
    struct ips_entry* entry;

    if (unlikely(!storage)) {
        return -EINVAL;
    }

    __be32 key8 = get_key8(key);

    entry = ips_get(storage, key8);

    if (likely(entry)) {
        if (unlikely(entry->ip != ip || entry->port != port)) {
            WRITE_ONCE(entry->ip, ip);
            WRITE_ONCE(entry->port, port);
            dst_cache_reset(&entry->dst_cache);
        }
        return 0;
    }

    entry = kmalloc(sizeof(struct ips_entry), GFP_ATOMIC);
    if (!entry) {
        return -ENOMEM;
    }

    int err = dst_cache_init(&entry->dst_cache, GFP_ATOMIC);
    if (err) {
        kfree(entry);
        return err;
    }

    entry->key = key8;
    entry->ip = ip;
    entry->port = port;
    hash_add(storage->table, &entry->node, (__force u32)key8);

    return 0;
}
