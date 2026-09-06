// SPDX-License-Identifier: GPL-2.0
/*
 * tnet - IPS table (RCU hashtable, add/get/expire)
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/ktime.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/types.h>

#define IPS_CHECK_DELAY_NS (600ull * NSEC_PER_SEC)
#define IPS_REMOVE_DELAY_NS (3600ull * NSEC_PER_SEC)

#include "impl.h"

static void ips_entry_free_rcu(struct rcu_head* rhf)
{
    struct ips_entry* entry = container_of(rhf, struct ips_entry, rhf);
    dst_cache_destroy(&entry->dst_cache);
    kfree(entry);
}

struct ips_storage* ips_init(void)
{
    struct ips_storage* storage = kmalloc(sizeof(struct ips_storage), GFP_KERNEL);

    if (!storage) {
        return ERR_PTR(-ENOMEM);
    }

    hash_init(storage->table);
    storage->ts = ktime_get_ns();

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
        hash_del_rcu(&entry->node);
        call_rcu(&entry->rhf, ips_entry_free_rcu);
    }

    synchronize_rcu();
    kfree(storage);
}

static u32 ips_hash(__be32 key)
{
    return jhash_1word((__force u32)key, 0);
}

struct ips_entry* ips_get(struct ips_storage* storage, __be32 key)
{
    if (unlikely(!storage)) {
        return ERR_PTR(-EINVAL);
    }

    struct ips_entry* entry;
    u32 h = ips_hash(key);

    hash_for_each_possible(storage->table, entry, node, h) {
        if (entry->key == key) {
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

    u64 now = ktime_get_ns();
    if (unlikely(now - storage->ts > IPS_CHECK_DELAY_NS)) {
        storage->ts = now;

        struct hlist_node* tmp;
        int i;
        hash_for_each_safe(storage->table, i, tmp, entry, node) {
            if (unlikely(now - entry->ts > IPS_REMOVE_DELAY_NS)) {
                hash_del_rcu(&entry->node);
                call_rcu(&entry->rhf, ips_entry_free_rcu);
            }
        }
    }

    entry = ips_get(storage, key);

    if (likely(entry)) {
        if (unlikely(entry->ip != ip || entry->port != port)) {
            WRITE_ONCE(entry->ip, ip);
            WRITE_ONCE(entry->port, port);
            dst_cache_reset(&entry->dst_cache);
        }
        WRITE_ONCE(entry->ts, now);
        return 0;
    }

    entry = kmalloc(sizeof(struct ips_entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }

    int err = dst_cache_init(&entry->dst_cache, GFP_KERNEL);
    if (err) {
        kfree(entry);
        return err;
    }

    entry->key = key;
    entry->ip = ip;
    entry->port = port;
    entry->ts = now;
    u32 h = ips_hash(key);
    hash_add_rcu(storage->table, &entry->node, h);

    return 0;
}
