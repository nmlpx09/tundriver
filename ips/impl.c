// SPDX-License-Identifier: GPL-2.0
/*
 * tnet - IPS table (rhashtable, add/get)
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/rhashtable.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <net/dst_cache.h>

#include "impl.h"

static const struct rhashtable_params ips_params = {
    .key_len             = sizeof(__be32),
    .key_offset          = offsetof(struct ips_entry, key),
    .head_offset         = offsetof(struct ips_entry, node),
    .automatic_shrinking = true,
};

struct ips_storage* ips_init(void)
{
    struct ips_storage* storage = kmalloc(sizeof(*storage), GFP_KERNEL);

    if (!storage) {
        return ERR_PTR(-ENOMEM);
    }

    int err = rhashtable_init(&storage->ht, &ips_params);
    if (err) {
        kfree(storage);
        return ERR_PTR(err);
    }

    return storage;
}

static void ips_entry_free(void* ptr, void* arg)
{
    struct ips_entry* entry = ptr;

    dst_cache_destroy(&entry->dst_cache);
    kfree(entry);
}

void ips_close(struct ips_storage* storage)
{
    if (!storage) {
        return;
    }

    rhashtable_free_and_destroy(&storage->ht, ips_entry_free, NULL);
    kfree(storage);
}

static __be32 get_key8(__be32 key32) {
    return key32 & htonl(0x000000FF);
}

struct ips_entry* ips_get(struct ips_storage* storage, __be32 key32)
{
    struct ips_entry* entry;

    if (unlikely(!storage)) {
        return NULL;
    }

    __be32 key8 = get_key8(key32);

    rcu_read_lock();
    entry = rhashtable_lookup_fast(&storage->ht, &key8, ips_params);
    rcu_read_unlock();

    return entry;
}

static int ips_add_peer(struct ips_storage* storage, __be32 key8, __be64 peer)
{
    rcu_read_lock();
    struct ips_entry* entry = rhashtable_lookup_fast(&storage->ht, &key8, ips_params);
    if (entry) {
        if (READ_ONCE(entry->peer) != peer) {
            WRITE_ONCE(entry->peer, peer);
            dst_cache_reset(&entry->dst_cache);
        }
        rcu_read_unlock();
        return 0;
    }
    rcu_read_unlock();
    return -ENOENT;
}

int ips_add(struct ips_storage* storage, __be32 key32, __be32 ip, __be16 port)
{
    struct ips_entry* entry;
    int err;

    if (unlikely(!storage)) {
        return -EINVAL;
    }

    __be32 key8 = get_key8(key32);
    __be64 peer = (__be64)port << 32 | (__be64)ip;

    if (likely(!ips_add_peer(storage, key8, peer))) {
        return 0;
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }

    err = dst_cache_init(&entry->dst_cache, GFP_KERNEL);
    if (err) {
        kfree(entry);
        return err;
    }

    entry->key = key8;
    entry->peer = peer;

    err = rhashtable_lookup_insert_fast(&storage->ht, &entry->node, ips_params);
    if (err == -EEXIST) {
        dst_cache_destroy(&entry->dst_cache);
        kfree(entry);
        return ips_add_peer(storage, key8, peer);
    }

    return err;
}
