#include <linux/slab.h>
#include <linux/jhash.h>

#include "impl.h"

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

    ips_clear(storage);
    kfree(storage);
}

static u32 ips_hash(__be32 key)
{
    return jhash_1word((__force u32)key, 0) & (IPS_HASH_SIZE - 1);
}

struct ips_entry* ips_get(struct ips_storage* storage, __be32 key)
{
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
    u32 h;

    if (!storage) {
        return -EINVAL;
    }

    entry = ips_get(storage, key);

    if (entry) {
        entry->ip = ip;
        entry->port = port;
        return 0;
    }

    entry = kmalloc(sizeof(struct ips_entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }

    entry->key = key;
    entry->ip = ip;
    entry->port = port;
    h = ips_hash(key);
    hash_add(storage->table, &entry->node, h);

    return 0;
}

int ips_del(struct ips_storage* storage, __be32 key)
{
    struct ips_entry* entry;

    if (!storage) {
        return -EINVAL;
    }

    entry = ips_get(storage, key);
    if (!entry) {
        return -ENOENT;
    }

    hash_del(&entry->node);
    kfree(entry);

    return 0;
}

bool ips_has(struct ips_storage* storage, __be32 key)
{
    if (!storage) {
        return false;
    }

    return ips_get(storage, key) != NULL;
}

void ips_clear(struct ips_storage* storage)
{
    struct ips_entry* entry;
    struct hlist_node* tmp;
    int i;

    if (!storage) {
        return;
    }

    hash_for_each_safe(storage->table, i, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }
}
