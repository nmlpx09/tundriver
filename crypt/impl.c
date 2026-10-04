// SPDX-License-Identifier: GPL-2.0
/*
 * tnet - encrypt/decrypt (substitution cipher)
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#include <linux/skbuff.h>

#include "impl.h"
#include "table.h"

static int crypt_skb(struct sk_buff* skb, const u8* table)
{
    int err = skb_ensure_writable(skb, skb->len);
    if (unlikely(err))
        return err;

    u8* data = skb->data;
    size_t len = skb_headlen(skb), i;

    for (i = 0; i + 3 < len; i += 4) {
        data[i] = table[data[i]];
        data[i + 1] = table[data[i + 1]];
        data[i + 2] = table[data[i + 2]];
        data[i + 3] = table[data[i + 3]];
    }

    for (; i < len; i++) {
        data[i] = table[data[i]];
    }
    return 0;
}

int encrypt(struct sk_buff* skb)
{
    if (unlikely(!skb)) {
        return -EINVAL;
    }

    return crypt_skb(skb, ENCRYPT_TABLE);
}

int decrypt(struct sk_buff* skb)
{
    if (unlikely(!skb)) {
        return -EINVAL;
    }

    return crypt_skb(skb, DECRYPT_TABLE);
}
