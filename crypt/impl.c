// SPDX-License-Identifier: GPL-2.0
/*
 * tnet - encrypt/decrypt (RC4 stream cipher)
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#include <linux/string.h>
#include <linux/skbuff.h>

#include "impl.h"

static inline void swap_u8(u8* a, u8* b)
{
    u8 tmp = *a;
    *a = *b;
    *b = tmp;
}

static int crypt_rc4(struct crypt_ctx* ctx, struct sk_buff* skb)
{
    int err;

    err = skb_ensure_writable(skb, skb->len);
    if (unlikely(err)) {
        return err;
    }

    u8* data = skb->data;
    const u8* prga = ctx->prga;
    const size_t len = skb_headlen(skb);
    const size_t lprga = ctx->lprga;

    for (size_t i = 0; i < len; ++i) {
        data[i] ^= prga[i % lprga];
    }

    return 0;
}

int encrypt(struct crypt_ctx* ctx, struct sk_buff* skb)
{
    if (unlikely(!skb || !ctx || ctx->lprga == 0))
        return -EINVAL;

    return crypt_rc4(ctx, skb);
}

int decrypt(struct crypt_ctx* ctx, struct sk_buff* skb)
{
    if (unlikely(!skb || !ctx || ctx->lprga == 0))
        return -EINVAL;

    return crypt_rc4(ctx, skb);
}

struct crypt_ctx* crypt_init(const char* key, size_t len)
{
    if (!key || !*key) {
        return ERR_PTR(-EINVAL);
    }

    const size_t keylen = strlen(key);
    const u8* key8 = (const u8*)key;

    u8 i = 0, j = 0;
    u8 s[256];

    do {
        s[i] = i;
    } while (++i);

    do {
        j += s[i] + key8[i % keylen];
        swap_u8(&s[i], &s[j]);
    } while (++i);

    i = 0;
    j = 0;

    struct crypt_ctx* ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);

    if (!ctx) {
        return ERR_PTR(-ENOMEM);
    }

    ctx->prga = kmalloc(len, GFP_KERNEL);

    if (!ctx->prga) {
        kfree(ctx);
        return ERR_PTR(-ENOMEM);
    }

    ctx->lprga = len;

    for (size_t k = 0; k < len; k++) {
        i = i + 1;
        j = j + s[i];

        swap_u8(&s[i], &s[j]);
        ctx->prga[k] = s[(s[i] + s[j]) & 0xFF];
    }

    return ctx;
}

void crypt_close(struct crypt_ctx* ctx)
{
    if (ctx) {
        kfree_sensitive(ctx->prga);
        kfree(ctx);
    }
}
