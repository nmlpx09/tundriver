/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - encrypt/decrypt (RC4 stream cipher)
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#ifndef CRYPT_IMPL_H
#define CRYPT_IMPL_H

#include <linux/skbuff.h>
#include <linux/types.h>

#include "types.h"

struct crypt_ctx* crypt_init(const char* key, size_t len);

void crypt_close(struct crypt_ctx* ctx);

int encrypt(struct crypt_ctx* ctx, struct sk_buff* skb);

int decrypt(struct crypt_ctx* ctx, struct sk_buff* skb);

#endif
