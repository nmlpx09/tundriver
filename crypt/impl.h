/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - encrypt/decrypt (ChaCha20-Poly1305 AEAD)
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#ifndef CRYPT_IMPL_H
#define CRYPT_IMPL_H

#include <linux/skbuff.h>
#include <linux/types.h>

#define CRYPT_KEY_SIZE    32  /* ChaCha20-Poly1305: 256-bit key */
#define CRYPT_NONCE_SIZE  12  /* 96-bit nonce */
#define CRYPT_TAG_SIZE    16  /* 128-bit Poly1305 auth tag */

int crypt_init(const char* key_b64);
void crypt_exit(void);

int encrypt(struct sk_buff* skb);
int decrypt(struct sk_buff* skb);

#endif
