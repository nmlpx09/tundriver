/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - encrypt/decrypt (substitution cipher)
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#ifndef CRYPT_IMPL_H
#define CRYPT_IMPL_H

#include <linux/skbuff.h>

int encrypt(struct sk_buff* skb);
int decrypt(struct sk_buff* skb);

#endif
