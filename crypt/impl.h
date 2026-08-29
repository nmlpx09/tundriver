/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - encrypt/decrypt (substitution cipher)
 *
 * Copyright (c) 2026 nmlpx <nmlpx09@duck.com>
 */

#ifndef CRYPT_IMPL_H
#define CRYPT_IMPL_H

#include <linux/types.h>

int encrypt(u8* rb, size_t rl, u8* sb, size_t sl);
int decrypt(u8* rb, size_t rl, u8* sb, size_t sl);

#endif
