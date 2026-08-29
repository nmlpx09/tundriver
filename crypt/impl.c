// SPDX-License-Identifier: GPL-2.0
/*
 * tnet - encrypt/decrypt (substitution cipher)
 *
 * Copyright (c) 2026 nmlpx <nmlpx09@duck.com>
 */

#include <linux/compiler.h>
#include <linux/errno.h>

#include "impl.h"
#include "table.h"

int encrypt(u8* rb, size_t rl, u8* sb, size_t sl)
{
    if (unlikely(!rb || !sb)) {
        return -EINVAL;
    }

    if (unlikely(rl < sl)) {
        return 0;
    }

    for (size_t i = 0; i < sl; ++i) {
        rb[i] = ENCRYPT_TABLE[sb[i]];
    }

    return sl;
}

int decrypt(u8* rb, size_t rl, u8* sb, size_t sl)
{
    if (unlikely(!rb || !sb)) {
        return -EINVAL;
    }

    if (unlikely(rl < sl)) {
        return 0;
    }

    for (size_t i = 0; i < sl; ++i) {
        rb[i] = DECRYPT_TABLE[sb[i]];
    }

    return sl;
}
