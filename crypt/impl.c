// SPDX-License-Identifier: GPL-2.0
/*
 * tnet - encrypt/decrypt (substitution cipher)
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#include <linux/compiler.h>
#include <linux/errno.h>

#include "impl.h"
#include "table.h"

int encrypt(u8* buf, size_t bufl)
{
    if (unlikely(!buf)) {
        return -EINVAL;
    }

    for (size_t i = 0; i < bufl; ++i) {
        buf[i] = ENCRYPT_TABLE[buf[i]];
    }

    return 0;
}

int decrypt(u8* buf, size_t bufl)
{
    if (unlikely(!buf)) {
        return -EINVAL;
    }

    for (size_t i = 0; i < bufl; ++i) {
        buf[i] = DECRYPT_TABLE[buf[i]];
    }

    return 0;
}
