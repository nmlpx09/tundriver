// SPDX-License-Identifier: GPL-2.0
/*
 * tnet - encrypt/decrypt (XOR stream cipher, unaligned + endian-safe)
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#include <asm/byteorder.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unaligned.h>

#include "impl.h"

#define MASK 0x137d95ef43652c81

int encrypt(u8* buf, size_t bufl)
{
    if (unlikely(!buf)) {
        return -EINVAL;
    }

    const u64 mask_be = cpu_to_be64(MASK);
    const u8* mb = (const u8*)&mask_be;

    size_t i = 0;
    for (; i + 8 <= bufl; i += 8) {
        put_unaligned_be64(get_unaligned_be64(buf + i) ^ mask_be, buf + i);
    }
    for (; i < bufl; ++i) {
        buf[i] ^= mb[i % 8];
    }

    return 0;
}

int decrypt(u8* buf, size_t bufl)
{
    return encrypt(buf, bufl);
}
