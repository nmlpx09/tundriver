/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CRYPT_TYPES_H
#define CRYPT_TYPES_H

#include <linux/types.h>

struct crypt_ctx {
    u8* prga;
    size_t lprga;
};

#endif