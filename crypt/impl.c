#include <linux/compiler.h>
#include <linux/errno.h>

#include <configs.h>

#include "impl.h"
#include "table.h"

int encrypt(u8* rb, u8* sb, size_t sl)
{
    if (unlikely(!rb || !sb)) {
        return -EINVAL;
    }

    if (unlikely(MAX_BUFFER_SIZE < sl)) {
        return 0;
    }

    size_t rl = 0;

    for (; rl < sl; ++rl) {
        rb[rl] = ENCRYPT_TABLE[sb[rl]];
    }

    return rl;
}

int decrypt(u8* rb, u8* sb, size_t sl)
{
    if (unlikely(!rb || !sb)) {
        return -EINVAL;
    }

    if (unlikely(MAX_BUFFER_SIZE < sl)) {
        return 0;
    }

    size_t rl = 0;

    for (; rl < sl; ++rl) {
        rb[rl] = DECRYPT_TABLE[sb[rl]];
    }

    return rl;
}
