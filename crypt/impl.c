#include <linux/compiler.h>

#include "impl.h"
#include "table.h"

static unchar encrypt_buffer[MAX_BUFFER_SIZE];
static unchar decrypt_buffer[MAX_BUFFER_SIZE];

struct crypt_result encrypt(unchar* buf, size_t len)
{
    struct crypt_result res = {.buf = encrypt_buffer, .len = 0};
    if (unlikely(sizeof(encrypt_buffer) < len)) {
        return res;
    }

    size_t res_len = 0;
    for (; res_len < len; ++res_len) {
        encrypt_buffer[res_len] = ENCRYPT_TABLE[buf[res_len]];
    }

    res.len = res_len;
    return res;
}

struct crypt_result decrypt(unchar* buf, size_t len)
{
    struct crypt_result res = {.buf = decrypt_buffer, .len = 0};
    if (unlikely(sizeof(decrypt_buffer) < len)) {
        return res;
    }

    size_t res_len = 0;
    for (; res_len < len; ++res_len) {
        decrypt_buffer[res_len] = DECRYPT_TABLE[buf[res_len]];
    }

    res.len = res_len;
    return res;
}
