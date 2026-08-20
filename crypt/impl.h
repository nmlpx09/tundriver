#ifndef CRYPT_IMPL_H
#define CRYPT_IMPL_H

#include <linux/types.h>

#include <configs.h>

struct crypt_result {
    void* buf;
    size_t len;
};

struct crypt_result encrypt(unchar* buf, size_t len);
struct crypt_result decrypt(unchar* buf, size_t len);

#endif
