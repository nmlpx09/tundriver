#include <linux/compiler.h>
#include <linux/slab.h>

#include <configs.h>

#include "impl.h"
#include "table.h"

struct crypt_data* crypt_init(void)
{
    struct crypt_data* res = kmalloc(sizeof(struct crypt_data), GFP_KERNEL);

    if (!res) {
        return ERR_PTR(-ENOMEM);
    }

    res->mbs = MAX_BUFFER_SIZE;
    res->encrbl = 0;
    res->decrbl = 0;

    res->encrb = kmalloc(res->mbs, GFP_KERNEL);

    if (!res->encrb) {
        kfree(res);
        return ERR_PTR(-ENOMEM);
    }

    res->decrb = kmalloc(res->mbs, GFP_KERNEL);

    if (!res->decrb) {
        kfree(res->encrb);
        kfree(res);
        return ERR_PTR(-ENOMEM);
    }

    return res;
}

void crypt_close(struct crypt_data* cd)
{
    if (!cd) {
        return;
    }

    kfree(cd->encrb);
    kfree(cd->decrb);
    kfree(cd);
}

int encrypt(struct crypt_data* cd, u8* buf, size_t len)
{
    if (unlikely(!cd || !cd->encrb)) {
        return -EINVAL;
    }

    if (unlikely(cd->mbs < len)) {
        return 0;
    }

    u8* encrb = cd->encrb;
    size_t res_len = 0;

    for (; res_len < len; ++res_len) {
        encrb[res_len] = ENCRYPT_TABLE[buf[res_len]];
    }

    cd->encrbl = res_len;
    return res_len;
}

int decrypt(struct crypt_data* cd, u8* buf, size_t len)
{
    if (unlikely(!cd || !cd->decrb)) {
        return -EINVAL;
    }

    if (unlikely(cd->mbs < len)) {
        return 0;
    }

    u8* decrb = cd->decrb;
    size_t res_len = 0;

    for (; res_len < len; ++res_len) {
        decrb[res_len] = DECRYPT_TABLE[buf[res_len]];
    }

    cd->decrbl = res_len;
    return res_len;
}
