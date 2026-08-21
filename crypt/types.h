#ifndef CRYPT_TYPES_H
#define CRYPT_TYPES_H

struct crypt_data {
    size_t mbs;
    unchar* encrb;
    size_t encrbl;
    unchar* decrb;
    size_t decrbl;
};

#endif
