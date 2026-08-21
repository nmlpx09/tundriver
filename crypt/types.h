#ifndef CRYPT_TYPES_H
#define CRYPT_TYPES_H

struct crypt_data {
    size_t mbs;
    u8* encrb;
    size_t encrbl;
    u8* decrb;
    size_t decrbl;
};

#endif
