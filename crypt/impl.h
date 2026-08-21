#ifndef CRYPT_IMPL_H
#define CRYPT_IMPL_H

#include "types.h"

struct crypt_data* crypt_init(void);
void crypt_close(struct crypt_data* cd);
void encrypt(struct crypt_data* cd, u8* buf, size_t len);
void decrypt(struct crypt_data* cd, u8* buf, size_t len);

#endif
