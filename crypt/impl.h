#ifndef CRYPT_IMPL_H
#define CRYPT_IMPL_H

#include "types.h"

struct crypt_data* crypt_init(void);
void crypt_close(struct crypt_data* cd);
int encrypt(struct crypt_data* cd, u8* buf, size_t len);
int decrypt(struct crypt_data* cd, u8* buf, size_t len);

#endif
