#ifndef IPS_IMPL_H
#define IPS_IMPL_H

#include <linux/types.h>

#include "types.h"

struct ips_storage* ips_init(void);

void ips_close(struct ips_storage* storage);

struct ips_entry* ips_get(struct ips_storage* storage, __be32 key);

int ips_add(struct ips_storage* storage, __be32 key, __be32 ip, __be16 port);

#endif
