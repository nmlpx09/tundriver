/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - IPS table (RCU hashtable, add/get/expire)
 *
 * Copyright (c) 2026 nmlpx <nmlpx09@duck.com>
 */

#ifndef IPS_IMPL_H
#define IPS_IMPL_H

#include <linux/err.h>
#include <linux/types.h>

#include "types.h"

struct ips_storage* ips_init(void);

void ips_close(struct ips_storage* storage);

struct ips_entry* ips_get(struct ips_storage* storage, __be32 key);

int ips_add(struct ips_storage* storage, __be32 key, __be32 ip, __be16 port);

#endif
