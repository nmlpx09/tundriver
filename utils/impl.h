/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tnet - IPv4 packet validation and IP extraction
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#ifndef UTILS_IMPL_H
#define UTILS_IMPL_H

#include <linux/types.h>

bool valid_ipv4_packet(u8* buf, size_t len);

__be32 get_src_ip_from_ipv4_packet(u8* buf, size_t len);

__be32 get_dst_ip_from_ipv4_packet(u8* buf, size_t len);

#endif
