// SPDX-License-Identifier: GPL-2.0
/*
 * tnet - IPv4 packet validation and IP extraction
 *
 * Copyright (c) 2026 nmlpx <nmlpx09@duck.com>
 */

#include <linux/string.h>

#include "impl.h"

bool valid_ipv4_packet(u8* buf, size_t len) {
    if (len < 20) {
        return false;
    }

    return (buf[0] & 0xF0) == 0x40;
}

__be32 get_src_ip_from_ipv4_packet(u8* buf, size_t len) {
    if (len < 20) {
        return 0;
    }

    __be32 val;
    memcpy(&val, buf + 12, sizeof(val));
    return val;
}

__be32 get_dst_ip_from_ipv4_packet(u8* buf, size_t len) {
    if (len < 20) {
        return 0;
    }

    __be32 val;
    memcpy(&val, buf + 16, sizeof(val));
    return val;
}
