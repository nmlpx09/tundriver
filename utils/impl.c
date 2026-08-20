#include <linux/string.h>

#include "impl.h"

bool valid_ipv4_packet(unchar* buf, size_t len) {
    if (len < 20) {
        return false;
    }

    return (buf[0] & 0xF0) == 0x40;
}

__be32 get_src_ip_from_ipv4_packet(unchar* buf, size_t len) {
    if (len < 20) {
        return 0;
    }

    __be32 val;
    memcpy(&val, buf + 12, sizeof(val));
    return val;
}

__be32 get_dst_ip_from_ipv4_packet(unchar* buf, size_t len) {
    if (len < 20) {
        return 0;
    }

    __be32 val;
    memcpy(&val, buf + 16, sizeof(val));
    return val;
}
