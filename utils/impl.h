#ifndef UTILS_IMPL_H
#define UTILS_IMPL_H

#include <linux/types.h>

bool valid_ipv4_packet(u8* buf, size_t len);

__be32 get_src_ip_from_ipv4_packet(u8* buf, size_t len);

__be32 get_dst_ip_from_ipv4_packet(u8* buf, size_t len);

#endif
