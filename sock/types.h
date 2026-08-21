#ifndef SOCK_TYPES_H
#define SOCK_TYPES_H

#include <linux/socket.h>

struct sock_data {
    size_t mbs;
    struct socket *sock;
    u8* readb;
    int readbl;
    __be32 sip;
    __be16 sport;
};

#endif
