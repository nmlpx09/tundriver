#ifndef SOCK_TYPES_H
#define SOCK_TYPES_H

#include <linux/socket.h>
#include <linux/types.h>

struct sock_data {
    size_t mbs;
    struct socket *sock;
    unchar* readb;
    int readbl;
    __be32 sip;
    __be16 sport;
};

#endif
