#include <linux/socket.h>

struct socket* sock_init(__be16 port);

void sock_close(struct socket *sock);

void sock_write(struct socket *sock, void* data, unsigned int len, __be32 ip, __be16 port);

int sock_read(struct socket *sock, void* data, unsigned int len);
