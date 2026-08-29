# tnet

Linux kernel module that creates a virtual network interface encapsulating IPv4 packets over encrypted UDP tunnels.

## Architecture

```
┌─────────────┐     ┌─────────────┐
│   Client    │     │   Server    │
│             │     │             │
│  tnet0      │────►│  tnet0      │
│  10.0.3.2   │ UDP │  10.0.3.1   │
│             │     │  NAT/MASQ   │
└─────────────┘     └─────────────┘
```

- **Client mode**: sends all encrypted traffic to a fixed `dest_ip:dest_port`
- **Server mode**: dynamically maps client source IPs to their return addresses (IPS table with RCU + hashtable, 10-minute check / 1-hour expiry)

### Data flow

```
tx: skb → strip eth header → validate IPv4 → encrypt → UDP send
rx: UDP recv → decrypt → validate IPv4 → add eth header → netif_rx
```

Encryption is a per-byte substitution cipher (256-entry lookup table). The server mode resolves the destination per-packet by looking up the inner IPv4 destination in the IPS table.

## Build

Requires kernel headers installed (`/lib/modules/$(uname -r)/build`).

```bash
make client    # build client mode (default)
make server    # build server mode (SERVER=1)
make clean
make install   # install module + depmod
```

## Module Parameters

| Parameter   | Type   | Permissions | Description             |
|-------------|--------|-------------|-------------------------|
| `dest_ip`   | charp  | 0444        | Destination IP address  |
| `dest_port` | int    | 0444        | Destination UDP port    |
| `src_port`  | int    | 0444        | Source UDP port         |

## Usage

### Client

```bash
sudo ./client.sh c   # connect
sudo ./client.sh d   # disconnect
```

### Server

```bash
sudo ./server.sh c   # connect
sudo ./server.sh d   # disconnect
```

## Source Structure

```
main.c          Module init/exit, netdevice ops, tx/rx work queues
types.h         tun_struct definition
sock/impl.c     Kernel UDP socket (bind, sendmsg, recvmsg)
sock/impl.h
crypt/impl.c    Encrypt/decrypt (substitution cipher)
crypt/impl.h
crypt/table.h   256-byte encrypt/decrypt lookup tables
ips/impl.c      IPS table (RCU hashtable, add/get/expire)
ips/impl.h
ips/types.h     ips_entry, ips_storage types
utils/impl.c    IPv4 packet validation and IP extraction
utils/impl.h
```

## Configuration

| Constant           | Value           | Description                |
|--------------------|-----------------|----------------------------|
| `MAX_BUFFER_SIZE`  | 1472            | Max payload buffer (bytes) |
| `SEND_FIFO_SIZE`   | 4096            | TX fifo depth (sk_buffs)   |
| `SOCKET_BUFFER_SIZE` | 4194304       | Socket recv/send buffer    |
| `IPS_HASH_BITS`    | 10              | IPS hashtable size (1024)  |
| `IPS_CHECK_DELAY`  | 600s            | IPS expiry check interval  |
| `IPS_REMOVE_DELAY` | 3600s           | IPS entry lifetime         |

## WIP

- AES-128-GCM encryption (replace substitution cipher)

## License

Copyright (c) 2026 nlmpx09

Licensed under the [GNU General Public License v2.0](LICENSE) (GPL-2.0), the same license as the Linux kernel.
