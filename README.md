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

Both directions are processed asynchronously by tx/rx work items on a dedicated unbound workqueue.

## Build & Install

Requires kernel headers installed (`/lib/modules/$(uname -r)/build`).

### Makefile targets

| Target                 | Description |
|------------------------|-------------|
| `make client`          | Build `tnet.ko` in client mode |
| `make server`          | Build `tnet.ko` in server mode (`SERVER=1`) |
| `make install_module`  | Install built `tnet.ko` to `/lib/modules/$(uname -r)/extra/` + `depmod` (build first) |
| `make install_client`  | Install `client.sh` as `/usr/bin/tun` |
| `make install_server`  | Install `server.sh` as `/usr/bin/tun` |
| `make install_service` | Install `tunnel.service` as a systemd unit |
| `make uninstall`       | Remove `/usr/bin/tun`, systemd unit and the module from `/lib/modules`, run `depmod` |
| `make clean`           | Remove build artifacts |

### Variables

| Variable  | Default               | Description                    |
|-----------|-----------------------|--------------------------------|
| `KVER`    | `$(uname -r)`         | Target kernel version          |
| `DESTDIR` | (empty)               | Packaging root (debs, chroots) |

### Recommended workflow

Build as user, `sudo` only for the copy step (avoids root-owned build artifacts):

```bash
make server && sudo make install_module && sudo make install_server
```

## Module Parameters

| Parameter   | Type   | Permissions | Description             |
|-------------|--------|-------------|-------------------------|
| `dest_ip`   | charp  | 0444        | Destination IP address  |
| `dest_port` | int    | 0444        | Destination UDP port    |
| `src_port`  | int    | 0444        | Source UDP port         |

## Usage

After `make install_module` + `make install_client` / `make install_server`:

### Client

```bash
sudo tun c   # connect
sudo tun d   # disconnect
```

### Server

```bash
tun c   # connect
tun d   # disconnect
tun r   # restart tunnel (reload module)
```

### systemd (server)

After `make install_service`:

```bash
systemctl daemon-reload    # reload systemd
systemctl start tunnel     # tun c
systemctl stop tunnel      # tun d
systemctl reload tunnel    # tun r
systemctl enable tunnel    # autostart on boot
```

## Source Structure

```
Makefile         Build, install/uninstall targets
client.sh        Client setup script (installed as /usr/bin/tun)
server.sh        Server setup script (installed as /usr/bin/tun)
tunnel.service   systemd unit for the server
main.c          Module init/exit, netdevice ops, tx/rx works on a dedicated workqueue
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
