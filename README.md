# tnet

Linux kernel module that creates a virtual network interface encapsulating IPv4 packets over encrypted UDP tunnels.

## Architecture

```
┌─────────────┐     ┌─────────────┐
│   Client    │     │   Server    │
│             │     │             │
│  tnet0      │◄───►│  tnet0      │
│  10.0.3.2   │ UDP │  10.0.3.1   │
│             │     │  NAT/MASQ   │
└─────────────┘     └─────────────┘
```

- **Client mode**: sends all encrypted traffic to a fixed `dest_ip:dest_port`
- **Server mode**: dynamically maps client source IPs to their return addresses (IPS hashtable, 256 buckets; entries persist for module lifetime)

### Data flow

```
tx: ndo_start_xmit → skb_orphan → ptr_ring_produce_bh → queue_work_on(cpu)
         worker: ptr_ring_consume_batched_bh → strip eth → validate IPv4 → encrypt → resolve peer → UDP send

rx: UDP recv (encap_rcv) → enqueue + NAPI schedule → poll: strip UDP header → decrypt → validate IPv4 → add eth header → napi_gro_receive
```

Encryption is a per-byte substitution cipher (256-entry lookup table). The server mode resolves the destination per-packet by looking up the inner IPv4 destination in the IPS table.

TX is asynchronous: `ndo_start_xmit` enqueues skbs into a `ptr_ring` (lockless MPMC ring buffer) and schedules a per-CPU worker via `queue_work_on`. Workers drain the ring in batches (`TX_BATCH`), encrypt, resolve the peer (server: IPS lookup; client: static endpoint), and send via `udp_tunnel_xmit_skb`. Round-robin CPU distribution parallelises encryption across cores.

RX is NAPI-based: the UDP `encap_rcv` callback enqueues skbs into a per-device RX queue and schedules NAPI; the poll routine drains the queue (bounded by `RX_Q_LIMIT` / NAPI budget), decrypts, and pushes up via `napi_gro_receive`.

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
# client
make client && sudo make install_module && sudo make install_client
# server
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
sudo tun c   # connect
sudo tun d   # disconnect
sudo tun r   # restart tunnel (reload module)
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
main.c          Module init/exit, netdevice ops, encap_rcv, NAPI poll, async TX (ptr_ring + workqueue), rx paths
types.h         tun_struct, tx_worker definitions
sock/impl.c     Kernel UDP socket (bind, udp_tunnel xmit)
sock/impl.h
crypt/impl.c    Encrypt/decrypt (substitution cipher)
crypt/impl.h
crypt/table.h   256-byte encrypt/decrypt lookup tables
ips/impl.c      IPS hashtable (add/get/close)
ips/impl.h
ips/types.h     ips_entry, ips_storage types
```

## Configuration

| Constant       | Value | Description                    |
|----------------|-------|--------------------------------|
| `MTU`          | 1472  | Device MTU (bytes)             |
| `RX_Q_LIMIT`   | 1024  | RX NAPI queue depth (sk_buffs) |
| `TX_RING_SIZE` | 1024  | TX ptr_ring depth (sk_buffs)  |
| `TX_BATCH`     | 32    | TX consume batch size          |

## WIP

- AES-128-GCM encryption (replace substitution cipher)

## License

Copyright (c) 2026 nlmpx09

Licensed under the [GNU General Public License v2.0](LICENSE) (GPL-2.0), the same license as the Linux kernel.
