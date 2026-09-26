# arpoison — ARP Spoofer for Wired LANs

A lightweight, cross-platform (Linux / macOS) C tool for ARP manipulation on
switched wired Ethernet LANs. It runs in two operation modes:

- **Mode 0 — ARP Poison** (default): performs a classic man-in-the-middle
  between two hosts by continuously feeding both of them forged ARP replies,
  so that all traffic between the two victims is routed through the attacker
  host (which has kernel IP forwarding enabled).
- **Mode 1 — Gratuitous ARP**: announces a forged `IP → MAC` binding to the
  local router (3 consecutive unsolicited ARP replies), e.g. to make the LAN
  forward a given IP to a given MAC address.

The code is organized in four thin layers — application logic, a packet
forgery framework, a platform abstraction, and protocol definitions — so the
attack logic is fully decoupled from the OS-specific socket/ioctl code.

> **⚠️ Responsible use**
> ARP spoofing intercepts and redirects traffic between hosts. Use this tool
> **only on networks you own or for which you have explicit, written
> permission** (lab, CTF, authorized penetration test). Unauthorized use on
> networks you do not control is illegal in most jurisdictions. The tool
> performs **no** decryption or payload inspection itself: it only rewrites
> L2/L3 addressing; any inspection of the forwarded traffic is out of scope.

---

## Table of Contents

1. [Architecture](#architecture)
   - [Layer overview](#layer-overview)
   - [Module responsibilities](#module-responsibilities)
   - [Key data structures](#key-data-structures)
   - [Platform abstraction](#platform-abstraction)
   - [Mode 0 — ARP Poison flow](#mode-0--arp-poison-flow)
   - [Mode 1 — Gratuitous ARP flow](#mode-1--gratuitous-arp-flow)
   - [Shutdown & cleanup](#shutdown--cleanup)
   - [Known issues & caveats](#known-issues--caveats)
2. [Building](#building)
3. [Usage](#usage)
4. [Project layout](#project-layout)
5. [License](#license)

---

## Architecture

### Layer overview

```
+---------------------------------------------------------------------+
|                          arpoison.c                                 |
|     CLI parsing · mode dispatch · flood loop · signal handlers      |
+-----------------------------+---------------------------------------+
                              |
         +--------------------+--------------------+
         |                                         |
+--------v------------------+            +---------v------------------+
|     packet_forge.c        |            |        platform.c          |
| NIC discovery (local &    |  uses      | raw sockets, MAC/IP read,  |
| peer), force_arp(),       |            | ARP-cache lookup,          |
| ARP + Ethernet forgery    |            | IP-forwarding control      |
+--------+------------------+            +---------+------------------+
         |                                           |
         |              shared definitions          |
+--------v-------------------------------------------v------------------+
| arp.h · ether-def.h · utils.c/h · color_codes.h                      |
| (ARP/Ethernet constants & wire structs, helpers, terminal colors)    |
+-----------------------------------------------------------------------+
```

### Module responsibilities

| File                    | Layer            | Responsibility |
|-------------------------|------------------|----------------|
| `src/arpoison.c`        | Application      | Entry point, root check, `getopt` CLI, both attack modes, flooding loop, signal handlers, `ip_forward` lifecycle |
| `src/packet_forge.c/h`  | Packet generation | `nic_info_t` discovery (local & peer NICs), `force_arp()` cache warm-up, `nic_info_t` factory from CLI strings, `ether_forgery()` / `arp_forgery()` header builders |
| `src/platform.c/h`      | OS abstraction   | One implementation each for Linux and macOS: raw packet socket open/send/close, local MAC/IP retrieval, kernel ARP-cache lookup, IP-forwarding get/set |
| `src/utils.c/h`         | Helpers          | `die()` fatal error handler, string append, `getTimestamp()`, `smart_IP_to_char()` |
| `src/arp.h`             | Protocol defs    | ARP hardware-type / opcode / flag constants and `struct ARP_packet_header` |
| `src/ether-def.h`       | Protocol defs    | Ethernet size / EtherType constants and packed `struct ETHER_packet_header` |
| `src/color_codes.h`     | UI               | ANSI escape-code macros (`RED`, `GREEN`, `YELLOW`, `BLUE`, `PURPLE`, `RESET`) |
| `Makefile`              | Build            | `clang -O3 -Wall`; links a **static** binary on Linux, dynamic on macOS |

### Key data structures

```c
/* packet_forge.h — container for everything known about one NIC */
struct _NIC_info {
    in_addr_t ip_address;                 /* host order           */
    u_int8_t  mac_address[ETHER_ADDR_LEN];
    unsigned char mac_address_string[18]; /* "aa:bb:cc:dd:ee:ff"  */
};
typedef struct _NIC_info nic_info_t;

/* ether-def.h — 14-byte Ethernet II header (packed) */
struct ETHER_packet_header {
    u_int8_t  h_dest[ETH_ALEN];
    u_int8_t  h_source[ETH_ALEN];
    u_int16_t h_proto;   /* big-endian on the wire */
} __attribute__((packed));

/* arp.h — 28-byte ARP payload */
struct ARP_packet_header {
    unsigned short ar_hrd;  /* ARPHRD_ETHER (1)              */
    unsigned short ar_pro;  /* ETHERTYPE_IP (0x0800)         */
    unsigned char  ar_hln;  /* 6                             */
    unsigned char  ar_pln;  /* 4                             */
    unsigned short ar_op;   /* ARPOP_REQUEST / ARPOP_REPLY   */
    unsigned char  ar_sha[6];
    unsigned char  ar_spa[4];
    unsigned char  ar_tha[6];
    unsigned char  ar_tpa[4];
};
```

Every frame is built in a fixed 60-byte stack buffer: 14 bytes of Ethernet
header followed by 28 bytes of ARP payload (42 bytes of meaningful data).

### Platform abstraction

All OS-specific syscalls live behind the `platform_*` API in `platform.h`;
`arpoison.c` and `packet_forge.c` never touch sockets or ioctls directly.

| Operation              | Linux                                        | macOS                                             |
|------------------------|----------------------------------------------|---------------------------------------------------|
| Open raw socket        | `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))` + `bind()` to `if_nametoindex()` | scan `/dev/bpf0..255`, `BIOCSETIF` to the interface, `BIOCSHDRCMPLT` |
| Send raw frame         | `sendto()` with `struct sockaddr_ll`         | `write()` to the BPF fd (interface baked in via `BIOCSETIF`) |
| Local MAC              | `ioctl(SIOCGIFHWADDR)`                        | `getifaddrs()` → `sockaddr_dl`                    |
| Local IP               | `ioctl(SIOCGIFADDR)` (shared implementation, works on both) | |
| ARP-cache lookup       | `ioctl(SIOCGARP)` with `struct arpreq`        | `sysctl(NET_RT_FLAGS, RTF_LLINFO)` route-table walk |
| IP forwarding get/set  | read/write `/proc/sys/net/ipv4/ip_forward`    | `sysctlbyname("net.inet.ip.forwarding")`          |

> Note: on macOS, opening BPF devices requires root (and the
> *Network Client* / *Developer* TCC authorization depending on the build
> context); the tool enforces `getuid() == 0` up front on both platforms.

### Mode 0 — ARP Poison flow

```
 1. getuid() == 0 ?  →  title banner, parse options (-i/-t/-m, positional IPs)
 2. register signal handlers (SIGINT/SIGTERM/SIGKILL*/SIGHUP → cleanup,
    SIGSEGV → segv_handler)
 3. ip_forward(1)          — enable kernel IP forwarding (MITM path)
 4. program_init()         — force_arp(victim1/2) ×3 each to warm the
                             kernel ARP cache, sleep 1 s
 5. get_hw_addr()          — local MAC/IP (nic_info_t "me")
 6. get_peer_hw_addr()     — MACs of victim1 & victim2 (with retries)
 7. forge frames:
       packet_IP1  → to victim1 : "victim2-IP is at MY MAC"   (ARPOP_REPLY)
       packet_IP2  → to victim2 : "victim1-IP is at MY MAC"   (ARPOP_REPLY)
       (+ 2 "cleanup" frames are forged — see Known issues)
 8. infinite flood loop:
       send packet_IP1 → sleep(timing/2) → send packet_IP2 → sleep(timing/2) → …
```

Resulting poisoned view on the wire:

```
   victim1                attacker                 victim2
  (192.168.1.10)        (192.168.1.5)           (192.168.1.20)
        |   ARP cache: victim2-IP → attacker-MAC  |
        +----------------------------------------+
                       all L2 traffic between the two victims
                       arrives at the attacker host and is IP-forwarded
```

`timing` is the full cycle between the two forged replies (seconds,
derived from the `-t` milliseconds option; default 2 s, minimum 1 s).

### Mode 1 — Gratuitous ARP flow

```
 1. parse options: <router IP> <new IP> <new MAC>
 2. resolve router MAC (get_peer_hw_addr, with retries) and own MAC
 3. forge one frame addressed to the router:
       "new-IP is at new-MAC" (ARPOP_REPLY, sha=new-MAC, spa=new-IP,
        tha=router-MAC, tpa=router-IP)
 4. send it 3 times, 1 s apart, then raise(SIGTERM) → clean exit
```

This updates the router's ARP table so that `new-IP` resolves to `new-MAC`
(e.g. after a NIC/MAC change, or to move a service between hosts).

### Shutdown & cleanup

On any caught termination signal (`sig_exit`) or segfault (`segv_handler`):

1. free transient `nic_info_t` allocations,
2. close the raw packet socket,
3. **restore kernel IP forwarding to off** (`ip_forward(0)`),
4. exit.

### Known issues & caveats

- **`kill -9` leaves IP forwarding on.** `SIGKILL` cannot be caught, so the
  cleanup path (which restores `ip_forward` to off) cannot run if the process
  is killed that way. All other catchable signals (`SIGINT`, `SIGTERM`,
  `SIGHUP`, `SIGSEGV`) do trigger the full cleanup.
- **Cleanup frames are built but never transmitted.**
  `packet_cleanup1/2` are fully forged (each restoring the *true*
  IP→MAC binding for the opposite victim — e.g. `packet_cleanup2` tells
  victim 2 that victim 1's IP is at victim 1's real MAC), but the flood
  loop and the shutdown handlers only ever send the two poison frames.
  Until they are wired into a send path, the victims keep their poisoned
  ARP entries after the tool exits.
- **`-t` is floored to whole seconds** (millisec → sec via `atoi` then
  `/1000`); values mapping to `< 1 s` fall back to the 2 s default, even
  though the log message says "2000 msec".
- **No `mkdir` in the Makefile** — `build/` and `bin/` must exist before
  `make` (see [Building](#building)).
- IPv4 / Ethernet-II only; not designed for Wi-Fi (management frames /
  different ARP behavior) or for non-broadcast multi-access segments.
- `smart_IP_to_char()` allocates a 16-byte buffer and is not safe for
  values outside the IPv4 range (it is only ever fed interface IPs).

---

## Building

**Requirements**

- `clang` (any C11-capable compiler works; set `CC` accordingly)
- Linux **or** macOS
- Root at *run* time (not required to build)

**Steps**

```sh
cd backend
mkdir -p build bin     # the Makefile assumes both exist
make                   # → bin/arpoison.bin
```

On Linux the binary is linked **statically** (`--static`); on macOS it is
linked dynamically.

| Target  | Action                                                        |
|---------|---------------------------------------------------------------|
| `make`  | compile the 4 objects into `build/*.o` and link `bin/arpoison.bin` |
| `make clean` | remove `build/*.o` and `bin/arpoison.bin`               |

`build/` and `bin/` are git-ignored; a fresh checkout must create them first.

---

## Usage

```
Syntax: arpoison.bin [options] params

  -i <int>       interface to flood the net on   (required, e.g. en0 / eth0)
  -m <mode>      0 = ARP Poison (default), 1 = Gratuitous ARP
  -t <millisec>  flood timing for poison mode  (default 2000)

Mode 0 params : <victim1 IP> <victim2 IP>
Mode 1 params : <router IP> <new IP> <new MAC>
```

Run with `sudo`. Stop poison mode with `Ctrl+C` — the handler closes the raw
socket and turns IP forwarding back off.

### Example 1 — ARP Poison (MITM)

```sh
# MITM between 192.168.1.10 and 192.168.1.20 on interface en0,
# full spoof cycle every 2000 ms:
sudo ./bin/arpoison.bin -i en0 -m 0 -t 2000 192.168.1.10 192.168.1.20

# default timing (2 s), default mode:
sudo ./bin/arpoison.bin -i eth0 192.168.1.10 192.168.1.20
```

While running, all traffic between the two victims is L2-forwarded to the
attacker host and IP-forwarded on to the real destination.

### Example 2 — Gratuitous ARP

```sh
# Announce to router 192.168.1.1 that 192.168.1.99 now lives at
# MAC aa:bb:cc:dd:ee:ff (3 attempts, 1 s apart, then exit):
sudo ./bin/arpoison.bin -i en0 -m 1 192.168.1.1 192.168.1.99 aa:bb:cc:dd:ee:ff
```

### Verifying the effect

On a victim host:

```sh
arp -a                                   # (macOS)
ip neigh show                            # (Linux)
sudo tcpdump -i en0 -n arp               # observe the forged replies
```

You should see the target IP resolve to the attacker's MAC address.

---

## Project layout

```
backend/
├── Makefile                 # clang build; static link on Linux
├── bin/                     # build output (git-ignored)
│   └── arpoison.bin
├── build/                   # object files (git-ignored)
└── src/
    ├── arpoison.c           # main program: CLI, modes, flood loop, signals
    ├── packet_forge.c/.h    # NIC discovery + Ethernet/ARP header forgery
    ├── platform.c/.h        # Linux/macOS abstraction (sockets, ioctls, sysctl)
    ├── utils.c/.h           # die(), append(), timestamps, IP formatting
    ├── arp.h                # ARP constants + wire struct
    ├── ether-def.h          # Ethernet constants + wire struct
    └── color_codes.h        # ANSI color macros
```

## License

Distributed under the terms of the **GNU General Public License v2**
(see the header of each source file).
