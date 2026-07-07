# FluxGuard — Phase 11 & Phase 12 Deep Explanation

> **Continuing from Phase 10** — The data plane is now fully autonomous, utilizing `BPF_MAP_TYPE_RINGBUF` for low-overhead logging and in-kernel auto-blacklisting. However, the system is still restricted to IPv4 networks, loses all blocked-IP states if the userspace brain restarts, contains a scaling flaw in its token-bucket math, and lacks a production-ready system architecture. Phase 11 implements comprehensive hardening (IPv6, persistence checkpoints, shared libraries, and token math corrections), and Phase 12 migrates FluxGuard into a multi-service production deployment on physical host network interfaces.

---

## Phase 11 — Hardening: Token Math, IPv6, & State Persistence

### 1. The Token Bucket Math Fix

In Phase 10, the token refill arithmetic was:
```c
__s64 refill = (elapsed_ns * KERN_PPS_LIMIT) / 1000000000ULL;
```
**The Bug**: This formula updates the token bucket using integer division. If `elapsed_ns * KERN_PPS_LIMIT` is less than `1,000,000,000` (which happens during high-frequency polls or packets arriving sub-millisecond apart), `refill` evaluates to `0`. Consequently, under heavy traffic, the bucket **never refills**, leading to permanent packet dropping (false-positives) because the time delta is too small to add a whole token.

**The Fix (Phase 11)**: Shift the math to calculate precise fractional token rates per nanosecond or track microsecond intervals accurately without losing precision:
```c
// Refill math corrected to ensure micro-refills register properly
__s64 refill = (elapsed_ns * KERN_PPS_LIMIT) / 1000000000ULL;
if (refill > 0) {
    tb->last_time = now;
    tb->tokens += refill;
    if (tb->tokens > KERN_PPS_LIMIT) {
        tb->tokens = KERN_PPS_LIMIT;
    }
}
```
*Note: In production versions, the time delta update is decoupled so that even if `refill` is zero, we do not advance `last_time`. This prevents the loss of fractional tokens by accumulation over subsequent packets.*

---

### 2. Native IPv6 Support

Phase 11 expands the XDP packet-processing pipeline to handle IPv6 (`ETH_P_IPV6`). Because IPv6 uses 128-bit (16-byte) source/destination addresses instead of 32-bit (4-byte) addresses, duplicate data structures and maps are introduced in kernel and userspace:

#### Kernel-Side IPv6 Maps:
```c
// IPv6 blacklist map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct in6_addr);  // 128-bit key
    __type(value, __u32);
} blacklist_map_v6 SEC(".maps");

// IPv6 meter map
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct in6_addr);
    __type(value, __u32);
} meter_map_v6 SEC(".maps");

// IPv6 rate token bucket map
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct in6_addr);
    __type(value, struct token_bucket);
} rate_map_v6 SEC(".maps");
```

#### The Kernel IPv6 Parsing Logic:
```c
if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
    if ((void *)(ip6h + 1) > data_end)
        return XDP_PASS;
        
    struct in6_addr src_ip6 = ip6h->saddr;
    
    // Perform parallel evaluation:
    // 1. Allowlist v6 lookup
    // 2. Token Bucket rate check v6
    // 3. Blacklist v6 lookup
    ...
}
```

---

### 3. State Persistence (JSON Checkpoint Recovery)

In previous versions, if the host or the `fluxguard_brain` daemon restarted, all knowledge of currently blocked IPs was wiped out in userspace. While the entries remained in the kernel `blacklist_map` temporarily, the brain could no longer manage their cooldown timers (amnesty). As a result, IPs blocked prior to the crash remained blocked indefinitely.

Phase 11 introduces **Persistence Checkpoints**:
- The brain periodically serializes the `blocked_until` memory dict to `/var/lib/fluxguard/blocked_ips.json`.
- On startup, the brain checks this file, deserializes it, and updates the kernel maps to restore the mitigation state:

```python
# Startup recovery logic
def load_persistence(filepath: str) -> Dict[str, float]:
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
            # Reconstruct the blocked_until dictionary with epoch timestamps
            return {ip: float(ts) for ip, ts in data.items()}
    except Exception as e:
        print(f"[WARN] Failed to load persistence checkpoint: {e}")
        return {}
```

---

### 4. Code Modularity: Shared BPF Module (`fluxguard_bpf.py`)

To eliminate duplicate ctypes boilerplate code in `fluxguard_brain.py`, `fluxguard_allow.py`, and `fluxguard_dashboard.py`, Phase 11 consolidates all BPF system call abstraction logic into a dedicated file: `fluxguard_bpf.py`.

#### Modular Structure:
```
                       [ fluxguard_bpf.py ]
                               │
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
  [ fluxguard_brain.py ]  [ fluxguard_allow.py ]  [ fluxguard_dashboard.py ]
```

This ensures that any architecture-specific details (like auto-detecting x86_64 vs aarch64 syscall IDs) or structure alignments (like `PercpuValue` sizes) are resolved in a single file.

---

## Phase 12 — Production Deployment

Phase 12 transitions FluxGuard from a network-namespace sandbox (`client`, `fluxguard`, `backend` virtual interfaces) into a production system protecting a real, physical host network interface (e.g., `eth0` or `ens3`).

```
    [ Internet Traffic ]
             │
             ▼
      [ Interface eth0 ] ──► ( XDP Hook: Native Driver Mode xdpdrv )
             │
      ┌──────┴──────────────────────────┐
      ▼ (If Allowed)                    ▼ (If Blocked / Rate-Limited)
[ Host Kernel Protocol Stack ]     [ Packet Dropped (Zero-Copy) ]
```

---

### 1. Native Driver Mode (`xdpdrv`)

In the sandbox lab, we attached XDP using generic mode (`xdpgeneric`). Generic mode executes **after** the kernel allocates a socket buffer (`sk_buff`) for the packet, which is slow.

In Phase 12, FluxGuard is attached using **Native Driver Mode (`xdpdrv`)**:
- The XDP program is loaded directly into the network card driver's receive ring buffer.
- Packet dropping (`XDP_DROP`) occurs before the kernel spends CPU cycles creating network structures.
- Modern production NICs (Mellanox, Intel, Broadcom) process this at physical line rate (10Gbps+).

```bash
# Attach in native mode on physical interface eth0
sudo ip link set dev eth0 xdpdrv obj /home/samarth/fluxguard/fluxguard_kern.o sec xdp
```

---

### 2. Production Service Configuration (Systemd Integration)

To ensure FluxGuard boots automatically on startup and logs output properly, it is integrated with `systemd` as system services.

#### `/etc/systemd/system/fluxguard.service`:
```ini
[Unit]
Description=FluxGuard DDoS Mitigation Engine (Brain)
After=network.target
Before=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/samarth/fluxguard
ExecStart=/home/samarth/fluxguard/venv/bin/python3 fluxguard_brain.py --config /etc/fluxguard/config.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

### 3. Unified REST API (`fluxguard_api.py`)

For enterprise monitoring and integration, Phase 12 introduces a REST API (`fluxguard_api.py`) running via Flask. This allows remote clients to inspect system status, query blocked lists, or programmatically append allowlist exceptions.

#### API Route Definitions:
- `GET /api/status`: Return global stats, packet counters, and shields-up status.
- `GET /api/blacklist`: List all currently blocked IPv4 and IPv6 addresses.
- `POST /api/allowlist`: Add a new IP to the allowlist.
- `DELETE /api/allowlist/<ip>`: Remove an IP from the allowlist.

---

### 4. Configuration File Structure

Rather than using long CLI flags, Phase 12 uses a structured, central configuration file `/etc/fluxguard/config.toml`:

```toml
[general]
interface = "eth0"
log_file = "/var/log/fluxguard.log"
persistence = "/var/lib/fluxguard/blocked_ips.json"

[limits]
pps_limit_v4 = 500000
pps_limit_v6 = 500000
global_pps_limit = 1000000

[api]
bind = "127.0.0.1"
port = 8080
```

---

## Phase 11 vs Phase 12 — Summary

| Feature | Phase 11 | Phase 12 |
|---------|----------|----------|
| **Deployment Target** | Sandbox Network Namespaces (`veth`) | Physical Host NICs (`eth0`, `ens3`) |
| **XDP Driver Mode** | Generic Mode (`xdpgeneric`) | Native Driver Mode (`xdpdrv`) |
| **IPv6 Protocol** | ✅ Supported (Dual-stack C pipeline) | ✅ Supported |
| **API Server** | ❌ None (Metrics server only) | ✅ REST API (`fluxguard_api.py`) |
| **System Daemon** | CLI Invocation | ✅ systemd services |
| **Configuration** | Argument Parser Flags | ✅ `/etc/fluxguard/config.toml` |

---

## OS Concepts Introduced in Phases 11–12

### 1. Native Driver Hooking (`xdpdrv`)
Unlike `xdpgeneric`, which hooks into the kernel networking stack (`netif_receive_skb`), native `xdpdrv` hooks into the device driver itself (e.g. `ixgbe_clean_rx_irq`). Packets are handled inside the network driver's polling loop, bypassing the network stack allocation phase entirely.

### 2. Dual-Stack Packet Parsing
In network engineering, handling IPv4 and IPv6 in the same low-level parser requires analyzing the Ethernet frame type (`h_proto`). IPv4 uses `0x0800` (`ETH_P_IP`), while IPv6 uses `0x86DD` (`ETH_P_IPV6`). The program must perform separate pointer arithmetic offsets and boundary checks depending on the frame type to read the address bytes safely.

### 3. File State Persistence (JSON Checkpointing)
To build fault-tolerant daemons, in-memory states are serialized to stable storage (`/var/lib/`). By using structured atomic operations (such as writing to a temporary file and calling `os.replace` to replace the old file), the daemon ensures that checkpoints are never corrupted in the middle of a write during a crash.

### 4. Systemd Service Lifecycle
Systemd runs services in isolated namespaces. By defining dependencies (`After=network.target`), systemd guarantees that FluxGuard starts only when interfaces are ready. `Restart=always` ensures that if the Python process experiences an out-of-memory error, the kernel manager restarts it automatically.
