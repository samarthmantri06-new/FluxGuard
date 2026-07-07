# FluxGuard — Phase 9 & Phase 10 Deep Explanation

> **Continuing from Phase 8** — The control plane now operates with zero subprocess overhead via `ctypes`, and the core rate-limiting mathematical bugs have been squashed. However, two limitations remain: (1) managing allowlists still requires typing raw hexadecimal `bpftool` commands, and (2) if the Python brain crashes, rate limiting is active but there is no mechanism to permanently block attackers or stream live block logs directly from the kernel ring buffer to userspace. Phase 9 resolves allowlist control usability, and Phase 10 introduces autonomous, kernel-enforced blacklisting and low-overhead event streaming via the BPF Ring Buffer.

---

## Phase 9 — Allowlist CLI & Per-IP Metric Dashboard

### Why Phase 9?

In previous phases, managing the allowlist required manually calculating IPv4 hexadecimal values and executing raw `bpftool` commands. For example:
- Adding `10.0.1.5` meant typing `sudo bpftool map update name allowlist_map key hex 0a 00 01 05 value hex 01 00 00 00`.

This approach is highly error-prone, hard to automate, and completely inaccessible to network administrators. Furthermore, the Prometheus metrics only exported aggregate block counts, meaning there was no way for external graphing tools (like Grafana) or the local console dashboard to check *which* specific IPs were currently blocked.

Phase 9 solves these limitations by introducing:
1. **`fluxguard_allow.py`**: A clean command-line interface (CLI) to query, add, and remove IPs from the BPF allowlist map using `ctypes`.
2. **Per-IP Prometheus Block Exporters**: The brain now exports a list of individual blocked IPs as explicit Prometheus label gauges.
3. **Status-Aware Dashboard**: The live dashboard reads this status to distinguish between `ACTIVE` and `BLOCKED` IPs dynamically.

---

### The Allowlist Management CLI (`fluxguard_allow.py`)

`fluxguard_allow.py` is a Python CLI that interacts directly with the pinned `allowlist_map` fd on the host filesystem. It imports the ctypes binding functions (`bpf_obj_get`, `set_map_u32`, `del_map_u32`, `dump_map_u32`) from the brain:

```python
# Example Usage:
# Add IP to allowlist:
sudo python3 fluxguard_allow.py add 10.0.1.5

# List all allowlisted IPs:
sudo python3 fluxguard_allow.py list

# Remove IP from allowlist:
sudo python3 fluxguard_allow.py del 10.0.1.5
```

Because it leverages the ctypes system, it executes in **microsecond speeds**, immediately updating the kernel space. The next packet arriving from the newly allowlisted IP is evaluated instantly by the kernel XDP program without any latency or packet drops.

---

### Per-IP Prometheus Metrics

To let the dashboard and external Prometheus servers track *who* is blocked, the `MetricsState` class in `fluxguard_metrics.py` was extended to include a set of blocked IPs:

```python
class MetricsState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._packets_by_ip: Dict[str, int] = {}
        self._blocked_ips_set: Set[str] = set()  # Tracks blocked IPs explicitly
        self._blocked_ips = 0
        ...

    def update_blocked_set(self, blocked_set: Set[str]) -> None:
        with self._lock:
            self._blocked_ips_set = set(blocked_set)

    def render_prometheus_text(self) -> str:
        with self._lock:
            ...
            blocked_set = sorted(list(self._blocked_ips_set))
            
        lines = [...] # Render meter packets and total count
        
        # New in Phase 9: export each blocked IP as a gauge with value 1
        if blocked_set:
            lines.extend([
                "# HELP fluxguard_blocked_ip Per-IP block status (1 = currently blocked).",
                "# TYPE fluxguard_blocked_ip gauge",
            ])
            for ip in blocked_set:
                safe = ip.replace("\\", "\\\\").replace('"', '\\"')
                lines.append('fluxguard_blocked_ip{ip="%s"} 1' % safe)
        
        return "\n".join(lines)
```

Example output of the new metrics format:
```prometheus
# HELP fluxguard_blocked_ip Per-IP block status (1 = currently blocked).
# TYPE fluxguard_blocked_ip gauge
fluxguard_blocked_ip{ip="10.0.1.1"} 1
fluxguard_blocked_ip{ip="10.0.1.2"} 1
```

---

### Dashboard Status Integration

The `fluxguard_dashboard.py` parses these per-IP lines. When displaying the top traffic-generating IPs, it checks if their IP is present in the `blocked_ips_set` parsed from the Prometheus metrics endpoint:

```python
for ip, cnt in top_ips:
    prev = prev_packets.get(ip, cnt)
    pps = (cnt - prev) / dt if dt > 0 else 0.0
    
    # Status coloring: Red for BLOCKED, Green for ACTIVE
    if ip in blocked_ips_set:
        status = "\033[31mBLOCKED\033[0m"
    else:
        status = "\033[32mACTIVE\033[0m"
        
    print(f"{ip:<18} | {status:<19} | {cnt:<12} | {pps:<10.1f}")
```

This represents the first end-to-end integration showing real-time mitigations reflecting directly in the visual UI console.

---

## Phase 10 — Proactive Kernel Mitigation & BPF Ring Buffer

### The Big Vulnerability: Brain Downtime / Crash

In all previous phases (Phases 1–9), if the Python brain crashed or was stopped (e.g., during updates or resource exhaustion), the system was left vulnerable:
1. The kernel XDP filter would run the token bucket checks.
2. If an IP exceeded the rate limit, it would drop packets *only as long as* the token bucket was empty (`tokens == 0`).
3. Because the Python brain wasn't running to detect this and insert a permanent entry into `blacklist_map`, the attacker could continue flooding the system. They would only be rate-limited, not completely cut off.

### Phase 10 Solution: Kernel-Enforced Autonomous Blacklisting

Phase 10 shifts the block decision **directly into the kernel**. When a packet violates the rate limit in kernel space, the kernel XDP program writes the block entry into `blacklist_map` **autonomously**, without waiting for the Python control plane.

```c
/* 6. In-kernel per-IP rate limiting & Auto-Blacklist */
struct token_bucket *tb = bpf_map_lookup_elem(&rate_map, &src_ip);
if (tb) {
    __u64 elapsed_ns = now - tb->last_time;
    if (elapsed_ns > 1000000ULL) { 
        __s64 refill = (elapsed_ns * KERN_PPS_LIMIT) / 1000000000ULL;
        if (refill > 0) {
            tb->last_time = now;
            tb->tokens += refill;
            if (tb->tokens > KERN_PPS_LIMIT) tb->tokens = KERN_PPS_LIMIT;
        }
    }
    
    tb->tokens -= 1;
    if (tb->tokens < 0) {
        /* AUTONOMOUS KERNEL BLOCK:
           The C code updates the blacklist_map directly! */
        __u32 blocked_val = 1;
        bpf_map_update_elem(&blacklist_map, &src_ip, &blocked_val, BPF_ANY);
        
        /* Event Streaming: Submit event to BPF Ring Buffer */
        struct attack_event *e = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*e), 0);
        if (e) {
            e->ip = src_ip;
            e->reason = 1; /* 1 = KERNEL_AUTO_BLOCK */
            e->timestamp = now;
            bpf_ringbuf_submit(e, 0);
        }
        
        return XDP_DROP;
    }
}
```

This represents a major paradigm shift:
- **Zero-Latency Mitigation**: Blocking happens on the very packet that pushes the token count below 0.
- **Resilience**: Even if the Python brain is completely dead (`pkill -9`), the kernel continues to block new attackers, preventing CPU exhaustion from network interrupts.

---

### Synchronization in Python (The Cooldown Timer Sync)

Because the kernel inserts entries into `blacklist_map` on its own, the Python brain must detect these "kernel-side" blocks and start cooldown timers for them. Otherwise, blocked IPs would be blacklisted forever (no amnesty).

The brain's loop is modified to scan `blacklist_map` and sync any new entries into Python's memory:

```python
curr_blacklist = dump_map_u32(blacklist_fd)

# Detect autonomous kernel blocks and sync them to python cooldown states!
for ip in curr_blacklist:
    if ip not in blocked_until:
        blocked_until[ip] = now + args.cooldown_sec
        metrics.inc_block_events()
        print(f"[KERNEL AUTO-BLOCK DETECTED] ip={ip}")
```

Once the timer (`cooldown_sec`) expires, Python calls `del_map_u32(blacklist_fd, ip)` to remove the entry, restoring connectivity.

---

### Low-Overhead Event Logging: The BPF Ring Buffer

When the kernel blocks an IP, we need to notify the dashboard immediately. In older eBPF implementations, we used `BPF_MAP_TYPE_PERF_EVENT_ARRAY`. However, Perf Events have high memory overhead because they allocate separate memory ring buffers for each CPU core.

Phase 10 uses the modern **`BPF_MAP_TYPE_RINGBUF`**:
- A single, memory-shared ring buffer shared across all CPUs.
- Lockless, multi-producer single-consumer (MPSC) design.
- Supports memory-mapping (`mmap`) directly into Python userspace for zero-copy reads.

#### The C Event Structure:
```c
struct attack_event {
    __u32 ip;
    __u32 reason;
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB memory buffer */
} event_ringbuf SEC(".maps");
```

#### How Python Reads the Ring Buffer via `mmap()`

Instead of calling a helper library, `fluxguard_dashboard.py` maps the raw kernel ring buffer directly into the Python process's memory space using the standard `mmap` module:

```python
# The kernel ring buffer starts with two control pages (consumer and producer pointers)
# followed by the actual data buffer.
PAGE_SIZE = 4096
RB_SIZE = 256 * PAGE_SIZE  # 256KB

fd = bpf_obj_get("/sys/fs/bpf/fluxguard/event_ringbuf")

# Memory map: 2 pages of headers + size of RingBuf
buf = mmap.mmap(fd, 2 * PAGE_SIZE + 2 * RB_SIZE, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
```

The parsing loop reads the consumer and producer pointers directly from the memory map:

```python
data_off = 2 * PAGE_SIZE

while True:
    # 1. Read consumer and producer offsets (64-bit unsigned integers)
    cons = struct.unpack_from("<Q", buf, 0)[0]
    prod = struct.unpack_from("<Q", buf, PAGE_SIZE)[0]
    
    # 2. Consume events until we catch up to the producer
    while cons < prod:
        pos = cons & (RB_SIZE - 1)
        hdr_len = struct.unpack_from("<I", buf, data_off + pos)[0]
        
        # 3. Check if record flag is valid (0xC0000000 masks represent internal BPF status flags)
        if (hdr_len & 0xC0000000) == 0:
            # Payload starts 8 bytes after header
            ip_bytes = buf[data_off + pos + 8 : data_off + pos + 12]
            ip_str = str(ipaddress.IPv4Address(bytes(ip_bytes)))
            reason_val = struct.unpack_from("<I", buf, data_off + pos + 12)[0]
            
            print(f"[KERNEL AUTO_BLOCK] {ip_str} - Reason: {reason_val}")
        
        # 4. Advance consumer pointer (entries are 8-byte aligned)
        total_len = (hdr_len & 0x0FFFFFFF) + 8
        total_len = (total_len + 7) & ~7
        cons += total_len
        
        # 5. Write updated consumer index back to ringbuf header page
        struct.pack_into("<Q", buf, 0, cons)
        
    time.sleep(0.02)
```

**Why this is extremely fast**:
- **Zero Syscalls per Event**: The events are read directly from memory pages shared with the kernel. Python only sleeps and checks memory offsets.
- **Zero Subprocesses**: No overhead whatsoever. The dashboard can display tens of thousands of logs per second with nearly 0% CPU footprint.

---

## Phase 9 vs Phase 10 — Summary

| Aspect | Phase 9 | Phase 10 |
|--------|---------|---------|
| Allowlist Control | ✅ Python CLI (`fluxguard_allow.py`) | unchanged |
| Per-IP Metrics | ✅ Exported to Prometheus server | unchanged |
| Dashboard status | ✅ Real-time color-coded IP statuses | ✅ RingBuf event streaming integration |
| Block Execution | ❌ Python Brain must detect and write | ✅ Kernel blocks autonomously |
| Crash Resilience | ❌ Vulnerable if Python brain exits | ✅ Fully protected even if Python is killed |
| Event Logging | ❌ Polls `blacklist_map` changes | ✅ Zero-copy Ring Buffer event streaming |

---

## OS Concepts Introduced in Phases 9–10

### 1. Zero-Copy Memory Mapping (`mmap`)
Memory mapping (`mmap`) bypasses the overhead of copying data between the kernel page cache and user buffers. By sharing memory pages directly between kernel space and the Python process, the BPF Ring Buffer allows the user program to access ring buffer headers and records directly via pointer offset math.

### 2. Multi-Producer Single-Consumer (MPSC) Queue
The BPF Ring Buffer acts as a lock-free MPSC queue. Multiple CPU cores (producers) can submit network events simultaneously using atomic memory reservations, while a single userspace Python reader (consumer) processes the events sequentially and updates the shared consumer pointer.

### 3. Ring Buffer Wrap-Around Handling
Ring buffers use a power-of-two size (e.g. 256KB). When the writer or reader reaches the end, offsets wrap back to `0`. By using a logical size bitmask (`pos = cons & (RB_SIZE - 1)`), the code translates the monotonically increasing 64-bit consumer counter into a safe buffer index without modulo operations.

### 4. Kernel-Space Policy Enforcement
Phase 10 showcases a hybrid security design. The **data plane (kernel)** is autonomous, fast, and makes local blocking decisions at line rate. The **control plane (userspace)** acts as a state manager, tracking historical state, processing metrics, and applying policies like timers or configs back to the data plane.
