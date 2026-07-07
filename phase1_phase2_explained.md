# FluxGuard — Phase 1 & Phase 2 Deep Explanation

---

## Phase 1 — Building the Network Topology

### What is Phase 1?

Phase 1 has **nothing to do with XDP or eBPF**. Its only job is to build a realistic, isolated network environment inside a single Ubuntu VM using **Linux Network Namespaces**. Think of it as building a miniature internet with three computers — but all inside one machine.

### Why Network Namespaces?

A Linux Network Namespace is a completely isolated copy of the kernel networking stack. Each namespace has its own:
- Network interfaces (NICs)
- IP routing table
- ARP table
- Firewall rules

Two processes in different namespaces cannot talk to each other unless you explicitly connect them. This gives us a safe, reproducible test lab without needing physical hardware.

### The Three Nodes

```
[client ns]          [fluxguard ns]         [backend ns]
 10.0.1.1    <-->    10.0.1.2               10.0.2.2
  veth-client        veth-fg-in             veth-backend
                     veth-fg-out
                      10.0.2.1
```

| Namespace | Role | IP Address | Interface |
|-----------|------|-----------|-----------|
| `client` | Simulated attacker / normal user | `10.0.1.1` | `veth-client` |
| `fluxguard` | Router + Firewall (XDP runs here) | `10.0.1.2` / `10.0.2.1` | `veth-fg-in`, `veth-fg-out` |
| `backend` | Protected server | `10.0.2.2` | `veth-backend` |

### The veth Pair Concept

A **veth (virtual Ethernet) pair** is like a network cable with two ends. Whatever goes in one end comes out the other. You create a pair and assign each end to a different namespace.

```
client ns          fluxguard ns
veth-client  <---> veth-fg-in     (this is where XDP will attach)

fluxguard ns       backend ns
veth-fg-out  <---> veth-backend
```

### Exact Phase 1 Commands Explained

```bash
# Step 1 — Install all tools needed for the project
sudo apt install -y clang llvm libelf-dev libpcap-dev gcc-multilib \
  linux-tools-$(uname -r) linux-headers-$(uname -r) \
  iproute2 python3 python3-pip hping3 tcpdump curl
```

- `clang` + `llvm` — compile C code to BPF bytecode
- `linux-headers` — kernel headers needed by the BPF compiler
- `iproute2` — the `ip` command for namespace and interface management
- `hping3` — crafts custom TCP/UDP packets for testing (simulates floods)
- `tcpdump` — packet capture to verify traffic is reaching backend

```bash
# Step 2 — Create three isolated namespaces
sudo ip netns add client
sudo ip netns add fluxguard
sudo ip netns add backend
```

```bash
# Step 3 — Create two veth cable pairs
sudo ip link add veth-client type veth peer name veth-fg-in
sudo ip link add veth-fg-out type veth peer name veth-backend
```

```bash
# Step 4 — Move each cable end into its namespace
sudo ip link set veth-client netns client
sudo ip link set veth-fg-in  netns fluxguard
sudo ip link set veth-fg-out netns fluxguard
sudo ip link set veth-backend netns backend
```

```bash
# Step 5 — Assign IP addresses
sudo ip netns exec client    ip addr add 10.0.1.1/24 dev veth-client
sudo ip netns exec fluxguard ip addr add 10.0.1.2/24 dev veth-fg-in
sudo ip netns exec fluxguard ip addr add 10.0.2.1/24 dev veth-fg-out
sudo ip netns exec backend   ip addr add 10.0.2.2/24 dev veth-backend
```

```bash
# Step 6 — Bring all interfaces up
sudo ip netns exec client    ip link set veth-client up
sudo ip netns exec fluxguard ip link set veth-fg-in  up
sudo ip netns exec fluxguard ip link set veth-fg-out up
sudo ip netns exec backend   ip link set veth-backend up
```

```bash
# Step 7 — Add default routes so traffic knows where to go
sudo ip netns exec client  ip route add default via 10.0.1.2
sudo ip netns exec backend ip route add default via 10.0.2.1

# Step 8 — Enable IP forwarding in fluxguard (makes it a router)
sudo ip netns exec fluxguard sysctl -w net.ipv4.ip_forward=1
```

- Without `ip_forward=1`, the fluxguard namespace would receive packets from the client but silently discard them instead of forwarding to the backend.

### Phase 1 Test

```bash
# Verify connectivity — client should be able to reach backend
sudo ip netns exec client ping -c 2 10.0.2.2
# Expected: 2 packets transmitted, 2 received — 0% packet loss
```

Then run a flood test to confirm the backend is reachable but **not yet protected**:

```bash
# Terminal 1 — watch backend
sudo ip netns exec backend tcpdump -i veth-backend -n tcp port 80

# Terminal 2 — flood from client
sudo ip netns exec client hping3 --flood -S -p 80 10.0.2.2
```

The backend tcpdump will show **thousands of SYN packets per second** — because Phase 1 has no filtering. This is the "before" state that FluxGuard will fix.

### What Phase 1 Does NOT Have

- No XDP program
- No rate limiting
- No blocking
- No metrics
- No persistence

It is purely a plumbing exercise. The lab now exists. Phases 2–12 build the actual DDoS mitigation system on top of it.

---

## Phase 2 — First XDP Program

### What is Phase 2?

Phase 2 writes, compiles, and loads the **very first version** of the XDP kernel program. It introduces two fundamental BPF concepts:
1. **BPF Maps** — shared key-value stores between the kernel program and userspace
2. **XDP Actions** — the four decisions an XDP program can return for each packet

### What is XDP?

**eXpress Data Path (XDP)** is a Linux kernel technology that lets you run a small C program directly inside the **NIC driver** — before the kernel even allocates a socket buffer (`sk_buff`) for the packet.

```
Packet arrives at the NIC
        │
        ▼ ← XDP hook runs HERE (in the driver, before anything else)
   [Your C program runs and returns one of:]
   XDP_DROP   → Packet is silently discarded. Fast, no memory allocated.
   XDP_PASS   → Packet continues to normal Linux networking stack.
   XDP_TX     → Packet is bounced back out the same interface.
   XDP_ABORT  → Error; packet dropped (used for debugging).
        │ (if XDP_PASS)
        ▼
   sk_buff allocated (~300 bytes of kernel memory)
        │
        ▼
   iptables / netfilter (hooks run here — MUCH later than XDP)
        │
        ▼
   Socket / userspace
```

**Key insight**: XDP drops packets before any memory is allocated. Under a 1 million pps flood, that saves **300 MB of kernel memory per second** compared to iptables.

### Phase 2 XDP Program — Full Code

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

// BPF Map 1: blacklist — IPs to drop
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);       // IPv4 address (4 bytes)
    __type(value, __u32);     // any non-zero = blocked
} blacklist_map SEC(".maps");

// BPF Map 2: meter — count packets per IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);       // source IP
    __type(value, __u32);     // packet count
} meter_map SEC(".maps");

SEC("xdp")
int fluxguard_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // 1. Parse Ethernet header — BOUNDS CHECK required by BPF verifier
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;  // malformed packet — let kernel handle it

    // 2. Only process IPv4 — pass everything else (ARP, IPv6) through
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // 3. Parse IP header — BOUNDS CHECK again
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;  // source IP in network byte order

    // 4. Increment packet counter for this source IP (atomic operation)
    __u32 *cnt = bpf_map_lookup_elem(&meter_map, &src_ip);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);   // atomic increment — safe on multi-core
    } else {
        __u32 init = 1;
        bpf_map_update_elem(&meter_map, &src_ip, &init, BPF_ANY);
    }

    // 5. Check blacklist — if found, DROP immediately
    __u32 *blocked = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (blocked)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### Line-by-Line Explanation

#### `SEC(".maps")` — BPF Section Declarations
Every BPF map must be declared with the `SEC(".maps")` attribute. The ELF object file (.o) will have a special section called `.maps` containing all map definitions. When the kernel loads the program, it reads this section and creates the actual in-kernel maps.

#### Bounds Checking — Why It's Mandatory
```c
if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
```
The **BPF verifier** (a kernel-side static analyzer) simulates all execution paths before allowing the program to load. It tracks pointer arithmetic. If you dereference `eth->h_proto` without first proving `eth + 1` fits within `[data, data_end)`, the verifier rejects your program with:
```
R1 invalid mem access 'map_value_or_null'
```
This prevents Heartbleed-style memory overread bugs.

#### `__sync_fetch_and_add` — Atomic Increment
XDP programs run on **every CPU core simultaneously**. If two packets from the same IP arrive at the exact same nanosecond, two CPU cores execute the XDP function at the same time. Without atomics:
```
CPU 0: read count=100, add 1 → write 101
CPU 1: read count=100 (stale), add 1 → write 101  ← lost!
```
With `__sync_fetch_and_add(cnt, 1)`, the increment is a single atomic hardware instruction — guaranteed correct.

#### `BPF_MAP_TYPE_HASH`
A hash table inside the kernel. Used in Phase 2 for both `blacklist_map` and `meter_map`. Key is the 4-byte source IP; value is a u32 counter.

### How to Compile

```bash
clang -O2 -g -Wall -target bpf \
    -c fluxguard_kern.c \
    -o fluxguard_kern.o
```

- `-target bpf` — tells clang to compile for the BPF virtual machine, not x86
- `-O2` — optimization required; BPF programs must be small and efficient
- The output `.o` is an ELF file with BPF bytecode, NOT x86 machine code

### How to Load and Attach

```bash
# Attach XDP program to the ingress of veth-fg-in inside the fluxguard namespace
sudo ip netns exec fluxguard \
    ip link set dev veth-fg-in xdpgeneric obj fluxguard_kern.o sec xdp
```

- `xdpgeneric` — software fallback mode. Virtual interfaces (veth) don't support native XDP driver mode. On a real physical NIC (e.g., Intel i40e), you would use `xdpdrv` for full performance.
- `sec xdp` — tells the kernel which ELF section to load (our `SEC("xdp")` function)

### Phase 2 Test

```bash
# Verify the program is attached
sudo ip netns exec fluxguard ip link show veth-fg-in
# Output will show: prog/xdp ...

# Verify maps were created
sudo ip netns exec fluxguard bpftool map show | grep -E "blacklist_map|meter_map"
```

At this point:
- **Every packet** through `veth-fg-in` is counted in `meter_map`
- **No packet is blocked yet** — `blacklist_map` is empty
- Blocking still requires manually inserting an IP into `blacklist_map` with `bpftool map update`

That manual step is what Phase 3 automates.

---

## Phase 1 vs Phase 2 — Key Differences

| Aspect | Phase 1 | Phase 2 |
|--------|---------|---------|
| What was built | Network plumbing (namespaces, veth, routes) | XDP kernel program |
| Language | Bash / shell commands | C (compiled to BPF bytecode) |
| Runs in | Userspace (ip command) | Kernel (XDP hook inside driver) |
| Blocking | None | None (manual only via bpftool) |
| Automation | None | None |
| Maps | None | `blacklist_map`, `meter_map` |
| Protection | None | Partial (must manually insert block entries) |

---

## Key OS Concepts Introduced in Phases 1–2

### 1. Linux Network Namespaces
Isolated network stack. Each `ip netns add X` creates a new namespace. `ip netns exec X <cmd>` runs a command inside that namespace's network context.

### 2. Virtual Ethernet Pairs (veth)
Always created in pairs. One end is in namespace A, the other in namespace B. Packets sent into one end come out the other. Used to connect namespaces together.

### 3. IP Forwarding
`net.ipv4.ip_forward=1` makes the kernel forward packets between interfaces. Without it, packets arriving on `veth-fg-in` destined for `10.0.2.2` would be silently dropped.

### 4. XDP (eXpress Data Path)
Runs a BPF program at the earliest possible point in the receive path — inside the NIC driver. Returns `XDP_DROP` to discard or `XDP_PASS` to continue.

### 5. BPF Maps
Kernel-resident key-value stores. Shared between the XDP program (running in kernel) and Python control plane (running in userspace). Accessed by the kernel via `bpf_map_lookup_elem()`/`bpf_map_update_elem()` and by userspace via the `bpf()` syscall.

### 6. BPF Verifier
Before any BPF program is loaded, the kernel verifier performs static analysis — checks all possible execution paths for: unbounded loops, out-of-bounds memory access, NULL dereferences. If verification fails, the program is rejected.

### 7. Atomic Operations
`__sync_fetch_and_add` is a GCC built-in that compiles to a hardware atomic instruction (e.g., `LOCK XADD` on x86). Guarantees no lost increments even when multiple CPU cores run the code simultaneously.
