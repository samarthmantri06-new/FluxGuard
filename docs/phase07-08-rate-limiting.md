# FluxGuard — Phase 7 & Phase 8 Deep Explanation

> **Continuing from Phase 6** — The brain is now reliable and structured. But it still relies on slow `bpftool` subprocesses to talk to BPF maps. Phase 7 replaces this with direct kernel syscalls via `ctypes` and adds in-kernel token-bucket rate limiting. Phase 8 fixes four correctness bugs discovered after deploying Phase 7.

---

## Phase 7 — ctypes Direct Syscall + In-Kernel Token Bucket

### The Big Problem with bpftool Subprocesses

Every map read in Phases 4–6 did this:

```
Python → fork() → exec("bpftool") → bpftool reads map → JSON to stdout → Python parses JSON
```

Each call costs:
- ~2ms for `fork()` + `exec()` overhead
- ~3ms for bpftool to open the map, iterate all keys, format JSON
- CPU time for JSON parsing (grows with map size)
- At 0.2s poll interval: **up to 25ms wasted per second = 12.5% CPU overhead just for I/O**

Under a spoof flood with 65,536 unique source IPs, the JSON output from `meter_map` alone could be several MB per poll — causing the brain to fall behind.

### The Phase 7 Solution: Direct `bpf()` Syscall via ctypes

Python can call any C function or Linux syscall using `ctypes` — no subprocess, no JSON, no fork. The BPF syscall interface is:

```c
// Kernel system call signature
int bpf(int cmd, union bpf_attr *attr, unsigned int size);
```

In Python:

```python
import ctypes, os, platform

# Load libc (the C standard library, which wraps Linux syscalls)
libc = ctypes.CDLL("libc.so.6", use_errno=True)

# SYS_BPF syscall number (differs by architecture)
# x86_64: 321, aarch64: 280
SYS_BPF = 321

def bpf_syscall(cmd: int, attr) -> int:
    # libc.syscall(syscall_number, cmd, &attr, size_of_attr)
    res = libc.syscall(SYS_BPF, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
    if res < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return res
```

**`ctypes.CDLL`** loads the C library. **`libc.syscall`** invokes the raw Linux `syscall()` instruction, bypassing the need for any subprocess.

### BPF Command Numbers

The `bpf()` syscall takes a `cmd` (command) integer telling the kernel what to do:

| cmd | Value | Purpose |
|-----|-------|---------|
| `BPF_MAP_LOOKUP_ELEM` | `1` | Look up a key in a map |
| `BPF_MAP_UPDATE_ELEM` | `2` | Insert or update a key-value pair |
| `BPF_MAP_DELETE_ELEM` | `3` | Delete a key |
| `BPF_MAP_GET_NEXT_KEY` | `4` | Iterate — get the next key after a given key |
| `BPF_OBJ_GET` | `7` | Open a pinned map by filesystem path |

### Opening a Pinned Map (BPF_OBJ_GET)

Maps pinned under `/sys/fs/bpf/` are like files — you open them with `BPF_OBJ_GET` and get back a file descriptor:

```python
class bpf_attr(ctypes.Union):
    class obj_get(ctypes.Structure):
        _fields_ = [
            ("pathname", ctypes.c_uint64),   # pointer to path string
            ("bpf_fd",   ctypes.c_uint32),
            ("file_flags", ctypes.c_uint32),
        ]
    _fields_ = [("obj_get", obj_get)]

def bpf_obj_get(path: str) -> int:
    attr = bpf_attr()
    # Cast the Python string to a C pointer and store its address as u64
    attr.obj_get.pathname = ctypes.cast(
        ctypes.c_char_p(path.encode()), ctypes.c_void_p
    ).value
    return bpf_syscall(7, attr)   # cmd=7 = BPF_OBJ_GET

# Usage
meter_fd = bpf_obj_get("/sys/fs/bpf/fluxguard/meter_map")
```

This is equivalent to `open("/sys/fs/bpf/fluxguard/meter_map", O_RDWR)` — returns an integer file descriptor that the kernel will recognise in subsequent BPF operations.

### Iterating a Map (BPF_MAP_GET_NEXT_KEY)

```python
class BpfKey(ctypes.Structure):
    _fields_ = [("bytes", ctypes.c_uint8 * 4)]   # 4-byte IPv4 key

def dump_map_u32(fd: int) -> Dict[str, int]:
    res = {}
    current_key = BpfKey()
    next_key    = BpfKey()
    value       = BpfValue()

    # Step 1: Get FIRST key (pass key=NULL → kernel returns first entry)
    attr = bpf_attr()
    attr.elem.map_fd = fd
    attr.elem.key    = 0               # NULL pointer = "give me the first key"
    attr.elem.value  = ctypes.addressof(current_key)
    bpf_syscall(4, attr)               # BPF_MAP_GET_NEXT_KEY with NULL key

    while True:
        # Step 2: Lookup value for current_key
        attr_l = bpf_attr()
        attr_l.elem.map_fd = fd
        attr_l.elem.key    = ctypes.addressof(current_key)
        attr_l.elem.value  = ctypes.addressof(value)
        bpf_syscall(1, attr_l)         # BPF_MAP_LOOKUP_ELEM
        res[key_to_ip(current_key)] = value.val

        # Step 3: Advance to next key
        attr_n = bpf_attr()
        attr_n.elem.map_fd = fd
        attr_n.elem.key    = ctypes.addressof(current_key)
        attr_n.elem.value  = ctypes.addressof(next_key)
        try:
            bpf_syscall(4, attr_n)     # BPF_MAP_GET_NEXT_KEY
            ctypes.memmove(ctypes.addressof(current_key),
                           ctypes.addressof(next_key),
                           ctypes.sizeof(BpfKey))
        except OSError:
            break   # errno=ENOENT means no more keys — iteration complete

    return res
```

This replaces the entire `bpftool --json map dump` pipeline with pure in-process syscalls.

### Map Pinning (Required for ctypes)

Maps must be **pinned to the BPF filesystem** before ctypes can open them by path:

```bash
# Mount BPF FS
sudo mount -t bpf none /sys/fs/bpf/
sudo mkdir -p /sys/fs/bpf/fluxguard

# Pin each map (get ID from bpftool, then pin)
for map in meter_map blacklist_map allowlist_map rate_map global_counter_map proto_filter_map; do
    ID=$(sudo ip netns exec fluxguard bpftool map show name $map | awk 'NR==1{print $1}' | tr -d ':')
    sudo ip netns exec fluxguard bpftool map pin id $ID /sys/fs/bpf/fluxguard/$map
done
```

After this, `/sys/fs/bpf/fluxguard/meter_map` exists as a filesystem entry. Python opens it with `bpf_obj_get()`.

### In-Kernel Token Bucket Rate Limiting

The biggest Phase 7 kernel feature: rate limiting without Python involvement. The XDP C program now tracks a **token bucket** per source IP and drops packets directly — even if the brain hasn't woken up yet.

```c
struct token_bucket {
    __u64 last_time;   // nanosecond timestamp of last refill
    __u64 tokens;      // current token count
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct token_bucket);
} rate_map SEC(".maps");
```

In the XDP function, after checking blacklist:

```c
__u64 now = bpf_ktime_get_ns();
struct token_bucket *tb = bpf_map_lookup_elem(&rate_map, &src_ip);
if (tb) {
    __u64 elapsed_ns = now - tb->last_time;
    __u64 refill = elapsed_ns / 10000;   // ← BROKEN: refills 100x too fast (fixed in Phase 11)
    tb->tokens += refill;
    if (tb->tokens > KERN_PPS_LIMIT) tb->tokens = KERN_PPS_LIMIT;
    tb->last_time = now;

    if (tb->tokens == 0) return XDP_DROP;
    tb->tokens -= 1;
} else {
    struct token_bucket new_tb = {now, KERN_PPS_LIMIT - 1};
    bpf_map_update_elem(&rate_map, &src_ip, &new_tb, BPF_ANY);
}
```

**Token bucket concept:**
- Each IP starts with `KERN_PPS_LIMIT` tokens (e.g. 1000)
- Each packet consumes 1 token
- Tokens refill over time proportional to elapsed nanoseconds
- When `tokens == 0`, the packet is dropped immediately — no Python needed

### `LRU_HASH` for Anti-Spoofing

Phase 7 changes `meter_map` and `rate_map` from `BPF_MAP_TYPE_HASH` to `BPF_MAP_TYPE_LRU_HASH`:

```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);   // LRU instead of plain HASH
    __uint(max_entries, 65536);
    ...
} meter_map SEC(".maps");
```

**Why?** A plain `HASH` map with `max_entries=65536` fills up under a random-source (spoofed) flood — every packet has a unique source IP. Once the map is full, `bpf_map_update_elem()` fails silently and new IPs are no longer tracked.

`LRU_HASH` automatically **evicts the least recently used entry** when the map is full. This prevents table exhaustion under spoofed floods while keeping recently-seen IPs tracked.

---

## Phase 8 — Four Correctness Fixes

> Phase 8 found and fixed four bugs introduced or left unresolved in Phase 7.

### Fix 1 — ctypes NULL Key Traversal Bug

**The bug:** Phase 7's `dump_map_u32` passed `key=NULL` to `BPF_MAP_GET_NEXT_KEY` to get the first key. But then it used the **wrong variable** to store the result:

```python
# WRONG (Phase 7): result stored in first_key but then current_key is never initialized
attr.elem.key   = 0                         # NULL → get first key
attr.elem.value = ctypes.addressof(first_key)
bpf_syscall(4, attr)
# BUG: current_key still has zero bytes (not copied from first_key)
```

**The fix (Phase 8):** After getting the first key, explicitly copy it into `current_key`:

```python
attr.elem.key   = 0
attr.elem.value = ctypes.addressof(first_key)
bpf_syscall(4, attr)

# FIX: copy first_key → current_key before entering the loop
ctypes.memmove(
    ctypes.addressof(current_key),
    ctypes.addressof(first_key),
    ctypes.sizeof(BpfKey)
)
# Now the loop starts with a valid key
```

Without this fix, the brain would iterate starting from IP `0.0.0.0` (all zero bytes) and either crash or silently miss all real entries.

### Fix 2 — Global Rate Map TOCTOU Race (PERCPU_ARRAY)

**The bug (Phase 7):** The global packet counter was a struct in a plain `BPF_MAP_TYPE_ARRAY`:

```c
struct global_rate { __u64 window_start; __u32 count; };
struct { __uint(type, BPF_MAP_TYPE_ARRAY); ... } global_pps_map SEC(".maps");
```

When two CPU cores process two packets simultaneously, both read `count=100`, both compute `count + 1 = 101`, both write back `101`. One increment is lost — a **TOCTOU (Time-of-Check-Time-of-Use) race**.

**The fix (Phase 8):** Replace with `BPF_MAP_TYPE_PERCPU_ARRAY`:

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_counter_map SEC(".maps");
```

In a PERCPU array:
- CPU 0 exclusively owns slot `[0][cpu0]`
- CPU 1 exclusively owns slot `[0][cpu1]`
- No two CPUs share the same memory cell — no race possible

Python sums all CPU slots to get the total:
```python
class PercpuValue(ctypes.Structure):
    _fields_ = [("vals", ctypes.c_uint64 * 128)]

def get_global_counter(fd: int) -> int:
    v = PercpuValue()
    # BPF_MAP_LOOKUP_ELEM on PERCPU_ARRAY fills all CPU slots at once
    bpf_syscall(1, attr)
    num_cpus = min(os.cpu_count() or 1, 128)
    return sum(v.vals[i] for i in range(num_cpus))
```

### Fix 3 — Map Pinning Grep Matched Wrong Maps

**The bug (Phase 7):** The pinning script used `grep` to find the map ID:

```bash
ID=$(sudo bpftool map show | grep "rate_map" | awk '{print $1}')
```

This matches any map whose name **contains** `rate_map` — including `global_rate_map`. So `rate_map` might get the ID of `global_rate_map` and be pinned with the wrong file descriptor.

**The fix (Phase 8):** Use `bpftool map show name <exact_name>` which does an exact name match:

```bash
ID=$(sudo bpftool map show name rate_map | awk 'NR==1{print $1}' | tr -d ':')
```

### Fix 4 — Token Field Type Changed from u32 to u64

**The bug (Phase 7):** `struct token_bucket` had `__u32 tokens`. A 32-bit counter at 1000 pps wraps in ~4.3 million seconds — fine. But the **refill** computation:

```c
__u64 elapsed_ns = now - tb->last_time;
__u64 refill = elapsed_ns / 10000;
```

`elapsed_ns` can be large (e.g. 1 second = 1,000,000,000 ns → refill = 100,000). Storing 100,000 into a `__u32 tokens` field is fine. But the intermediate arithmetic could overflow if tokens was `__u32` while elapsed was `__u64`.

**The fix (Phase 8):** Make `tokens` a `__u64`:

```c
struct token_bucket {
    __u64 last_time;
    __u64 tokens;    // changed from __u32 to __u64
};
```

> Note: The **refill formula itself** (`elapsed_ns / 10000`) is still wrong here — it refills 100× too fast. That formula bug is fixed in **Phase 11**.

### Phase 8 Test Commands

```bash
# Step 1: Recompile and reload XDP with Phase 8 kernel
clang -O2 -g -Wall -target bpf -c fluxguard_kern.c -o fluxguard_kern.o
sudo ip netns exec fluxguard ip link set dev veth-fg-in xdp off
sudo ip netns exec fluxguard ip link set dev veth-fg-in xdpgeneric obj fluxguard_kern.o sec xdp

# Step 2: Pin all maps with EXACT name match (Fix 3)
for map in meter_map blacklist_map allowlist_map rate_map global_counter_map proto_filter_map; do
    ID=$(sudo ip netns exec fluxguard bpftool map show name $map | awk 'NR==1{print $1}' | tr -d ':')
    sudo ip netns exec fluxguard bpftool map pin id $ID /sys/fs/bpf/fluxguard/$map
done

# Step 3: Test ctypes NULL key fix — should return a valid dict, not crash
python3 -c "
import sys; sys.path.insert(0, '/home/samarth/fluxguard')
from fluxguard_brain import bpf_obj_get, dump_map_u32
fd = bpf_obj_get('/sys/fs/bpf/fluxguard/meter_map')
print(dump_map_u32(fd))
"
# Expected: {} or {ip: count} — not a crash

# Step 4: Confirm PERCPU map type was used
sudo ip netns exec fluxguard bpftool map show name global_counter_map
# Expected: type percpu_array ...

# Step 5: Start brain and dashboard
sudo python3 /home/samarth/fluxguard/fluxguard_brain.py \
    --netns fluxguard --pps-threshold 1000 --verbose \
    --log-file /home/samarth/fluxguard/fluxguard.log &

python3 /home/samarth/fluxguard/fluxguard_dashboard.py \
    --metrics-url http://127.0.0.1:9090/metrics --refresh 2
```

---

## Phase 7 vs Phase 8 — Summary

| Aspect | Phase 7 | Phase 8 |
|--------|---------|---------|
| Map I/O | ✅ Direct ctypes syscall (no subprocess) | unchanged |
| Token bucket | ✅ In-kernel, no brain needed for drops | unchanged |
| LRU maps | ✅ Spoof-flood resistant | unchanged |
| Ctypes NULL key | ❌ Bug — first key never copied | ✅ `memmove` after first key fetch |
| Global counter | ❌ TOCTOU race on shared struct | ✅ PERCPU_ARRAY, zero-race |
| Map pinning | ❌ grep matches substrings | ✅ `bpftool map show name <exact>` |
| Token field type | ❌ `__u32 tokens` (arithmetic risk) | ✅ `__u64 tokens` |

---

## OS Concepts Introduced in Phases 7–8

### 1. Linux `syscall()` via ctypes
`libc.syscall(number, ...)` invokes a raw Linux system call. This is lower-level than any Python library — it bypasses the standard library and speaks directly to the kernel.

### 2. ctypes Memory Layout
`ctypes.Structure` and `ctypes.Union` map Python objects to specific byte layouts in memory. `_fields_` defines the field name and type. `ctypes.c_uint8 * 4` is a C array of 4 bytes. `ctypes.addressof(obj)` returns the raw memory address (a Python integer) which can be passed to the kernel as a pointer.

### 3. BPF Map Filesystem (BPFFS)
Mounted at `/sys/fs/bpf/`, BPFFS gives BPF objects (maps, programs) persistent paths on the filesystem. A "pinned" map stays alive even after the program that created it exits, as long as the BPFFS path exists. Opening a pinned map is functionally identical to opening a file — you get an integer file descriptor.

### 4. Token Bucket Algorithm
A classic rate-limiting algorithm:
- **Bucket** holds up to `LIMIT` tokens
- **Refill** adds tokens at a rate of 1 per `1/LIMIT` seconds
- **Each packet** consumes 1 token
- **Empty bucket** → drop
- Allows short bursts (bucket is full at idle) but enforces long-term rate

### 5. PERCPU Data Structures (Eliminating Locks)
In the kernel, concurrent access is normally protected by spinlocks. Locks are slow under high contention. PERCPU data avoids locks by giving **each CPU its own private copy** of the data. No other CPU ever reads or writes a given CPU's slot. The total is only computed in userspace (Python brain), where a single-threaded process sums all slots at once.

### 6. TOCTOU Race Condition
Time-of-Check-Time-of-Use. A class of concurrency bug where:
1. Thread A reads a value (Check)
2. Thread B modifies the value
3. Thread A acts on its stale reading (Use) — wrong result

The global counter TOCTOU in Phase 7 was: CPU 0 reads count, CPU 1 reads count, both increment their local copies, both write back — one increment is lost. PERCPU_ARRAY eliminates this by ensuring each CPU has an independent slot.

### 7. LRU Eviction Policy
Least Recently Used: when a hash map is full and a new key needs to be inserted, the entry that was **accessed least recently** is evicted. This keeps the map full of "active" IPs (ones currently sending packets) and discards stale entries from IPs that stopped communicating.
