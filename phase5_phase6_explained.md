# FluxGuard — Phase 5 & Phase 6 Deep Explanation

> **Continuing from Phase 4** — At this point the brain can automatically detect and block attackers using `bpftool` subprocesses. Phase 5 adds a kernel-side allowlist bypass and structured JSON logging. Phase 6 hardens the brain for reliability.

---

## Phase 5 — Allowlist + Structured Logging

### Why an Allowlist?

In Phase 4, the brain blocks **any** IP that exceeds the PPS threshold — including your own monitoring systems, load balancers, or legitimate high-traffic clients. An allowlist gives you a set of IPs that are **permanently exempt** from rate limiting, no matter how many packets they send.

The allowlist is implemented in the **kernel**, not Python. This means:
- Allowlisted IPs bypass all checks with zero overhead
- The allowlist check happens at the XDP hook, before even the meter counter
- Python only needs to write entries into `allowlist_map` — no polling needed

### Kernel Change: Adding `allowlist_map`

The XDP program gets a third map added:

```c
// New in Phase 5
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // source IPv4
    __type(value, __u32);  // 1 = allowed
} allowlist_map SEC(".maps");
```

And the filter function now checks this **before** metering or blacklisting:

```c
SEC("xdp")
int fluxguard_filter(struct xdp_md *ctx) {
    // ... parse eth + ip headers ...

    __u32 src_ip = iph->saddr;

    // 1. Allowlist check — if found, bypass ALL rate limiting
    __u32 *allowed = bpf_map_lookup_elem(&allowlist_map, &src_ip);
    if (allowed)
        return XDP_PASS;   // <-- exits before meter or blacklist

    // 2. Meter (count packets per IP)
    __u32 *cnt = bpf_map_lookup_elem(&meter_map, &src_ip);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u32 init = 1;
        bpf_map_update_elem(&meter_map, &src_ip, &init, BPF_ANY);
    }

    // 3. Blacklist check
    __u32 *blocked = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (blocked)
        return XDP_DROP;

    return XDP_PASS;
}
```

**Decision order matters:** Allowlist → Meter → Blacklist → Pass

This means an allowlisted IP doesn't even get counted in `meter_map`, so the brain never sees them and never considers blocking them.

### Recompile + Reload After Kernel Change

Any change to `fluxguard_kern.c` requires a full recompile and re-attach:

```bash
cd /home/samarth/fluxguard

# Recompile
clang -O2 -g -Wall -target bpf -c fluxguard_kern.c -o fluxguard_kern.o

# Detach old program
sudo ip netns exec fluxguard ip link set dev veth-fg-in xdpgeneric off

# Attach new program
sudo ip netns exec fluxguard ip link set dev veth-fg-in xdpgeneric obj fluxguard_kern.o sec xdp

# Verify 3 maps now exist
sudo ip netns exec fluxguard bpftool map show | grep -E "blacklist_map|meter_map|allowlist_map"
```

### Adding an IP to the Allowlist

```bash
# Add 10.0.2.1 (the fluxguard→backend gateway) to allowlist
# Key: 10.0.2.1 = 0a 00 02 01
sudo ip netns exec fluxguard bpftool map update \
    name allowlist_map \
    key hex 0a 00 02 01 \
    value hex 01 00 00 00

# Verify
sudo ip netns exec fluxguard bpftool --json map dump name allowlist_map
```

### Structured JSON Logging (Phase 5)

Phase 5 upgrades the logging from `print()` statements to **structured JSON lines** — one JSON object per line, each with an ISO 8601 timestamp:

```python
def append_json_log(path: str, event: str, fields: Dict[str, Any]) -> None:
    ts = datetime.datetime.now(datetime.timezone.utc) \
             .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    record = {"timestamp": ts, "event": event}
    record.update(fields)
    line = json.dumps(record, separators=(",", ":")) + "\n"
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line)
```

Example log entries:
```json
{"timestamp":"2026-05-20T15:00:01.234Z","event":"BLOCK","ip":"10.0.1.1","pps":45230.7,"counter":9046,"blocked_count":1,"dt":0.2001}
{"timestamp":"2026-05-20T15:00:01.440Z","event":"TICK","observed_ips":3,"blocked_count":1,"dt":0.2002}
{"timestamp":"2026-05-20T15:00:31.234Z","event":"UNBLOCK","ip":"10.0.1.1","blocked_count":0,"dt":0.2001}
```

The `separators=(",", ":")` removes whitespace — keeps each line compact for log files that may grow to millions of lines.

### Phase 5 Test Commands

```bash
# Reset maps before testing
sudo ip netns exec fluxguard bpftool map deleteall name meter_map
sudo ip netns exec fluxguard bpftool map deleteall name blacklist_map
sudo ip netns exec fluxguard bpftool map deleteall name allowlist_map
: > /home/samarth/fluxguard/fluxguard.log   # truncate log file

# Terminal 1: Start brain with JSON logging
sudo python3 /home/samarth/fluxguard/fluxguard_brain.py \
    --netns fluxguard \
    --pps-threshold 1000 \
    --poll-interval 0.2 \
    --cooldown-sec 30 \
    --verbose \
    --log-file /home/samarth/fluxguard/fluxguard.log

# Terminal 2: Watch Prometheus metrics update live
watch -n 2 curl -s http://127.0.0.1:9090/metrics

# Terminal 3: Stream JSON log
tail -f /home/samarth/fluxguard/fluxguard.log

# Terminal 4: Flood (brain should block within ~0.2s)
sudo ip netns exec client hping3 --flood -S -p 80 10.0.2.2
```

### What Phase 5 Does NOT Fix

- Brain still uses slow `bpftool` subprocesses (fixed in Phase 7)
- No kernel-side rate limiting (fixed in Phase 7)
- Brain can still accidentally block the gateway IP if it generates traffic (fixed by allowlist — but only if you add it manually)
- The log file is re-opened on every write (fixed in Phase 6)

---

## Phase 6 — Brain Hardening

### What is Phase 6?

Phase 6 is a **reliability and correctness hardening** of `fluxguard_brain.py`. No new features are added to the kernel. The focus is entirely on making the Python control plane production-safe. Four specific problems are fixed:

| Fix | Problem | Solution |
|-----|---------|----------|
| **A** | u32 counter wrap silently corrupts PPS math | Wrap-safe delta using bitmask |
| **B** | Log file re-opened on every entry = performance drain | Single open file descriptor |
| **C** | No graceful shutdown on SIGTERM (e.g. `systemctl stop`) | Signal handlers + clean exit |
| **D** | Metrics server binding `0.0.0.0` exposed to network | Default bind to `127.0.0.1` |

### Fix A — U32 Counter Wrap-Safe Delta

The kernel's `meter_map` value is a `__u32` — it wraps at `2³² = 4,294,967,296`. If an IP sends a huge flood and the counter overflows, the Phase 4 delta calculation gives a **massive negative number**, which looks like an impossibly high PPS:

```python
# WRONG (Phase 4 — breaks on wrap)
delta = curr - prev
# If curr=5 (after wrap) and prev=4294967290:
# delta = 5 - 4294967290 = -4294967285 ← wrong!
```

Phase 6 fix:
```python
# CORRECT — u32 arithmetic always stays in [0, 2^32)
delta = (curr - prev) & 0xFFFFFFFF
# (5 - 4294967290) & 0xFFFFFFFF = (-4294967285) & 0xFFFFFFFF = 11
# 11 packets in this poll window — correct!
```

**Why this works:** `& 0xFFFFFFFF` masks to 32 bits. In Python, integers are arbitrary precision, so without the mask a wrap produces a large negative number. With the mask, the subtraction wraps correctly to match the kernel's u32 arithmetic.

### Fix B — Single Open Log File Descriptor

Phase 4/5 opened the log file on every write:
```python
# SLOW — two OS syscalls (open + close) per log line
def append_json_log(path: str, ...):
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line)
```

Under a flood, the brain logs a `TICK` entry every 0.2 seconds and a `BLOCK` entry for each new attacker. At 100 blocks/second, that's 100+ file opens and closes per second — expensive.

Phase 6 fix — open the file **once** in `main()` and pass the file descriptor throughout:
```python
def main() -> int:
    # ...
    with open(args.log_file, "a", encoding="utf-8") as log_fd:
        monitor(args, metrics, log_fd)   # log_fd stays open for entire session

def write_json_log(fd: TextIO, event: str, fields: Dict) -> None:
    # fd is already open — no open/close overhead
    fd.write(json.dumps(record) + "\n")
    fd.flush()   # flush after each write so tail -f works in real time
```

### Fix C — Graceful SIGTERM / SIGINT Shutdown

In Phase 4, pressing `Ctrl+C` raises `KeyboardInterrupt` and the brain crashes mid-operation — potentially leaving orphan block entries in `blacklist_map` with no timer to unblock them.

Phase 6 introduces a `threading.Event` based shutdown:

```python
shutdown_event = threading.Event()

def handle_sigterm(signum: int, frame: Any) -> None:
    shutdown_event.set()   # signal the main loop to exit cleanly

# Register for both Ctrl+C and systemctl stop
signal.signal(signal.SIGTERM, handle_sigterm)
signal.signal(signal.SIGINT, handle_sigterm)
```

The main loop changes from `while True:` to:
```python
while not shutdown_event.is_set():
    # ... normal operation ...

    # Sleep in small chunks so shutdown is responsive
    sleep_left = args.poll_interval
    while sleep_left > 0 and not shutdown_event.is_set():
        time.sleep(min(0.1, sleep_left))
        sleep_left -= 0.1

# After loop exits — clean up
print("\nFluxGuard brain shutdown complete.")
```

**Why chunk the sleep?** If you `time.sleep(0.2)` and SIGTERM arrives after 0.01 seconds, the process doesn't respond for another 0.19 seconds. Sleeping in 0.1-second chunks means the brain responds to shutdown within ~0.1 seconds.

### Fix D — Metrics Bind to Loopback

Phase 4/5 bound the metrics server to `0.0.0.0:9090` — every network interface, including external-facing ones. Anyone on your network (or the internet, if the firewall allows it) could read your metrics.

Phase 6 changes the default to `127.0.0.1`:
```python
p.add_argument("--metrics-host", default="127.0.0.1")
```

This keeps metrics local. To expose them to an external Prometheus server, you use an SSH tunnel or a reverse proxy — not by opening the port to the world.

### Phase 6 Launch Command (Same as Phase 5, same flags)

```bash
sudo python3 /home/samarth/fluxguard/fluxguard_brain.py \
    --netns fluxguard \
    --pps-threshold 1000 \
    --poll-interval 0.2 \
    --cooldown-sec 30 \
    --verbose \
    --log-file /home/samarth/fluxguard/fluxguard.log \
    --metrics-host 127.0.0.1 \
    --metrics-port 9090
```

### Remaining Problems After Phase 6

| Problem | Status |
|---------|--------|
| bpftool subprocess overhead (~5ms per poll) | Still present — fixed in **Phase 7** |
| No kernel-side rate limiting | Still present — fixed in **Phase 7** |
| No allowlist CLI (must use bpftool manually) | Fixed in **Phase 9** |
| No live dashboard | Fixed in **Phase 9** |
| No IPv6 support | Fixed in **Phase 11** |
| State lost on brain restart | Fixed in **Phase 11** |

---

## Phase 5 vs Phase 6 — What Each Fixed

| Concern | Phase 5 | Phase 6 |
|---------|---------|---------|
| Allowlisted IPs | ✅ Kernel-side bypass | unchanged |
| Log format | ✅ JSON lines with ISO timestamps | ✅ Single open FD |
| Counter wrap | ❌ Broken (huge negative PPS) | ✅ `& 0xFFFFFFFF` mask |
| Graceful shutdown | ❌ `KeyboardInterrupt` crash | ✅ `SIGTERM`/`SIGINT` handlers |
| Metrics exposure | ❌ Bound to `0.0.0.0` | ✅ Bound to `127.0.0.1` |
| Performance | ❌ File re-opened per log entry | ✅ Single open file handle |

---

## OS Concepts Introduced in Phases 5–6

### 1. Kernel-Userspace Map Sharing
The `allowlist_map` is written by Python (via `bpftool`) and read by the C XDP program on every packet. This is the fundamental BPF communication model: **userspace writes policy, kernel enforces it at line rate**.

### 2. Integer Overflow and Bitmask Arithmetic
Kernel BPF values are fixed-width integers. Python uses arbitrary precision. Without the `& 0xFFFFFFFF` mask, subtraction of a wrapped u32 value produces a large negative Python integer — which looks like a massive PPS reading and would trigger a false block.

### 3. POSIX Signals (SIGTERM, SIGINT)
- `SIGTERM` — sent by `systemctl stop` or `kill <pid>`. The default action is immediate termination. Installing a handler lets you clean up first.
- `SIGINT` — sent by `Ctrl+C`. Python normally converts this to `KeyboardInterrupt`. Overriding it with `signal.signal(signal.SIGINT, handler)` gives you the same clean shutdown as SIGTERM.

### 4. File Descriptor Lifetime
An open file descriptor is a kernel resource (an entry in the process's file descriptor table). Keeping it open across many writes avoids repeated `open()` and `close()` syscalls. `fd.flush()` after each write ensures the data is sent to the OS buffer and visible to `tail -f` in real time.

### 5. Prometheus Text Format
Prometheus scrapes metrics in a specific text format:
```
# HELP metric_name Description of what this metric measures.
# TYPE metric_name gauge
metric_name{label="value"} 42
```
- `gauge` — current value (can go up or down), e.g. number of blocked IPs
- `counter` — monotonically increasing total, e.g. cumulative block events
- Labels (e.g. `{ip="10.0.1.1"}`) allow filtering and grouping in dashboards
