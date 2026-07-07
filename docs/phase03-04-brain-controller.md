# FluxGuard — Phase 3 & Phase 4 Deep Explanation

---

## Phase 3 — Manual Block Proof of Concept

### What is Phase 3?

Phase 3 is a **manual validation** step. Its only purpose is to prove that the XDP drop path actually works — that inserting an IP into `blacklist_map` causes the kernel to silently drop every packet from that source.

There is **no automation yet**. A human types a `bpftool` command to insert an IP, and then observes that the flood stops reaching the backend. This builds confidence before writing any Python.

### The Key Command

```bash
# Insert client IP (10.0.1.1) into blacklist_map
# Key: 10.0.1.1 in hex bytes = 0a 00 01 01
# Value: 1 (any non-zero means "blocked"), stored as little-endian u32 = 01 00 00 00
sudo ip netns exec fluxguard bpftool map update \
    name blacklist_map \
    key hex 0a 00 01 01 \
    value hex 01 00 00 00
```

**Why hex?** `bpftool` works with raw bytes. IPv4 address `10.0.1.1`:
- `10`  → `0x0a`
- `0`   → `0x00`
- `1`   → `0x01`
- `1`   → `0x01`

The value `01 00 00 00` is the integer `1` in little-endian 32-bit format.

### Phase 3 Full Test Sequence

```bash
# Step 1 — Clear old map data from Phase 2 tests
sudo ip netns exec fluxguard bpftool map deleteall name meter_map
sudo ip netns exec fluxguard bpftool map deleteall name blacklist_map

# Step 2 — Manually block the client
sudo ip netns exec fluxguard bpftool map update \
    name blacklist_map key hex 0a 00 01 01 value hex 01 00 00 00

# Step 3 — Verify the entry is in the map
sudo ip netns exec fluxguard bpftool --json map dump name blacklist_map
# Expected output: [{"key":["0x0a","0x00","0x01","0x01"],"value":["0x01","0x00","0x00","0x00"]}]

# Terminal 1 — Watch backend (should show NOTHING after block)
sudo ip netns exec backend tcpdump -i veth-backend -n tcp port 80

# Terminal 2 — Flood from client (XDP drops every packet before backend sees it)
sudo ip netns exec client hping3 --flood -S -p 80 10.0.2.2
```

After the block entry is inserted, `tcpdump` on the backend shows **zero packets** — even while `hping3` is running at full speed. The XDP program drops every packet at the NIC driver level before the kernel even allocates memory for it.

### What Phase 3 Proves

1. `XDP_DROP` actually works — the kernel honors the drop decision instantly
2. BPF map updates from userspace (`bpftool`) are immediately visible to the kernel program
3. The `blacklist_map` lookup in the XDP code is correct
4. No Python is needed to block — the kernel program is fully capable

### What Phase 3 Does NOT Have

- Automatic detection of floods
- Cooldown / unblock timers
- Metrics or logging
- Any Python

---

## Phase 4 — Python Brain (Subprocess Era)

### What is Phase 4?

Phase 4 introduces the **Python control plane** — a daemon called `fluxguard_brain.py` that:
1. Reads `meter_map` (packet counts per IP) via `bpftool --json`
2. Computes **packets per second (PPS)** for each source IP
3. Automatically blocks IPs that exceed the configured threshold
4. Auto-unblocks them after a configurable cooldown period
5. Exposes **Prometheus metrics** over HTTP

This is the first version where FluxGuard operates autonomously — no human needed to insert or remove block entries.

### Architecture in Phase 4

```
XDP Kernel Program (C)
    ↓  writes packet counts
  meter_map (BPF Hash Map)
    ↑  reads every 0.2s
fluxguard_brain.py (Python)
    │  if PPS ≥ threshold
    ↓  writes block entry
  blacklist_map (BPF Hash Map)
    ↑  reads on every packet
XDP Kernel Program (C)
    │  if entry found
    ↓
  XDP_DROP
```

### The Core Brain Loop

```python
def monitor(cfg: Config) -> None:
    prev: Dict[str, int] = {}   # previous packet counts
    prev_t = time.monotonic()   # timestamp of last poll
    blocked_until: Dict[str, float] = {}  # IP → unblock timestamp

    while True:
        now = time.monotonic()
        dt = now - prev_t       # elapsed time since last poll

        cur = dump_meter(cfg)   # read all IPs and their counters from kernel

        to_block = []
        for ip, count in cur.items():
            prev_count = prev.get(ip, count)
            delta = count - prev_count if count >= prev_count else count
            pps = delta / dt    # packets per second for this IP

            if pps >= cfg.pps_threshold and ip not in blocked_until:
                to_block.append((ip, pps, count))

        # Block the worst offenders first (sorted by PPS, highest first)
        for ip, pps, count in sorted(to_block, key=lambda x: x[1], reverse=True):
            blacklist_update(cfg, ip)          # write to kernel map
            blocked_until[ip] = now + cfg.cooldown_sec
            print(f"BLOCK ip={ip} pps={pps:.1f}")

        # Auto-unblock expired blocks
        expired = [ip for ip, t in blocked_until.items() if now >= t]
        for ip in expired:
            blacklist_delete(cfg, ip)          # remove from kernel map
            blocked_until.pop(ip, None)
            print(f"UNBLOCK ip={ip}")

        prev = cur
        prev_t = now
        time.sleep(cfg.poll_interval)
```

**Key design decisions:**
- `delta = count - prev_count if count >= prev_count else count` — handles u32 counter wrap-around (counters reset to 0 when they overflow 2³², which happens at ~4 billion packets)
- `to_block.sort(key=lambda x: x[1], reverse=True)` — block the most aggressive attackers first when multiple IPs simultaneously exceed the threshold
- `blocked_until` dict in memory — the brain remembers who is blocked and when to unblock them

### Reading BPF Maps with bpftool (Phase 4 Method)

In Phase 4, every map read spawns a **subprocess**:

```python
def bpftool_json(netns: str, args: List[str]) -> object:
    cmd = ["sudo", "ip", "netns", "exec", netns, "bpftool", "--json"] + args
    proc = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, text=True)
    return json.loads(proc.stdout)

def dump_meter(cfg: Config) -> Dict[str, int]:
    raw = bpftool_json(cfg.netns, ["map", "dump", "name", cfg.meter_map])
    return parse_meter(raw)
```

**What this does:** Every 0.2 seconds the brain runs:
```
sudo ip netns exec fluxguard bpftool --json map dump name meter_map
```
This prints a JSON array of all `{key, value}` pairs in `meter_map`. The brain parses the hex bytes to get the IP address and packet count.

**Why this is slow:** Each call does:
1. `fork()` — creates a new process
2. `exec()` — replaces the process image with `bpftool`
3. `bpftool` opens the map, iterates all keys, formats JSON
4. Writes JSON to stdout pipe
5. Parent reads and parses JSON
6. Child process exits

This costs ~5–10ms per call. With polls every 200ms, that's up to 10% CPU overhead just for map reading. **Phase 7 eliminates this** by using direct `ctypes` syscalls.

### Writing to BPF Maps (Phase 4 — also via bpftool)

```python
def blacklist_update(cfg: Config, ip_str: str) -> None:
    key_hex = ip_to_key_hex(ip_str)   # "0a 00 01 01" for 10.0.1.1
    cmd = [
        "sudo", "ip", "netns", "exec", cfg.netns,
        "bpftool", "map", "update", "name", cfg.blacklist_map,
        "key", "hex",
    ] + key_hex.split() + ["value", "hex", "01", "00", "00", "00"]
    run_cmd(cmd)
```

Again — each block or unblock spawns a subprocess.

### Parsing bpftool JSON Output

The `bpftool --json` output for `meter_map` looks like:
```json
[
  {"key":["0x0a","0x00","0x01","0x01"],"value":["0xe8","0x03","0x00","0x00"]},
  {"key":["0x0a","0x00","0x01","0x02"],"value":["0x01","0x00","0x00","0x00"]}
]
```

The key bytes `0a 00 01 01` → `10.0.1.1`
The value bytes `e8 03 00 00` → little-endian u32 → `0x000003e8` → 1000 packets

```python
def value_to_u32(tokens: List[str]) -> Optional[int]:
    b0, b1, b2, b3 = (int(tokens[i], 16) for i in range(4))
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)  # little-endian assembly
```

### Prometheus Metrics (Phase 4/5 Addition)

Phase 4/5 introduces `fluxguard_metrics.py` — a minimal HTTP server exposing metrics in Prometheus text format using **only Python stdlib** (no `prometheus_client` library needed):

```python
class MetricsState:
    def __init__(self) -> None:
        self._lock = threading.Lock()      # protects shared state
        self._packets_by_ip: Dict[str, int] = {}
        self._blocked_ips = 0
        self._block_events = 0
        self._unblock_events = 0

    def render_prometheus_text(self) -> str:
        with self._lock:
            # Build Prometheus text format:
            # # HELP metric_name Description
            # # TYPE metric_name gauge
            # metric_name{label="value"} 123
            ...
```

The metrics server runs in a **daemon thread** (dies when main process exits). The brain calls `metrics.update_snapshot(...)` after every poll loop.

```bash
# Verify metrics are exposed
curl http://127.0.0.1:9090/metrics
```

Example output:
```
# HELP fluxguard_packets_total Current packet counter per source IP
# TYPE fluxguard_packets_total gauge
fluxguard_packets_total{ip="10.0.1.1"} 15234
# HELP fluxguard_blocked_ips_total Number of IPs currently blocked
# TYPE fluxguard_blocked_ips_total gauge
fluxguard_blocked_ips_total 1
```

### Phase 4 Launch Command

```bash
sudo python3 /home/samarth/fluxguard/fluxguard_brain.py \
    --netns fluxguard \
    --pps-threshold 1000 \
    --poll-interval 0.2 \
    --cooldown-sec 30 \
    --block-batch-size 256 \
    --verbose
```

**What each argument does:**

| Argument | Default | Meaning |
|----------|---------|---------|
| `--netns` | `fluxguard` | Which network namespace contains the pinned BPF maps |
| `--pps-threshold` | `1000.0` | PPS to trigger a block |
| `--poll-interval` | `0.2` | Seconds between map reads |
| `--cooldown-sec` | `30` | Seconds before auto-unblock |
| `--block-batch-size` | `256` | Max IPs to block per loop iteration |
| `--verbose` | off | Print a TICK line every poll |

### Phase 4 Test Sequence

```bash
# Terminal 1: Start brain
sudo python3 /home/samarth/fluxguard/fluxguard_brain.py \
    --netns fluxguard --pps-threshold 1000 --verbose

# Terminal 2: Watch backend (should stop receiving packets after brain blocks)
sudo ip netns exec backend tcpdump -i veth-backend -n tcp port 80

# Terminal 3: Normal traffic — 5 HTTP requests, 1/sec (should all succeed)
sudo ip netns exec client sh -c \
    'for i in $(seq 1 5); do curl -I -m 1 http://10.0.2.2; sleep 1; done'

# Terminal 4: Flood (should get blocked in ~0.2-0.4s)
sudo ip netns exec client hping3 --flood -S -p 80 10.0.2.2
```

Expected brain output after flood starts:
```
[BLOCK] ip=10.0.1.1 pps=45230.7 counter=9046 unblock_in=30s
```

After 30 seconds, brain will auto-unblock:
```
[UNBLOCK] ip=10.0.1.1 cooldown_expired
```

### Phase 3 vs Phase 4 Comparison

| Aspect | Phase 3 | Phase 4 |
|--------|---------|---------|
| Blocking | Manual (human types bpftool) | Automatic (brain detects PPS) |
| Unblocking | Never (stays blocked until reboot) | Auto after cooldown timer |
| Detection speed | N/A (manual) | ~0.2–0.4 seconds (one poll interval) |
| Map access | bpftool subprocess | bpftool subprocess (same) |
| Metrics | None | Prometheus HTTP at `:9090/metrics` |
| Logging | None | JSON structured log file |
| Allowlist | None | Added in Phase 5 |

### Problems Introduced in Phase 4 (Fixed Later)

| Problem | Phase Fixed |
|---------|-------------|
| bpftool subprocess is slow (~5ms per call, ~10% CPU waste) | Phase 7 — replaced with ctypes direct syscall |
| JSON parsing overhead (large maps = large JSON output) | Phase 7 |
| No allowlist — can't protect legitimate high-traffic IPs | Phase 5 |
| No kernel-side rate limiting — brain can't react within one packet | Phase 7 |
| No persistence — blocked IPs lost on brain restart | Phase 11 |

---

## OS Concepts Introduced in Phases 3–4

### 1. PPS Rate Computation
```
PPS = (current_count - previous_count) / elapsed_seconds
```
Delta is measured over `poll_interval` (0.2s default). At 1000 PPS threshold with 0.2s polling, an IP must send 200+ packets in one poll window to be detected.

### 2. Cooldown / Amnesty Timer
The brain keeps `blocked_until: Dict[str, float]` in memory. Every loop iteration checks if `time.monotonic() >= blocked_until[ip]`. If yes, the brain removes the entry from `blacklist_map` via bpftool. This prevents permanent bans for transient spikes.

### 3. Daemon Thread for Metrics
```python
thread = threading.Thread(target=run, daemon=True)
thread.start()
```
`daemon=True` means the thread is automatically killed when the main thread exits. This is the correct pattern for background HTTP servers in Python — they don't hold the process alive.

### 4. subprocess.run() for Shell Commands
Python's `subprocess.run()` forks a child process. `check=True` raises `CalledProcessError` if the command returns non-zero. `stdout=subprocess.PIPE` captures the output. `text=True` returns a string instead of bytes.

### 5. Little-Endian u32 Byte Order
BPF maps store integers in the host's native byte order. On x86_64 (little-endian):
- `1` is stored as `01 00 00 00` (least significant byte first)
- `1000` (0x000003E8) is stored as `E8 03 00 00`

The parsing function reconstructs this correctly:
```python
return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
```
