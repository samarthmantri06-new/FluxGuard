# FluxGuard

[![CI](https://github.com/samarthmantri06-new/FluxGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/samarthmantri06-new/FluxGuard/actions/workflows/ci.yml)

**XDP/eBPF in-kernel DDoS mitigation for Linux.**

FluxGuard rate-limits and auto-blocks flooding source IPs at the NIC driver level — before
packets ever reach the network stack — using an XDP/eBPF program. A userspace Python "brain"
manages the block lifecycle, exposes Prometheus metrics, and persists state, talking to the
kernel **only** through pinned eBPF maps.

> **Scope note:** FluxGuard is a systems-programming project, validated in a Linux network-namespace
> lab and an Ubuntu VM (see the runbooks in `docs/runbooks/`). The configured ceiling
> (`GLOBAL_PPS_LIMIT = 500000`) is a *policy limit*, not a hardware benchmark. A repeatable
> benchmark harness lives at `scripts/load_test.py`; see [Performance](#performance) for how to
> run it and record real numbers.

---

## Why it's interesting

- **Runs in the kernel, at the driver.** Filtering happens in XDP — the earliest hook in the
  Linux receive path — so dropped packets cost almost nothing.
- **No bcc, no libbpf.** `fluxguard_bpf.py` issues the raw `bpf(2)` syscall directly via
  `ctypes`/`libc`, hand-rolling the `bpf_attr` union and every map operation.
- **The kernel is the source of truth.** The XDP program itself blocks abusive IPs and emits
  events; userspace only manages timers and unblocking. No shared state except the maps.
- **Real systems techniques:** per-CPU lock-free counters, `LRU_HASH` maps to survive
  random-source spoof floods, token-bucket rate limiting, and a BPF ring buffer for events.
- **Full IPv4 + IPv6 dual stack**, Prometheus metrics, JSON persistence, systemd units,
  a read-only TUI, an allowlist CLI, and a REST API.

---

## Architecture

```
                 ┌─────────────────────── Linux kernel ───────────────────────┐
   packets  ───► │  XDP hook: fluxguard_filter (fluxguard_kern.c)              │
                 │   per-CPU counter → global token bucket (Shields-Up)        │
                 │   → allowlist → proto filter → per-IP meter                 │
                 │   → blacklist → per-IP token bucket                         │
                 │   on bucket exhaustion: kernel writes blacklist_map +       │
                 │                          emits attack_event on ring buffer  │
                 └───────────────┬───────────────────────────┬────────────────┘
                   pinned eBPF maps (/sys/fs/bpf/fluxguard)  ring buffer
                                 │                            │
        ┌────────────────────────┼────────────────┬──────────┴───────────┐
        ▼                        ▼                ▼                      ▼
   fluxguard_brain.py      fluxguard_allow.py  fluxguard_api.py   fluxguard_dashboard.py
   (block lifecycle,       (allowlist CLI)     (Flask REST)       (TUI: metrics + live
    unblock, persist,                                              ring-buffer events)
    Prometheus /metrics)
```

Every userspace component imports `fluxguard_bpf.py` — the **only** module that touches the
`bpf(2)` syscall.

## Components

| File | Role |
|------|------|
| `fluxguard_kern.c`       | XDP/eBPF filter. Per-IP + global token buckets, auto-blacklist, ring-buffer events. Source of truth. |
| `fluxguard_bpf.py`       | Raw `bpf(2)` syscall layer (ctypes). Map key/value structs + get/set/delete/dump, v4 & v6. |
| `fluxguard_brain.py`     | Long-running control loop. Turns kernel auto-blocks into timed blocks; unblocks on expiry; persists to JSON. |
| `fluxguard_metrics.py`   | `MetricsState` + Prometheus text exporter (`/metrics`). |
| `fluxguard_dashboard.py` | Read-only TUI; mmaps the ring buffer to show live kernel auto-block events. |
| `fluxguard_allow.py`     | Standalone allowlist CLI (`add`/`del`/`list`, v4+v6). |
| `fluxguard_api.py`       | Flask REST API for allowlist / blocked-list / metrics. |
| `fluxguard_config.py`    | `FluxGuardConfig` dataclass + JSON loader. |

## Kernel filter pipeline (per packet)

1. Global per-CPU packet counter
2. Global "Shields-Up" token bucket (aggregate PPS cap)
3. Allowlist bypass
4. Protocol filter (e.g. drop all UDP)
5. Per-IP meter (packet counter)
6. Blacklist check → `XDP_DROP`
7. Per-IP token bucket → on exhaustion, kernel auto-blacklists the IP and emits an event

`KERN_PPS_LIMIT` = 1000 pps/IP, `GLOBAL_PPS_LIMIT` = 500000 pps — compile-time constants in
`fluxguard_kern.c` (the authoritative values; `fluxguard_config.py` mirrors them for display).

---

## Project structure

```
src/                     application code (kernel + control plane)
  fluxguard_kern.c         XDP/eBPF filter (source of truth)
  fluxguard_bpf.py         raw bpf(2) syscall layer (ctypes)
  fluxguard_brain.py       control loop / block lifecycle
  fluxguard_metrics.py     Prometheus exporter
  fluxguard_dashboard.py   read-only TUI
  fluxguard_allow.py       allowlist CLI
  fluxguard_api.py         Flask REST API
  fluxguard_config.py      config dataclass + JSON loader
tests/                   pure-Python unit tests (no root, no BPF)
scripts/                 helper scripts (load test, codebase dump)
docs/                    design writeups (phaseNN-*.md) + runbooks/ (command logs)
.github/workflows/       CI
Makefile                 build / attach / run / test entrypoints
```

Everything is driven through the `Makefile` — you rarely invoke files in `src/` by hand.

## Build & run (Linux, root)

```bash
make build                      # compile fluxguard_kern.o with clang
make verify                     # sanity-check maps/xdp sections

# netns lab:
sudo make attach IFACE=veth-fg  # load XDP + pin all maps under /sys/fs/bpf/fluxguard
sudo make run-brain             # start the control loop

# real NIC (native driver mode):
sudo make attach IFACE=eth0 XDP_MODE=xdpdrv
```

Exercise it:

```bash
# per-IP flood → triggers in-kernel auto-block
sudo ip netns exec client hping3 --flood -S -p 80 10.0.2.2
# random-source flood → triggers global Shields-Up
sudo ip netns exec client hping3 --flood --rand-source -S -p 80 10.0.2.2

curl -s http://127.0.0.1:9090/metrics | grep -E "blocked_ip|shields|global"
```

The full labeled test plan (TEST 1–13) lives in the phase runbooks (see below).

## Tests

Pure-Python unit tests that run on **any** OS (no root, no BPF):

```bash
make test        # or: python3 -m pytest tests/ -v
```

They cover the token-bucket refill math (mirror of the C helper), IP↔key round-tripping,
and config loading.

---

## Performance

`scripts/load_test.py` drives `hping3` at increasing packet rates against the protected
interface and records, per step: **pps sent** (client TX delta), **pps passed** (backend RX
delta), **pps dropped**, and the XDP program's real cost — **ns/packet** and **CPU%** — read
from `bpftool prog show` with `kernel.bpf_stats_enabled=1`.

```bash
# lab must be up and FluxGuard attached first (see docs/runbooks/)
sudo python3 scripts/load_test.py \
    --target 10.0.2.2 --rates 1000,5000,20000,100000,500000 \
    --duration 5 --csv results.csv
```

It needs root, a real kernel, and a loaded XDP program, so it **cannot run in CI** — run it
in the Ubuntu VM / netns lab.

Measured results (fill in after running on your hardware — replace this placeholder):

| Target PPS | Sent | Passed | Dropped | Drop % | XDP ns/pkt | XDP CPU % | Env |
|-----------:|-----:|-------:|--------:|-------:|-----------:|----------:|-----|
| _TBD_ | _TBD_ | _TBD_ | _TBD_ | _TBD_ | _TBD_ | _TBD_ | _CPU model, kernel, xdpgeneric/xdpdrv_ |

> **TODO:** record a short demo GIF (asciinema/terminal capture) of a live flood being
> auto-blocked, and embed it here. (Recording is a manual step — not scriptable from CI.)

---

## Project history

Built from scratch in numbered phases. Each phase has a runbook
(`docs/runbooks/phaseNN-*.txt`) and a design writeup (`docs/phaseNN-*.md`):

| Phase | Milestone |
|-------|-----------|
| 1–2   | netns topology + initial XDP program |
| 3–4   | manual block test + brain controller |
| 5–6   | Prometheus metrics + hardening (SIGTERM, allowlist-aware) |
| 7–8   | rate limiting refinements |
| 9–10  | in-kernel auto-blacklist + ring-buffer event stream |
| 11    | shared BPF module + IPv6 dual stack + persistence |
| 12    | config management + REST API + systemd deployment |
| 13    | release hardening: API fixes, packaging, tests, docs |

## Requirements

- Linux with a kernel supporting XDP + BPF ring buffer (5.8+)
- `clang`/LLVM, `bpftool`, `iproute2`
- Python 3.8+ (`pip install -r requirements.txt`)

## License

GPL-2.0 — see [LICENSE](LICENSE). The kernel eBPF program must be GPL-licensed to use GPL-only
BPF helpers, so the whole project follows suit.
