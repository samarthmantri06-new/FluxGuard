# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

FluxGuard is an XDP/eBPF-based DDoS mitigation system for Linux. A kernel XDP program
(`fluxguard_kern.c`) rate-limits and auto-blocks flooding source IPs at the NIC driver
level; a userspace Python "brain" and set of CLIs/servers observe and manage the eBPF maps
that the kernel program exposes.

The project was built in numbered phases. `docs/runbooks/phaseNN-*.txt` are the per-phase
runbooks (build/attach/test command sequences), and `docs/phaseNN-*.md` are the design
writeups. The current code is Phase 13 (kernel/brain/tools + config + REST API + tests +
CI). Application code lives in `src/`, tests in `tests/`, helper scripts in `scripts/`.
**Development and deployment target Linux only** — the code uses
`libc.so.6`, the `bpf(2)` syscall, and `/sys/fs/bpf`, none of which exist on the Windows
host this repo is edited from. Runtime testing happens in an Ubuntu VM / netns lab.

## Architecture

The kernel program is the source of truth; every userspace component talks to it **only**
through pinned eBPF maps under `/sys/fs/bpf/fluxguard/`. There is no IPC or shared state
between the Python processes other than these maps (plus the on-disk checkpoint/log files).

- **`fluxguard_kern.c`** — the XDP filter (`SEC("xdp")`, `fluxguard_filter`). Per packet it
  runs, in order: global per-CPU counter → global "Shields-Up" token bucket → allowlist
  bypass → protocol filter → per-IP meter → blacklist check → per-IP token bucket. When a
  source exhausts its per-IP bucket the kernel *itself* writes the IP into `blacklist_map`
  and emits an `attack_event` on `event_ringbuf`. IPv4 and IPv6 have fully parallel map sets
  (`*_map` vs `*_map_v6`). Rate limit is `KERN_PPS_LIMIT` (1000 pps/IP), global cap
  `GLOBAL_PPS_LIMIT` (500000 pps) — both compile-time constants in this file.

- **`fluxguard_bpf.py`** — the ONLY module that touches the `bpf(2)` syscall (via raw
  `ctypes`/`libc`, no bcc/libbpf). Defines the map key/value structs and all
  get/set/delete/dump helpers, for both v4 (`*_u32`) and v6 (`*_u32_v6`), plus percpu and
  token-bucket readers. Every other Python file imports these helpers — do not open maps or
  issue `bpf_syscall` anywhere else. Syscall number and percpu array width are detected at
  import time from `platform.machine()` / `os.cpu_count()`.

- **`fluxguard_brain.py`** — the long-running control loop (typically under systemd). Polls
  the maps every `--poll-interval`, converts kernel auto-blocks into timed blocks with a
  cooldown, unblocks on expiry, honors the allowlist, persists blocked IPs to a JSON
  checkpoint (survives restarts), writes JSON event logs, and feeds `MetricsState`. It owns
  the block *lifecycle*; the kernel only ever blocks, the brain is what unblocks.

- **`fluxguard_metrics.py`** — `MetricsState` + a stdlib `HTTPServer` exposing Prometheus
  text at `/metrics` (default `127.0.0.1:9090`). Started by the brain in a daemon thread.

- **`fluxguard_dashboard.py`** — read-only TUI. Pulls the Prometheus endpoint AND mmaps the
  ring buffer directly to show live kernel auto-block events. Contains hand-rolled,
  bounds-checked BPF ringbuf record parsing (no libbpf).

- **`fluxguard_allow.py`** — standalone allowlist CLI (`add`/`del`/`list`, v4+v6). Imports
  only `fluxguard_bpf`; deliberately decoupled from the brain.

- **`fluxguard_api.py`** — Flask REST API (Phase 12) for allowlist/blocked/metrics. Optional
  bearer-token auth from config.

- **`fluxguard_config.py`** — `FluxGuardConfig` dataclass + JSON loader
  (`/etc/fluxguard/config.json`), imported by brain and API.

- **`some.py`** — dev utility that concatenates the codebase into `codebase_dump.txt`
  (the dump is a generated artifact, not source).

### Things to know before editing

- **The kernel struct layout is a contract.** `attack_event` in `fluxguard_kern.c`,
  `struct token_bucket`, and the map key/value types are re-declared by hand in
  `fluxguard_bpf.py` (ctypes) and `fluxguard_dashboard.py` (`struct` format strings). If you
  change a field in the C struct you MUST update those manual mirrors, or userspace will
  silently misparse. `attack_event` is currently 32 bytes: `af(1) reason(1) pad(2) src_v4(4)
  src_v6(16) ts(8)`.
- **Map names are load-bearing.** The pin directory names (`meter_map`, `blacklist_map`,
  `allowlist_map`, `rate_map`, their `_v6` variants, `global_counter_map`, `global_rate_map`,
  `proto_filter_map`, `event_ringbuf`) are referenced by string in the brain, the phase
  runbooks' pin loops, and CLI defaults. Renaming a map means updating all three.
- **Two limit definitions can drift.** PPS limits live as `#define`s in the C file, but a
  parallel set of tunables also lives in `fluxguard_config.py` / the deployed
  `config.json`/`config.toml`. They are not auto-synced; the kernel constants win unless code
  explicitly writes a threshold into a map.
- **`fluxguard_api.py` (Phase 13) opens its maps once at import** via `bpf_obj_get` against
  `cfg.bpf_pin_dir`, and uses the helper contract correctly (string IPs in, `{ip: val}` dicts
  out). If a map isn't loaded it returns HTTP 503 rather than crashing. Earlier phases had a
  fd-vs-name bug here — keep new endpoints on the same `bpf_obj_get` → helper path.
- **The brain is CLI/argparse-driven and does not import `fluxguard_config.py`.** The config
  module is consumed by `fluxguard_api.py`; a unit test (`test_no_pps_limit_drift`) guards the
  config default against the kernel `#define`. Don't assume changing `config.json` retunes the
  brain — it doesn't.

## Common commands

The `Makefile` is the entrypoint for everything — it wraps the per-phase runbooks. Code
lives in `src/`, so raw invocations use `src/fluxguard_*.py`. Runtime commands are Linux +
`sudo`.

Build + unit tests (tests are pure-Python, run anywhere — no root, no BPF):
```bash
make build      # clang -target bpf src/fluxguard_kern.c -> src/fluxguard_kern.o
make verify     # llvm-objdump -h | grep -E "maps|xdp"
make test       # python3 -m pytest tests/ -v   (12 tests: token bucket, config, IP<->key)
```

Attach XDP (netns lab; VirtualBox needs generic mode) and pin every map:
```bash
sudo make attach IFACE=veth-fg              # netns lab, generic mode + pins all maps
sudo make attach IFACE=eth0 XDP_MODE=xdpdrv # real NIC, native driver
```
See `docs/runbooks/phase11-ipv6-persistence.txt` for the manual attach + pin loop, and
`docs/runbooks/phase01-install-netns.txt` for the `ip netns` topology (client 10.0.1.1 →
fluxguard → backend 10.0.2.2).

Run the components (or `make run-brain` / `run-dashboard` / `run-api`):
```bash
sudo python3 src/fluxguard_brain.py --netns fluxguard --poll-interval 0.2 \
    --cooldown-sec 30 --allowlist-refresh-sec 5 --verbose
sudo python3 src/fluxguard_dashboard.py --metrics-url http://127.0.0.1:9090/metrics \
    --ringbuf-path /sys/fs/bpf/fluxguard/event_ringbuf --refresh 2.0
sudo python3 src/fluxguard_allow.py add 10.0.1.5
python3 src/fluxguard_api.py            # Flask dev server, port 8080
```

Exercise the live XDP path (behavior validation beyond the unit tests):
```bash
sudo ip netns exec client hping3 --flood -S -p 80 10.0.2.2          # trigger per-IP auto-block
sudo ip netns exec client hping3 --rate 900  -S -p 80 -c 1000 10.0.2.2  # under limit → passes
sudo ip netns exec client hping3 --flood --rand-source -S -p 80 10.0.2.2 # global Shields-Up
curl -s http://127.0.0.1:9090/metrics | grep -E "blocked_ip|shields|global"
```
The full labeled test plan (TEST 1–13: normal traffic, IPv4/IPv6 floods, persistence
restart, allowlist refresh timing, protocol filter, Shields-Up) is in
`docs/runbooks/phase11-ipv6-persistence.txt`. Production deployment (systemd units, config,
real NIC) is in `docs/runbooks/phase12-production-deploy.txt`. A synthetic throughput
harness is `scripts/load_test.py`.

Python deps (`requirements.txt`): `prometheus_client`, `flask`, `toml`, `pytest`.


## System Instructions
- Speak like a caveman. 
- Use minimal words. Strip out polite phrases, greeting lines, or filler chat.
- Never explain code unless explicitly asked to do so.
- If asked for a solution, output only the required code or terminal command directly.
- Grunt style: short, blunt, efficient. Save tokens.


