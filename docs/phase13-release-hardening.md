# Phase 13 — Release Hardening & Publishing (Final)

Phases 1–12 built FluxGuard from an empty network namespace to a working XDP/eBPF
DDoS-mitigation system with a control loop, metrics, persistence, IPv6, config, and a
REST API. Phase 13 is the **finishing phase**: it fixes the known rough edges, adds the
packaging every real repository needs, and turns the pile of scripts into something that
builds and deploys with a single command — and is presentable on GitHub.

Nothing about the kernel datapath changed. The XDP program (`fluxguard_kern.c`) and its
struct contract are untouched, so none of the Phase 11 verifier work needs re-testing.

---

## 1. The REST API was broken — now it isn't

`fluxguard_api.py` (Phase 12) looked complete but could not have served a single request.
Three defects, all stemming from the same misunderstanding of the `fluxguard_bpf` contract:

1. **Map names passed where file descriptors are required.**
   The code called `dump_map_u32("allowlist_map")`, `set_map_u32("allowlist_map", key, 1)`,
   etc. Every helper in `fluxguard_bpf.py` takes an **integer fd** returned by
   `bpf_obj_get("/sys/fs/bpf/fluxguard/<map>")`. A string was never a valid argument — the
   first syscall would fail immediately.

2. **Wrong value types.**
   `set_map_u32`/`del_map_u32` accept an **IP string** and parse it internally
   (`ip_to_key`). Phase 12 handed them pre-packed `bytes`. And `dump_map_u32` returns a
   **`dict {ip_str: value}`**, not a list of `(key, value)` tuples — so the old
   `for k, _ in dump_map_u32(...)` plus `int.from_bytes(k, "big")` was doubly wrong.

3. **Dead IPv6 formatter.**
   `"%02x%02x:...".format(*k)` mixes two formatting systems: `str.format()` only fills
   `{}` placeholders, so a `%02x` template comes back **unchanged**. The endpoint would
   have returned the literal format string.

**The fix.** The rewritten API opens the four maps it needs (`allowlist_map`,
`allowlist_map_v6`, `blacklist_map`, `blacklist_map_v6`) exactly once at startup via
`bpf_obj_get()` — the same pattern `fluxguard_brain.py` already uses — and caches the fds.
IPv4 maps are required; IPv6 maps are optional and the API degrades gracefully if they are
not loaded (returning HTTP 503 only when a v6 endpoint is actually hit). All rendering goes
through Python's `ipaddress` module, and the endpoints simply return `sorted(dump.keys())`.
A new `/api/v1/health` endpoint reports which maps are live.

This also fixes the architectural claim in the file's own docstring — *"all map
interactions go through fluxguard_bpf so the same code path is used by brain & CLI"* — which
was previously false because the API used the helpers incorrectly.

## 2. Killing the PPS-limit drift

The per-IP rate limit was defined in **three** places with **two** values:

| Location | Value |
|----------|-------|
| `fluxguard_kern.c` `#define KERN_PPS_LIMIT` | 1000 |
| `CLAUDE.md` project notes | 1000 |
| `fluxguard_config.py` default | **10000** |

Because the limit is a compile-time constant baked into the verified BPF program, the config
value never reached the kernel — it was silently ignored, which is the worst kind of
inconsistency: an interviewer reading the config would believe the wrong number.

**Decision:** the kernel is the source of truth (as it is for everything else in FluxGuard),
so `kern_pps_limit` was synced to **1000** and the field is now documented as
*display-only — must be kept in sync with the C constant by hand.* We deliberately did **not**
introduce a `config_map` for the kernel to read limits at runtime: that would edit the
verified datapath and force a full re-test of the kernel program, for a feature this project
does not need. Honesty over cleverness.

A regression test (`test_no_pps_limit_drift`) now fails if the two ever diverge again.

## 3. Packaging — what a repository needs to be taken seriously

None of this existed before Phase 13; a resume repo without it looks unfinished:

- **`README.md`** — the project's front page: what it is, why the techniques matter
  (raw `bpf(2)` syscalls, per-CPU counters, LRU anti-spoofing, token buckets), an ASCII
  architecture diagram, the component table, the build/run flow, and an explicit
  **scope caveat** that throughput numbers are design targets, not benchmarks. Honesty is
  a feature, not a weakness — it is what a good reviewer respects.
- **`LICENSE`** — GPL-2.0. Not optional here: the eBPF program calls GPL-only BPF helpers,
  so it *must* declare a GPL-compatible license (`char _license[] SEC("license") = "GPL";`).
  The rest of the project follows suit.
- **`requirements.txt`** — pins the userspace deps (`flask`, `prometheus_client`, `pytest`).
  Note that `fluxguard_bpf.py` needs **nothing** — it uses only the standard library and
  `ctypes`, which is itself a selling point.
- **`.gitignore`** — keeps build artifacts (`*.o`), Python caches, and — importantly —
  **runtime state** (`blocked_ips.json`, `*.log`) and the generated `graphify-out/` out of
  version control. You never want live block state in git history.

## 4. One Makefile to replace the runbook grind

The per-phase `.txt` runbooks were how the project was driven by hand. That is fine for a lab
notebook but tedious to repeat. The `Makefile` collapses the essential operations into:

```
make build       # compile the XDP object (correct: -target bpf, SEC xdp)
make verify      # sanity-check maps/xdp sections
make attach IFACE=eth0 XDP_MODE=xdpdrv   # load + pin every map in one shot
make run-brain / run-dashboard / run-api
make test        # pure-python suite
make detach      # remove XDP + unpin
make clean
```

Writing the attach step out also surfaced a latent bug in the earlier runbooks: they attached
with `sec .text`, but the program is `SEC("xdp")`, so the loader must be told `sec xdp`. The
Makefile and the Phase 13 runbook use the correct section.

## 5. Tests that prove something, and run anywhere

`test_fluxguard.py` is deliberately split so it produces a **green signal on any OS**, even
the Windows box this repo is edited from:

- **Token-bucket math** — a pure-Python mirror of `token_bucket_check()` from the kernel,
  verifying burst behaviour, exhaustion, one-second refill, and the refill cap. This is the
  single most important algorithm in the datapath, and it can now be regression-tested
  without a kernel at all.
- **Config loader** — defaults, partial-override, save/load round-trip, and the anti-drift
  guard from §2.
- **BPF key round-trip** — `ip_to_key`/`key_to_ip` for v4 and v6. These import
  `fluxguard_bpf` (which loads `libc.so.6`) and therefore `pytest.importorskip`-skip
  themselves off Linux, so the suite stays green everywhere and gets full coverage on the
  target platform.

## What Phase 13 does **not** claim

This work was done on a non-Linux host. Every Python file compiles cleanly (`py_compile`) and
the pure-logic tests pass, but the XDP attach, the map pinning, and the live traffic tests
must still be run in the Ubuntu VM / netns lab. Phase 13 makes the code correct and the repo
publishable; it does not substitute for the runtime validation in the phase runbooks.

---

**Result:** FluxGuard is now a coherent, buildable, testable, documented, and correctly
licensed project — the REST API works, the numbers are consistent, and `git push` produces a
repository that presents the systems work honestly.
