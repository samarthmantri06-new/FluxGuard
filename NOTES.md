# Cleanup pass — change log

Repo hygiene / CI / benchmarking pass. **No eBPF or control-plane logic was changed** — this
was structure, docs, CI, and a benchmark harness only. Commits are additive (no history
rewrite, no force-push).

## Commits in this pass

1. **Reorganize repo into `src/ docs/ tests/ scripts/`**
   - Kernel + control-plane code → `src/`
   - `test_fluxguard.py` → `tests/` (+ `tests/conftest.py` puts `src/` on `sys.path`)
   - Phase writeups → `docs/phaseNN-*.md`; command runbooks → `docs/runbooks/phaseNN-*.txt`
     (renamed by topic instead of `FLUXGUARD_COMMANDS_samarth_phaseN.txt`)
   - `some.py` (a codebase-dump dev utility) → `scripts/dump_codebase.py`, fixed to walk the
     repo root regardless of cwd
   - Updated `Makefile`, `README.md`, and both systemd unit files for the new paths

2. **Move `CLAUDE.md` → `.claude/CLAUDE.md`** and refresh its path references. `.gitignore`
   now tracks `.claude/CLAUDE.md` but ignores machine-local `.claude/settings.local.json`.

3. **CI updated for the new layout** (`.github/workflows/ci.yml`). Two jobs, clearly labeled:
   - `tests` — **functional**: `pytest` on the pure-Python suite (runs for real in CI)
   - `ebpf-build` — **compile-only**: `make build` + assert `maps`/`xdp` ELF sections exist.
     GitHub runners can't load/attach XDP, so this proves it *compiles*, not that it runs.

4. **Load-test harness `scripts/load_test.py` + README Performance section.** Sweeps packet
   rates with `hping3`, records pps sent/passed/dropped (iface counters) and real XDP
   ns/packet + CPU% (`bpftool prog show` with `kernel.bpf_stats_enabled=1`).
   
   **Test Run Summary:** Re-ran the benchmark on Intel Core i5-13420H / Linux 6.17.0 using up to 32 parallel `hping3` workers (`--max-workers 32`). Despite parallelization, the `hping3` generator remained the bottleneck, failing to reach even 70% of the requested target rates (maxing out at ~22,000 PPS). The `[WARNING] generator_bottleneck` flag was triggered for all rows. The `README.md` Performance table was updated with these findings and all rows were explicitly labeled as "generator-limited, not FluxGuard-limited".

## Still TODO (manual — not doable from Claude Code)

- **GitHub repo metadata:** add a one-line description and topics/tags
  (`ebpf`, `xdp`, `ddos-mitigation`, `linux-kernel`, `cybersecurity`, `networking`).
- **Run the benchmark** in the VM/lab and paste real numbers into the README Performance table.
- **Record a demo GIF** of a live flood being auto-blocked and embed it in the README.
