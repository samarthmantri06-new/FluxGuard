#!/usr/bin/env python3
"""
FluxGuard load test / benchmark harness.

Generates TCP-SYN flood traffic at a series of increasing packet rates against a
FluxGuard-protected interface and records, per rate step:

    pps_sent      packets/sec the generator actually pushed   (client TX delta)
    pps_passed    packets/sec that survived XDP to the backend (backend RX delta)
    pps_dropped   pps_sent - pps_passed
    drop_pct      percentage dropped by the XDP filter
    xdp_ns_pkt    average nanoseconds the XDP program spent per packet
    xdp_cpu_pct   fraction of one CPU core the XDP program consumed

WHY hping3: it is already a project dependency (used throughout docs/runbooks/),
so there is nothing new to install. Rate is controlled with `-i uMICROSECONDS`
(interval per packet); 1_000_000 / pps microseconds gives the target rate.

WHY bpftool for CPU: with `kernel.bpf_stats_enabled=1` the kernel accounts
run_time_ns + run_cnt per BPF program. Sampling `bpftool prog show` before/after
each step yields the XDP program's real per-packet cost and CPU share — far more
accurate than watching top(1), which lumps XDP work into softirq.

----------------------------------------------------------------------------
THIS DOES NOT RUN IN CI. It needs root, a real kernel with a loaded+attached XDP
program, and the netns lab (or a real NIC). Run it on the Ubuntu VM / lab host:

    # bring up the lab + attach FluxGuard first (see docs/runbooks/), then:
    sudo python3 scripts/load_test.py \
        --client-ns client --backend-ns backend \
        --client-if veth-client --backend-if veth-backend \
        --target 10.0.2.2 --rates 1000,5000,20000,100000,500000 \
        --duration 5 --csv results.csv

Defaults match the phase-1 netns topology
(client 10.0.1.1 -> fluxguard -> backend 10.0.2.2).
----------------------------------------------------------------------------
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

BPF_STATS_SYSCTL = "/proc/sys/kernel/bpf_stats_enabled"


def die(msg: str) -> None:
    print(f"[FATAL] {msg}", file=sys.stderr)
    sys.exit(1)


def preflight() -> None:
    if os.geteuid() != 0:
        die("must run as root (raw sockets + bpftool + netns).")
    for tool in ("hping3", "bpftool", "ip"):
        if shutil.which(tool) is None:
            die(f"required tool not found on PATH: {tool}")


def read_iface_counter(ns: Optional[str], iface: str, kind: str) -> int:
    """Read /sys/class/net/<iface>/statistics/<kind>_packets, optionally in a netns."""
    path = f"/sys/class/net/{iface}/statistics/{kind}_packets"
    if ns:
        out = subprocess.run(
            ["ip", "netns", "exec", ns, "cat", path],
            capture_output=True, text=True,
        )
        if out.returncode != 0:
            die(f"cannot read {kind}_packets for {iface} in ns {ns}: {out.stderr.strip()}")
        return int(out.stdout.strip())
    with open(path, "r", encoding="utf-8") as f:
        return int(f.read().strip())


def bpf_prog_stats(prog_name: str) -> Tuple[int, int]:
    """Return (run_time_ns, run_cnt) for the named BPF prog via `bpftool prog show`."""
    out = subprocess.run(
        ["bpftool", "-j", "prog", "show"], capture_output=True, text=True
    )
    if out.returncode != 0:
        return (0, 0)
    import json
    try:
        progs = json.loads(out.stdout)
    except json.JSONDecodeError:
        return (0, 0)
    for p in progs:
        if p.get("name") == prog_name or prog_name in (p.get("name") or ""):
            return (int(p.get("run_time_ns", 0)), int(p.get("run_cnt", 0)))
    return (0, 0)


def enable_bpf_stats() -> bool:
    try:
        with open(BPF_STATS_SYSCTL, "r", encoding="utf-8") as f:
            already = f.read().strip() == "1"
        if not already:
            with open(BPF_STATS_SYSCTL, "w", encoding="utf-8") as f:
                f.write("1")
        return already
    except OSError:
        print("[WARN] cannot enable kernel.bpf_stats_enabled — XDP CPU columns will be blank.")
        return True  # pretend "already" so we don't try to restore


def restore_bpf_stats(was_already_on: bool) -> None:
    if was_already_on:
        return
    try:
        with open(BPF_STATS_SYSCTL, "w", encoding="utf-8") as f:
            f.write("0")
    except OSError:
        pass


def run_step(args: argparse.Namespace, pps: int) -> Dict[str, float]:
    count = pps * args.duration
    workers = min(args.max_workers, max(1, pps // 1000 + (1 if pps % 1000 else 0))) if pps >= 1000 else 1
    pps_per_worker = max(1, pps // workers)
    count_per_worker = max(1, count // workers)
    interval_us = max(1, 1_000_000 // pps_per_worker)

    tx0 = read_iface_counter(args.client_ns, args.client_if, "tx")
    rx0 = read_iface_counter(args.backend_ns, args.backend_if, "rx")
    ns0, cnt0 = bpf_prog_stats(args.prog_name)
    t0 = time.monotonic()

    procs = []
    for _ in range(workers):
        hping = ["hping3", "-S", "-p", str(args.port), "-i", f"u{interval_us}",
                 "-c", str(count_per_worker), args.target]
        cmd = (["ip", "netns", "exec", args.client_ns] + hping) if args.client_ns else hping
        procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    for p in procs:
        p.wait()

    dt = time.monotonic() - t0
    tx1 = read_iface_counter(args.client_ns, args.client_if, "tx")
    rx1 = read_iface_counter(args.backend_ns, args.backend_if, "rx")
    ns1, cnt1 = bpf_prog_stats(args.prog_name)

    sent = max(0, tx1 - tx0)
    passed = max(0, rx1 - rx0)
    dropped = max(0, sent - passed)
    pps_sent = sent / dt if dt > 0 else 0.0
    pps_passed = passed / dt if dt > 0 else 0.0
    pps_dropped = dropped / dt if dt > 0 else 0.0
    drop_pct = (dropped / sent * 100.0) if sent else 0.0

    run_ns = ns1 - ns0
    run_cnt = cnt1 - cnt0
    xdp_ns_pkt = (run_ns / run_cnt) if run_cnt else 0.0
    xdp_cpu_pct = (run_ns / (dt * 1e9) * 100.0) if dt > 0 else 0.0

    return {
        "target_pps": pps, "pps_sent": pps_sent, "pps_passed": pps_passed,
        "pps_dropped": pps_dropped, "drop_pct": drop_pct,
        "xdp_ns_pkt": xdp_ns_pkt, "xdp_cpu_pct": xdp_cpu_pct,
    }


def main() -> int:
    p = argparse.ArgumentParser(description="FluxGuard load test / benchmark")
    p.add_argument("--client-ns", default="client", help="netns of the traffic generator ('' for host)")
    p.add_argument("--backend-ns", default="backend", help="netns of the protected backend ('' for host)")
    p.add_argument("--client-if", default="veth-client", help="generator iface (TX counted)")
    p.add_argument("--backend-if", default="veth-backend", help="backend iface (RX counted)")
    p.add_argument("--target", default="10.0.2.2", help="target IP to flood")
    p.add_argument("--port", type=int, default=80)
    p.add_argument("--prog-name", default="fluxguard_filter", help="XDP prog name for bpftool stats")
    p.add_argument("--rates", default="1000,5000,20000,100000,500000",
                   help="comma-separated target PPS steps")
    p.add_argument("--duration", type=int, default=5, help="seconds per rate step")
    p.add_argument("--max-workers", type=int, default=1, help="Max parallel hping3 workers")
    p.add_argument("--csv", default="", help="optional path to write CSV results")
    args = p.parse_args()
    # Empty string means "host namespace".
    args.client_ns = args.client_ns or None
    args.backend_ns = args.backend_ns or None

    preflight()
    rates = [int(r) for r in args.rates.split(",") if r.strip()]
    was_on = enable_bpf_stats()

    header = ("target_pps", "pps_sent", "pps_passed", "pps_dropped",
              "drop_pct", "xdp_ns_pkt", "xdp_cpu_pct")
    print(f"FluxGuard load test — target={args.target} duration={args.duration}s/step\n")
    print("{:>10} {:>12} {:>12} {:>12} {:>9} {:>11} {:>11}".format(
        "targetPPS", "sent", "passed", "dropped", "drop%", "ns/pkt", "xdpCPU%"))
    print("-" * 82)

    rows: List[Dict[str, float]] = []
    try:
        for pps in rates:
            row = run_step(args, pps)
            rows.append(row)
            print("{:>10} {:>12.0f} {:>12.0f} {:>12.0f} {:>8.1f}% {:>11.1f} {:>10.1f}%".format(
                row["target_pps"], row["pps_sent"], row["pps_passed"],
                row["pps_dropped"], row["drop_pct"], row["xdp_ns_pkt"], row["xdp_cpu_pct"]))
            if row["pps_sent"] < pps * 0.7:
                print(f"  [WARNING] generator_bottleneck: sent {row['pps_sent']:.0f} pps, target was {pps}. Try increasing --max-workers.")
    finally:
        restore_bpf_stats(was_on)

    if args.csv and rows:
        import csv
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=header)
            w.writeheader()
            w.writerows(rows)
        print(f"\nWrote {len(rows)} rows to {args.csv}")

    print("\nNote: paste these numbers into README.md's Performance section, "
          "with your CPU model / kernel version / XDP mode (generic vs native).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
