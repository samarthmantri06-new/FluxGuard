#!/usr/bin/env python3
from __future__ import annotations
import argparse
import datetime
import json
import os
import signal
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, TextIO, Set

from fluxguard_metrics import MetricsState, start_metrics_server
from fluxguard_bpf import (
    bpf_obj_get,
    set_map_u32,
    del_map_u32,
    dump_map_u32,
    set_map_u32_v6,
    del_map_u32_v6,
    dump_map_u32_v6,
    get_global_tokens,
)

PERSISTENCE_FILE = "/home/samarth/fluxguard/blocked_ips.json"
shutdown_event = threading.Event()

def handle_sigterm(signum: int, frame: Any) -> None:
    shutdown_event.set()

def write_json_log(fd: TextIO, event: str, fields: Dict[str, Any]) -> None:
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    record: Dict[str, Any] = {"timestamp": ts, "event": event}
    record.update(fields)
    line = json.dumps(record, separators=(",", ":")) + "\n"
    fd.write(line)
    fd.flush()

def save_checkpoint(blocked_until: Dict[str, float]) -> None:
    """Save block timestamps to disk for persistence."""
    try:
        data = {ip: ts for ip, ts in blocked_until.items()}
        os.makedirs(os.path.dirname(PERSISTENCE_FILE), exist_ok=True)
        with open(PERSISTENCE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception as e:
        print(f"[WARN] Failed to write checkpoint: {e}", file=sys.stderr)

def load_checkpoint() -> Dict[str, float]:
    """Load blocked IPs and timers from checkpoint file."""
    if not os.path.exists(PERSISTENCE_FILE):
        return {}
    try:
        with open(PERSISTENCE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return {ip: float(ts) for ip, ts in data.items()}
    except Exception as e:
        print(f"[WARN] Failed to read checkpoint: {e}", file=sys.stderr)
        return {}

def monitor(args: argparse.Namespace, metrics: MetricsState, log_fd: TextIO) -> None:
    base = f"/sys/fs/bpf/{args.netns}"
    
    # 1. Open IPv4 Maps
    try:
        meter_fd = bpf_obj_get(f"{base}/meter_map")
        blacklist_fd = bpf_obj_get(f"{base}/blacklist_map")
        allowlist_fd = bpf_obj_get(f"{base}/allowlist_map")
        global_rate_fd = bpf_obj_get(f"{base}/global_rate_map")
    except OSError as exc:
        print(f"[FATAL] Failed to access IPv4 BPF maps: {exc}", file=sys.stderr)
        sys.exit(1)

    # 2. Open IPv6 Maps (Optional/Graceful if not loaded in kernel yet)
    meter_v6_fd = None
    blacklist_v6_fd = None
    allowlist_v6_fd = None
    try:
        meter_v6_fd = bpf_obj_get(f"{base}/meter_map_v6")
        blacklist_v6_fd = bpf_obj_get(f"{base}/blacklist_map_v6")
        allowlist_v6_fd = bpf_obj_get(f"{base}/allowlist_map_v6")
        print("IPv6 support enabled: detected v6 maps.")
    except OSError:
        print("IPv6 support disabled or maps not found. Continuing with IPv4 only.")

    # 3. Setup protocol filter if needed
    if args.drop_proto is not None:
        try:
            proto_fd = bpf_obj_get(f"{base}/proto_filter_map")
            from fluxguard_bpf import set_proto_filter
            set_proto_filter(proto_fd, args.drop_proto, 1)
            print(f"Set protocol filter rule: drop protocol {args.drop_proto}")
        except OSError:
            print("[WARN] Failed to set protocol filter. Map not found.")

    prev_ts = time.monotonic()
    
    # Load persistence checkpoint
    blocked_until = load_checkpoint()
    print(f"Loaded {len(blocked_until)} blocks from persistence checkpoint.")
    
    # Re-apply any persistent blocks back into kernel maps
    for ip in list(blocked_until.keys()):
        try:
            if ":" in ip:
                if blacklist_v6_fd:
                    set_map_u32_v6(blacklist_v6_fd, ip, 1)
            else:
                set_map_u32(blacklist_fd, ip, 1)
        except OSError:
            pass

    allowlist_cache: Dict[str, int] = {}
    allowlist_v6_cache: Dict[str, int] = {}
    allowlist_ts = 0.0
    prev_global_tokens = 0
    
    print(f"Phase 11 Brain started. Cooldown={args.cooldown_sec}s. Allowlist refresh={args.allowlist_refresh_sec}s.")

    while not shutdown_event.is_set():
        now = time.monotonic()
        dt = now - prev_ts
        if dt <= 0:
            dt = args.poll_interval

        # Refresh allowlists
        if now - allowlist_ts >= args.allowlist_refresh_sec:
            try:
                allowlist_cache = dump_map_u32(allowlist_fd)
                if allowlist_v6_fd:
                    allowlist_v6_cache = dump_map_u32_v6(allowlist_v6_fd)
                allowlist_ts = now
            except OSError:
                pass

        curr_blacklist = {}
        curr_blacklist_v6 = {}
        curr_counts = {}
        curr_counts_v6 = {}
        global_tokens = 0
        
        try:
            curr_blacklist = dump_map_u32(blacklist_fd)
            curr_counts = dump_map_u32(meter_fd)
            if blacklist_v6_fd:
                curr_blacklist_v6 = dump_map_u32_v6(blacklist_v6_fd)
            if meter_v6_fd:
                curr_counts_v6 = dump_map_u32_v6(meter_v6_fd)
            global_tokens = get_global_tokens(global_rate_fd)
        except OSError:
            pass

        # Shields up check
        if global_tokens <= 0 and global_tokens < prev_global_tokens:
            metrics.inc_global_pps_exceeded()
            print(f"[SHIELDS UP DETECTED] Global Token Bucket exhausted by Kernel!")
            write_json_log(log_fd, "SHIELDS_UP", {"global_tokens": global_tokens})

        # Process kernel auto-blocks (IPv4)
        for ip in curr_blacklist:
            if ip not in blocked_until and ip not in allowlist_cache:
                blocked_until[ip] = now + args.cooldown_sec
                metrics.inc_block_events()
                save_checkpoint(blocked_until)
                print(f"[KERNEL AUTO-BLOCK DETECTED] ip={ip} (IPv4) unblock_in={args.cooldown_sec}s")
                write_json_log(log_fd, "AUTO_BLOCK", {"ip": ip, "blocked_count": len(blocked_until)})

        # Process kernel auto-blocks (IPv6)
        for ip in curr_blacklist_v6:
            if ip not in blocked_until and ip not in allowlist_v6_cache:
                blocked_until[ip] = now + args.cooldown_sec
                metrics.inc_block_events()
                save_checkpoint(blocked_until)
                print(f"[KERNEL AUTO-BLOCK DETECTED] ip={ip} (IPv6) unblock_in={args.cooldown_sec}s")
                write_json_log(log_fd, "AUTO_BLOCK", {"ip": ip, "blocked_count": len(blocked_until)})

        # Gracefully unblock expired blocks
        if blocked_until:
            expired = [ip for ip, ts in blocked_until.items() if now >= ts]
            if expired:
                for ip in expired:
                    try:
                        if ":" in ip:
                            if blacklist_v6_fd:
                                del_map_u32_v6(blacklist_v6_fd, ip)
                        else:
                            del_map_u32(blacklist_fd, ip)
                        metrics.inc_unblock_events()
                        print(f"[UNBLOCK] ip={ip} cooldown_expired")
                        write_json_log(log_fd, "UNBLOCK", {"ip": ip, "blocked_count": len(blocked_until) - 1})
                    except OSError:
                        pass
                    finally:
                        blocked_until.pop(ip, None)
                save_checkpoint(blocked_until)

        # Merge IPv4 and IPv6 packet statistics for metrics snapshot
        all_counts = {}
        all_counts.update(curr_counts)
        all_counts.update(curr_counts_v6)

        metrics.update_blocked_set(set(blocked_until.keys()))
        metrics.update_snapshot(all_counts, len(blocked_until))

        if not args.no_log_ticks:
            write_json_log(log_fd, "TICK", {"observed_ips": len(all_counts), "blocked_count": len(blocked_until), "global_tokens": global_tokens})

        if args.verbose:
            print(f"[TICK] ips={len(all_counts)} blocked={len(blocked_until)} dt={dt:.3f}s")

        prev_global_tokens = global_tokens
        prev_ts = now
        
        sleep_left = min(args.poll_interval, 1.0)
        while sleep_left > 0 and not shutdown_event.is_set():
            chunk = min(0.1, sleep_left)
            time.sleep(chunk)
            sleep_left -= chunk

def main() -> int:
    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGINT, handle_sigterm)

    p = argparse.ArgumentParser()
    p.add_argument("--netns", default="fluxguard")
    p.add_argument("--poll-interval", type=float, default=0.2)
    p.add_argument("--cooldown-sec", type=int, default=30)
    p.add_argument("--allowlist-refresh-sec", type=float, default=5.0)
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--no-log-ticks", action="store_true")
    p.add_argument("--log-file", default="/home/samarth/fluxguard/fluxguard.log")
    p.add_argument("--metrics-host", default="127.0.0.1")
    p.add_argument("--metrics-port", type=int, default=9090)
    p.add_argument("--drop-proto", type=int, help="Protocol ID to drop")
    args = p.parse_args()

    metrics = MetricsState()
    start_metrics_server(metrics, args.metrics_host, args.metrics_port)

    with open(args.log_file, "a", encoding="utf-8") as log_fd:
        try:
            monitor(args, metrics, log_fd)
        except Exception as exc:
            print(f"[FATAL] {exc}", file=sys.stderr)
            return 1
            
    print("\nFluxGuard brain shutdown complete.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
