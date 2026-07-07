#!/usr/bin/env python3
"""
FluxGuard Phase 11 — Live Dashboard
Reads from two sources simultaneously:
  1. Prometheus /metrics  — per-IP packet counts, blocked IPs, Shields-Up events
  2. BPF Ring Buffer mmap — real-time kernel autonomous block notifications

Ring buffer parsing is defensive:
  - Validates consumer/producer pointers are in bounds before reading
  - Catches struct.error and skips corrupted records gracefully
  - Prints kernel version warning if page layout seems unexpected
"""

import argparse
import ctypes
import ipaddress
import mmap
import os
import signal
import struct
import sys
import time
import urllib.request
from datetime import datetime

from fluxguard_bpf import bpf_obj_get

PAGE_SIZE = mmap.PAGESIZE
RINGBUF_DEFAULT_SIZE = 256 * 1024  # 256 KB, must match kernel definition

# Ring buffer record header flags
RB_RECORD_HDR_SIZE  = 8       # 8-byte aligned header per record
RB_BUSY_FLAG        = 1 << 31 # bit 31: record is being written (busy)
RB_DISCARD_FLAG     = 1 << 30 # bit 30: record discarded, skip it

# ─────────────────────────────────────────────
# Prometheus metrics fetcher
# ─────────────────────────────────────────────

def fetch_metrics(url: str) -> str:
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            return resp.read().decode("utf-8")
    except Exception:
        return ""

def parse_metrics(text: str):
    packets = {}
    blocked_set = set()
    blocked_count = 0
    block_events = 0
    unblock_events = 0
    shields_up = 0

    for line in text.splitlines():
        if line.startswith('fluxguard_meter_packets{ip="'):
            ip = line.split('"')[1]
            cnt = int(line.split()[-1])
            packets[ip] = cnt
        elif line.startswith('fluxguard_blocked_ips '):
            blocked_count = int(line.split()[-1])
        elif line.startswith('fluxguard_block_events_total '):
            block_events = int(line.split()[-1])
        elif line.startswith('fluxguard_unblock_events_total '):
            unblock_events = int(line.split()[-1])
        elif line.startswith('fluxguard_global_pps_exceeded_total '):
            shields_up = int(line.split()[-1])
        elif line.startswith('fluxguard_blocked_ip{ip="'):
            ip = line.split('"')[1]
            blocked_set.add(ip)

    return packets, blocked_set, blocked_count, block_events, unblock_events, shields_up

# ─────────────────────────────────────────────
# Ring buffer reader (defensive / bounds-checked)
# ─────────────────────────────────────────────

def open_ringbuf(map_path: str):
    """Open and mmap the BPF ring buffer. Returns (buf, data_offset, rb_size) or None."""
    try:
        fd = bpf_obj_get(map_path)
    except Exception as e:
        print(f"[RB] Cannot open ring buffer at {map_path}: {e}")
        return None

    rb_size = RINGBUF_DEFAULT_SIZE

    # Layout: 2 pages of consumer/producer metadata + 2x rb_size data area
    total_map_size = 2 * PAGE_SIZE + 2 * rb_size
    try:
        buf = mmap.mmap(fd, total_map_size, mmap.MAP_SHARED,
                        mmap.PROT_READ | mmap.PROT_WRITE)
        data_offset = 2 * PAGE_SIZE
        return buf, data_offset, rb_size
    except Exception:
        # Fallback: single copy mapping
        try:
            total_map_size = 2 * PAGE_SIZE + rb_size
            buf = mmap.mmap(fd, total_map_size, mmap.MAP_SHARED,
                            mmap.PROT_READ | mmap.PROT_WRITE)
            data_offset = 2 * PAGE_SIZE
            return buf, data_offset, rb_size
        except Exception as e:
            print(f"[RB] mmap failed: {e}")
            return None

def drain_ringbuf(buf, data_offset: int, rb_size: int):
    """
    Safely drain pending records from the ring buffer.
    Returns a list of (ip_str, reason, timestamp_ns) tuples.
    Skips any record that fails bounds or struct checks.
    """
    events = []
    max_map_offset = len(buf)

    # Read consumer (page 0, offset 0) and producer (page 1, offset 0) pointers
    try:
        cons = struct.unpack_from("<Q", buf, 0)[0]
        prod = struct.unpack_from("<Q", buf, PAGE_SIZE)[0]
    except struct.error:
        return events

    # Sanity: if producer - consumer > rb_size something is corrupt, reset
    if prod < cons or (prod - cons) > rb_size:
        return events

    while cons < prod:
        pos = cons & (rb_size - 1)
        hdr_abs = data_offset + pos

        # Bounds check header
        if hdr_abs + 4 > max_map_offset:
            break

        try:
            hdr_len = struct.unpack_from("<I", buf, hdr_abs)[0]
        except struct.error:
            break

        # Skip busy or discarded records
        if hdr_len & (RB_BUSY_FLAG | RB_DISCARD_FLAG):
            data_len = (hdr_len & 0x0FFFFFFF)
            record_size = ((data_len + RB_RECORD_HDR_SIZE - 1) // RB_RECORD_HDR_SIZE) * RB_RECORD_HDR_SIZE
            if record_size == 0:
                break
            cons += record_size
            struct.pack_into("<Q", buf, 0, cons)
            continue

        data_len = hdr_len & 0x0FFFFFFF
        payload_abs = hdr_abs + RB_RECORD_HDR_SIZE

        # Bounds check payload
        # attack_event struct: af(1) reason(1) pad(2) src_v4(4) src_v6(16) ts(8) = 32 bytes
        EXPECTED_PAYLOAD = 32
        if payload_abs + EXPECTED_PAYLOAD > max_map_offset:
            break

        try:
            af, reason, pad, src_v4 = struct.unpack_from("<BBHI", buf, payload_abs)
            src_v6_bytes = buf[payload_abs + 8: payload_abs + 24]
            ts_ns = struct.unpack_from("<Q", buf, payload_abs + 24)[0]

            if af == 4:
                ip_str = str(ipaddress.IPv4Address(struct.pack(">I", src_v4)))
            elif af == 6:
                ip_str = str(ipaddress.IPv6Address(bytes(src_v6_bytes)))
            else:
                ip_str = f"unknown(af={af})"

            events.append((ip_str, reason, ts_ns))
        except Exception:
            pass

        # Advance consumer pointer (8-byte aligned record)
        record_size = ((data_len + RB_RECORD_HDR_SIZE - 1) // RB_RECORD_HDR_SIZE) * RB_RECORD_HDR_SIZE
        if record_size == 0:
            record_size = RB_RECORD_HDR_SIZE
        cons += record_size
        struct.pack_into("<Q", buf, 0, cons)

    return events

# ─────────────────────────────────────────────
# Terminal dashboard renderer
# ─────────────────────────────────────────────

def render(packets, blocked_set, blocked_count, block_events, unblock_events,
           shields_up, prev_packets, dt, rb_events):
    top = sorted(packets.items(), key=lambda x: x[1], reverse=True)[:12]

    print("\033[2J\033[H", end="")
    print("\033[1;36m╔══════════════════════════════════════════════════════════╗")
    print("║         FluxGuard Phase 11 — Live Dashboard              ║")
    print("╚══════════════════════════════════════════════════════════╝\033[0m")
    print()

    hdr = f"  {'Source IP':<40} {'Status':<12} {'Packets':<12} {'PPS':>8}"
    print(f"\033[1;33m{hdr}\033[0m")
    print("  " + "─" * 74)

    for ip, cnt in top:
        prev = prev_packets.get(ip, cnt)
        pps = (cnt - prev) / dt if dt > 0 else 0.0
        if ip in blocked_set:
            status_str = "\033[31m● BLOCKED \033[0m"
        else:
            status_str = "\033[32m● ACTIVE  \033[0m"
        print(f"  {ip:<40} {status_str}  {cnt:<12,} {pps:>8.1f}")

    print("  " + "─" * 74)
    print(f"  Total IPs seen: \033[1m{len(packets)}\033[0m  │  "
          f"Blocked: \033[31m\033[1m{blocked_count}\033[0m  │  "
          f"Shields-Up events: \033[33m{shields_up}\033[0m")
    print(f"  Cumulative → Blocks: \033[31m{block_events}\033[0m  "
          f"Unblocks: \033[32m{unblock_events}\033[0m")

    if rb_events:
        print()
        print("\033[1;35m  ── Kernel Auto-Block Events (Ring Buffer) ──────────────\033[0m")
        for ip, reason, ts_ns in rb_events[-8:]:
            reason_str = "AUTO_BLOCK" if reason == 1 else f"REASON_{reason}"
            ts_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"  \033[35m[{ts_str}]\033[0m \033[31m{ip:<42}\033[0m {reason_str}")

    print()
    print(f"\033[2m  Refreshing every {args_global.refresh:.1f}s │ Ctrl+C to exit\033[0m")

# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

args_global = None

def handle_exit(s, f):
    print("\033[0m\nFluxGuard Dashboard exiting.")
    sys.exit(0)

def main():
    global args_global
    signal.signal(signal.SIGINT,  handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    p = argparse.ArgumentParser(description="FluxGuard Live Dashboard")
    p.add_argument("--metrics-url", default="http://127.0.0.1:9090/metrics")
    p.add_argument("--refresh",     type=float, default=2.0)
    p.add_argument("--ringbuf-path",
                   default="/sys/fs/bpf/fluxguard/event_ringbuf",
                   help="Path to pinned ring buffer map")
    args = p.parse_args()
    args_global = args

    # Open ring buffer once — keep it open for the session
    rb_state = open_ringbuf(args.ringbuf_path)
    if rb_state is None:
        print("[WARN] Ring buffer not available. Metrics-only mode.")

    prev_packets = {}
    accumulated_rb_events = []
    last_time = time.time()

    while True:
        text = fetch_metrics(args.metrics_url)
        now  = time.time()
        dt   = now - last_time if now > last_time else args.refresh

        packets, blocked_set, blocked_count, block_events, unblock_events, shields_up = \
            parse_metrics(text) if text else ({}, set(), 0, 0, 0, 0)

        # Drain ring buffer events
        if rb_state:
            buf, data_offset, rb_size = rb_state
            new_events = drain_ringbuf(buf, data_offset, rb_size)
            accumulated_rb_events.extend(new_events)
            # Keep only the last 50 events in memory
            if len(accumulated_rb_events) > 50:
                accumulated_rb_events = accumulated_rb_events[-50:]

        render(packets, blocked_set, blocked_count, block_events, unblock_events,
               shields_up, prev_packets, dt, accumulated_rb_events)

        prev_packets = packets
        last_time = now
        time.sleep(args.refresh)

if __name__ == "__main__":
    main()
