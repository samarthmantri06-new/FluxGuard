#!/usr/bin/env python3
"""
FluxGuard Phase 11 — Allowlist Management CLI
Decoupled from fluxguard_brain.py; imports only from fluxguard_bpf.
Supports IPv4 and IPv6 address management.

Usage:
    sudo python3 fluxguard_allow.py add 10.0.1.5
    sudo python3 fluxguard_allow.py del 10.0.1.5
    sudo python3 fluxguard_allow.py list
    sudo python3 fluxguard_allow.py add 2001:db8::1
"""

import argparse
import ipaddress
import sys

from fluxguard_bpf import (
    bpf_obj_get,
    set_map_u32,
    del_map_u32,
    dump_map_u32,
    set_map_u32_v6,
    del_map_u32_v6,
    dump_map_u32_v6,
)

def is_ipv6(addr: str) -> bool:
    try:
        ipaddress.IPv6Address(addr)
        return True
    except ValueError:
        return False

def main() -> int:
    p = argparse.ArgumentParser(description="FluxGuard Allowlist Management (IPv4 + IPv6)")
    p.add_argument("action", choices=["add", "del", "list"])
    p.add_argument("ip", nargs="?", help="IP address to add/del (IPv4 or IPv6)")
    p.add_argument("--map-path-v4", default="/sys/fs/bpf/fluxguard/allowlist_map",
                   help="Path to pinned IPv4 allowlist map")
    p.add_argument("--map-path-v6", default="/sys/fs/bpf/fluxguard/allowlist_map_v6",
                   help="Path to pinned IPv6 allowlist map")
    args = p.parse_args()

    # Open IPv4 map (required)
    try:
        fd_v4 = bpf_obj_get(args.map_path_v4)
    except OSError as e:
        print(f"Error: Cannot access IPv4 allowlist map at {args.map_path_v4}: {e}", file=sys.stderr)
        return 1

    # Open IPv6 map (optional)
    fd_v6 = None
    try:
        fd_v6 = bpf_obj_get(args.map_path_v6)
    except OSError:
        pass  # IPv6 map not loaded — gracefully continue

    if args.action == "list":
        try:
            ipv4_entries = dump_map_u32(fd_v4)
            if not ipv4_entries:
                print("IPv4 allowlist: (empty)")
            else:
                print("IPv4 allowlist:")
                for ip in sorted(ipv4_entries.keys()):
                    print(f"  {ip}")

            if fd_v6:
                ipv6_entries = dump_map_u32_v6(fd_v6)
                if not ipv6_entries:
                    print("IPv6 allowlist: (empty)")
                else:
                    print("IPv6 allowlist:")
                    for ip in sorted(ipv6_entries.keys()):
                        print(f"  {ip}")
            else:
                print("IPv6 allowlist: (map not loaded)")
        except OSError as e:
            print(f"Error listing allowlist: {e}", file=sys.stderr)
            return 1

    elif args.action == "add":
        if not args.ip:
            print("Error: IP address required for 'add'", file=sys.stderr)
            return 1
        try:
            if is_ipv6(args.ip):
                if fd_v6 is None:
                    print(f"Error: IPv6 allowlist map not found at {args.map_path_v6}", file=sys.stderr)
                    return 1
                set_map_u32_v6(fd_v6, args.ip, 1)
                print(f"[ALLOW] Added IPv6 {args.ip}")
            else:
                set_map_u32(fd_v4, args.ip, 1)
                print(f"[ALLOW] Added IPv4 {args.ip}")
        except (OSError, ValueError) as e:
            print(f"Error adding {args.ip}: {e}", file=sys.stderr)
            return 1

    elif args.action == "del":
        if not args.ip:
            print("Error: IP address required for 'del'", file=sys.stderr)
            return 1
        try:
            if is_ipv6(args.ip):
                if fd_v6 is None:
                    print(f"Error: IPv6 allowlist map not found at {args.map_path_v6}", file=sys.stderr)
                    return 1
                del_map_u32_v6(fd_v6, args.ip)
                print(f"[ALLOW] Removed IPv6 {args.ip}")
            else:
                del_map_u32(fd_v4, args.ip)
                print(f"[ALLOW] Removed IPv4 {args.ip}")
        except (OSError, ValueError) as e:
            print(f"Error removing {args.ip}: {e}", file=sys.stderr)
            return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
