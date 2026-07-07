#!/usr/bin/env python3
"""
FluxGuard Phase 12 — Configuration Management
Loads settings from /etc/fluxguard/config.json (or a path you specify).
Falls back to safe defaults if file is missing.
Both brain and API server import this module.
"""

from __future__ import annotations
import json
import os
from dataclasses import dataclass, field, asdict
from typing import List

DEFAULT_CONFIG_PATH = "/etc/fluxguard/config.json"

@dataclass
class FluxGuardConfig:
    # Network
    interface: str = "eth0"               # Real NIC to attach XDP to
    xdp_mode: str = "auto"               # "native", "generic", or "auto"
    bpf_pin_dir: str = "/sys/fs/bpf/fluxguard"

    # Thresholds — INFORMATIONAL ONLY.
    # The authoritative limits are compile-time #defines in fluxguard_kern.c
    # (KERN_PPS_LIMIT, GLOBAL_PPS_LIMIT). These fields exist so tooling/metrics
    # can display the intended values; they are NOT pushed into the kernel, so
    # keep them in sync with the C constants by hand. Kernel always wins.
    kern_pps_limit: int = 1000           # MUST match KERN_PPS_LIMIT in fluxguard_kern.c
    global_pps_limit: int = 500000       # MUST match GLOBAL_PPS_LIMIT in fluxguard_kern.c

    # Brain behaviour
    poll_interval: float = 0.2           # How often brain reads maps (seconds)
    cooldown_sec: int = 900              # Block duration before auto-unblock
    block_batch_size: int = 256          # Max IPs to block per loop
    allowlist_refresh_sec: float = 5.0   # How often brain re-reads allowlist map

    # Persistence
    persistence_file: str = "/var/lib/fluxguard/blocked_ips.json"
    log_file: str = "/var/log/fluxguard/fluxguard.log"

    # Metrics
    metrics_host: str = "127.0.0.1"
    metrics_port: int = 9090

    # REST API
    api_host: str = "127.0.0.1"
    api_port: int = 8080
    api_token: str = ""                  # Bearer token for auth; empty = no auth

    # Protocol drop list (protocol numbers to drop by default)
    drop_protocols: List[int] = field(default_factory=list)

    # Verbose
    verbose: bool = False
    no_log_ticks: bool = True


def load_config(path: str = DEFAULT_CONFIG_PATH) -> FluxGuardConfig:
    """Load config from JSON file, falling back to defaults for missing keys."""
    cfg = FluxGuardConfig()
    if not os.path.exists(path):
        return cfg
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for key, val in data.items():
            if hasattr(cfg, key):
                setattr(cfg, key, val)
    except Exception as e:
        print(f"[WARN] Config load failed ({path}): {e} — using defaults")
    return cfg


def save_config(cfg: FluxGuardConfig, path: str = DEFAULT_CONFIG_PATH) -> None:
    """Save current config to JSON file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(asdict(cfg), f, indent=2)


# Default config template written by Phase 12 setup
DEFAULT_CONFIG_TEMPLATE = """{
  "interface": "eth0",
  "xdp_mode": "auto",
  "bpf_pin_dir": "/sys/fs/bpf/fluxguard",
  "kern_pps_limit": 1000,
  "global_pps_limit": 500000,
  "poll_interval": 0.2,
  "cooldown_sec": 900,
  "block_batch_size": 256,
  "allowlist_refresh_sec": 5.0,
  "persistence_file": "/var/lib/fluxguard/blocked_ips.json",
  "log_file": "/var/log/fluxguard/fluxguard.log",
  "metrics_host": "127.0.0.1",
  "metrics_port": 9090,
  "api_host": "127.0.0.1",
  "api_port": 8080,
  "api_token": "change-me-secret",
  "drop_protocols": [],
  "verbose": false,
  "no_log_ticks": true
}
"""
