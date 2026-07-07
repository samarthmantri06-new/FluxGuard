#!/usr/bin/env python3
"""
FluxGuard Phase 12/13 – Minimal REST API
Provides administrative operations (allowlist, blocked-list, metrics proxy) over HTTP.
Uses Flask (lightweight, built-in dev server) – replace with gunicorn/uvicorn in production.

All map interactions go through `fluxguard_bpf.py`, exactly like the brain & CLI, so the
same code path (and struct/key handling) is used everywhere.

Phase 13 fixes vs Phase 12:
  - Maps are now opened ONCE at startup via bpf_obj_get() (Phase 12 wrongly passed map
    *name strings* straight into the helpers, which expect an integer fd).
  - Uses the helper contract correctly: set_/del_map_u32[_v6]() take an IP *string*
    (not packed bytes) and dump_map_u32[_v6]() returns a dict {ip_str: value}.
  - IPv6 rendering uses `ipaddress` (Phase 12 used a dead "%02x...".format() template
    that returned the literal string unchanged).
"""

from __future__ import annotations
import ipaddress
import urllib.request
from typing import Dict, Optional

from flask import Flask, request, jsonify, abort

# Import the shared BPF helpers
from fluxguard_bpf import (
    bpf_obj_get,
    dump_map_u32,
    dump_map_u32_v6,
    set_map_u32,
    set_map_u32_v6,
    del_map_u32,
    del_map_u32_v6,
)

# Load configuration (same config file used by the brain — Phase 12)
from fluxguard_config import load_config, FluxGuardConfig

cfg: FluxGuardConfig = load_config()

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Map handles — opened once at import time from the pinned BPF filesystem.
# IPv4 maps are required; IPv6 maps are optional (graceful if not loaded).
# ---------------------------------------------------------------------------
_PIN = cfg.bpf_pin_dir.rstrip("/")


def _try_open(path: str) -> Optional[int]:
    try:
        return bpf_obj_get(path)
    except OSError:
        return None


ALLOWLIST_FD = _try_open(f"{_PIN}/allowlist_map")
ALLOWLIST_V6_FD = _try_open(f"{_PIN}/allowlist_map_v6")
BLACKLIST_FD = _try_open(f"{_PIN}/blacklist_map")
BLACKLIST_V6_FD = _try_open(f"{_PIN}/blacklist_map_v6")


def _require(fd: Optional[int], name: str) -> int:
    if fd is None:
        abort(503, description=f"BPF map '{name}' not available at {_PIN} (is FluxGuard loaded?)")
    return fd


def _canonical_v6(ip: str) -> str:
    """Return the canonical compressed form of an IPv6 address string."""
    return str(ipaddress.IPv6Address(ip))


# ---------------------------------------------------------------------------
# Helper – simple bearer-token auth (optional)
# ---------------------------------------------------------------------------
def _check_auth() -> bool:
    token = cfg.api_token
    if not token:
        return True  # no auth required
    auth = request.headers.get("Authorization", "")
    return auth == f"Bearer {token}"


@app.before_request
def before():
    if not _check_auth():
        abort(401, description="Invalid or missing API token")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.route("/api/v1/allowlist", methods=["GET", "POST", "DELETE"])
def allowlist():
    if request.method == "GET":
        v4: Dict[str, int] = dump_map_u32(_require(ALLOWLIST_FD, "allowlist_map"))
        v6: Dict[str, int] = dump_map_u32_v6(ALLOWLIST_V6_FD) if ALLOWLIST_V6_FD else {}
        return jsonify({"ipv4": sorted(v4.keys()), "ipv6": sorted(v6.keys())})

    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    if not ip:
        abort(400, description="Missing 'ip' field")

    # Validate + route on address family. The helpers parse the string themselves.
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as e:
        abort(400, description=f"Invalid IP: {e}")

    try:
        if addr.version == 6:
            fd = _require(ALLOWLIST_V6_FD, "allowlist_map_v6")
            canon = _canonical_v6(ip)
            if request.method == "POST":
                set_map_u32_v6(fd, canon, 1)
                return jsonify({"added": canon}), 201
            del_map_u32_v6(fd, canon)
            return jsonify({"deleted": canon}), 200
        else:
            fd = _require(ALLOWLIST_FD, "allowlist_map")
            if request.method == "POST":
                set_map_u32(fd, ip, 1)
                return jsonify({"added": ip}), 201
            del_map_u32(fd, ip)
            return jsonify({"deleted": ip}), 200
    except OSError as e:
        abort(500, description=f"BPF map op failed: {e}")


@app.route("/api/v1/blocked", methods=["GET"])
def blocked():
    v4: Dict[str, int] = dump_map_u32(_require(BLACKLIST_FD, "blacklist_map"))
    v6: Dict[str, int] = dump_map_u32_v6(BLACKLIST_V6_FD) if BLACKLIST_V6_FD else {}
    return jsonify({"ipv4": sorted(v4.keys()), "ipv6": sorted(v6.keys())})


@app.route("/api/v1/metrics", methods=["GET"])
def metrics_proxy():
    # Proxy to the Prometheus exporter the brain already runs.
    url = f"http://{cfg.metrics_host}:{cfg.metrics_port}/metrics"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = resp.read()
            ctype = resp.headers.get("Content-Type", "text/plain")
            return body, resp.getcode(), {"Content-Type": ctype}
    except Exception as e:
        abort(502, description=str(e))


@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "pin_dir": _PIN,
        "maps": {
            "allowlist_map": ALLOWLIST_FD is not None,
            "allowlist_map_v6": ALLOWLIST_V6_FD is not None,
            "blacklist_map": BLACKLIST_FD is not None,
            "blacklist_map_v6": BLACKLIST_V6_FD is not None,
        },
    })


# ---------------------------------------------------------------------------
# Run (systemd invokes this via ExecStart; use gunicorn/uvicorn for real prod)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host=cfg.api_host, port=cfg.api_port, debug=False)
