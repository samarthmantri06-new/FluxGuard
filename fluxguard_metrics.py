#!/usr/bin/env python3
"""
FluxGuard Phase 11 — Prometheus text metrics over HTTP supporting IPv4 and IPv6.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Set

class MetricsState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._packets_by_ip: Dict[str, int] = {}
        self._blocked_ips_set: Set[str] = set()
        self._blocked_ips = 0
        self._block_events = 0
        self._unblock_events = 0
        self._global_pps_exceeded = 0

    def update_snapshot(self, packets_by_ip: Dict[str, int], blocked_ips: int) -> None:
        with self._lock:
            self._packets_by_ip = dict(packets_by_ip)
            self._blocked_ips = int(blocked_ips)

    def update_blocked_set(self, blocked_set: Set[str]) -> None:
        with self._lock:
            self._blocked_ips_set = set(blocked_set)

    def inc_block_events(self) -> None:
        with self._lock:
            self._block_events += 1

    def inc_unblock_events(self) -> None:
        with self._lock:
            self._unblock_events += 1
            
    def inc_global_pps_exceeded(self) -> None:
        with self._lock:
            self._global_pps_exceeded += 1

    def render_prometheus_text(self) -> str:
        with self._lock:
            packets = sorted(self._packets_by_ip.items())
            blocked = self._blocked_ips
            blocked_set = sorted(list(self._blocked_ips_set))
            be = self._block_events
            ue = self._unblock_events
            gpps = self._global_pps_exceeded

        lines = [
            "# HELP fluxguard_meter_packets Current packet counter per source IP (IPv4 or IPv6) from meter_maps.",
            "# TYPE fluxguard_meter_packets gauge",
        ]
        for ip, cnt in packets:
            safe = ip.replace("\\", "\\\\").replace('"', '\\"')
            lines.append('fluxguard_meter_packets{ip="%s"} %d' % (safe, cnt))
        
        lines.extend([
            "# HELP fluxguard_blocked_ips Number of IPs currently blocked by the brain.",
            "# TYPE fluxguard_blocked_ips gauge",
            "fluxguard_blocked_ips %d" % blocked,
        ])
        
        if blocked_set:
            lines.extend([
                "# HELP fluxguard_blocked_ip Per-IP block status (1 = currently blocked, supports IPv4/IPv6).",
                "# TYPE fluxguard_blocked_ip gauge",
            ])
            for ip in blocked_set:
                safe = ip.replace("\\", "\\\\").replace('"', '\\"')
                lines.append('fluxguard_blocked_ip{ip="%s"} 1' % safe)

        lines.extend([
            "# HELP fluxguard_block_events_total Cumulative block events.",
            "# TYPE fluxguard_block_events_total counter",
            "fluxguard_block_events_total %d" % be,
            "# HELP fluxguard_unblock_events_total Cumulative unblock events.",
            "# TYPE fluxguard_unblock_events_total counter",
            "fluxguard_unblock_events_total %d" % ue,
            "# HELP fluxguard_global_pps_exceeded_total Global Shields-Up events triggered.",
            "# TYPE fluxguard_global_pps_exceeded_total counter",
            "fluxguard_global_pps_exceeded_total %d" % gpps,
            "",
        ])
        return "\n".join(lines)

def start_metrics_server(state: MetricsState, host: str, port: int) -> threading.Thread:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return
        def do_GET(self) -> None:
            if self.path != "/metrics":
                self.send_response(404)
                self.end_headers()
                return
            body = state.render_prometheus_text().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def run() -> None:
        server = HTTPServer((host, port), Handler)
        server.serve_forever()

    thread = threading.Thread(target=run, name="fluxguard-metrics", daemon=True)
    thread.start()
    return thread
