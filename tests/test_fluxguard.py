#!/usr/bin/env python3
"""
FluxGuard pure-Python unit tests.

These run on ANY OS with no root and no BPF — they exercise the parts of FluxGuard
that are pure logic. Tests that need the raw bpf(2) syscall layer (fluxguard_bpf, which
loads libc.so.6 at import) are skipped automatically on non-Linux hosts.

    python3 -m pytest tests/ -v
    # or, without pytest installed:
    python3 tests/test_fluxguard.py
"""

import os
import json
import tempfile

import pytest


# ---------------------------------------------------------------------------
# Token bucket — pure-Python mirror of token_bucket_check() in fluxguard_kern.c.
# Keep this in lock-step with the C helper (FIX-1 refill math).
# ---------------------------------------------------------------------------
KERN_PPS_LIMIT = 1000
NS_PER_SEC = 1_000_000_000


def token_bucket_check(tb, now):
    """Mirror of the C helper. tb = {'last_time', 'tokens'}. Returns 1=DROP, 0=PASS."""
    elapsed_ns = now - tb["last_time"]
    if elapsed_ns > 0:
        refill = (elapsed_ns * KERN_PPS_LIMIT) // NS_PER_SEC
        if refill > 0:
            tb["last_time"] = now
            tb["tokens"] += refill
            if tb["tokens"] > KERN_PPS_LIMIT:
                tb["tokens"] = KERN_PPS_LIMIT
    tb["tokens"] -= 1
    return 1 if tb["tokens"] < 0 else 0


class TestTokenBucket:
    def test_fresh_bucket_passes(self):
        tb = {"last_time": 0, "tokens": KERN_PPS_LIMIT}
        assert token_bucket_check(tb, 1) == 0

    def test_burst_within_limit_passes(self):
        # A full bucket at t=0 should allow KERN_PPS_LIMIT packets before dropping.
        tb = {"last_time": 0, "tokens": KERN_PPS_LIMIT}
        drops = sum(token_bucket_check(tb, 0) for _ in range(KERN_PPS_LIMIT))
        assert drops == 0

    def test_exhaustion_drops(self):
        tb = {"last_time": 0, "tokens": KERN_PPS_LIMIT}
        for _ in range(KERN_PPS_LIMIT):
            token_bucket_check(tb, 0)
        # No time elapsed → no refill → next packet drops.
        assert token_bucket_check(tb, 0) == 1

    def test_refill_one_second_restores_full_rate(self):
        tb = {"last_time": 0, "tokens": 0}
        # After 1s exactly KERN_PPS_LIMIT tokens are refilled (capped at the limit).
        assert token_bucket_check(tb, NS_PER_SEC) == 0
        assert tb["tokens"] == KERN_PPS_LIMIT - 1

    def test_refill_is_capped_at_limit(self):
        tb = {"last_time": 0, "tokens": KERN_PPS_LIMIT}
        # 10 seconds elapsed but tokens must not exceed KERN_PPS_LIMIT.
        token_bucket_check(tb, 10 * NS_PER_SEC)
        assert tb["tokens"] <= KERN_PPS_LIMIT

    def test_partial_refill(self):
        # Half a second → ~half the limit refilled.
        tb = {"last_time": 0, "tokens": 0}
        token_bucket_check(tb, NS_PER_SEC // 2)
        assert tb["tokens"] == (KERN_PPS_LIMIT // 2) - 1


# ---------------------------------------------------------------------------
# Config loader — pure stdlib, runs everywhere.
# ---------------------------------------------------------------------------
class TestConfig:
    def test_defaults_when_missing(self):
        from fluxguard_config import load_config
        cfg = load_config("/nonexistent/path/config.json")
        assert cfg.kern_pps_limit == 1000          # synced to kernel #define
        assert cfg.global_pps_limit == 500000
        assert cfg.metrics_port == 9090

    def test_no_pps_limit_drift(self):
        # config default MUST match the kernel constant to avoid the documented drift.
        from fluxguard_config import FluxGuardConfig
        assert FluxGuardConfig().kern_pps_limit == 1000

    def test_roundtrip(self):
        from fluxguard_config import FluxGuardConfig, load_config, save_config
        cfg = FluxGuardConfig(kern_pps_limit=1000, api_port=9999, verbose=True)
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            save_config(cfg, path)
            loaded = load_config(path)
            assert loaded.api_port == 9999
            assert loaded.verbose is True
        finally:
            os.remove(path)

    def test_partial_override_keeps_defaults(self):
        from fluxguard_config import load_config
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"api_port": 1234}, f)
            cfg = load_config(path)
            assert cfg.api_port == 1234
            assert cfg.metrics_port == 9090   # untouched → default
        finally:
            os.remove(path)


# ---------------------------------------------------------------------------
# BPF key round-trip — needs fluxguard_bpf, which loads libc.so.6 at import.
# Skipped automatically on non-Linux hosts. (importorskip only catches
# ImportError; ctypes.CDLL raises FileNotFoundError/OSError, so guard manually.)
# ---------------------------------------------------------------------------
try:
    import fluxguard_bpf as bpf
    _HAS_BPF = True
except Exception:  # OSError/FileNotFoundError on non-Linux, or missing libc
    bpf = None
    _HAS_BPF = False


@pytest.mark.skipif(not _HAS_BPF, reason="fluxguard_bpf needs libc.so.6 (Linux only)")
class TestBpfKey:
    def test_ipv4_roundtrip(self):
        for ip in ("10.0.1.5", "192.168.0.1", "255.255.255.255", "0.0.0.0"):
            assert bpf.key_to_ip(bpf.ip_to_key(ip)) == ip

    def test_ipv6_roundtrip(self):
        for ip in ("2001:db8::1", "::1", "fe80::1"):
            k = bpf.ip_to_key_v6(ip)
            import ipaddress
            assert bpf.key_to_ip_v6(k) == str(ipaddress.IPv6Address(ip))


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
