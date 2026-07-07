// ==============================================================================
// FluxGuard Phase 11 — XDP Kernel Program
// Fixes applied vs Phase 10:
//   FIX-1: Token bucket refill math corrected to exact rate
//           elapsed_ns * KERN_PPS_LIMIT / 1e9  (was broken: elapsed_ns / 10000)
//   FIX-2: Full IPv6 pipeline — meter, allowlist, blacklist, rate limiting
//           with parallel maps for 128-bit source addresses
//   RETAIN: LRU_HASH for meter/rate maps (prevents table exhaustion under spoof)
//   RETAIN: PERCPU_ARRAY global counter (lock-free, fully atomic per-CPU)
//   RETAIN: BPF Ring Buffer for autonomous block event stream
//   RETAIN: In-kernel auto-blacklist on token exhaustion
// ==============================================================================

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES        65536
#define MAX_ENTRIES_V6     16384

// FIX-1: Correct rate limit constants
// 1000 packets/sec per IP — refill formula: elapsed_ns * KERN_PPS_LIMIT / 1_000_000_000
#define KERN_PPS_LIMIT     1000LL
#define GLOBAL_PPS_LIMIT   500000LL

// ─────────────────────────────────────────────
// IPv4 Maps
// ─────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u32);
} blacklist_map SEC(".maps");

// LRU prevents table exhaustion under random-source flood attacks
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u32);
} meter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} allowlist_map SEC(".maps");

struct token_bucket {
    __u64 last_time;
    __s64 tokens;
};

// LRU rate map — evicts least recently seen IPs automatically
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct token_bucket);
} rate_map SEC(".maps");

// ─────────────────────────────────────────────
// IPv6 Maps  (FIX-2: new parallel IPv6 pipeline)
// ─────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES_V6);
    __type(key, struct in6_addr);
    __type(value, __u32);
} blacklist_map_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES_V6);
    __type(key, struct in6_addr);
    __type(value, __u32);
} meter_map_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct in6_addr);
    __type(value, __u32);
} allowlist_map_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES_V6);
    __type(key, struct in6_addr);
    __type(value, struct token_bucket);
} rate_map_v6 SEC(".maps");

// ─────────────────────────────────────────────
// Shared Infrastructure Maps
// ─────────────────────────────────────────────

// PERCPU_ARRAY: lock-free per-CPU global packet counter
// No TOCTOU race — each CPU owns its own slot exclusively
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_counter_map SEC(".maps");

// Global token bucket for Shields-Up mode (aggregate PPS cap)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct token_bucket);
} global_rate_map SEC(".maps");

// Protocol filter — e.g., drop all UDP (proto=17)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u8);
    __type(value, __u32);
} proto_filter_map SEC(".maps");

// Ring buffer — streams autonomous block events to userspace dashboard
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} event_ringbuf SEC(".maps");

// ─────────────────────────────────────────────
// Event struct for ring buffer
// ─────────────────────────────────────────────

#define AF_INET4 4
#define AF_INET6 6

struct attack_event {
    __u8  af;           // AF_INET4 or AF_INET6
    __u8  reason;       // 1 = KERN_AUTO_BLOCK, 2 = GLOBAL_SHIELDS_UP
    __u16 pad;
    __u32 src_v4;       // valid if af == AF_INET4
    __u8  src_v6[16];   // valid if af == AF_INET6
    __u64 timestamp;
};

// ─────────────────────────────────────────────
// Helper: run token bucket rate check
// FIX-1: Correct refill math — exactly KERN_PPS_LIMIT tokens per second
// ─────────────────────────────────────────────

static __always_inline int token_bucket_check(struct token_bucket *tb, __u64 now)
{
    __u64 elapsed_ns = now - tb->last_time;

    // Refill: exactly KERN_PPS_LIMIT tokens per second
    // 1 token = 1 packet allowed; refill proportional to elapsed time
    if (elapsed_ns > 0) {
        // elapsed_ns is unsigned and > 0 here; BPF target rejects signed 64-bit
        // division, so compute the refill with unsigned div (identical result).
        __u64 refill = (elapsed_ns * (__u64)KERN_PPS_LIMIT) / 1000000000ULL;
        if (refill > 0) {
            tb->last_time = now;
            tb->tokens += (__s64)refill;
            if (tb->tokens > KERN_PPS_LIMIT)
                tb->tokens = KERN_PPS_LIMIT;
        }
    }

    tb->tokens -= 1;
    return (tb->tokens < 0) ? 1 : 0; // 1 = DROP
}

// ─────────────────────────────────────────────
// XDP Main Filter
// ─────────────────────────────────────────────

SEC("xdp")
int fluxguard_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u64 now      = bpf_ktime_get_ns();

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __be16 proto = eth->h_proto;

    // ─── Global per-CPU packet counter (shields-up detection) ─────────────
    __u32 gc_key = 0;
    __u64 *gc = bpf_map_lookup_elem(&global_counter_map, &gc_key);
    if (gc) (*gc)++;

    // ─── Global Shields-Up token bucket ───────────────────────────────────
    __u32 zero = 0;
    struct token_bucket *gtb = bpf_map_lookup_elem(&global_rate_map, &zero);
    if (gtb) {
        __u64 g_elapsed = now - gtb->last_time;
        if (g_elapsed > 100000000ULL) { // refill every 100ms
            // g_elapsed is unsigned and > 0 here; unsigned div (BPF has no signed div).
            __u64 g_refill = (g_elapsed * (__u64)GLOBAL_PPS_LIMIT) / 1000000000ULL;
            gtb->last_time = now;
            gtb->tokens += (__s64)g_refill;
            if (gtb->tokens > GLOBAL_PPS_LIMIT)
                gtb->tokens = GLOBAL_PPS_LIMIT;
        }
        gtb->tokens -= 1;
        if (gtb->tokens < 0) {
            if (gtb->tokens < -100000LL)
                gtb->tokens = -100000LL;
            return XDP_DROP;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // IPv4 Path
    // ═══════════════════════════════════════════════════════════════════════
    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        __u32 src_ip = iph->saddr;
        __u8  ip_proto = iph->protocol;

        // 1. Allowlist bypass
        if (bpf_map_lookup_elem(&allowlist_map, &src_ip))
            return XDP_PASS;

        // 2. Protocol filter
        __u32 *proto_action = bpf_map_lookup_elem(&proto_filter_map, &ip_proto);
        if (proto_action && *proto_action == 1)
            return XDP_DROP;

        // 3. Meter (packet counter per IP)
        __u32 *cnt = bpf_map_lookup_elem(&meter_map, &src_ip);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        } else {
            __u32 init = 1;
            bpf_map_update_elem(&meter_map, &src_ip, &init, BPF_ANY);
        }

        // 4. Blacklist check
        if (bpf_map_lookup_elem(&blacklist_map, &src_ip))
            return XDP_DROP;

        // 5. Per-IP token bucket (FIX-1 refill math applied via helper)
        struct token_bucket *tb = bpf_map_lookup_elem(&rate_map, &src_ip);
        if (tb) {
            if (token_bucket_check(tb, now)) {
                // Auto-blacklist this IP in-kernel
                __u32 bval = 1;
                bpf_map_update_elem(&blacklist_map, &src_ip, &bval, BPF_ANY);

                // Emit ring buffer event
                struct attack_event *ev = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*ev), 0);
                if (ev) {
                    ev->af        = AF_INET4;
                    ev->reason    = 1;
                    ev->pad       = 0;
                    ev->src_v4    = src_ip;
                    ev->timestamp = now;
                    bpf_ringbuf_submit(ev, 0);
                }
                return XDP_DROP;
            }
        } else {
            struct token_bucket new_tb = {};
            new_tb.last_time = now;
            new_tb.tokens    = KERN_PPS_LIMIT - 1;
            bpf_map_update_elem(&rate_map, &src_ip, &new_tb, BPF_ANY);
        }

        return XDP_PASS;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // IPv6 Path  (FIX-2: new — mirrors IPv4 logic with 128-bit keys)
    // ═══════════════════════════════════════════════════════════════════════
    if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;

        struct in6_addr src6 = ip6h->saddr;
        __u8 ip6_proto = ip6h->nexthdr;

        // 1. Allowlist bypass
        if (bpf_map_lookup_elem(&allowlist_map_v6, &src6))
            return XDP_PASS;

        // 2. Protocol filter (shared map, same proto numbers)
        __u32 *proto_action = bpf_map_lookup_elem(&proto_filter_map, &ip6_proto);
        if (proto_action && *proto_action == 1)
            return XDP_DROP;

        // 3. Meter
        __u32 *cnt6 = bpf_map_lookup_elem(&meter_map_v6, &src6);
        if (cnt6) {
            __sync_fetch_and_add(cnt6, 1);
        } else {
            __u32 init = 1;
            bpf_map_update_elem(&meter_map_v6, &src6, &init, BPF_ANY);
        }

        // 4. Blacklist check
        if (bpf_map_lookup_elem(&blacklist_map_v6, &src6))
            return XDP_DROP;

        // 5. Per-IP token bucket (same FIX-1 helper)
        struct token_bucket *tb6 = bpf_map_lookup_elem(&rate_map_v6, &src6);
        if (tb6) {
            if (token_bucket_check(tb6, now)) {
                __u32 bval = 1;
                bpf_map_update_elem(&blacklist_map_v6, &src6, &bval, BPF_ANY);

                struct attack_event *ev = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*ev), 0);
                if (ev) {
                    ev->af        = AF_INET6;
                    ev->reason    = 1;
                    ev->pad       = 0;
                    ev->src_v4    = 0;
                    __builtin_memcpy(ev->src_v6, &src6, 16);
                    ev->timestamp = now;
                    bpf_ringbuf_submit(ev, 0);
                }
                return XDP_DROP;
            }
        } else {
            struct token_bucket new_tb = {};
            new_tb.last_time = now;
            new_tb.tokens    = KERN_PPS_LIMIT - 1;
            bpf_map_update_elem(&rate_map_v6, &src6, &new_tb, BPF_ANY);
        }

        return XDP_PASS;
    }

    // All other EtherTypes (ARP, etc.) — pass through
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
