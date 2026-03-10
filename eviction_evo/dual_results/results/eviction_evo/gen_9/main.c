// BPF page cache eviction policy with network awareness.
// This file is evolved by ShinkaEvolve. The EVOLVE-BLOCK contains the
// eviction strategy that will be optimized to maximize throughput.
//
// Fixed infrastructure (outside EVOLVE-BLOCK):
//   - Includes, license, map definitions
//   - Network monitoring kprobe (tcp_recvmsg) that captures TCP metrics
//   - struct_ops registration at the end
//
// What the LLM can evolve (inside EVOLVE-BLOCK):
//   - Constants and thresholds (e.g., time windows, scoring weights)
//   - The eviction callback (bpf_evict_cb): decides per-folio evict vs keep
//   - folio_added: how new folios are classified and tracked
//   - folio_accessed: how re-accesses update metadata
//   - folio_evicted: cleanup on eviction
//   - evict_folios: the top-level eviction orchestration
//   - Any helper functions or additional data structures
//
// Available BPF APIs (from cache_ext_lib.bpf.h):
//   bpf_cache_ext_list_add(list, folio)        — add folio to head of list
//   bpf_cache_ext_list_add_tail(list, folio)    — add folio to tail of list
//   bpf_cache_ext_list_del(list, folio)         — remove folio from list
//   bpf_cache_ext_list_move(list, folio, tail)  — move folio within list (tail=false→head/front, tail=true→tail/back)
//   bpf_cache_ext_list_iterate(memcg, list, callback, eviction_ctx) — iterate list, callback returns EVICT_NODE or CONTINUE_ITER
//   bpf_cache_ext_list_iterate_extended(memcg, list, callback, opts, eviction_ctx) — iterate with continue_list for promotions
//   bpf_cache_ext_list_sample(memcg, list, callback, ratio, eviction_ctx) — sample random folios
//   bpf_cache_ext_ds_registry_new_list(memcg)   — allocate a new list, returns list handle
//
// Folio helpers:
//   folio_nr_pages(folio), folio_index(folio)
//   folio_test_uptodate/lru/dirty/writeback/unevictable(folio)
//
// Callback return values:
//   CACHE_EXT_EVICT_NODE    — evict this folio
//   CACHE_EXT_CONTINUE_ITER — keep this folio (skip)
//
// Network metrics available as globals (updated each tcp_recvmsg on port 9100):
//   last_packet_ts      — timestamp (ns) of last TCP packet on monitored port
//   net_prev_packet_ts  — timestamp (ns) of the packet before that (for inter-arrival delta)
//   net_recv_count      — total number of tcp_recvmsg calls on monitored port
//
// TCP connection quality (from struct tcp_sock of latest recv):
//   net_srtt_us         — smoothed RTT in usec (kernel stores srtt<<3, divide by 8 for true RTT)
//   net_mdev_us         — RTT mean deviation (jitter indicator) in usec
//
// TCP throughput counters (cumulative on the connection):
//   net_bytes_received  — total bytes received on the connection
//   net_bytes_acked     — total bytes acknowledged by remote (proxy for bytes sent)
//   net_segs_in         — total segments received
//   net_segs_out        — total segments sent
//   net_delivered       — total packets successfully delivered
//
// TCP congestion / flow-control state:
//   net_snd_cwnd        — congestion window size (segments)
//   net_snd_ssthresh    — slow-start threshold (segments)
//   net_rcv_wnd         — advertised receive window (bytes)
//   net_packets_out     — packets currently in flight (unacknowledged)
//
// TCP error / loss indicators:
//   net_total_retrans   — lifetime retransmissions on connection
//   net_retrans_out     — retransmitted segments currently in flight
//   net_lost            — segments considered lost
//
// Per-folio metadata in folio_metadata_map:
//   last_access_ts — timestamp (ns) of last access to this folio

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

// -- Per-folio metadata -------------------------------------------------------
struct net_folio_metadata {
    u64 last_access_ts;
    u32 access_count;        // number of times this folio was accessed
    u32 access_tier;         // tier classification (0=cold, 1=warm, 2=hot)
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);          // (u64)folio pointer
    __type(value, struct net_folio_metadata);
    __uint(max_entries, 1000000);
} folio_metadata_map SEC(".maps");

// -- Debug counters -----------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, u64);
} debug_counters SEC(".maps");

// -- Network state (updated by kprobe below) ----------------------------------
u64 last_packet_ts = 0;

// -- Extended network metrics (snapshot from tcp_sock per recv) ---------------
// Request counting / timing:
u64 net_recv_count = 0;        // total tcp_recvmsg calls on monitored port
u64 net_prev_packet_ts = 0;    // previous packet timestamp (for inter-arrival)
// TCP connection quality:
u32 net_srtt_us = 0;           // smoothed RTT in usec (kernel srtt<<3)
u32 net_mdev_us = 0;           // RTT mean deviation (jitter) in usec
// TCP throughput counters:
u64 net_bytes_received = 0;    // total bytes received on connection
u64 net_bytes_acked = 0;       // total bytes acked (proxy for sent)
u32 net_segs_in = 0;           // total segments received
u32 net_segs_out = 0;          // total segments sent
u32 net_delivered = 0;         // total delivered segments
// TCP congestion / flow-control:
u32 net_snd_cwnd = 0;          // congestion window (segments)
u32 net_snd_ssthresh = 0;      // slow-start threshold
u32 net_rcv_wnd = 0;           // receive window (bytes)
u32 net_packets_out = 0;       // packets currently in flight
// TCP error / loss:
u32 net_total_retrans = 0;     // lifetime retransmissions
u32 net_retrans_out = 0;       // retransmits currently in flight
u32 net_lost = 0;              // segments considered lost

// -- Helpers (fixed) ----------------------------------------------------------
static __always_inline void bump_counter(u32 idx) {
    u64 *val = bpf_map_lookup_elem(&debug_counters, &idx);
    if (val) __sync_fetch_and_add(val, 1);
}

static __always_inline bool is_folio_relevant(struct folio *folio) {
    if (!folio || !folio->mapping || !folio->mapping->host)
        return false;
    return inode_in_watchlist(folio->mapping->host->i_ino);
}

// EVOLVE-BLOCK-START
// -- Multi-tier list handles (evolved) -----------------------------------------
static u64 hot_list;
static u64 warm_list;
static u64 cold_list;

// =============================================================================
// EVICTION POLICY — Adaptive Recency Decay with Burst Protection
// =============================================================================

// -- Tunable constants --------------------------------------------------------
// Tier-specific base decay half-lives (time for score to halve)
#define DECAY_HALF_LIFE_COLD_NS  100000000ULL   // 100 ms (cold decays fast)
#define DECAY_HALF_LIFE_WARM_NS  400000000ULL   // 400 ms (warm moderate)
#define DECAY_HALF_LIFE_HOT_NS   800000000ULL   // 800 ms (hot decays slow)

// Network idle timeout
#define NET_IDLE_TIMEOUT_NS      5000000000ULL  // 5 s
// Access count threshold for hot
#define HOT_ACCESS_THRESHOLD     4
// Burst detection: inter-arrival time threshold
#define BURST_THRESHOLD_NS       5000000ULL     // 5 ms

// Eviction score thresholds (base values, scaled by congestion)
#define BASE_EVICT_THRESHOLD_COLD   150
#define BASE_EVICT_THRESHOLD_WARM   200
#define BASE_EVICT_THRESHOLD_HOT    100

// Congestion scaling for decay (higher = slower decay during congestion)
#define CONGESTION_DECAY_DAMPEN     500ULL

// Burst protection: freeze decay during bursts
#define BURST_DECAY_FREEZE_FACTOR   10ULL

// -- Helper: Compute network congestion score (0-1000 scale) --
static __always_inline u32 compute_congestion_score(void) {
    u32 score = 0;

    u32 rtt_us = net_srtt_us >> 3;
    if (rtt_us > 100000)
        score += 400;
    else if (rtt_us > 50000)
        score += 300;
    else if (rtt_us > 20000)
        score += 200;
    else if (rtt_us > 5000)
        score += 100;

    u32 mdev_us = net_mdev_us >> 3;
    if (mdev_us > 20000)
        score += 250;
    else if (mdev_us > 10000)
        score += 200;
    else if (mdev_us > 5000)
        score += 150;
    else if (mdev_us > 1000)
        score += 100;

    if (net_retrans_out > 5 || net_lost > 0)
        score += 200;
    else if (net_total_retrans > 10)
        score += 150;
    else if (net_total_retrans > 0)
        score += 50;

    if (net_packets_out > 0 && net_snd_cwnd > 0) {
        if (net_packets_out * 2 > net_snd_cwnd)
            score += 150;
        else if (net_packets_out * 3 > net_snd_cwnd)
            score += 100;
    }

    return (score > 1000) ? 1000 : score;
}

// -- Helper: Detect burst mode --
static __always_inline bool is_burst(u64 now) {
    if (net_prev_packet_ts == 0)
        return false;
    u64 inter_arrival_ns = (now > net_prev_packet_ts) ?
        (now - net_prev_packet_ts) : 0;
    return (inter_arrival_ns < BURST_THRESHOLD_NS);
}

// -- Helper: Compute adaptive decay rate based on congestion and burst mode --
// Returns decay half-life in nanoseconds (higher = slower decay = more protection)
static __always_inline u64 get_adaptive_decay_half_life(u32 tier, u32 congestion, bool in_burst) {
    u64 base_half_life;
    
    if (tier == 2)  // hot
        base_half_life = DECAY_HALF_LIFE_HOT_NS;
    else if (tier == 1)  // warm
        base_half_life = DECAY_HALF_LIFE_WARM_NS;
    else  // cold
        base_half_life = DECAY_HALF_LIFE_COLD_NS;

    // Burst protection: freeze decay (multiply half-life by large factor)
    if (in_burst) {
        base_half_life = base_half_life * BURST_DECAY_FREEZE_FACTOR;
    }

    // Congestion-based damping: high congestion slows decay
    // Scale from base to base * 2 depending on congestion
    u64 congestion_factor = (congestion * 1000) / CONGESTION_DECAY_DAMPEN;
    if (congestion_factor > 1000)
        congestion_factor = 1000;
    
    base_half_life = base_half_life + (base_half_life * congestion_factor) / 1000;

    return base_half_life;
}

// -- Helper: Compute exponential decay score --
// Score starts at 1000, decays exponentially based on age and half-life
// Formula: score = 1000 * (0.5) ^ (age / half_life)
// Approximated with integer arithmetic
static __always_inline u32 compute_decay_score(u64 age_ns, u64 half_life_ns) {
    if (age_ns == 0)
        return 1000;
    
    // Clamp to prevent overflow
    if (age_ns > half_life_ns * 10)
        return 0;
    
    // Compute (age / half_life) as fixed-point (scaled by 256)
    u64 decay_factor = (age_ns * 256) / half_life_ns;
    
    // Approximate 2^x using bit shifts and linear interpolation
    // For small x, 2^x ≈ 1 + x*ln(2)
    // We use a lookup-like approach with bit shifts
    u32 score = 1000;
    
    // Each bit represents a power of 2
    // decay_factor in [0, 256] means we can have up to 8 halvings
    if (decay_factor >= 256) {
        score = score >> 1;  // 0.5x
        decay_factor -= 256;
    }
    if (decay_factor >= 128) {
        score = score >> 1;
        decay_factor -= 128;
    }
    if (decay_factor >= 64) {
        score = score >> 1;
        decay_factor -= 64;
    }
    if (decay_factor >= 32) {
        score = score >> 1;
        decay_factor -= 32;
    }
    if (decay_factor >= 16) {
        score = score >> 1;
        decay_factor -= 16;
    }
    if (decay_factor >= 8) {
        score = score >> 1;
        decay_factor -= 8;
    }
    if (decay_factor >= 4) {
        score = score >> 1;
        decay_factor -= 4;
    }
    if (decay_factor >= 2) {
        score = score >> 1;
        decay_factor -= 2;
    }
    if (decay_factor >= 1) {
        // Linear interpolation for fractional part
        score = score - (score >> 1);  // Approximate 0.707x
    }

    return score;
}

// -- Helper: Compute frequency bonus (compounds with access count) --
static __always_inline u32 compute_frequency_bonus(u32 access_count) {
    if (access_count >= 6)
        return 400;
    else if (access_count >= 5)
        return 350;
    else if (access_count >= 4)
        return 300;
    else if (access_count >= 3)
        return 200;
    else if (access_count >= 2)
        return 100;
    else
        return 0;
}

// -- Helper: Get adaptive eviction threshold based on congestion --
static __always_inline u32 get_evict_threshold(u32 tier, u32 congestion) {
    u32 base_threshold;
    
    if (tier == 2)  // hot
        base_threshold = BASE_EVICT_THRESHOLD_HOT;
    else if (tier == 1)  // warm
        base_threshold = BASE_EVICT_THRESHOLD_WARM;
    else  // cold
        base_threshold = BASE_EVICT_THRESHOLD_COLD;

    // Scale threshold inversely with congestion:
    // High congestion → higher threshold (keep more pages)
    // Low congestion → lower threshold (evict more aggressively)
    u32 congestion_adjustment = (congestion * base_threshold) / 1000;
    
    return base_threshold + congestion_adjustment;
}

// -- Eviction callback for cold_list --
static int bpf_evict_cold_cb(int idx, struct cache_ext_list_node *node) {
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta)
        return CACHE_EXT_EVICT_NODE;

    if (folio_test_dirty(node->folio) || folio_test_writeback(node->folio))
        return CACHE_EXT_CONTINUE_ITER;

    u64 age_ns = (now > meta->last_access_ts) ? (now - meta->last_access_ts) : 0;
    u32 congestion = compute_congestion_score();
    bool in_burst = is_burst(now);

    u64 half_life = get_adaptive_decay_half_life(0, congestion, in_burst);
    u32 decay_score = compute_decay_score(age_ns, half_life);
    u32 freq_bonus = compute_frequency_bonus(meta->access_count);
    u32 total_score = decay_score + freq_bonus;

    u32 threshold = get_evict_threshold(0, congestion);

    if (total_score < threshold)
        return CACHE_EXT_EVICT_NODE;

    return CACHE_EXT_CONTINUE_ITER;
}

// -- Eviction callback for warm_list --
static int bpf_evict_warm_cb(int idx, struct cache_ext_list_node *node) {
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta)
        return CACHE_EXT_EVICT_NODE;

    if (folio_test_dirty(node->folio) || folio_test_writeback(node->folio))
        return CACHE_EXT_CONTINUE_ITER;

    u64 age_ns = (now > meta->last_access_ts) ? (now - meta->last_access_ts) : 0;
    u32 congestion = compute_congestion_score();
    bool in_burst = is_burst(now);

    u64 half_life = get_adaptive_decay_half_life(1, congestion, in_burst);
    u32 decay_score = compute_decay_score(age_ns, half_life);
    u32 freq_bonus = compute_frequency_bonus(meta->access_count);
    u32 total_score = decay_score + freq_bonus;

    u32 threshold = get_evict_threshold(1, congestion);

    if (total_score < threshold)
        return CACHE_EXT_EVICT_NODE;

    return CACHE_EXT_CONTINUE_ITER;
}

// -- Eviction callback for hot_list --
static int bpf_evict_hot_cb(int idx, struct cache_ext_list_node *node) {
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta)
        return CACHE_EXT_EVICT_NODE;

    if (folio_test_dirty(node->folio) || folio_test_writeback(node->folio))
        return CACHE_EXT_CONTINUE_ITER;

    u64 age_ns = (now > meta->last_access_ts) ? (now - meta->last_access_ts) : 0;
    u32 congestion = compute_congestion_score();
    bool in_burst = is_burst(now);

    u64 half_life = get_adaptive_decay_half_life(2, congestion, in_burst);
    u32 decay_score = compute_decay_score(age_ns, half_life);
    u32 freq_bonus = compute_frequency_bonus(meta->access_count);
    u32 total_score = decay_score + freq_bonus;

    u32 threshold = get_evict_threshold(2, congestion);

    if (total_score < threshold)
        return CACHE_EXT_EVICT_NODE;

    return CACHE_EXT_CONTINUE_ITER;
}

// -- struct_ops: init ---------------------------------------------------------
s32 BPF_STRUCT_OPS_SLEEPABLE(evolved_init, struct mem_cgroup *memcg)
{
    hot_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (!hot_list)
        return -1;

    warm_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (!warm_list)
        return -1;

    cold_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (!cold_list)
        return -1;

    return 0;
}

// -- struct_ops: evict_folios -------------------------------------------------
void BPF_STRUCT_OPS(evolved_evict_folios,
                    struct cache_ext_eviction_ctx *eviction_ctx,
                    struct mem_cgroup *memcg)
{
    bump_counter(0);

    // Evict from cold list first (most aggressive)
    bpf_cache_ext_list_iterate(memcg, cold_list, bpf_evict_cold_cb, eviction_ctx);

    // Then warm list
    bpf_cache_ext_list_iterate(memcg, warm_list, bpf_evict_warm_cb, eviction_ctx);

    // Finally hot list (most conservative)
    bpf_cache_ext_list_iterate(memcg, hot_list, bpf_evict_hot_cb, eviction_ctx);
}

// -- struct_ops: folio_added --------------------------------------------------
void BPF_STRUCT_OPS(evolved_folio_added, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    u64 key = (u64)folio;

    int ret = bpf_cache_ext_list_add_tail(cold_list, folio);
    if (ret != 0) {
        bump_counter(1);
        return;
    }

    struct net_folio_metadata new_meta = {
        .last_access_ts = bpf_ktime_get_ns(),
        .access_count  = 1,
        .access_tier   = 0,
    };
    bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
    bump_counter(2);
}

// -- struct_ops: folio_accessed -----------------------------------------------
void BPF_STRUCT_OPS(evolved_folio_accessed, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    u64 key = (u64)folio;
    u64 now = bpf_ktime_get_ns();

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta) {
        bpf_cache_ext_list_add_tail(cold_list, folio);
        struct net_folio_metadata new_meta = {
            .last_access_ts = now,
            .access_count  = 1,
            .access_tier   = 0,
        };
        bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
        bump_counter(3);
        return;
    }

    meta->last_access_ts = now;
    meta->access_count += 1;

    u32 old_tier = meta->access_tier;
    if (meta->access_count >= HOT_ACCESS_THRESHOLD)
        meta->access_tier = 2;
    else if (meta->access_count >= 2)
        meta->access_tier = 1;
    else
        meta->access_tier = 0;

    if (meta->access_tier > old_tier) {
        bpf_cache_ext_list_del(folio);

        if (meta->access_tier == 2) {
            bpf_cache_ext_list_add(hot_list, folio);
        } else if (meta->access_tier == 1) {
            bpf_cache_ext_list_add(warm_list, folio);
        }
    } else {
        if (meta->access_tier == 2)
            bpf_cache_ext_list_move(hot_list, folio, false);
        else if (meta->access_tier == 1)
            bpf_cache_ext_list_move(warm_list, folio, false);
        else
            bpf_cache_ext_list_move(cold_list, folio, false);
    }

    bump_counter(4);
}

// -- struct_ops: folio_evicted ------------------------------------------------
void BPF_STRUCT_OPS(evolved_folio_evicted, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    bpf_cache_ext_list_del(folio);

    u64 key = (u64)folio;
    bpf_map_delete_elem(&folio_metadata_map, &key);
    bump_counter(5);
}

// EVOLVE-BLOCK-END

// =============================================================================
// NETWORK MONITORING (fixed — not evolved)
// =============================================================================

SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    // Monitor the net_leveldb_server port (9100) and common DB ports
    if (sport == 9100 || sport == 9001 || sport == 9002) {
        // Basic identification
        net_prev_packet_ts = last_packet_ts;
        last_packet_ts = bpf_ktime_get_ns();
        net_recv_count += 1;

        // Read TCP metrics from tcp_sock (sock is embedded at offset 0)
        struct tcp_sock *tp = (struct tcp_sock *)sk;

        // Connection quality
        net_srtt_us        = BPF_CORE_READ(tp, srtt_us);
        net_mdev_us        = BPF_CORE_READ(tp, mdev_us);

        // Throughput counters
        net_bytes_received = BPF_CORE_READ(tp, bytes_received);
        net_bytes_acked    = BPF_CORE_READ(tp, bytes_acked);
        net_segs_in        = BPF_CORE_READ(tp, segs_in);
        net_segs_out       = BPF_CORE_READ(tp, segs_out);
        net_delivered      = BPF_CORE_READ(tp, delivered);

        // Congestion / flow control
        net_snd_cwnd       = BPF_CORE_READ(tp, snd_cwnd);
        net_snd_ssthresh   = BPF_CORE_READ(tp, snd_ssthresh);
        net_rcv_wnd        = BPF_CORE_READ(tp, rcv_wnd);
        net_packets_out    = BPF_CORE_READ(tp, packets_out);

        // Error / loss
        net_total_retrans  = BPF_CORE_READ(tp, total_retrans);
        net_retrans_out    = BPF_CORE_READ(tp, retrans_out);
        net_lost           = BPF_CORE_READ(tp, lost);
    }
    return 0;
}

// -- struct_ops registration --------------------------------------------------
SEC(".struct_ops.link")
struct cache_ext_ops evolved_ops = {
    .init           = (void *)evolved_init,
    .evict_folios   = (void *)evolved_evict_folios,
    .folio_added    = (void *)evolved_folio_added,
    .folio_evicted  = (void *)evolved_folio_evicted,
    .folio_accessed = (void *)evolved_folio_accessed,
    .admit_folio    = (void *)0,
};