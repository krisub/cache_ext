// BPF page cache eviction policy using kernel-libvulcan abstractions.
// This file is evolved by ShinkaEvolve.  The EVOLVE-BLOCK contains
// per-feature listener configuration, the scoring function, and
// struct_ops callbacks.
//
// =======================================================================
// ARCHITECTURE -- Separation of Duties (libvulcan for kernelspace)
// =======================================================================
//
// FIXED infrastructure (outside EVOLVE-BLOCK):
//   - Includes, license, map definitions
//   - Vulcan listener state maps (MinMax, EWMA, RollingWindow, Average
//     for each global feature)
//   - Per-folio metadata map (with embedded per-folio listeners)
//   - Network monitoring kprobe (tcp_recvmsg) -- updates raw globals AND
//     calls vulcan_update_feature for each global feature using gf_configs[]
//   - struct_ops registration
//
// Library headers (cache_ext/vulcan_bpf/):
//   - vulcan_bpf.h     -- listener primitives, config types, per-folio helpers
//   - vulcan_feature.h  -- feature dispatch (vulcan_update_feature) and
//                          accessor functions (vulcan_get_ewma, etc.)
//
// BASELINE: The eviction policy below mimics cache_ext_sampling.bpf.c (LFU).
// Evolution starts from this baseline. The LLM may add network-aware logic
// via vulcan_get_* accessors; gf_configs and folio_cfg control which listeners
// are active. DO NOT modify networking infrastructure (kprobe, maps, includes).
//
// What the LLM evolves (inside EVOLVE-BLOCK):
//   - gf_configs[] -- enable listeners for network metrics (baseline: all 0)
//   - folio_cfg    -- per-folio interval tracking (baseline: disabled)
//   - SAMPLE_SIZE  -- candidates per eviction slot
//   - bpf_score_fn(node) -> s64 -- lower = evict first; S64_MAX = protect
//   - struct_ops callbacks (init, evict_folios, folio_added, folio_accessed,
//     folio_evicted) — evolve eviction logic only
//
// =======================================================================
// GLOBAL FEATURE ACCESSOR API  (usable inside bpf_score_fn)
// =======================================================================
//
// Only returns meaningful values for listeners enabled in gf_configs[].
// Calling an accessor for a disabled listener safely returns 0.
//
//   vulcan_get_min(GF_xxx)              -- observed minimum  (needs MINMAX)
//   vulcan_get_max(GF_xxx)              -- observed maximum  (needs MINMAX)
//   vulcan_get_ewma(GF_xxx)             -- EWMA value        (needs EWMA)
//   vulcan_get_avg(GF_xxx)              -- running average    (needs AVG)
//   vulcan_get_latest(GF_xxx)           -- most recent value  (needs RW)
//   vulcan_get_kth_recent(GF_xxx, k)    -- k-th most recent   (needs RW)
//   vulcan_get_window_avg(GF_xxx)       -- rolling-window avg (needs RW)
//   vulcan_get_window_count(GF_xxx)     -- entries in window   (needs RW)
//
// Global feature IDs:
//   GF_SRTT_US          -- smoothed RTT (usec, kernel srtt<<3)
//   GF_MDEV_US          -- RTT mean deviation / jitter (usec)
//   GF_SND_CWND         -- congestion window (segments)
//   GF_SND_SSTHRESH     -- slow-start threshold (segments)
//   GF_RCV_WND          -- advertised receive window (bytes)
//   GF_PACKETS_OUT      -- packets currently in flight
//   GF_TOTAL_RETRANS    -- lifetime retransmissions
//   GF_RETRANS_OUT      -- retransmits currently in flight
//   GF_LOST             -- segments considered lost
//   GF_SEGS_IN          -- total TCP segments received
//   GF_SEGS_OUT         -- total TCP segments sent
//   GF_DELIVERED        -- total packets delivered
//   GF_BYTES_RECEIVED   -- total bytes received
//   GF_BYTES_ACKED      -- total bytes acknowledged
//   GF_INTER_ARRIVAL    -- inter-packet arrival time (ns)
//   GF_RECV_COUNT       -- total tcp_recvmsg calls
//
// =======================================================================
// PER-FOLIO METADATA  (struct vulcan_folio_metadata, in folio_metadata_map)
// =======================================================================
//
//   meta->access_count             -- number of accesses (u32)
//   meta->last_access_ts           -- timestamp of last access (u64 ns)
//   meta->prev_access_ts           -- timestamp of access before that (u64 ns)
//   meta->interval_minmax.min_val  -- min inter-access interval (needs MINMAX)
//   meta->interval_minmax.max_val  -- max inter-access interval (needs MINMAX)
//   meta->interval_ewma.value      -- EWMA of inter-access interval (needs EWMA)
//
// Per-folio helpers (call from folio hooks):
//   vulcan_folio_init(now)                     -> initialized metadata struct
//   vulcan_folio_on_access(meta, now, &cfg)    -- update enabled per-folio listeners
//
// =======================================================================
// LISTENER CONFIGURATION API
// =======================================================================
//
// Listener bitmask flags (OR together in .listener_mask):
//   VULCAN_LISTENER_MINMAX  -- enable MinMax listener
//   VULCAN_LISTENER_EWMA    -- enable EWMA listener (set .ewma_alpha)
//   VULCAN_LISTENER_AVG     -- enable running Average listener
//   VULCAN_LISTENER_RW      -- enable RollingWindow listener (set .rw_size)
//   VULCAN_LISTENER_ALL     -- shorthand for all four
//
// Per-feature config struct (struct vulcan_feature_config):
//   .listener_mask  -- OR of VULCAN_LISTENER_* flags
//   .ewma_alpha     -- [0..1000] EWMA smoothing (only if EWMA enabled)
//   .rw_size        -- [1..16] rolling window size (only if RW enabled)
//
// Per-folio config struct (struct vulcan_folio_config):
//   .listener_mask  -- OR of VULCAN_LISTENER_MINMAX, VULCAN_LISTENER_EWMA
//   .ewma_alpha     -- [0..1000] EWMA smoothing for per-folio intervals
//
// =======================================================================
// RAW NETWORK GLOBALS  (still available for direct access)
// =======================================================================
//
//   last_packet_ts, net_prev_packet_ts, net_recv_count
//   net_srtt_us, net_mdev_us
//   net_bytes_received, net_bytes_acked, net_segs_in, net_segs_out, net_delivered
//   net_snd_cwnd, net_snd_ssthresh, net_rcv_wnd, net_packets_out
//   net_total_retrans, net_retrans_out, net_lost
//
// =======================================================================
// BPF LIST / EVICTION APIs
// =======================================================================
//
//   bpf_cache_ext_list_add(list, folio)
//   bpf_cache_ext_list_add_tail(list, folio)
//   bpf_cache_ext_list_del(folio)
//   bpf_cache_ext_list_move(list, folio, tail)
//   bpf_cache_ext_list_sample(memcg, list, score_fn, &opts, ctx)
//   bpf_cache_ext_list_iterate(memcg, list, cb, ctx)
//   bpf_cache_ext_ds_registry_new_list(memcg)
//
// Folio helpers:
//   folio_test_dirty/writeback/unevictable/uptodate/lru(folio)
//   folio_nr_pages(folio), folio_index(folio)
//
// =======================================================================

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"
#include "vulcan_bpf/vulcan_bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

// =============================================================================
// GLOBAL FEATURE IDS
// =============================================================================

#define VULCAN_NUM_GLOBAL_FEATURES 16

enum vulcan_global_feature {
    GF_SRTT_US = 0,
    GF_MDEV_US,
    GF_SND_CWND,
    GF_SND_SSTHRESH,
    GF_RCV_WND,
    GF_PACKETS_OUT,
    GF_TOTAL_RETRANS,
    GF_RETRANS_OUT,
    GF_LOST,
    GF_SEGS_IN,
    GF_SEGS_OUT,
    GF_DELIVERED,
    GF_BYTES_RECEIVED,
    GF_BYTES_ACKED,
    GF_INTER_ARRIVAL,
    GF_RECV_COUNT,
    GF_COUNT,
};

// =============================================================================
// MAPS  (BPF maps that vulcan_feature.h dispatches into)
// =============================================================================

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct vulcan_folio_metadata);
    __uint(max_entries, 1000000);
} folio_metadata_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, struct vulcan_minmax);
} vulcan_gminmax SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, struct vulcan_ewma);
} vulcan_gewma SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, struct vulcan_rolling_window);
} vulcan_grw SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, struct vulcan_avg);
} vulcan_gavg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, u64);
} debug_counters SEC(".maps");

// Include feature dispatch layer (needs maps declared above)
#include "vulcan_bpf/vulcan_feature.h"

// =============================================================================
// RAW NETWORK GLOBALS (updated by kprobe)
// =============================================================================

u64 last_packet_ts     = 0;
u64 net_prev_packet_ts = 0;
u64 net_recv_count     = 0;
u32 net_srtt_us        = 0;
u32 net_mdev_us        = 0;
u64 net_bytes_received = 0;
u64 net_bytes_acked    = 0;
u32 net_segs_in        = 0;
u32 net_segs_out       = 0;
u32 net_delivered      = 0;
u32 net_snd_cwnd       = 0;
u32 net_snd_ssthresh   = 0;
u32 net_rcv_wnd        = 0;
u32 net_packets_out    = 0;
u32 net_total_retrans  = 0;
u32 net_retrans_out    = 0;
u32 net_lost           = 0;

// =============================================================================
// HELPERS (fixed)
// =============================================================================

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
// =============================================================================
// EVICTION POLICY -- everything below (until the closing marker) is evolved
// =============================================================================

// -- Per-feature listener configuration --------------------------------------
// Enable high-performing listeners to track network conditions adaptively.
// These provide real-time network state for adaptive cache protection.
static const struct vulcan_feature_config gf_configs[VULCAN_NUM_GLOBAL_FEATURES] = {
    [GF_SRTT_US]        = { .listener_mask = VULCAN_LISTENER_EWMA,
                            .ewma_alpha = 150 },
    [GF_MDEV_US]        = { .listener_mask = 0 },
    [GF_SND_CWND]       = { .listener_mask = VULCAN_LISTENER_EWMA,
                            .ewma_alpha = 200 },
    [GF_SND_SSTHRESH]   = { .listener_mask = 0 },
    [GF_RCV_WND]        = { .listener_mask = 0 },
    [GF_PACKETS_OUT]    = { .listener_mask = VULCAN_LISTENER_EWMA,
                            .ewma_alpha = 200 },
    [GF_TOTAL_RETRANS]  = { .listener_mask = 0 },
    [GF_RETRANS_OUT]    = { .listener_mask = 0 },
    [GF_LOST]           = { .listener_mask = VULCAN_LISTENER_MINMAX },
    [GF_SEGS_IN]        = { .listener_mask = 0 },
    [GF_SEGS_OUT]       = { .listener_mask = 0 },
    [GF_DELIVERED]      = { .listener_mask = 0 },
    [GF_BYTES_RECEIVED] = { .listener_mask = 0 },
    [GF_BYTES_ACKED]    = { .listener_mask = 0 },
    [GF_INTER_ARRIVAL]  = { .listener_mask = 0 },
    [GF_RECV_COUNT]     = { .listener_mask = 0 },
};

// -- Per-folio listener configuration ----------------------------------------
// Track per-folio heat using EWMA and MINMAX of inter-access intervals.
// This distinguishes genuinely hot folios (low interval_ewma) from cold ones.
static const struct vulcan_folio_config folio_cfg = {
    .listener_mask = VULCAN_LISTENER_EWMA | VULCAN_LISTENER_MINMAX,
    .ewma_alpha    = 250,
};

// -- Tunable constants --------------------------------------------------------
#define SAMPLE_SIZE 20  // Candidates per eviction slot (same as cache_ext_sampling)

static u64 main_list;

// LevelDB: index block is at end of file; protect last page (same as sampling).
static inline bool is_last_page_in_file(struct folio *folio)
{
    struct address_space *mapping = folio->mapping;
    if (!mapping || !mapping->host)
        return false;
    if (folio_test_large(folio) || folio_test_hugetlb(folio))
        return false;
    unsigned long long file_size = i_size_read(mapping->host);
    unsigned long long page_index = folio_index(folio);
    unsigned long long page_size = 4096;
    unsigned long long last_page_index =
        (file_size + page_size - 1) / page_size - 1;
    return page_index == last_page_index;
}

/*
 * Network-aware LFU with sophisticated adaptive protection.
 * Kernel picks LOWEST score in each batch. S64_MAX = never prefer as victim.
 *
 * Combines RTT sensitivity, per-folio heat tracking (via interval_ewma),
 * and recency to make intelligent eviction decisions under varying network
 * conditions. Loss detection applies modest protection to prevent thrashing.
 */
static s64 bpf_score_fn(struct cache_ext_list_node *node)
{
    struct folio *folio = node->folio;
    if (!folio)
        return S64_MAX;

    if (folio_test_dirty(folio) || folio_test_writeback(folio))
        return S64_MAX;
    if (!folio_test_uptodate(folio) || !folio_test_lru(folio))
        return S64_MAX;

    u64 key = (u64)folio;
    struct vulcan_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);
    if (!meta)
        return S64_MAX;

    /* Recency-weighted base score: prioritize recently-active folios over cold ones
     * with similar historical access counts. Linear decay from +50% boost (< 1 second)
     * to 0% boost (10+ seconds). This captures working-set dynamics by making temporal
     * locality a first-class component of the score. */
    u64 now = bpf_ktime_get_ns();
    u64 time_since_access = now - meta->last_access_ts;
    s64 recency_factor = 0;

    if (time_since_access < 1000000000ULL) {  /* < 1 second */
        recency_factor = 50;  /* 50% boost for very recent accesses */
    } else if (time_since_access < 10000000000ULL) {  /* 1-10 seconds */
        /* Linear decay: 50% at 1s, 0% at 10s */
        s64 elapsed_seconds = (time_since_access - 1000000000ULL) / 1000000000ULL;
        recency_factor = 50 - (elapsed_seconds * 50 / 9);  /* decay over 9 seconds */
        if (recency_factor < 0) recency_factor = 0;
    }
    /* else: time_since_access >= 10s, recency_factor remains 0 */

    s64 base_score = ((s64)meta->access_count * (100 + recency_factor)) / 100;

    /* Network-aware protection: boost when RTT is high (cache misses are expensive) */
    s64 srtt_ewma = vulcan_get_ewma(GF_SRTT_US);
    s64 network_factor = 100;  /* baseline: 1.0x in fixed-point (÷100) */

    /* Elevated RTT (>5ms smoothed): protect working set more aggressively */
    if (srtt_ewma > 5000) {
        network_factor = 125;  /* 1.25x protection */
    }
    if (srtt_ewma > 10000) {
        network_factor = 150;  /* 1.5x protection for >10ms RTT */
    }

    /* Packet loss detected: apply conservative protection boost.
     * Only boost when loss is detected AND RTT is elevated to avoid
     * stale loss signals causing sustained over-protection. */
    s64 max_lost = vulcan_get_max(GF_LOST);
    if (max_lost > 0 && srtt_ewma > 3000) {  /* Loss + RTT >3ms */
        network_factor = (network_factor * 115) / 100;  /* 15% additional boost */
    }

    /* Congestion window saturation detection: secondary network factor.
     * High packets_out/snd_cwnd ratio indicates window saturation, where
     * cache misses incur queuing delays independent of RTT. Use safe unsigned
     * arithmetic to compute saturation percentage and apply modest additive boost. */
    s64 packets_out_ewma = vulcan_get_ewma(GF_PACKETS_OUT);
    s64 snd_cwnd_ewma = vulcan_get_ewma(GF_SND_CWND);

    if (snd_cwnd_ewma > 0 && packets_out_ewma > 0) {
        u64 congestion_ratio = ((u64)packets_out_ewma * 100) / (u64)snd_cwnd_ewma;
        if (congestion_ratio > 90) {
            network_factor += 10;  /* 10% additional boost for very high saturation */
        } else if (congestion_ratio > 70) {
            network_factor += 5;   /* 5% additional boost for moderate saturation */
        }
    }

    /* Apply network-aware protection factor */
    s64 score = (base_score * network_factor) / 100;

    /* Per-folio heat via interval EWMA: distinguish hot vs cold folios.
     * Low interval_ewma means frequent accesses (hot).
     * High interval_ewma means infrequent accesses (cold). */
    s64 interval_ewma = meta->interval_ewma.value;
    if (interval_ewma > 0 && interval_ewma < 1000000000) {  /* < 1 second */
        /* Hot folio: very frequent accesses, protect strongly */
        score += 100;
    } else if (interval_ewma > 10000000000) {  /* > 10 seconds */
        /* Cold folio: infrequent accesses, prefer as victim */
        if (score > 100) score -= 100;
    }

    /* LevelDB: protect index block (last page of file) */
    if (is_last_page_in_file(folio))
        score += 100000;

    return score;
}

// -- struct_ops: init ---------------------------------------------------------
s32 BPF_STRUCT_OPS_SLEEPABLE(evolved_init, struct mem_cgroup *memcg)
{
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (!main_list)
        return -1;
    return 0;
}

// -- struct_ops: evict_folios -------------------------------------------------
void BPF_STRUCT_OPS(evolved_evict_folios,
                    struct cache_ext_eviction_ctx *eviction_ctx,
                    struct mem_cgroup *memcg)
{
    bump_counter(0);
    struct sampling_options opts = { .sample_size = SAMPLE_SIZE };
    bpf_cache_ext_list_sample(memcg, main_list, bpf_score_fn, &opts,
                  eviction_ctx);
}

// -- struct_ops: folio_added --------------------------------------------------
void BPF_STRUCT_OPS(evolved_folio_added, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    int ret = bpf_cache_ext_list_add_tail(main_list, folio);
    if (ret != 0) {
        bump_counter(1);
        return;
    }

    u64 key = (u64)folio;
    struct vulcan_folio_metadata new_meta =
        vulcan_folio_init(bpf_ktime_get_ns());
    bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
    bump_counter(2);
}

// -- struct_ops: folio_accessed -----------------------------------------------
void BPF_STRUCT_OPS(evolved_folio_accessed, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    u64 key = (u64)folio;
    struct vulcan_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta) {
        int ret = bpf_cache_ext_list_add(main_list, folio);
        if (ret != 0)
            bpf_cache_ext_list_move(main_list, folio, false);
        struct vulcan_folio_metadata new_meta =
            vulcan_folio_init(bpf_ktime_get_ns());
        bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
        bump_counter(3);
        return;
    }

    /* Update per-folio listeners (interval_ewma and minmax) to track access heat */
    vulcan_folio_on_access(meta, bpf_ktime_get_ns(), &folio_cfg);
    bump_counter(4);
}

// -- struct_ops: folio_evicted ------------------------------------------------
void BPF_STRUCT_OPS(evolved_folio_evicted, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    u64 key = (u64)folio;
    bpf_map_delete_elem(&folio_metadata_map, &key);
    bump_counter(5);
}

// EVOLVE-BLOCK-END

// =============================================================================
// NETWORK MONITORING (fixed -- not evolved)
// =============================================================================
// Baseline: kprobe DISABLED so we match initial_sampling (no kprobe). Having
// tcp_recvmsg attached causes 0-throughput timeouts even with early-exit.
// When the LLM enables any gf_configs listener, they MUST uncomment (change
// #if 0 to #if 1) so vulcan_get_* accessors receive data.
#if 1
SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (sport != 9100 && sport != 9001 && sport != 9002)
        return 0;

    /* Baseline: when no listeners enabled, exit immediately — zero overhead.
     * Matches initial_sampling (no kprobe work). When LLM enables listeners,
     * this check fails and we do the full update. */
    {
        u32 any_enabled = 0;
#pragma unroll
        for (u32 i = 0; i < VULCAN_NUM_GLOBAL_FEATURES; i++) {
            any_enabled |= gf_configs[i].listener_mask;
        }
        if (!any_enabled)
            return 0;
    }

    net_prev_packet_ts = last_packet_ts;
    last_packet_ts     = bpf_ktime_get_ns();
    net_recv_count    += 1;

    struct tcp_sock *tp = (struct tcp_sock *)sk;

    net_srtt_us        = BPF_CORE_READ(tp, srtt_us);
    net_mdev_us        = BPF_CORE_READ(tp, mdev_us);
    net_bytes_received = BPF_CORE_READ(tp, bytes_received);
    net_bytes_acked    = BPF_CORE_READ(tp, bytes_acked);
    net_segs_in        = BPF_CORE_READ(tp, segs_in);
    net_segs_out       = BPF_CORE_READ(tp, segs_out);
    net_delivered      = BPF_CORE_READ(tp, delivered);
    net_snd_cwnd       = BPF_CORE_READ(tp, snd_cwnd);
    net_snd_ssthresh   = BPF_CORE_READ(tp, snd_ssthresh);
    net_rcv_wnd        = BPF_CORE_READ(tp, rcv_wnd);
    net_packets_out    = BPF_CORE_READ(tp, packets_out);
    net_total_retrans  = BPF_CORE_READ(tp, total_retrans);
    net_retrans_out    = BPF_CORE_READ(tp, retrans_out);
    net_lost           = BPF_CORE_READ(tp, lost);

    s64 inter_arrival = 0;
    if (net_prev_packet_ts > 0)
        inter_arrival = (s64)(last_packet_ts - net_prev_packet_ts);

    // Pack raw values into an array matching GF_* enum order, then dispatch
    // to only the listeners each feature has enabled via gf_configs[].
    s64 raw_values[VULCAN_NUM_GLOBAL_FEATURES];
    raw_values[GF_SRTT_US]        = (s64)net_srtt_us;
    raw_values[GF_MDEV_US]        = (s64)net_mdev_us;
    raw_values[GF_SND_CWND]       = (s64)net_snd_cwnd;
    raw_values[GF_SND_SSTHRESH]   = (s64)net_snd_ssthresh;
    raw_values[GF_RCV_WND]        = (s64)net_rcv_wnd;
    raw_values[GF_PACKETS_OUT]    = (s64)net_packets_out;
    raw_values[GF_TOTAL_RETRANS]  = (s64)net_total_retrans;
    raw_values[GF_RETRANS_OUT]    = (s64)net_retrans_out;
    raw_values[GF_LOST]           = (s64)net_lost;
    raw_values[GF_SEGS_IN]        = (s64)net_segs_in;
    raw_values[GF_SEGS_OUT]       = (s64)net_segs_out;
    raw_values[GF_DELIVERED]      = (s64)net_delivered;
    raw_values[GF_BYTES_RECEIVED] = (s64)net_bytes_received;
    raw_values[GF_BYTES_ACKED]    = (s64)net_bytes_acked;
    raw_values[GF_INTER_ARRIVAL]  = inter_arrival;
    raw_values[GF_RECV_COUNT]     = (s64)net_recv_count;

    for (u32 i = 0; i < VULCAN_NUM_GLOBAL_FEATURES && i < 16; i++) {
        if (gf_configs[i].listener_mask)
            vulcan_update_feature(i, raw_values[i], &gf_configs[i]);
    }

    return 0;
}
#endif /* kprobe disabled for baseline */

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