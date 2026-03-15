// BPF page cache eviction policy using kernel-libvulcan abstractions.
// This file is evolved by ShinkaEvolve.  The EVOLVE-BLOCK contains
// configuration constants, the scoring function, and struct_ops callbacks.
//
// ═══════════════════════════════════════════════════════════════════════
// ARCHITECTURE — Separation of Duties (libvulcan for kernelspace)
// ═══════════════════════════════════════════════════════════════════════
//
// FIXED infrastructure (outside EVOLVE-BLOCK):
//   - Includes, license, map definitions
//   - Vulcan listener state maps (MinMax, EWMA, RollingWindow, Average
//     for each global feature)
//   - Per-folio metadata struct and map (with embedded per-folio listeners)
//   - Global feature accessor functions (vulcan_get_min, vulcan_get_max, …)
//   - Per-folio helper functions (vulcan_folio_init, vulcan_folio_on_access)
//   - vulcan_update_global — feeds raw metrics into all listener types
//   - Network monitoring kprobe (tcp_recvmsg) — updates raw globals AND
//     calls vulcan_update_global for every global feature
//   - struct_ops registration
//
// What the LLM evolves (inside EVOLVE-BLOCK):
//   - Configuration constants:
//       VULCAN_EWMA_ALPHA   — EWMA smoothing for global features [0..1000]
//       VULCAN_RW_SIZE      — rolling window size for global features [1..16]
//       VULCAN_FOLIO_EWMA_ALPHA — EWMA smoothing for per-folio intervals
//       SAMPLE_SIZE         — candidates sampled per eviction slot
//   - bpf_score_fn(node) → s64 — returns a VALUE score for each folio
//       ◆ HIGHER score  = more valuable = keep longer
//       ◆ LOWER  score  = less valuable = evict first
//       ◆ S64_MAX       = never evict (dirty / writeback)
//   - evolved_init          — allocate list(s)
//   - evolved_evict_folios  — orchestrate eviction (calls list_sample)
//   - evolved_folio_added   — track new folios
//   - evolved_folio_accessed — update metadata on re-access
//   - evolved_folio_evicted — cleanup on eviction
//
// ═══════════════════════════════════════════════════════════════════════
// GLOBAL FEATURE ACCESSOR API  (usable inside bpf_score_fn)
// ═══════════════════════════════════════════════════════════════════════
//
//   vulcan_get_min(GF_xxx)              — observed minimum
//   vulcan_get_max(GF_xxx)              — observed maximum
//   vulcan_get_ewma(GF_xxx)             — exponentially weighted moving avg
//   vulcan_get_avg(GF_xxx)              — running arithmetic average
//   vulcan_get_latest(GF_xxx)           — most recent value in rolling window
//   vulcan_get_kth_recent(GF_xxx, k)    — k-th most recent (0=latest)
//   vulcan_get_window_avg(GF_xxx)       — rolling-window average
//   vulcan_get_window_count(GF_xxx)     — number of values in window
//
// Global feature IDs:
//   GF_SRTT_US          — smoothed RTT (usec, kernel srtt<<3)
//   GF_MDEV_US          — RTT mean deviation / jitter (usec)
//   GF_SND_CWND         — congestion window (segments)
//   GF_SND_SSTHRESH     — slow-start threshold (segments)
//   GF_RCV_WND          — advertised receive window (bytes)
//   GF_PACKETS_OUT      — packets currently in flight
//   GF_TOTAL_RETRANS    — lifetime retransmissions
//   GF_RETRANS_OUT      — retransmits currently in flight
//   GF_LOST             — segments considered lost
//   GF_SEGS_IN          — total TCP segments received
//   GF_SEGS_OUT         — total TCP segments sent
//   GF_DELIVERED        — total packets delivered
//   GF_BYTES_RECEIVED   — total bytes received
//   GF_BYTES_ACKED      — total bytes acknowledged
//   GF_INTER_ARRIVAL    — inter-packet arrival time (ns)
//   GF_RECV_COUNT       — total tcp_recvmsg calls
//
// ═══════════════════════════════════════════════════════════════════════
// PER-FOLIO METADATA  (struct vulcan_folio_metadata, in folio_metadata_map)
// ═══════════════════════════════════════════════════════════════════════
//
//   meta->access_count             — number of accesses (u32)
//   meta->last_access_ts           — timestamp of last access (u64 ns)
//   meta->prev_access_ts           — timestamp of access before that (u64 ns)
//   meta->interval_minmax.min_val  — minimum inter-access interval (s64 ns)
//   meta->interval_minmax.max_val  — maximum inter-access interval (s64 ns)
//   meta->interval_ewma.value      — EWMA of inter-access interval (s64 ns)
//
// Per-folio helpers (call from folio hooks):
//   vulcan_folio_init(now)                         → initialized metadata struct
//   vulcan_folio_on_access(meta, now, ewma_alpha)  — update all per-folio listeners
//
// ═══════════════════════════════════════════════════════════════════════
// RAW NETWORK GLOBALS  (still available for direct access)
// ═══════════════════════════════════════════════════════════════════════
//
//   last_packet_ts, net_prev_packet_ts, net_recv_count
//   net_srtt_us, net_mdev_us
//   net_bytes_received, net_bytes_acked, net_segs_in, net_segs_out, net_delivered
//   net_snd_cwnd, net_snd_ssthresh, net_rcv_wnd, net_packets_out
//   net_total_retrans, net_retrans_out, net_lost
//
// ═══════════════════════════════════════════════════════════════════════
// BPF LIST / EVICTION APIs
// ═══════════════════════════════════════════════════════════════════════
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
// ═══════════════════════════════════════════════════════════════════════

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"
#include "vulcan_bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

// ═════════════════════════════════════════════════════════════════════════════
// GLOBAL FEATURE IDS
// ═════════════════════════════════════════════════════════════════════════════

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

// ═════════════════════════════════════════════════════════════════════════════
// PER-FOLIO METADATA (with embedded per-folio listeners)
// ═════════════════════════════════════════════════════════════════════════════

struct vulcan_folio_metadata {
    u64 last_access_ts;
    u64 prev_access_ts;
    u32 access_count;
    u32 _pad;
    struct vulcan_minmax interval_minmax;
    struct vulcan_ewma   interval_ewma;
};

// ═════════════════════════════════════════════════════════════════════════════
// MAPS
// ═════════════════════════════════════════════════════════════════════════════

// Per-folio metadata
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct vulcan_folio_metadata);
    __uint(max_entries, 1000000);
} folio_metadata_map SEC(".maps");

// Global listener state — one entry per global feature
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

// Debug counters
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, u64);
} debug_counters SEC(".maps");

// ═════════════════════════════════════════════════════════════════════════════
// RAW NETWORK GLOBALS (updated by kprobe)
// ═════════════════════════════════════════════════════════════════════════════

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

// ═════════════════════════════════════════════════════════════════════════════
// HELPERS (fixed)
// ═════════════════════════════════════════════════════════════════════════════

static __always_inline void bump_counter(u32 idx) {
    u64 *val = bpf_map_lookup_elem(&debug_counters, &idx);
    if (val) __sync_fetch_and_add(val, 1);
}

static __always_inline bool is_folio_relevant(struct folio *folio) {
    if (!folio || !folio->mapping || !folio->mapping->host)
        return false;
    return inode_in_watchlist(folio->mapping->host->i_ino);
}

// ═════════════════════════════════════════════════════════════════════════════
// VULCAN — Update all listener types for one global feature
// ═════════════════════════════════════════════════════════════════════════════

static __always_inline void vulcan_update_global(u32 feature_id, s64 value,
                                                 u32 ewma_alpha,
                                                 u32 rw_size)
{
    struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_gminmax, &feature_id);
    if (mm) vulcan_minmax_update(mm, value);

    struct vulcan_ewma *ew = bpf_map_lookup_elem(&vulcan_gewma, &feature_id);
    if (ew) vulcan_ewma_update(ew, value, ewma_alpha);

    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_grw, &feature_id);
    if (rw) vulcan_rw_update(rw, value, rw_size);

    struct vulcan_avg *av = bpf_map_lookup_elem(&vulcan_gavg, &feature_id);
    if (av) vulcan_avg_update(av, value);
}

// ═════════════════════════════════════════════════════════════════════════════
// VULCAN — Global feature accessor functions
// ═════════════════════════════════════════════════════════════════════════════

static __always_inline s64 vulcan_get_min(u32 fid) {
    struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_gminmax, &fid);
    return mm ? vulcan_minmax_get_min(mm) : 0;
}

static __always_inline s64 vulcan_get_max(u32 fid) {
    struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_gminmax, &fid);
    return mm ? vulcan_minmax_get_max(mm) : 0;
}

static __always_inline s64 vulcan_get_ewma(u32 fid) {
    struct vulcan_ewma *ew = bpf_map_lookup_elem(&vulcan_gewma, &fid);
    return ew ? vulcan_ewma_get(ew) : 0;
}

static __always_inline s64 vulcan_get_avg(u32 fid) {
    struct vulcan_avg *av = bpf_map_lookup_elem(&vulcan_gavg, &fid);
    return av ? vulcan_avg_get(av) : 0;
}

static __always_inline s64 vulcan_get_latest(u32 fid) {
    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_grw, &fid);
    return rw ? vulcan_rw_get_latest(rw) : 0;
}

static __always_inline s64 vulcan_get_kth_recent(u32 fid, u32 k) {
    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_grw, &fid);
    return rw ? vulcan_rw_get_kth_recent(rw, k) : 0;
}

static __always_inline s64 vulcan_get_window_avg(u32 fid) {
    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_grw, &fid);
    return rw ? vulcan_rw_get_avg(rw) : 0;
}

static __always_inline u32 vulcan_get_window_count(u32 fid) {
    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_grw, &fid);
    return rw ? vulcan_rw_get_count(rw) : 0;
}

// ═════════════════════════════════════════════════════════════════════════════
// VULCAN — Per-folio helpers
// ═════════════════════════════════════════════════════════════════════════════

static __always_inline struct vulcan_folio_metadata
vulcan_folio_init(u64 now)
{
    struct vulcan_folio_metadata m = {
        .last_access_ts  = now,
        .prev_access_ts  = 0,
        .access_count    = 1,
        ._pad            = 0,
        .interval_minmax = { .min_val = 0, .max_val = 0, .count = 0, ._pad = 0 },
        .interval_ewma   = { .value = 0, .initialized = 0, ._pad = 0 },
    };
    return m;
}

static __always_inline void
vulcan_folio_on_access(struct vulcan_folio_metadata *meta, u64 now,
                       u32 folio_ewma_alpha)
{
    if (meta->last_access_ts > 0 && meta->access_count > 0) {
        s64 interval = (s64)(now - meta->last_access_ts);
        vulcan_minmax_update(&meta->interval_minmax, interval);
        vulcan_ewma_update(&meta->interval_ewma, interval, folio_ewma_alpha);
    }
    meta->prev_access_ts = meta->last_access_ts;
    meta->last_access_ts = now;
    meta->access_count++;
}

// EVOLVE-BLOCK-START
// ═════════════════════════════════════════════════════════════════════════════
// EVICTION POLICY — everything below (until EVOLVE-BLOCK-END) is evolved
// ═════════════════════════════════════════════════════════════════════════════

// -- Configuration constants -------------------------------------------------
// EWMA smoothing for global features: 0=no smoothing, 1000=instant (no memory)
#define VULCAN_EWMA_ALPHA       100   // α = 0.10
// Rolling window size for global features (max 16)
#define VULCAN_RW_SIZE          8
// EWMA smoothing for per-folio inter-access intervals
#define VULCAN_FOLIO_EWMA_ALPHA 200   // α = 0.20
// Number of candidates to sample per eviction slot
#define SAMPLE_SIZE             20

static u64 main_list;

// -- Scoring function --------------------------------------------------------
// Called for each sampled folio during eviction.
// Return s64 score: HIGHER = keep, LOWER = evict first, S64_MAX = unevictable.
static s64 bpf_score_fn(struct cache_ext_list_node *node)
{
    struct folio *folio = node->folio;

    if (folio_test_dirty(folio) || folio_test_writeback(folio))
        return S64_MAX;

    u64 key = (u64)folio;
    struct vulcan_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);
    if (!meta)
        return 0;

    u64 now    = bpf_ktime_get_ns();
    s64 age_ns = (s64)(now - meta->last_access_ts);

    // Base score: access count (more accesses = more valuable)
    s64 score = (s64)meta->access_count * 1000000;

    // Recency bonus
    if (age_ns < 100000000)        // < 100 ms
        score += 10000000;
    else if (age_ns < 1000000000)  // < 1 s
        score += 1000000;

    // Network pressure: protect hot folios when RTT is elevated or loss present
    s64 srtt_ewma = vulcan_get_ewma(GF_SRTT_US);
    s64 lost_max  = vulcan_get_max(GF_LOST);
    if ((srtt_ewma > 50000 || lost_max > 0) && meta->access_count >= 3)
        score += 5000000;

    // Congestion-aware: boost score when cwnd is small (network bottleneck)
    s64 cwnd = vulcan_get_ewma(GF_SND_CWND);
    if (cwnd > 0 && cwnd < 20 && age_ns < 500000000)
        score += 3000000;

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
    bpf_cache_ext_list_sample(memcg, main_list, bpf_score_fn,
                              &opts, eviction_ctx);
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

    vulcan_folio_on_access(meta, bpf_ktime_get_ns(), VULCAN_FOLIO_EWMA_ALPHA);
    bpf_cache_ext_list_move(main_list, folio, false);
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

// ═════════════════════════════════════════════════════════════════════════════
// NETWORK MONITORING (fixed — not evolved)
// ═════════════════════════════════════════════════════════════════════════════

SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (sport != 9100 && sport != 9001 && sport != 9002)
        return 0;

    // Update raw globals
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

    // Feed raw values into vulcan listener pipeline.
    // Fallback defaults if the LLM removed the #defines.
#ifndef VULCAN_EWMA_ALPHA
#define VULCAN_EWMA_ALPHA 100
#endif
#ifndef VULCAN_RW_SIZE
#define VULCAN_RW_SIZE 8
#endif

    vulcan_update_global(GF_SRTT_US,        (s64)net_srtt_us,        VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);
    vulcan_update_global(GF_MDEV_US,        (s64)net_mdev_us,        VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);
    vulcan_update_global(GF_SND_CWND,       (s64)net_snd_cwnd,       VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);
    vulcan_update_global(GF_SND_SSTHRESH,   (s64)net_snd_ssthresh,   VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);
    vulcan_update_global(GF_RCV_WND,        (s64)net_rcv_wnd,        VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);
    vulcan_update_global(GF_PACKETS_OUT,    (s64)net_packets_out,    VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);
    vulcan_update_global(GF_TOTAL_RETRANS,  (s64)net_total_retrans,  VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);
    vulcan_update_global(GF_RETRANS_OUT,    (s64)net_retrans_out,    VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);
    vulcan_update_global(GF_LOST,           (s64)net_lost,           VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);
    vulcan_update_global(GF_SEGS_IN,        (s64)net_segs_in,        VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);
    vulcan_update_global(GF_SEGS_OUT,       (s64)net_segs_out,       VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);
    vulcan_update_global(GF_DELIVERED,      (s64)net_delivered,      VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);
    vulcan_update_global(GF_BYTES_RECEIVED, (s64)net_bytes_received, VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);
    vulcan_update_global(GF_BYTES_ACKED,    (s64)net_bytes_acked,    VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);
    vulcan_update_global(GF_RECV_COUNT,     (s64)net_recv_count,     VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);

    // Derived feature: inter-packet arrival time
    s64 inter_arrival = 0;
    if (net_prev_packet_ts > 0)
        inter_arrival = (s64)(last_packet_ts - net_prev_packet_ts);
    vulcan_update_global(GF_INTER_ARRIVAL, inter_arrival, VULCAN_EWMA_ALPHA, VULCAN_RW_SIZE);

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
