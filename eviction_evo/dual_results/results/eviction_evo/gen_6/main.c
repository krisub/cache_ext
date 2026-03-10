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
// -- List handles (evolved) ---------------------------------------------------
static u64 hot_list;
static u64 warm_list;
static u64 cold_list;

// -- Cached congestion state (per eviction cycle) ----------------------------
static u32 cached_congestion_score = 0;
static bool cached_session_active = false;
static bool cached_in_burst = false;

// =============================================================================
// EVICTION POLICY — Congestion-Adaptive Tier Promotion
// =============================================================================

// -- Tunable constants --------------------------------------------------------
#define BASE_RECENT_ACCESS_NS    100000000ULL   // 100 ms
#define BASE_WORKING_SET_NS      1000000000ULL  // 1 s
#define NET_IDLE_TIMEOUT_NS      5000000000ULL  // 5 s
#define BURST_THRESHOLD_NS       5000000ULL     // 5 ms inter-arrival = burst

// Congestion thresholds for tier promotion adaptation
#define HIGH_CONGESTION_THRESHOLD  700
#define LOW_CONGESTION_THRESHOLD   300

// Access count thresholds (base values, will be scaled by congestion)
#define BASE_WARM_THRESHOLD        2
#define BASE_HOT_THRESHOLD         4

// -- Helper: Compute congestion score (0-1000 scale) --
static __always_inline u32 compute_congestion_score(void)
{
    u32 score = 0;

    // Factor 1: RTT level (0-400 points)
    u32 rtt_us = net_srtt_us >> 3;  // kernel stores srtt<<3
    if (rtt_us > 100000)
        score += 400;
    else if (rtt_us > 50000)
        score += 300;
    else if (rtt_us > 20000)
        score += 200;
    else if (rtt_us > 5000)
        score += 100;

    // Factor 2: Jitter / mdev (0-250 points)
    u32 mdev_us = net_mdev_us >> 3;
    if (mdev_us > 20000)
        score += 250;
    else if (mdev_us > 10000)
        score += 200;
    else if (mdev_us > 5000)
        score += 150;
    else if (mdev_us > 1000)
        score += 100;

    // Factor 3: Retransmissions (0-200 points)
    if (net_retrans_out > 5 || net_lost > 0)
        score += 200;
    else if (net_total_retrans > 10)
        score += 150;
    else if (net_total_retrans > 0)
        score += 50;

    // Factor 4: Congestion window pressure (0-150 points)
    if (net_packets_out > 0 && net_snd_cwnd > 0) {
        if (net_packets_out * 2 > net_snd_cwnd)
            score += 150;
        else if (net_packets_out * 3 > net_snd_cwnd)
            score += 100;
    }

    return (score > 1000) ? 1000 : score;
}

// -- Helper: Get adaptive tier thresholds based on congestion --
static __always_inline void get_adaptive_thresholds(u32 congestion,
                                                     u32 *warm_threshold,
                                                     u32 *hot_threshold)
{
    if (congestion > HIGH_CONGESTION_THRESHOLD) {
        // High congestion: lower thresholds to promote faster
        *warm_threshold = 1;   // promote to warm at 1 access
        *hot_threshold = 2;    // promote to hot at 2 accesses
    } else if (congestion > LOW_CONGESTION_THRESHOLD) {
        // Medium congestion: moderate thresholds
        *warm_threshold = 2;
        *hot_threshold = 3;
    } else {
        // Low congestion: aggressive thresholds
        *warm_threshold = 3;
        *hot_threshold = 6;
    }
}

// -- Helper: Get adaptive time windows based on congestion --
static __always_inline u64 get_adaptive_recent_window(u32 congestion)
{
    u64 base = BASE_RECENT_ACCESS_NS;
    // Scale: low congestion → 100ms, high congestion → 200ms
    u64 scale = (congestion * 100) / 1000;
    return base + scale;
}

static __always_inline u64 get_adaptive_working_set_window(u32 congestion)
{
    u64 base = BASE_WORKING_SET_NS;
    // Scale: low congestion → 1s, high congestion → 2s
    u64 scale = (congestion * 1000000000ULL) / 1000;
    return base + scale;
}

// -- Eviction callback for cold_list --
static int bpf_evict_cold_cb(int idx, struct cache_ext_list_node *node)
{
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta)
        return CACHE_EXT_EVICT_NODE;

    if (folio_test_dirty(node->folio) || folio_test_writeback(node->folio))
        return CACHE_EXT_CONTINUE_ITER;

    // Cold list: aggressive eviction in low congestion, protective in high
    u64 age_ns = (now > meta->last_access_ts) ? (now - meta->last_access_ts) : 0;

    if (cached_congestion_score > HIGH_CONGESTION_THRESHOLD) {
        // High congestion: protect cold folios longer
        if (age_ns > 1000000000ULL)  // 1s
            return CACHE_EXT_EVICT_NODE;
    } else if (cached_congestion_score > LOW_CONGESTION_THRESHOLD) {
        // Medium congestion
        if (age_ns > 500000000ULL)  // 500ms
            return CACHE_EXT_EVICT_NODE;
    } else {
        // Low congestion: aggressive eviction
        if (age_ns > 200000000ULL)  // 200ms
            return CACHE_EXT_EVICT_NODE;
    }

    return CACHE_EXT_CONTINUE_ITER;
}

// -- Eviction callback for warm_list --
static int bpf_evict_warm_cb(int idx, struct cache_ext_list_node *node)
{
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta)
        return CACHE_EXT_EVICT_NODE;

    if (folio_test_dirty(node->folio) || folio_test_writeback(node->folio))
        return CACHE_EXT_CONTINUE_ITER;

    u64 age_ns = (now > meta->last_access_ts) ? (now - meta->last_access_ts) : 0;
    u64 working_set_window = get_adaptive_working_set_window(cached_congestion_score);

    // Warm list: moderate protection
    if (cached_congestion_score > HIGH_CONGESTION_THRESHOLD) {
        // High congestion: protect warm folios in working set
        if (age_ns < working_set_window)
            return CACHE_EXT_CONTINUE_ITER;
        if (age_ns > working_set_window * 2)
            return CACHE_EXT_EVICT_NODE;
    } else if (cached_congestion_score > LOW_CONGESTION_THRESHOLD) {
        // Medium congestion
        if (age_ns < working_set_window / 2)
            return CACHE_EXT_CONTINUE_ITER;
        if (age_ns > working_set_window)
            return CACHE_EXT_EVICT_NODE;
    } else {
        // Low congestion: aggressive eviction of warm
        if (age_ns > 300000000ULL)  // 300ms
            return CACHE_EXT_EVICT_NODE;
    }

    return CACHE_EXT_CONTINUE_ITER;
}

// -- Eviction callback for hot_list --
static int bpf_evict_hot_cb(int idx, struct cache_ext_list_node *node)
{
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta)
        return CACHE_EXT_EVICT_NODE;

    if (folio_test_dirty(node->folio) || folio_test_writeback(node->folio))
        return CACHE_EXT_CONTINUE_ITER;

    u64 age_ns = (now > meta->last_access_ts) ? (now - meta->last_access_ts) : 0;
    u64 recent_window = get_adaptive_recent_window(cached_congestion_score);

    // Hot list: very conservative eviction
    if (cached_congestion_score > HIGH_CONGESTION_THRESHOLD) {
        // High congestion: nearly untouchable
        if (age_ns > recent_window * 3)
            return CACHE_EXT_EVICT_NODE;
    } else if (cached_congestion_score > LOW_CONGESTION_THRESHOLD) {
        // Medium congestion
        if (age_ns > recent_window * 2)
            return CACHE_EXT_EVICT_NODE;
    } else {
        // Low congestion: still protective but more willing to evict
        if (age_ns > recent_window)
            return CACHE_EXT_EVICT_NODE;
    }

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
    
    // Compute and cache congestion state for this eviction cycle
    u64 now = bpf_ktime_get_ns();
    cached_congestion_score = compute_congestion_score();
    cached_session_active = (now - last_packet_ts) < NET_IDLE_TIMEOUT_NS;
    cached_in_burst = (last_packet_ts > net_prev_packet_ts) &&
                      ((last_packet_ts - net_prev_packet_ts) < BURST_THRESHOLD_NS);
    
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
    
    // Add new folios to cold list
    int ret = bpf_cache_ext_list_add_tail(cold_list, folio);
    if (ret != 0) {
        bump_counter(1);
        return;
    }

    // Initialize metadata
    struct net_folio_metadata new_meta = {
        .last_access_ts = bpf_ktime_get_ns(),
        .access_count  = 1,
        .access_tier   = 0,  // cold
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
        // First access: add to cold list
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

    // Update metadata
    meta->last_access_ts = now;
    meta->access_count += 1;

    // Compute adaptive thresholds based on current congestion
    u32 congestion = compute_congestion_score();
    u32 warm_threshold, hot_threshold;
    get_adaptive_thresholds(congestion, &warm_threshold, &hot_threshold);

    // Determine new tier based on adaptive thresholds
    u32 old_tier = meta->access_tier;
    u32 new_tier = old_tier;

    if (meta->access_count >= hot_threshold)
        new_tier = 2;  // hot
    else if (meta->access_count >= warm_threshold)
        new_tier = 1;  // warm
    else
        new_tier = 0;  // cold

    meta->access_tier = new_tier;

    // Promote folio if tier changed
    if (new_tier > old_tier) {
        // Remove from current list
        bpf_cache_ext_list_del(folio);

        // Add to appropriate new list
        if (new_tier == 2) {
            bpf_cache_ext_list_add(hot_list, folio);  // hot at head
        } else if (new_tier == 1) {
            bpf_cache_ext_list_add(warm_list, folio);  // warm at head
        }
        bump_counter(6);
    } else {
        // Same tier: move to head (MRU position)
        if (new_tier == 2)
            bpf_cache_ext_list_move(hot_list, folio, false);
        else if (new_tier == 1)
            bpf_cache_ext_list_move(warm_list, folio, false);
        else
            bpf_cache_ext_list_move(cold_list, folio, false);
        bump_counter(7);
    }
}

// -- struct_ops: folio_evicted ------------------------------------------------
void BPF_STRUCT_OPS(evolved_folio_evicted, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    // Remove from the appropriate list
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