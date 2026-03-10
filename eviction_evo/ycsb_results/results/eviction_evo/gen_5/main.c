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

// ── Per-folio metadata ──────────────────────────────────────────────
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
// -- List handles for three tiers -----------------------------------------------
static u64 cold_list;
static u64 warm_list;
static u64 hot_list;
static u64 smoothed_inter_arrival_ns = 0;
static u64 last_demotion_ts = 0;

// =============================================================================
// EVICTION POLICY — multi-tier adaptive approach
// =============================================================================

// -- Tunable constants --------------------------------------------------------
#define NET_IDLE_TIMEOUT_NS         5000000000ULL  // 5 s
#define BURST_THRESHOLD_US          10000ULL       // 10 ms
#define HIGH_RTT_THRESHOLD_US       50000ULL       // 50 ms
#define DEMOTION_INTERVAL_NS        100000000ULL   // 100 ms (how often to demote)
#define COLD_RETENTION_NS           50000000ULL    // 50 ms
#define WARM_RETENTION_NS           200000000ULL   // 200 ms
#define HOT_RETENTION_NS            1000000000ULL  // 1 s
#define BURST_SMOOTH_SHIFT          3              // 1/8 smoothing

// -- Helper: update smoothed burst rate ----------------------------------------
static __always_inline void update_smoothed_burst_rate(void)
{
    u64 inter_arrival = (last_packet_ts > net_prev_packet_ts) ?
                        (last_packet_ts - net_prev_packet_ts) : 0;

    if (inter_arrival > 0) {
        smoothed_inter_arrival_ns = (smoothed_inter_arrival_ns * 7) / 8 +
                                     (inter_arrival * 1) / 8;
    }
}

// -- Helper: determine if we should demote folios -----
static __always_inline bool should_demote_now(u64 now)
{
    // Demote at most every DEMOTION_INTERVAL_NS
    if (now - last_demotion_ts < DEMOTION_INTERVAL_NS)
        return false;

    // Don't demote during active bursts
    u64 burst_threshold_ns = BURST_THRESHOLD_US * 1000;
    if (smoothed_inter_arrival_ns > 0 && smoothed_inter_arrival_ns < burst_threshold_ns)
        return false;

    return true;
}

// -- Helper: compute retention time based on network state --------------------
static __always_inline u64 get_tier_retention_ns(u32 tier)
{
    bool is_congested = (net_lost > 0) || (net_retrans_out > 0);
    bool high_rtt = (net_srtt_us > HIGH_RTT_THRESHOLD_US);

    // During congestion or high RTT, reduce retention to tighten working set
    u64 congestion_factor = (is_congested || high_rtt) ? 1 : 2;

    switch (tier) {
        case 0:  // cold
            return COLD_RETENTION_NS / congestion_factor;
        case 1:  // warm
            return WARM_RETENTION_NS / congestion_factor;
        case 2:  // hot
            return HOT_RETENTION_NS / congestion_factor;
        default:
            return COLD_RETENTION_NS;
    }
}

// -- Eviction callback for cold tier (most aggressive) ------------------------
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

    u64 retention = get_tier_retention_ns(0);
    bool recently_used = (now - meta->last_access_ts) < retention;

    // Keep recently accessed cold folios; evict old ones
    if (recently_used)
        return CACHE_EXT_CONTINUE_ITER;

    return CACHE_EXT_EVICT_NODE;
}

// -- Eviction callback for warm tier (moderate) --------------------------------
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

    u64 retention = get_tier_retention_ns(1);
    bool recently_used = (now - meta->last_access_ts) < retention;

    if (recently_used)
        return CACHE_EXT_CONTINUE_ITER;

    return CACHE_EXT_EVICT_NODE;
}

// -- Eviction callback for hot tier (protective) --------------------------------
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

    u64 retention = get_tier_retention_ns(2);
    bool recently_used = (now - meta->last_access_ts) < retention;

    // Only evict hot folios if they're very old
    if (recently_used)
        return CACHE_EXT_CONTINUE_ITER;

    return CACHE_EXT_EVICT_NODE;
}

// -- Demotion callback: move warm folios to cold if old enough ----------------
static int bpf_demote_warm_cb(int idx, struct cache_ext_list_node *node)
{
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta)
        return CACHE_EXT_CONTINUE_ITER;

    // If warm folio hasn't been accessed in a while, demote to cold
    u64 warm_demotion_threshold = WARM_RETENTION_NS * 2;
    if (now - meta->last_access_ts > warm_demotion_threshold) {
        // Move to cold list
        bpf_cache_ext_list_del(node->folio);
        bpf_cache_ext_list_add_tail(cold_list, node->folio);
        meta->tier = 0;
        return CACHE_EXT_CONTINUE_ITER;
    }

    return CACHE_EXT_CONTINUE_ITER;
}

// -- Demotion callback: move hot folios to warm if old enough ------------------
static int bpf_demote_hot_cb(int idx, struct cache_ext_list_node *node)
{
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta)
        return CACHE_EXT_CONTINUE_ITER;

    // If hot folio hasn't been accessed in a while, demote to warm
    u64 hot_demotion_threshold = HOT_RETENTION_NS * 2;
    if (now - meta->last_access_ts > hot_demotion_threshold) {
        // Move to warm list
        bpf_cache_ext_list_del(node->folio);
        bpf_cache_ext_list_add_tail(warm_list, node->folio);
        meta->tier = 1;
        return CACHE_EXT_CONTINUE_ITER;
    }

    return CACHE_EXT_CONTINUE_ITER;
}

// -- struct_ops: init ---------------------------------------------------------
s32 BPF_STRUCT_OPS_SLEEPABLE(evolved_init, struct mem_cgroup *memcg)
{
    cold_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (!cold_list)
        return -1;

    warm_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (!warm_list)
        return -1;

    hot_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (!hot_list)
        return -1;

    return 0;
}

// -- struct_ops: evict_folios -------------------------------------------------
void BPF_STRUCT_OPS(evolved_evict_folios,
                    struct cache_ext_eviction_ctx *eviction_ctx,
                    struct mem_cgroup *memcg)
{
    u64 now = bpf_ktime_get_ns();

    bump_counter(0);

    // Perform demotion if enough time has passed
    if (should_demote_now(now)) {
        bpf_cache_ext_list_iterate(memcg, hot_list, bpf_demote_hot_cb, eviction_ctx);
        bpf_cache_ext_list_iterate(memcg, warm_list, bpf_demote_warm_cb, eviction_ctx);
        last_demotion_ts = now;
    }

    // Evict in order: cold (aggressive) → warm (moderate) → hot (protective)
    bpf_cache_ext_list_iterate(memcg, cold_list, bpf_evict_cold_cb, eviction_ctx);
    bpf_cache_ext_list_iterate(memcg, warm_list, bpf_evict_warm_cb, eviction_ctx);
    bpf_cache_ext_list_iterate(memcg, hot_list, bpf_evict_hot_cb, eviction_ctx);
}

// -- struct_ops: folio_added --------------------------------------------------
void BPF_STRUCT_OPS(evolved_folio_added, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    update_smoothed_burst_rate();

    // New folios start in cold tier
    int ret = bpf_cache_ext_list_add_tail(cold_list, folio);
    if (ret != 0) {
        bump_counter(1);
        return;
    }

    u64 key = (u64)folio;
    struct net_folio_metadata new_meta = {
        .last_access_ts = bpf_ktime_get_ns(),
        .access_count  = 1,
        .tier          = 0,  // cold
    };
    bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
    bump_counter(2);
}

// -- struct_ops: folio_accessed -----------------------------------------------
void BPF_STRUCT_OPS(evolved_folio_accessed, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    update_smoothed_burst_rate();

    u64 key = (u64)folio;
    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    u64 now = bpf_ktime_get_ns();

    if (!meta) {
        // Folio not tracked yet — add to cold tier
        int ret = bpf_cache_ext_list_add(cold_list, folio);
        if (ret != 0) {
            // Already in a list — move to head of current tier
            bpf_cache_ext_list_move(cold_list, folio, false);
        }
        struct net_folio_metadata new_meta = {
            .last_access_ts = now,
            .access_count  = 1,
            .tier          = 0,
        };
        bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
        bump_counter(3);
        return;
    }

    // Update metadata
    meta->last_access_ts = now;
    meta->access_count += 1;

    // Promote tier on access: cold → warm → hot
    u32 old_tier = meta->tier;
    u32 new_tier = old_tier;

    if (old_tier == 0 && meta->access_count >= 2) {
        // Promote cold → warm
        new_tier = 1;
        bpf_cache_ext_list_del(folio);
        bpf_cache_ext_list_add(warm_list, folio);
    } else if (old_tier == 1 && meta->access_count >= 4) {
        // Promote warm → hot
        new_tier = 2;
        bpf_cache_ext_list_del(folio);
        bpf_cache_ext_list_add(hot_list, folio);
    } else {
        // Move to head of current tier (MRU)
        if (old_tier == 0)
            bpf_cache_ext_list_move(cold_list, folio, false);
        else if (old_tier == 1)
            bpf_cache_ext_list_move(warm_list, folio, false);
        else
            bpf_cache_ext_list_move(hot_list, folio, false);
    }

    meta->tier = new_tier;
    bump_counter(4);
}

// -- struct_ops: folio_evicted ------------------------------------------------
void BPF_STRUCT_OPS(evolved_folio_evicted, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    // Remove from whichever tier it's in
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