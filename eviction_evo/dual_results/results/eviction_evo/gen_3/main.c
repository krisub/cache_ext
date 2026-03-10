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
// EVICTION POLICY — burst-aware network-adaptive tiering
// =============================================================================

// -- Tunable constants --------------------------------------------------------
// Base time window for "recently used"
#define BASE_RECENT_ACCESS_NS    50000000ULL    // 50 ms
// Base time window for working set
#define BASE_WORKING_SET_NS      800000000ULL   // 800 ms
// Network idle timeout
#define NET_IDLE_TIMEOUT_NS      5000000000ULL  // 5 s
// Base access count threshold for hot (adjusted dynamically)
#define BASE_HOT_THRESHOLD       3
// Burst detection: inter-arrival time threshold (usec)
#define BURST_THRESHOLD_US       5000ULL        // 5 ms
// Sequential scan detection: folios accessed in sequence
#define SEQUENTIAL_DISTANCE      32              // folios within 32 pages = sequential

// -- Helper: Compute burst detection score ---
// Returns true if we're in a burst (packets arriving quickly)
static __always_inline bool is_burst(u64 now) {
    if (net_prev_packet_ts == 0)
        return false;

    u64 inter_arrival_ns = (now > net_prev_packet_ts) ?
        (now - net_prev_packet_ts) : 0;

    // Consider it a burst if packets arrive within 5ms of each other
    return (inter_arrival_ns < 5000000ULL);
}

// -- Helper: Compute network congestion score (0-1000 scale, higher = more congested) --
static __always_inline u32 compute_congestion_score(void) {
    u32 score = 0;

    // Factor 1: RTT level (0-400 points) - tuned for 1-10ms proxy range
    // High RTT means each cache miss is costly
    u32 rtt_us = net_srtt_us >> 3;  // kernel stores srtt<<3, divide by 8
    if (rtt_us > 20000)
        score += 400;  // RTT > 20ms = heavy congestion
    else if (rtt_us > 10000)
        score += 350;  // RTT > 10ms
    else if (rtt_us > 5000)
        score += 250;  // RTT > 5ms
    else if (rtt_us > 2000)
        score += 150;  // RTT > 2ms
    else if (rtt_us > 500)
        score += 50;   // RTT > 0.5ms (baseline)

    // Factor 2: Jitter / mdev (0-250 points) - more granular
    u32 mdev_us = net_mdev_us >> 3;
    if (mdev_us > 10000)
        score += 250;
    else if (mdev_us > 5000)
        score += 200;
    else if (mdev_us > 2000)
        score += 150;
    else if (mdev_us > 1000)
        score += 100;
    else if (mdev_us > 500)
        score += 50;

    // Factor 3: Retransmissions (0-200 points) - immediate penalty for loss
    if (net_lost > 0)
        score += 200;  // Any loss = critical
    else if (net_retrans_out > 3)
        score += 150;
    else if (net_retrans_out > 0)
        score += 100;
    else if (net_total_retrans > 20)
        score += 50;

    // Factor 4: Congestion window pressure (0-150 points)
    // Small cwnd relative to packets_out = bottleneck
    if (net_packets_out > 0 && net_snd_cwnd > 0) {
        if (net_packets_out * 2 > net_snd_cwnd)
            score += 150;
        else if (net_packets_out * 3 > net_snd_cwnd)
            score += 100;
        else if (net_packets_out * 4 > net_snd_cwnd)
            score += 50;
    }

    return (score > 1000) ? 1000 : score;
}

// -- Helper: Compute adaptive time windows based on network conditions --
static __always_inline u64 get_adaptive_recent_window(u32 congestion) {
    // Scale from BASE_RECENT_ACCESS_NS (50ms) to 150ms based on congestion
    // High congestion → wider window to protect recency
    u64 window = BASE_RECENT_ACCESS_NS;
    window += (BASE_RECENT_ACCESS_NS * congestion) / 1000;  // add 0-50ms
    return window;
}

static __always_inline u64 get_adaptive_working_set_window(u32 congestion) {
    // Scale from BASE_WORKING_SET_NS (800ms) to 2s based on congestion
    u64 window = BASE_WORKING_SET_NS;
    window += (BASE_WORKING_SET_NS * congestion) / 500;  // add 0-1.6s
    return (window > 2000000000ULL) ? 2000000000ULL : window;
}

// -- Helper: Compute folio eviction score (higher = keep it) --
static __always_inline u32 compute_folio_score(struct net_folio_metadata *meta,
                                                u64 now, u32 congestion,
                                                bool in_burst, bool session_active) {
    u32 score = 0;

    if (!meta)
        return 0;

    u64 age_ns = (now > meta->last_access_ts) ? (now - meta->last_access_ts) : 0;
    u64 recent_window = get_adaptive_recent_window(congestion);
    u64 working_set_window = get_adaptive_working_set_window(congestion);

    // Recency score (0-500 points)
    // Linear decay from 500 (just accessed) to 0 (beyond recent window)
    if (age_ns < recent_window) {
        score += 500 - (500 * age_ns) / recent_window;
    }

    // Frequency score (0-300 points)
    // Logarithmic: access_count 1→50, 2→100, 3→150, 4+→300
    if (meta->access_count >= 4)
        score += 300;
    else if (meta->access_count == 3)
        score += 150;
    else if (meta->access_count == 2)
        score += 100;
    else if (meta->access_count == 1)
        score += 50;

    // Burst protection bonus (0-200 points)
    // During bursts, protect the working set more aggressively
    if (in_burst && age_ns < working_set_window) {
        score += 200 - (200 * age_ns) / working_set_window;
    }

    // Congestion protection (0-100 points)
    // In high congestion, protect pages in working set more
    if (session_active && age_ns < working_set_window && congestion > 500) {
        score += (congestion - 500) / 5;  // 0-100 points
    }

    // Tier bonus: hot folios get extra protection
    if (meta->access_tier == 2)
        score += 150;
    else if (meta->access_tier == 1)
        score += 75;

    return score;
}

// -- Eviction callback for cold_list (most aggressive eviction) --
static int bpf_evict_cold_cb(int idx, struct cache_ext_list_node *node) {
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta)
        return CACHE_EXT_EVICT_NODE;

    if (folio_test_dirty(node->folio) || folio_test_writeback(node->folio))
        return CACHE_EXT_CONTINUE_ITER;

    // Cold list: evict cold folios that haven't been accessed recently
    if (meta->access_tier == 0) {
        u64 age_ns = (now > meta->last_access_ts) ?
            (now - meta->last_access_ts) : 0;
        if (age_ns > 500000000ULL)  // older than 500ms
            return CACHE_EXT_EVICT_NODE;
    }

    return CACHE_EXT_CONTINUE_ITER;
}

// -- Eviction callback for warm_list (moderate eviction) --
static int bpf_evict_warm_cb(int idx, struct cache_ext_list_node *node) {
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta)
        return CACHE_EXT_EVICT_NODE;

    if (folio_test_dirty(node->folio) || folio_test_writeback(node->folio))
        return CACHE_EXT_CONTINUE_ITER;

    u32 congestion = compute_congestion_score();
    bool session_active = (now - last_packet_ts) < NET_IDLE_TIMEOUT_NS;
    bool in_burst = is_burst(now);

    u32 score = compute_folio_score(meta, now, congestion, in_burst, session_active);

    // Evict warm folios with low score
    if (score < 200)
        return CACHE_EXT_EVICT_NODE;

    return CACHE_EXT_CONTINUE_ITER;
}

// -- Eviction callback for hot_list (conservative eviction) --
static int bpf_evict_hot_cb(int idx, struct cache_ext_list_node *node) {
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta)
        return CACHE_EXT_EVICT_NODE;

    if (folio_test_dirty(node->folio) || folio_test_writeback(node->folio))
        return CACHE_EXT_CONTINUE_ITER;

    u32 congestion = compute_congestion_score();
    bool session_active = (now - last_packet_ts) < NET_IDLE_TIMEOUT_NS;
    bool in_burst = is_burst(now);

    u32 score = compute_folio_score(meta, now, congestion, in_burst, session_active);

    // Only evict hot folios with very low score (highly protective)
    if (score < 100)
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

    // Add new folios to cold list (FIFO tail)
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

    // Determine new tier based on access count
    u32 old_tier = meta->access_tier;
    if (meta->access_count >= HOT_ACCESS_THRESHOLD)
        meta->access_tier = 2;  // hot
    else if (meta->access_count >= 2)
        meta->access_tier = 1;  // warm
    else
        meta->access_tier = 0;  // cold

    // Promote folio if tier changed
    if (meta->access_tier > old_tier) {
        // Remove from current list
        bpf_cache_ext_list_del(folio);

        // Add to appropriate new list
        if (meta->access_tier == 2) {
            bpf_cache_ext_list_add(hot_list, folio);  // hot at head
        } else if (meta->access_tier == 1) {
            bpf_cache_ext_list_add(warm_list, folio);  // warm at head
        }
    } else {
        // Same tier: move to head (MRU position)
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