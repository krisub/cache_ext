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
// -- Phase detection and network health scoring (evolved) ----------------------
static u64 hot_list;
static u64 warm_list;
static u64 cold_list;

// Phase tracking: detect if we're in a "read burst" or "write phase"
static u32 current_phase = 0;  // 0=unknown, 1=read_burst, 2=write_phase
static u64 last_phase_update_ts = 0;
static u32 prev_recv_count = 0;
static u32 prev_inter_arrival_us = 0;

// -- Constants ----------------------------------------------------------------
#define NET_IDLE_TIMEOUT_NS      5000000000ULL  // 5 s
#define PHASE_WINDOW_NS          1000000000ULL  // 1 s (detect phase over this window)
#define READ_BURST_INTER_ARRIVAL_US  1000ULL   // < 1ms = read burst
#define WRITE_PHASE_INTER_ARRIVAL_US 10000ULL  // > 10ms = write phase
#define HOT_ACCESS_THRESHOLD     3

// -- Helper: Compute network health score (0-1000, higher = worse) --
static __always_inline u32 compute_network_health_score(void) {
    u32 score = 0;

    // Factor 1: RTT (0-350 points)
    u32 rtt_us = net_srtt_us >> 3;
    if (rtt_us > 100000)
        score += 350;
    else if (rtt_us > 50000)
        score += 280;
    else if (rtt_us > 20000)
        score += 200;
    else if (rtt_us > 5000)
        score += 100;
    else if (rtt_us > 1000)
        score += 50;

    // Factor 2: Jitter/mdev (0-250 points)
    u32 mdev_us = net_mdev_us >> 3;
    if (mdev_us > 20000)
        score += 250;
    else if (mdev_us > 10000)
        score += 200;
    else if (mdev_us > 5000)
        score += 150;
    else if (mdev_us > 1000)
        score += 75;

    // Factor 3: Loss/retransmission (0-250 points)
    if (net_retrans_out > 0 || net_lost > 0)
        score += 250;
    else if (net_total_retrans > 20)
        score += 200;
    else if (net_total_retrans > 5)
        score += 100;

    // Factor 4: Congestion window pressure (0-150 points)
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

// -- Helper: Detect current request phase --
static __always_inline void update_phase(u64 now) {
    if (now - last_phase_update_ts < PHASE_WINDOW_NS)
        return;  // Don't update too frequently

    last_phase_update_ts = now;

    // Compute current inter-arrival time
    u64 inter_arrival_ns = (now > net_prev_packet_ts) ? 
        (now - net_prev_packet_ts) : 0;
    u32 inter_arrival_us = (inter_arrival_ns > 1000000ULL) ? 
        (inter_arrival_ns / 1000) : 0;

    // Detect phase transition based on inter-arrival pattern
    if (inter_arrival_us > 0 && inter_arrival_us < READ_BURST_INTER_ARRIVAL_US) {
        current_phase = 1;  // read_burst
    } else if (inter_arrival_us > WRITE_PHASE_INTER_ARRIVAL_US) {
        current_phase = 2;  // write_phase
    } else {
        current_phase = 0;  // unknown/mixed
    }

    prev_inter_arrival_us = inter_arrival_us;
}

// -- Helper: Compute adaptive time windows based on phase and network health --
static __always_inline u64 get_recency_window(u32 health_score) {
    // Base: 60ms in good conditions, up to 200ms in bad conditions
    u64 base = 60000000ULL;
    base += (health_score * 140000000ULL) / 1000;  // add 0-140ms
    return (base > 200000000ULL) ? 200000000ULL : base;
}

static __always_inline u64 get_working_set_window(u32 health_score, u32 phase) {
    u64 base = 600000000ULL;  // 600ms base
    
    // Expand window during read bursts (need to keep more pages)
    if (phase == 1)
        base = 900000000ULL;
    
    // Expand further in bad network conditions
    base += (health_score * 600000000ULL) / 1000;
    return (base > 1500000000ULL) ? 1500000000ULL : base;
}

// -- Helper: Compute folio "future value" score (will it be accessed soon?) --
static __always_inline u32 compute_future_value(struct net_folio_metadata *meta,
                                                 u64 now, u32 health_score,
                                                 u32 phase) {
    if (!meta)
        return 0;

    u32 score = 0;
    u64 age_ns = (now > meta->last_access_ts) ? (now - meta->last_access_ts) : 0;

    // Base recency score (0-400 points)
    u64 recency_window = get_recency_window(health_score);
    if (age_ns < recency_window) {
        score += 400 - (400 * age_ns) / recency_window;
    }

    // Frequency score: decay during congestion (0-300 points)
    // High-frequency pages are less valuable when network is congested
    // (they're likely sequential scans)
    u32 freq_contribution = 300;
    if (health_score > 600) {
        // High congestion: reduce frequency value by 50%
        freq_contribution = 150;
    } else if (health_score > 400) {
        // Moderate congestion: reduce by 25%
        freq_contribution = 225;
    }

    if (meta->access_count >= HOT_ACCESS_THRESHOLD)
        score += freq_contribution;
    else if (meta->access_count >= 2)
        score += (freq_contribution * 2) / 3;
    else if (meta->access_count >= 1)
        score += freq_contribution / 3;

    // Phase-matched access bonus (0-200 points)
    // If folio was accessed in current phase, boost its value
    if (phase > 0 && meta->phase_tag == phase) {
        u64 working_set_window = get_working_set_window(health_score, phase);
        if (age_ns < working_set_window) {
            score += 200 - (200 * age_ns) / working_set_window;
        }
    }

    // RTT-based predictive protection (0-150 points)
    // Pages accessed within one RTT are likely to be accessed again
    u32 rtt_us = net_srtt_us >> 3;
    u64 rtt_ns = (u64)rtt_us * 1000;
    if (rtt_ns > 0 && age_ns < rtt_ns) {
        score += 150 - (150 * age_ns) / rtt_ns;
    }

    // Tier bonus (0-100 points)
    if (meta->access_tier == 2)
        score += 100;
    else if (meta->access_tier == 1)
        score += 50;

    return score;
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

    // Aggressive eviction from cold list
    u64 age_ns = (now > meta->last_access_ts) ? (now - meta->last_access_ts) : 0;
    if (age_ns > 400000000ULL)  // older than 400ms
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

    u32 health_score = compute_network_health_score();
    bool session_active = (now - last_packet_ts) < NET_IDLE_TIMEOUT_NS;

    u32 future_value = compute_future_value(meta, now, health_score, current_phase);

    // Moderate eviction: evict warm pages with low future value
    if (!session_active || future_value < 150)
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

    u32 health_score = compute_network_health_score();
    bool session_active = (now - last_packet_ts) < NET_IDLE_TIMEOUT_NS;

    u32 future_value = compute_future_value(meta, now, health_score, current_phase);

    // Conservative eviction: only evict hot pages with very low future value
    if (!session_active || future_value < 50)
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
    u64 now = bpf_ktime_get_ns();
    bump_counter(0);
    
    // Update phase detection
    update_phase(now);
    
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
    u64 now = bpf_ktime_get_ns();
    
    // Add new folios to cold list
    int ret = bpf_cache_ext_list_add_tail(cold_list, folio);
    if (ret != 0) {
        bump_counter(1);
        return;
    }

    // Initialize metadata with current phase tag
    struct net_folio_metadata new_meta = {
        .last_access_ts = now,
        .access_count  = 1,
        .access_tier   = 0,
        .phase_tag     = current_phase,
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
            .phase_tag     = current_phase,
        };
        bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
        bump_counter(3);
        return;
    }

    // Update metadata
    meta->last_access_ts = now;
    meta->access_count += 1;
    
    // Update phase tag if in a detected phase
    if (current_phase > 0)
        meta->phase_tag = current_phase;

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
            bpf_cache_ext_list_add(hot_list, folio);
        } else if (meta->access_tier == 1) {
            bpf_cache_ext_list_add(warm_list, folio);
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
