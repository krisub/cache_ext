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
//   - Network monitoring kprobe (tcp_recvmsg) -- updates raw globals,
//     calls vulcan_tag_update_feature (per client_tag from server port) for
//     enabled gf_configs[] features (GF_CLIENT_TAG is folio-driven only)
//   - struct_ops registration
//
// Library headers (cache_ext/vulcan_bpf/):
//   - vulcan_bpf.h     -- listener primitives, config types, per-folio helpers
//   - vulcan_feature.h  -- feature dispatch (vulcan_update_feature) and
//                          accessor functions (vulcan_get_ewma, etc.)
//
// BASELINE: LFU scoring like cache_ext_sampling.bpf.c; gf_configs all zero.
// Evolution can enable listeners; when enabled, kprobe fills per-tag maps only
// (see fixed tcp_recvmsg loop). For multi-client scoring use vulcan_tag_get_*
// with meta->client_tag. DO NOT modify networking infrastructure
// (kprobe, maps, includes).
//
// What the LLM evolves (inside EVOLVE-BLOCK):
//   - gf_configs[] -- per GF_*: listener_mask (VULCAN_LISTENER_*) + ewma_alpha / rw_size
//   - folio_cfg    -- per-folio interval tracking (baseline: disabled)
//   - SAMPLE_SIZE  -- candidates per eviction slot
//   - bpf_score_fn(node) -> s64 -- lower = evict first; INT64_MAX = protect
//   - struct_ops callbacks (init, evict_folios, folio_added, folio_accessed,
//     folio_evicted) — evolve eviction logic only
//
// =======================================================================
// GLOBAL FEATURE ACCESSOR API  (usable inside bpf_score_fn)
// =======================================================================
//
// vulcan_get_* global maps are not fed by tcp_recvmsg here. Per-tag data exists
// for GF_* rows with non-zero gf_configs[i].listener_mask; disabled accessors
// return 0.
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
// Per-client_tag accessors (same listener bits as gf_configs[i]; use
// meta->client_tag — matches kprobe port→tag routing):
//   vulcan_tag_get_min/max/ewma/avg/latest/kth_recent/window_avg/window_count
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
//   GF_CLIENT_TAG       -- client tag of folio on each access (fed by folio hooks)
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

#define VULCAN_NUM_GLOBAL_FEATURES 17

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
    GF_CLIENT_TAG,
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
    __uint(max_entries, 17);
    __type(key, u32);
    __type(value, struct vulcan_minmax);
} vulcan_gminmax SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 17);
    __type(key, u32);
    __type(value, struct vulcan_ewma);
} vulcan_gewma SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 17);
    __type(key, u32);
    __type(value, struct vulcan_rolling_window);
} vulcan_grw SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 17);
    __type(key, u32);
    __type(value, struct vulcan_avg);
} vulcan_gavg SEC(".maps");

struct vulcan_tag_feature_key {
    u32 client_tag;
    u32 feature_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct vulcan_tag_feature_key);
    __type(value, struct vulcan_minmax);
} vulcan_tgminmax SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct vulcan_tag_feature_key);
    __type(value, struct vulcan_ewma);
} vulcan_tgewma SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct vulcan_tag_feature_key);
    __type(value, struct vulcan_rolling_window);
} vulcan_tgrw SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct vulcan_tag_feature_key);
    __type(value, struct vulcan_avg);
} vulcan_tgavg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 17);
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

static __always_inline bool is_folio_relevant(struct folio *folio)
{
    if (!folio || !folio->mapping || !folio->mapping->host)
        return false;
    return inode_in_watchlist(folio->mapping->host->i_ino);
}

static __always_inline u32 folio_client_tag(struct folio *folio)
{
    if (!folio || !folio->mapping || !folio->mapping->host)
        return 0;
    return inode_get_client_tag(folio->mapping->host->i_ino);
}

static __always_inline u32 net_client_tag_from_sport(u16 sport)
{
    if (sport == 9100 || sport == 9001)
        return 1;
    if (sport == 9101 || sport == 9002)
        return 2;
    return 0;
}

static __always_inline void
vulcan_tag_update_feature(u32 client_tag, u32 feature_id, s64 raw_value,
                          const struct vulcan_feature_config *cfg)
{
    if (!client_tag || !cfg || !cfg->listener_mask)
        return;
    if (feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return;

    struct vulcan_tag_feature_key key = {
        .client_tag = client_tag,
        .feature_id = feature_id,
    };

    if (cfg->listener_mask & VULCAN_LISTENER_MINMAX) {
        struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_tgminmax, &key);
        if (!mm) {
            struct vulcan_minmax init = {};
            bpf_map_update_elem(&vulcan_tgminmax, &key, &init, BPF_ANY);
            mm = bpf_map_lookup_elem(&vulcan_tgminmax, &key);
        }
        if (mm)
            vulcan_minmax_update(mm, raw_value);
    }

    if (cfg->listener_mask & VULCAN_LISTENER_EWMA) {
        struct vulcan_ewma *e = bpf_map_lookup_elem(&vulcan_tgewma, &key);
        if (!e) {
            struct vulcan_ewma init = {};
            bpf_map_update_elem(&vulcan_tgewma, &key, &init, BPF_ANY);
            e = bpf_map_lookup_elem(&vulcan_tgewma, &key);
        }
        if (e)
            vulcan_ewma_update(e, raw_value, cfg->ewma_alpha);
    }

    if (cfg->listener_mask & VULCAN_LISTENER_AVG) {
        struct vulcan_avg *a = bpf_map_lookup_elem(&vulcan_tgavg, &key);
        if (!a) {
            struct vulcan_avg init = {};
            bpf_map_update_elem(&vulcan_tgavg, &key, &init, BPF_ANY);
            a = bpf_map_lookup_elem(&vulcan_tgavg, &key);
        }
        if (a)
            vulcan_avg_update(a, raw_value);
    }

    if (cfg->listener_mask & VULCAN_LISTENER_RW) {
        struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_tgrw, &key);
        if (!rw) {
            struct vulcan_rolling_window init = {};
            bpf_map_update_elem(&vulcan_tgrw, &key, &init, BPF_ANY);
            rw = bpf_map_lookup_elem(&vulcan_tgrw, &key);
        }
        if (rw)
            vulcan_rw_update(rw, raw_value, cfg->rw_size);
    }
}

static __always_inline s64 __attribute__((unused))
vulcan_tag_get_ewma(u32 client_tag, u32 feature_id)
{
    if (!client_tag || feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    struct vulcan_tag_feature_key key = {
        .client_tag = client_tag,
        .feature_id = feature_id,
    };
    struct vulcan_ewma *e = bpf_map_lookup_elem(&vulcan_tgewma, &key);
    return e ? vulcan_ewma_get(e) : 0;
}

static __always_inline s64 __attribute__((unused))
vulcan_tag_get_min(u32 client_tag, u32 feature_id)
{
    if (!client_tag || feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    struct vulcan_tag_feature_key key = {
        .client_tag = client_tag,
        .feature_id = feature_id,
    };
    struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_tgminmax, &key);
    return mm ? vulcan_minmax_get_min(mm) : 0;
}

static __always_inline s64 __attribute__((unused))
vulcan_tag_get_max(u32 client_tag, u32 feature_id)
{
    if (!client_tag || feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    struct vulcan_tag_feature_key key = {
        .client_tag = client_tag,
        .feature_id = feature_id,
    };
    struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_tgminmax, &key);
    return mm ? vulcan_minmax_get_max(mm) : 0;
}

static __always_inline s64 __attribute__((unused))
vulcan_tag_get_avg(u32 client_tag, u32 feature_id)
{
    if (!client_tag || feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    struct vulcan_tag_feature_key key = {
        .client_tag = client_tag,
        .feature_id = feature_id,
    };
    struct vulcan_avg *a = bpf_map_lookup_elem(&vulcan_tgavg, &key);
    return a ? vulcan_avg_get(a) : 0;
}

static __always_inline s64 __attribute__((unused))
vulcan_tag_get_latest(u32 client_tag, u32 feature_id)
{
    if (!client_tag || feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    struct vulcan_tag_feature_key key = {
        .client_tag = client_tag,
        .feature_id = feature_id,
    };
    struct vulcan_rolling_window *rw =
        bpf_map_lookup_elem(&vulcan_tgrw, &key);
    return rw ? vulcan_rw_get_latest(rw) : 0;
}

static __always_inline s64 __attribute__((unused))
vulcan_tag_get_kth_recent(u32 client_tag, u32 feature_id, u32 k)
{
    if (!client_tag || feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    struct vulcan_tag_feature_key key = {
        .client_tag = client_tag,
        .feature_id = feature_id,
    };
    struct vulcan_rolling_window *rw =
        bpf_map_lookup_elem(&vulcan_tgrw, &key);
    return rw ? vulcan_rw_get_kth_recent(rw, k) : 0;
}

static __always_inline s64 __attribute__((unused))
vulcan_tag_get_window_avg(u32 client_tag, u32 feature_id)
{
    if (!client_tag || feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    struct vulcan_tag_feature_key key = {
        .client_tag = client_tag,
        .feature_id = feature_id,
    };
    struct vulcan_rolling_window *rw =
        bpf_map_lookup_elem(&vulcan_tgrw, &key);
    return rw ? vulcan_rw_get_avg(rw) : 0;
}

static __always_inline u32 __attribute__((unused))
vulcan_tag_get_window_count(u32 client_tag, u32 feature_id)
{
    if (!client_tag || feature_id >= VULCAN_NUM_GLOBAL_FEATURES)
        return 0;
    struct vulcan_tag_feature_key key = {
        .client_tag = client_tag,
        .feature_id = feature_id,
    };
    struct vulcan_rolling_window *rw =
        bpf_map_lookup_elem(&vulcan_tgrw, &key);
    return rw ? vulcan_rw_get_count(rw) : 0;
}

// EVOLVE-BLOCK-START
// =============================================================================
// EVICTION POLICY -- everything below (until the closing marker) is evolved
// =============================================================================
#include "LLM.h"

// EVOLVE-BLOCK-END

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
    new_meta.client_tag = folio_client_tag(folio);
    bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
    vulcan_tag_update_feature(new_meta.client_tag, GF_CLIENT_TAG,
                              (s64)new_meta.client_tag,
                              &gf_configs[GF_CLIENT_TAG]);
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
        new_meta.client_tag = folio_client_tag(folio);
        bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
        vulcan_tag_update_feature(new_meta.client_tag, GF_CLIENT_TAG,
                                  (s64)new_meta.client_tag,
                                  &gf_configs[GF_CLIENT_TAG]);
        bump_counter(3);
        return;
    }

    vulcan_folio_on_access(meta, bpf_ktime_get_ns(), &folio_cfg);
    vulcan_tag_update_feature(meta->client_tag, GF_CLIENT_TAG,
                              (s64)meta->client_tag,
                              &gf_configs[GF_CLIENT_TAG]);
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

// =============================================================================
// NETWORK MONITORING (fixed -- not evolved)
// =============================================================================
// Baseline: kprobe returns immediately when every gf_configs[i].listener_mask
// is zero. tcp_recvmsg stays attached but does no TCP work in that case.
#if 1
SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (sport != 9100 && sport != 9101 && sport != 9001 && sport != 9002)
        return 0;
    u32 client_tag = net_client_tag_from_sport(sport);

    /* When no listeners enabled, exit immediately — zero overhead. */
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
    // per-tag updates for each GF_* with non-zero gf_configs[i].listener_mask.
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
    raw_values[GF_CLIENT_TAG]     = 0; // not applicable in kprobe context

    /* Per-tag only; GF_CLIENT_TAG is updated from folio hooks, not recvmsg. */
    for (u32 i = 0; i < VULCAN_NUM_GLOBAL_FEATURES && i < 17; i++) {
        if (i == GF_CLIENT_TAG)
            continue;
        if (gf_configs[i].listener_mask)
            vulcan_tag_update_feature(client_tag, i, raw_values[i],
                                      &gf_configs[i]);
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
