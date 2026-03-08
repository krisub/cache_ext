// BPF page cache eviction policy with network awareness.
// This file is evolved by ShinkaEvolve. The EVOLVE-BLOCK contains the
// eviction strategy that will be optimized to maximize throughput.
//
// Fixed infrastructure (outside EVOLVE-BLOCK):
//   - Includes, license, map definitions
//   - Network monitoring kprobe (tcp_recvmsg) that tracks active_db_pid
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
// Network metrics available as globals:
//   active_db_pid  — PID of process currently handling TCP requests (0 if idle)
//   last_packet_ts — timestamp (ns) of last TCP packet on monitored port
//
// Per-folio metadata in folio_metadata_map:
//   owner_pid      — PID that first brought this folio into cache
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
    u32 owner_pid;
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

// ── Debug counters ──────────────────────────────────────────────────
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, u64);
} debug_counters SEC(".maps");

// ── Network state (updated by kprobe below) ─────────────────────────
u64 last_packet_ts = 0;
u32 active_db_pid = 0;

// ── Helpers (fixed) ──────────────────────────────────────────────────
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
// ── List handles + eviction policy constants (evolved) ────────────────
static u64 main_list;

// ══════════════════════════════════════════════════════════════════════
// EVICTION POLICY — everything below is evolved by ShinkaEvolve
// ══════════════════════════════════════════════════════════════════════

// ── Tunable constants ───────────────────────────────────────────────
// Base time windows (will be scaled by tier frequency multiplier)
#define BASE_HOT_WINDOW_NS      800000000ULL   // 800 ms base for hot folios
#define BASE_WARM_WINDOW_NS     400000000ULL   // 400 ms base for warm folios
#define BASE_COLD_WINDOW_NS     100000000ULL   // 100 ms base for cold folios

// Network session detection windows
#define ACTIVE_PHASE_NS         1000000000ULL  // 1 s — packet within this = active
#define IDLE_PHASE_NS           5000000000ULL  // 5 s — packet within this = idle
#define SESSION_TIMEOUT_NS      5000000000ULL  // 5 s — beyond this = offline

// Frequency thresholds
#define HOT_ACCESS_THRESHOLD    3
#define WARM_ACCESS_THRESHOLD   2

// Decay parameters
#define FREQ_DECAY_NS           2000000000ULL  // 2 s without access = decay opportunity
#define ACTIVE_DB_BONUS_NS      500000000ULL   // 500 ms extra protection for active_db_pid

// Sampling ratio: sample 30% of candidates for fast rejection
#define SAMPLE_RATIO            300            // ratio in per-mille (300 = 30%)

// ── Helper: compute adaptive protection window based on tier and frequency ──
static __always_inline u64 get_protection_window(u32 access_count, u32 tier)
{
    u64 base_window = 0;
    u32 threshold = 0;

    if (tier == 2) {  // hot
        base_window = BASE_HOT_WINDOW_NS;
        threshold = HOT_ACCESS_THRESHOLD;
    } else if (tier == 1) {  // warm
        base_window = BASE_WARM_WINDOW_NS;
        threshold = WARM_ACCESS_THRESHOLD;
    } else {  // cold
        base_window = BASE_COLD_WINDOW_NS;
        threshold = 1;
    }

    // Scale window by frequency multiplier: (access_count / threshold)
    // Clamped to prevent overflow; scaled by 10 for integer math
    u32 freq_excess = (access_count > threshold) ? (access_count - threshold) : 0;
    u64 multiplier = 10 + (freq_excess * 3);  // 10 base, +3 per excess access
    if (multiplier > 30)
        multiplier = 30;

    return (base_window * multiplier) / 10;
}

// ── Helper: compute recency-frequency score (for intelligent decisions) ──
// Higher score = keep, Lower score = evict
// Score = access_count * (1 + decay_factor)
// where decay_factor decreases with time since last access
static __always_inline u64 compute_folio_score(
    struct net_folio_metadata *meta,
    u64 now,
    bool is_active_db,
    u32 session_phase)
{
    u64 time_since_access = now - meta->last_access_ts;

    // Decay factor: starts at 1000 (scaled), decreases with age
    // At FREQ_DECAY_NS, decay_factor = 500 (50%)
    // At 2*FREQ_DECAY_NS, decay_factor = 0
    u64 decay_factor = 1000;
    if (time_since_access < FREQ_DECAY_NS) {
        decay_factor = 1000 - (time_since_access * 500) / FREQ_DECAY_NS;
    } else if (time_since_access < (2 * FREQ_DECAY_NS)) {
        decay_factor = (500 * (2 * FREQ_DECAY_NS - time_since_access)) / FREQ_DECAY_NS;
    } else {
        decay_factor = 0;
    }

    // Base score: access_count * decay_factor (scaled by 1000)
    u64 score = ((u64)meta->access_count) * decay_factor / 1000;

    // Bonus for active_db_pid: +50 to score
    if (is_active_db && session_phase < IDLE_PHASE_NS)
        score += 50;

    // Phase-based adjustment: during idle, penalize non-active-db folios
    if (session_phase > ACTIVE_PHASE_NS && !is_active_db && meta->owner_pid != active_db_pid)
        score = (score * 2) / 3;  // reduce by 33%

    return score;
}

// ── Eviction iteration callback (sampling phase) ─────────────────────
// Called during sampling pass: evict cold/old folios quickly
static int bpf_evict_sample_cb(int idx, struct cache_ext_list_node *node)
{
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta)
        return CACHE_EXT_EVICT_NODE;

    // Skip dirty/writeback folios (kernel can't evict them)
    if (folio_test_dirty(node->folio) || folio_test_writeback(node->folio))
        return CACHE_EXT_CONTINUE_ITER;

    u64 time_since_access = now - meta->last_access_ts;

    // Aggressive sampling: evict cold folios older than BASE_COLD_WINDOW_NS
    if (meta->access_tier == 0 && time_since_access > (2 * BASE_COLD_WINDOW_NS))
        return CACHE_EXT_EVICT_NODE;

    // Keep everything else for detailed iteration pass
    return CACHE_EXT_CONTINUE_ITER;
}

// ── Main eviction iteration callback ─────────────────────────────────
// Called for each folio during detailed eviction scan.
static int bpf_evict_cb(int idx, struct cache_ext_list_node *node)
{
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta)
        return CACHE_EXT_EVICT_NODE;

    // Skip dirty / under-writeback folios
    if (folio_test_dirty(node->folio) || folio_test_writeback(node->folio))
        return CACHE_EXT_CONTINUE_ITER;

    // ── Session phase detection ────────────────────────────────────
    u64 time_since_packet = now - last_packet_ts;
    u32 session_phase = time_since_packet;
    bool session_online = (time_since_packet < SESSION_TIMEOUT_NS);
    bool is_active_db = (meta->owner_pid == active_db_pid) && (active_db_pid != 0);

    // ── Adaptive window-based protection ────────────────────────────
    u64 protection_window = get_protection_window(meta->access_count, meta->access_tier);

    // Add active_db bonus during online session
    if (session_online && is_active_db)
        protection_window += ACTIVE_DB_BONUS_NS;

    u64 time_since_access = now - meta->last_access_ts;
    bool in_protection_window = (time_since_access < protection_window);

    // Keep if in protection window
    if (in_protection_window)
        return CACHE_EXT_CONTINUE_ITER;

    // ── Score-based fallback for edge cases ──────────────────────
    // Only compute detailed score if not obviously old
    if (time_since_access < (3 * BASE_HOT_WINDOW_NS)) {
        u64 score = compute_folio_score(meta, now, is_active_db, session_phase);
        if (score > 100)  // threshold for keeping borderline folios
            return CACHE_EXT_CONTINUE_ITER;
    }

    // Evict by default
    return CACHE_EXT_EVICT_NODE;
}

// ── struct_ops: init ────────────────────────────────────────────────
s32 BPF_STRUCT_OPS_SLEEPABLE(evolved_init, struct mem_cgroup *memcg)
{
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (!main_list)
        return -1;
    return 0;
}

// ── struct_ops: evict_folios ────────────────────────────────────────
// Two-phase eviction: sample fast rejection first, then detailed scan
void BPF_STRUCT_OPS(evolved_evict_folios,
                    struct cache_ext_eviction_ctx *eviction_ctx,
                    struct mem_cgroup *memcg)
{
    bump_counter(0);

    // Phase 1: Sample 30% of list for quick rejection of obvious cold folios
    // This reduces average iteration depth during high eviction pressure
    bpf_cache_ext_list_sample(memcg, main_list, bpf_evict_sample_cb,
                              SAMPLE_RATIO, eviction_ctx);
    bump_counter(1);

    // Phase 2: Detailed iteration with adaptive window scoring
    bpf_cache_ext_list_iterate(memcg, main_list, bpf_evict_cb, eviction_ctx);
}

// ── struct_ops: folio_added ─────────────────────────────────────────
void BPF_STRUCT_OPS(evolved_folio_added, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    int ret = bpf_cache_ext_list_add_tail(main_list, folio);
    if (ret != 0) {
        bump_counter(2);
        return;
    }

    u64 key = (u64)folio;
    struct net_folio_metadata new_meta = {
        .owner_pid     = bpf_get_current_pid_tgid() >> 32,
        .last_access_ts = bpf_ktime_get_ns(),
        .access_count  = 1,
        .access_tier   = 0,  // cold
    };
    bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
    bump_counter(3);
}

// ── struct_ops: folio_accessed ──────────────────────────────────────
void BPF_STRUCT_OPS(evolved_folio_accessed, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)folio;
    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta) {
        // Folio not tracked yet — add it
        int ret = bpf_cache_ext_list_add(main_list, folio);
        if (ret != 0) {
            bpf_cache_ext_list_move(main_list, folio, false);
        }
        struct net_folio_metadata new_meta = {
            .owner_pid     = bpf_get_current_pid_tgid() >> 32,
            .last_access_ts = now,
            .access_count  = 1,
            .access_tier   = 0,
        };
        bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
        bump_counter(4);
        return;
    }

    // ── Adaptive frequency decay based on session phase ────────────
    u64 time_since_access = now - meta->last_access_ts;
    u64 time_since_packet = now - last_packet_ts;

    if (time_since_access > FREQ_DECAY_NS && meta->access_count > 0) {
        // Decay rate depends on session phase
        if (time_since_packet > IDLE_PHASE_NS) {
            // Offline: aggressive decay (−2)
            if (meta->access_count >= 2)
                meta->access_count -= 2;
            else
                meta->access_count = 0;
        } else if (time_since_packet > ACTIVE_PHASE_NS) {
            // Idle phase: standard decay (−1)
            meta->access_count -= 1;
        }
        // Active phase: no decay on this interval
    }

    // Update existing metadata
    meta->last_access_ts = now;
    meta->access_count += 1;

    // Update tier based on access count
    if (meta->access_count >= HOT_ACCESS_THRESHOLD)
        meta->access_tier = 2;
    else if (meta->access_count >= WARM_ACCESS_THRESHOLD)
        meta->access_tier = 1;
    else
        meta->access_tier = 0;

    // Move to head (MRU)
    bpf_cache_ext_list_move(main_list, folio, false);
    bump_counter(5);
}

// ── struct_ops: folio_evicted ───────────────────────────────────────
void BPF_STRUCT_OPS(evolved_folio_evicted, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    bpf_cache_ext_list_del(folio);

    u64 key = (u64)folio;
    bpf_map_delete_elem(&folio_metadata_map, &key);
    bump_counter(6);
}

// EVOLVE-BLOCK-END

// ══════════════════════════════════════════════════════════════════════
// NETWORK MONITORING (fixed — not evolved)
// ══════════════════════════════════════════════════════════════════════

SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    // Monitor the net_leveldb_server port (9100) and common DB ports
    if (sport == 9100 || sport == 9001 || sport == 9002) {
        last_packet_ts = bpf_ktime_get_ns();
        active_db_pid  = bpf_get_current_pid_tgid() >> 32;
    }
    return 0;
}

// ── struct_ops registration ─────────────────────────────────────────
SEC(".struct_ops.link")
struct cache_ext_ops evolved_ops = {
    .init           = (void *)evolved_init,
    .evict_folios   = (void *)evolved_evict_folios,
    .folio_added    = (void *)evolved_folio_added,
    .folio_evicted  = (void *)evolved_folio_evicted,
    .folio_accessed = (void *)evolved_folio_accessed,
    .admit_folio    = (void *)0,
};