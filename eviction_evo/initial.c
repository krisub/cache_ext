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
// Time window: folios accessed within this window are "recently used"
#define RECENT_ACCESS_NS    100000000ULL   // 100 ms
// Time window: network session considered active if packet within this window
#define NET_IDLE_TIMEOUT_NS 5000000000ULL  // 5 s
// Working set window: protect active-DB folios accessed within this window
#define WORKING_SET_NS      1000000000ULL  // 1 s
// Access count threshold: folios with >= this many accesses are "hot"
#define HOT_ACCESS_THRESHOLD 3

// ── Eviction iteration callback ─────────────────────────────────────
// Called for each folio during eviction scan.
// Return CACHE_EXT_EVICT_NODE to evict, CACHE_EXT_CONTINUE_ITER to keep.
static int bpf_evict_cb(int idx, struct cache_ext_list_node *node)
{
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    // No metadata → unknown folio → evict
    if (!meta)
        return CACHE_EXT_EVICT_NODE;

    // Skip dirty / under-writeback folios (kernel can't evict them anyway)
    if (folio_test_dirty(node->folio) || folio_test_writeback(node->folio))
        return CACHE_EXT_CONTINUE_ITER;

    // ── Network-aware heuristics ────────────────────────────────────

    bool session_active = (now - last_packet_ts) < NET_IDLE_TIMEOUT_NS;
    bool is_active_db   = (meta->owner_pid == active_db_pid) && (active_db_pid != 0);
    bool recently_used  = (now - meta->last_access_ts) < RECENT_ACCESS_NS;
    bool in_working_set = (now - meta->last_access_ts) < WORKING_SET_NS;
    bool is_hot         = (meta->access_count >= HOT_ACCESS_THRESHOLD);

    // Protect hot folios (many accesses) that were recently touched
    if (is_hot && recently_used)
        return CACHE_EXT_CONTINUE_ITER;

    // During an active network session, protect the active DB's working set
    if (session_active && is_active_db && in_working_set)
        return CACHE_EXT_CONTINUE_ITER;

    // Protect any recently accessed folio
    if (recently_used)
        return CACHE_EXT_CONTINUE_ITER;

    // Everything else → evict
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
void BPF_STRUCT_OPS(evolved_evict_folios,
                    struct cache_ext_eviction_ctx *eviction_ctx,
                    struct mem_cgroup *memcg)
{
    bump_counter(0);
    bpf_cache_ext_list_iterate(memcg, main_list, bpf_evict_cb, eviction_ctx);
}

// ── struct_ops: folio_added ─────────────────────────────────────────
void BPF_STRUCT_OPS(evolved_folio_added, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    // Add to tail of main list (FIFO-like insertion)
    int ret = bpf_cache_ext_list_add_tail(main_list, folio);
    if (ret != 0) {
        bump_counter(1);
        return;
    }

    // Initialize metadata
    u64 key = (u64)folio;
    struct net_folio_metadata new_meta = {
        .owner_pid     = bpf_get_current_pid_tgid() >> 32,
        .last_access_ts = bpf_ktime_get_ns(),
        .access_count  = 1,
        .access_tier   = 0,  // cold
    };
    bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
    bump_counter(2);
}

// ── struct_ops: folio_accessed ──────────────────────────────────────
void BPF_STRUCT_OPS(evolved_folio_accessed, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    u64 key = (u64)folio;
    struct net_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta) {
        // Folio not tracked yet — add it
        int ret = bpf_cache_ext_list_add(main_list, folio);
        if (ret != 0) {
            // Already in a list — just move to head (MRU); third arg is 'tail', so false = head
            bpf_cache_ext_list_move(main_list, folio, false);
        }
        struct net_folio_metadata new_meta = {
            .owner_pid     = bpf_get_current_pid_tgid() >> 32,
            .last_access_ts = bpf_ktime_get_ns(),
            .access_count  = 1,
            .access_tier   = 0,
        };
        bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
        bump_counter(3);
        return;
    }

    // Update existing metadata
    meta->last_access_ts = bpf_ktime_get_ns();
    meta->access_count += 1;

    // Update tier based on access count
    if (meta->access_count >= HOT_ACCESS_THRESHOLD)
        meta->access_tier = 2;  // hot
    else if (meta->access_count >= 2)
        meta->access_tier = 1;  // warm
    else
        meta->access_tier = 0;  // cold

    // Move to head of list (MRU position); third arg is 'tail', so false = head
    bpf_cache_ext_list_move(main_list, folio, false);
    bump_counter(4);
}

// ── struct_ops: folio_evicted ───────────────────────────────────────
void BPF_STRUCT_OPS(evolved_folio_evicted, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    // Remove from the list FIRST, before metadata is gone.
    // Without this, the eviction iterator holds a dangling folio pointer
    // in main_list, causing kernel memory corruption (GPF in userspace).
    bpf_cache_ext_list_del(folio);

    u64 key = (u64)folio;
    bpf_map_delete_elem(&folio_metadata_map, &key);
    bump_counter(5);
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
