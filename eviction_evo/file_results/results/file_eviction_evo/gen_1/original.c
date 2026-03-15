// BPF page cache eviction policy with CPU/scheduler awareness.
// This file is evolved by ShinkaEvolve. The EVOLVE-BLOCK contains the
// eviction strategy that will be optimized to maximize throughput.
//
// Fixed infrastructure (outside EVOLVE-BLOCK):
//   - Includes, license, map definitions
//   - Scheduler monitoring kprobe (vfs_read) that captures CPU/scheduler metrics
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
// Scheduler/CPU metrics available as globals (updated on each vfs_read of watched files):
//   sched_last_read_ts       — timestamp (ns) of last watched vfs_read
//   sched_prev_read_ts       — timestamp of the read before that (for inter-arrival delta)
//   sched_read_count         — total vfs_read calls on watched files
//
// Per-process scheduling state (from the task doing the read):
//   sched_nice               — nice value of the reader (-20 to 19; lower = higher priority)
//   sched_prio               — effective scheduler priority (lower = higher priority)
//   sched_static_prio        — static priority (nice-based, 100-139 for normal tasks)
//
// CPU execution metrics (from sched_entity):
//   sched_vruntime           — CFS virtual runtime (ns) — fair-share CPU accounting
//   sched_sum_exec_runtime   — total CPU time consumed by this task (ns)
//   sched_nr_migrations      — number of CPU migrations for this task
//
// Run queue state (from cfs_rq of the current CPU):
//   sched_nr_running         — number of runnable tasks on this CPU's CFS queue
//   sched_cfs_load           — load weight of the CFS run queue
//
// Process identification:
//   sched_pid                — PID of the process doing the read
//   sched_tgid               — thread group ID (process ID)
//   sched_on_cpu             — which CPU the task is running on
//
// Per-folio metadata in folio_metadata_map (struct sched_folio_metadata).
// FIXED — do NOT add, remove, or rename fields. Only these four exist:
//   last_access_ts    — timestamp (ns) of last access to this folio
//   access_count      — number of accesses
//   accessor_nice     — nice value of the process that last accessed this folio
//   accessor_pid      — PID of the last accessor

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

// -- Per-folio metadata -------------------------------------------------------
struct sched_folio_metadata {
    u64 last_access_ts;
    u32 access_count;
    s32 accessor_nice;       // nice value of the process that last accessed
    u32 accessor_pid;        // PID of the last accessor
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);          // (u64)folio pointer
    __type(value, struct sched_folio_metadata);
    __uint(max_entries, 1000000);
} folio_metadata_map SEC(".maps");

// -- Debug counters -----------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, u64);
} debug_counters SEC(".maps");

// -- Scheduler state (updated by kprobe below) --------------------------------
u64 sched_last_read_ts = 0;
u64 sched_prev_read_ts = 0;
u64 sched_read_count = 0;

// Per-process scheduling (snapshot from task_struct of latest vfs_read):
s32 sched_nice = 0;              // nice value (-20 to 19)
s32 sched_prio = 0;              // effective priority
s32 sched_static_prio = 120;     // static priority (120 = nice 0)

// CPU execution metrics (from sched_entity):
u64 sched_vruntime = 0;          // CFS virtual runtime (ns)
u64 sched_sum_exec_runtime = 0;  // total CPU time consumed (ns)
u64 sched_nr_migrations = 0;     // CPU migration count

// Run queue state:
u32 sched_nr_running = 0;        // runnable tasks on this CPU's CFS queue
u64 sched_cfs_load = 0;          // CFS run queue load weight

// Process identification:
u32 sched_pid = 0;               // PID
u32 sched_tgid = 0;              // thread group ID
u32 sched_on_cpu = 0;            // which CPU

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
// -- List handles + eviction policy constants (evolved) -----------------------
static u64 main_list;


// =============================================================================
// EVICTION POLICY — everything below is evolved by ShinkaEvolve
// =============================================================================

// -- Tunable constants --------------------------------------------------------
#define RECENT_ACCESS_NS     100000000ULL   // 100 ms
#define WORKING_SET_NS       1000000000ULL  // 1 s
#define HOT_ACCESS_THRESHOLD 3

// Nice value boundary: processes with nice <= this are "high priority"
#define HIGH_PRIO_NICE_MAX   0

// -- Eviction iteration callback ----------------------------------------------
static int bpf_evict_cb(int idx, struct cache_ext_list_node *node)
{
    u64 now = bpf_ktime_get_ns();
    u64 key = (u64)node->folio;

    struct sched_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta)
        return CACHE_EXT_EVICT_NODE;

    if (folio_test_dirty(node->folio) || folio_test_writeback(node->folio))
        return CACHE_EXT_CONTINUE_ITER;

    // -- Scheduler-aware heuristics -------------------------------------------

    bool recently_used  = (now - meta->last_access_ts) < RECENT_ACCESS_NS;
    bool in_working_set = (now - meta->last_access_ts) < WORKING_SET_NS;
    bool is_hot         = (meta->access_count >= HOT_ACCESS_THRESHOLD);
    bool high_prio      = (meta->accessor_nice <= HIGH_PRIO_NICE_MAX);

    // Protect hot folios from high-priority processes
    if (is_hot && high_prio && in_working_set)
        return CACHE_EXT_CONTINUE_ITER;

    // Protect hot folios that were recently touched (any priority)
    if (is_hot && recently_used)
        return CACHE_EXT_CONTINUE_ITER;

    // When the CPU is busy (many runnable tasks), protect the working set
    // of high-priority processes to reduce their I/O wait
    if (sched_nr_running > 4 && high_prio && in_working_set)
        return CACHE_EXT_CONTINUE_ITER;

    // Protect any recently accessed folio
    if (recently_used)
        return CACHE_EXT_CONTINUE_ITER;

    return CACHE_EXT_EVICT_NODE;
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
    bpf_cache_ext_list_iterate(memcg, main_list, bpf_evict_cb, eviction_ctx);
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

    // Capture the scheduler context of the process adding this folio
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    s32 nice = BPF_CORE_READ(task, static_prio) - 120;
    u32 pid  = bpf_get_current_pid_tgid() >> 32;

    u64 key = (u64)folio;
    struct sched_folio_metadata new_meta = {
        .last_access_ts = bpf_ktime_get_ns(),
        .access_count   = 1,
        .accessor_nice  = nice,
        .accessor_pid   = pid,
    };
    bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
    bump_counter(2);
}

// -- struct_ops: folio_accessed -----------------------------------------------
void BPF_STRUCT_OPS(evolved_folio_accessed, struct folio *folio)
{
    if (!is_folio_relevant(folio))
        return;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    s32 nice = BPF_CORE_READ(task, static_prio) - 120;
    u32 pid  = bpf_get_current_pid_tgid() >> 32;

    u64 key = (u64)folio;
    struct sched_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_metadata_map, &key);

    if (!meta) {
        int ret = bpf_cache_ext_list_add(main_list, folio);
        if (ret != 0) {
            bpf_cache_ext_list_move(main_list, folio, false);
        }
        struct sched_folio_metadata new_meta = {
            .last_access_ts = bpf_ktime_get_ns(),
            .access_count   = 1,
            .accessor_nice  = nice,
            .accessor_pid   = pid,
        };
        bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
        bump_counter(3);
        return;
    }

    meta->last_access_ts = bpf_ktime_get_ns();
    meta->access_count += 1;
    meta->accessor_nice = nice;
    meta->accessor_pid  = pid;

    // Move to head (MRU); tail=false → head
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

// =============================================================================
// SCHEDULER MONITORING (fixed — not evolved)
// =============================================================================

SEC("kprobe/vfs_read")
int trace_vfs_read(struct pt_regs *ctx)
{
    struct file *f = (struct file *)PT_REGS_PARM1(ctx);
    if (!f) return 0;

    u64 ino = BPF_CORE_READ(f, f_inode, i_ino);
    if (!inode_in_watchlist(ino)) return 0;

    // Timing
    sched_prev_read_ts = sched_last_read_ts;
    sched_last_read_ts = bpf_ktime_get_ns();
    sched_read_count += 1;

    // Read scheduler metrics from current task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Process priority / niceness
    sched_static_prio = BPF_CORE_READ(task, static_prio);
    sched_prio        = BPF_CORE_READ(task, prio);
    sched_nice        = sched_static_prio - 120;  // nice = static_prio - 120

    // CPU execution metrics from sched_entity
    sched_vruntime         = BPF_CORE_READ(task, se.vruntime);
    sched_sum_exec_runtime = BPF_CORE_READ(task, se.sum_exec_runtime);
    sched_nr_migrations    = BPF_CORE_READ(task, se.nr_migrations);

    // Run queue state
    struct cfs_rq *cfs = BPF_CORE_READ(task, se.cfs_rq);
    if (cfs) {
        sched_nr_running = BPF_CORE_READ(cfs, nr_running);
        sched_cfs_load   = BPF_CORE_READ(cfs, load.weight);
    }

    // Process identification
    u64 pid_tgid = bpf_get_current_pid_tgid();
    sched_pid    = (u32)pid_tgid;
    sched_tgid   = (u32)(pid_tgid >> 32);
    sched_on_cpu = BPF_CORE_READ(task, on_cpu);

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